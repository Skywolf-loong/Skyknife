"""
LLM 客户端：复用 config.yaml / 环境变量中的 Key，带 Token 用量回写。

- 真实客户端 LLMClient 走 OpenAI 兼容接口（与现有 core.llm_broker 一致）。
- DryRunLLM 用于离线联调/演示，不需要网络与 Key。
- **响应缓存**：确定性调用（temperature <= 阈值）按内容哈希命中缓存，相同 prompt
  不再重复请求，直接省 token；命中不写 llm_usage，避免虚增消耗。
"""
import json
import os
from typing import Callable, Dict, List, Optional

from .context import CACHE
from .paths import load_config

DEFAULT_URL = "https://api.deepseek.com/v1/chat/completions"


def normalize_api_url(url: Optional[str]) -> str:
    """把用户填的 base_url / api_url 规范化为完整 chat/completions 端点。

    兼容三种写法：
      - https://api.deepseek.com                -> https://api.deepseek.com/chat/completions
      - https://api.deepseek.com/v1             -> https://api.deepseek.com/v1/chat/completions
      - https://api.deepseek.com/v1/chat/completions -> 原样返回
    避免「把 base_url 直接当端点 POST」导致的 404（此前版本的默认端点始终带完整路径）。
    """
    u = (url or DEFAULT_URL).strip().rstrip("/")
    if not u:
        return DEFAULT_URL
    if u.endswith("/chat/completions"):
        return u
    return u + "/chat/completions"


def _resolve_api_key() -> Optional[str]:
    # 1. 环境变量
    key = os.environ.get("DEEPSEEK_API_KEY") or os.environ.get("OPENAI_API_KEY")
    if key:
        return key
    # 2. 复用 core.llm_broker（若可导入）
    try:
        import sys
        from pathlib import Path
        root = Path(__file__).resolve().parent.parent
        if str(root) not in sys.path:
            sys.path.insert(0, str(root))
        from core.llm_broker import get_api_key as _core_key  # type: ignore
        return _core_key()
    except Exception:
        pass
    # 3. config.yaml
    cfg = load_config()
    return cfg.get("api_key")


class LLMClient:
    """OpenAI 兼容客户端，支持用量统计回写。"""

    def __init__(self, session_store=None, task_id: Optional[str] = None, cfg: Dict = None,
                 api_key: Optional[str] = None):
        self.cfg = cfg or load_config()
        self.llm_cfg = self.cfg.get("llm", {})
        self.session_store = session_store
        self.task_id = task_id
        # 兼容 api_url（历史）与 base_url（设置页）两种字段名，并做端点规范化
        raw = self.llm_cfg.get("api_url") or self.llm_cfg.get("base_url") or DEFAULT_URL
        self.url = normalize_api_url(raw)
        # 界面保存的 Key 优先于环境变量 / config.yaml
        self.api_key = api_key or None

    def chat(self, messages: List[Dict], agent: str = "planner",
             model: Optional[str] = None, temperature: Optional[float] = None,
             max_tokens: Optional[int] = None, retries: int = 2,
             use_cache: Optional[bool] = None) -> str:
        from .context import estimate_tokens

        eff_model = model or self.llm_cfg.get("model", "deepseek-chat")
        eff_temp = self.llm_cfg.get("temperature", 0.1) if temperature is None else temperature
        eff_maxtok = self.llm_cfg.get("max_tokens", 2000) if max_tokens is None else max_tokens

        # ---- 响应缓存：确定性调用命中即省一次往返与全部 token ----
        cache_on = CACHE.cacheable(eff_temp) if use_cache is None else bool(use_cache)
        ckey = None
        if cache_on:
            ckey = CACHE.key(messages, eff_model, eff_temp, eff_maxtok)
            hit = CACHE.get(ckey)
            if hit is not None:
                return hit

        import requests

        api_key = self.api_key or _resolve_api_key()
        if not api_key:
            raise RuntimeError("未找到 API Key，请设置 DEEPSEEK_API_KEY 或在 config.yaml 配置 api_key")

        payload = {
            "model": eff_model,
            "messages": messages,
            "temperature": eff_temp,
            "max_tokens": eff_maxtok,
            "stream": False,
        }
        headers = {"Content-Type": "application/json",
                   "Authorization": f"Bearer {api_key}"}
        timeout = self.llm_cfg.get("request_timeout", 120)

        last_err = None
        for attempt in range(retries + 1):
            try:
                resp = requests.post(self.url, headers=headers, json=payload, timeout=timeout)
                resp.raise_for_status()
                data = resp.json()
                content = data["choices"][0]["message"]["content"].strip()
                usage = data.get("usage", {}) or {}
                if ckey:
                    CACHE.put(ckey, content,
                              usage.get("prompt_tokens", 0),
                              usage.get("completion_tokens", 0))
                if self.session_store and self.task_id:
                    self.session_store.log_usage(
                        self.task_id, agent, payload["model"],
                        usage.get("prompt_tokens", 0),
                        usage.get("completion_tokens", 0),
                    )
                return content
            except Exception as e:  # noqa
                last_err = e
                if attempt < retries:
                    continue
        raise RuntimeError(f"LLM 调用失败: {last_err}")


class DryRunLLM:
    """
    离线假 LLM：按调用次数返回预置响应序列，用于联调编排逻辑。
    responder(messages, agent) -> str 可自定义；否则使用 responses 列表轮转。
    """

    def __init__(self, responses: Optional[List[str]] = None,
                 responder: Optional[Callable[[List[Dict], str], str]] = None,
                 session_store=None, task_id=None):
        self.responses = responses or []
        self.responder = responder
        self.idx = 0
        self.session_store = session_store
        self.task_id = task_id
        self.calls = []

    def chat(self, messages: List[Dict], agent: str = "planner", **kw) -> str:
        self.calls.append({"agent": agent, "messages": messages})
        if self.session_store and self.task_id:
            self.session_store.log_usage(self.task_id, agent, "dry-run", 100, 50)
        if self.responder:
            return self.responder(messages, agent)
        if not self.responses:
            return json.dumps({"kind": "finish", "reason": "no more responses"})
        r = self.responses[min(self.idx, len(self.responses) - 1)]
        self.idx += 1
        return r
