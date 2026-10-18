"""
上下文压缩与 Token 优化。

三件事（零第三方依赖）：
1. **token 估算**：中文按字、英文按 ~4 字符估算，用于预算控制与"压缩是否值得"的判断。
2. **会话压缩 compress_messages**：长会话只保留 system + 最近若干条，把更早的
   工具结果/助手思考折叠成一条结构化摘要，避免 ReAct 循环把上下文越滚越大。
3. **LLM 响应缓存 ResponseCache**：对确定性调用（低温度）按 内容哈希 命中缓存，
   相同 prompt 不再重复请求，直接省 token（渗透流程里重复提问非常常见）。

全部为纯函数 / 轻量类，失败不影响主流程。
"""
import hashlib
import json
import re
import threading
from collections import OrderedDict
from typing import Any, Dict, List, Optional, Tuple

_CJK_RE = re.compile(r"[\u4e00-\u9fff\u3040-\u30ff\uac00-\ud7af]")


def estimate_tokens(text: Any) -> int:
    """粗略估算 token 数：中日韩字符 1 字≈1 token，其余按 ~4 字符≈1 token。"""
    s = "" if text is None else str(text)
    if not s:
        return 0
    cjk = len(_CJK_RE.findall(s))
    other = max(0, len(s) - cjk)
    return int(cjk + other / 4) + 1


def messages_tokens(messages: List[Dict]) -> int:
    if not messages:
        return 0
    total = 0
    for m in messages:
        c = m.get("content")
        if isinstance(c, list):
            c = " ".join(str(x.get("text") if isinstance(x, dict) else x) for x in c)
        total += estimate_tokens(c) + 4
    return total


def _digest_line(text: str, limit: int = 200) -> str:
    """把一段长文本压成一行要害（首行 + 首个数字/URL 特征）。"""
    s = str(text or "").strip()
    if not s:
        return ""
    first = s.splitlines()[0].strip()
    if len(first) > limit:
        first = first[:limit] + "…"
    return first


def compress_messages(messages: List[Dict], keep_recent: int = 6,
                      max_tokens: int = 6000,
                      summarizer=None) -> Tuple[List[Dict], Dict]:
    """把过长的消息序列压缩到预算内。

    - 始终保留第 1 条（system）与最后 keep_recent 条；
    - 中间部分折叠成一条 user 消息（"早期上下文摘要"）；summarizer 可自定义摘要器
      （例如调用 LLM），否则退化为规则摘录。
    返回 (新消息, 统计)；未超预算时原样返回。
    """
    msgs = list(messages or [])
    used = messages_tokens(msgs)
    stat = {"compressed": False, "tokens_before": used, "tokens_after": used,
            "dropped": 0}
    if used <= max_tokens or len(msgs) <= keep_recent + 1:
        return msgs, stat

    head = msgs[0]
    tail = msgs[-keep_recent:]
    middle = msgs[1:len(msgs) - keep_recent]
    if not middle:
        return msgs, stat

    if callable(summarizer):
        try:
            summary = summarizer(middle)
        except Exception:
            summary = None
    else:
        summary = None
    if not summary:
        lines = []
        for m in middle:
            role = m.get("role", "?")
            tag = {"assistant": "思考", "user": "结果", "tool": "结果"}.get(role, role)
            text = m.get("content")
            if isinstance(text, list):
                text = " ".join(str(x) for x in text)
            d = _digest_line(text)
            if d:
                lines.append(f"- [{tag}] {d}")
        summary = ("【早期上下文已压缩，以下为要点摘要；如需细节请用过程检索工具查回】\n"
                   + "\n".join(lines[:40]))

    folded = {"role": "user",
              "content": summary + f"\n（以上为 {len(middle)} 条早期消息的压缩摘要）"}
    out = [head, folded] + list(tail)
    after = messages_tokens(out)
    stat.update({"compressed": True, "tokens_after": after,
                 "dropped": len(middle)})
    return out, stat


class ResponseCache:
    """确定性 LLM 调用的内容哈希缓存（线程安全 LRU）。

    仅当 temperature <= ``max_temp`` 且开启时才使用；命中直接返回旧响应，
    不产生任何 token 消耗。
    """

    def __init__(self, max_entries: int = 512, max_temp: float = 0.3,
                 enabled: bool = True):
        self.max_entries = max(8, int(max_entries))
        self.max_temp = float(max_temp)
        self.enabled = bool(enabled)
        self._data: "OrderedDict[str, str]" = OrderedDict()
        self._lock = threading.RLock()
        self.hits = 0
        self.misses = 0
        self.saved_tokens = 0

    # ---------- key ----------
    @staticmethod
    def key(messages: List[Dict], model: str, temperature: float,
            max_tokens: Any) -> str:
        try:
            payload = json.dumps(
                {"m": messages, "model": model, "t": round(float(temperature), 3),
                 "mt": max_tokens}, ensure_ascii=False, sort_keys=True, default=str)
        except Exception:
            payload = str(messages) + str(model)
        return hashlib.sha256(payload.encode("utf-8", "ignore")).hexdigest()

    def cacheable(self, temperature: float) -> bool:
        return self.enabled and float(temperature or 0) <= self.max_temp

    def get(self, key: str) -> Optional[str]:
        if not self.enabled:
            return None
        with self._lock:
            if key in self._data:
                self._data.move_to_end(key)
                self.hits += 1
                return self._data[key]
            self.misses += 1
            return None

    def put(self, key: str, value: str, prompt_tokens: int = 0,
            completion_tokens: int = 0):
        if not self.enabled or value is None:
            return
        with self._lock:
            self._data[key] = value
            self._data.move_to_end(key)
            self.saved_tokens += int(prompt_tokens or 0) + int(completion_tokens or 0)
            while len(self._data) > self.max_entries:
                self._data.popitem(last=False)

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            total = self.hits + self.misses
            return {"enabled": self.enabled, "entries": len(self._data),
                    "hits": self.hits, "misses": self.misses,
                    "hit_rate": round(self.hits / total, 4) if total else 0.0,
                    "saved_tokens": self.saved_tokens}

    def clear(self):
        with self._lock:
            self._data.clear()


# 进程级共享缓存（各 LLMClient / Agent 复用）
CACHE = ResponseCache()


def cache_stats() -> Dict[str, Any]:
    return CACHE.stats()
