"""
运行期配置持久化（agent6_data/settings.json）。

约定：
- 读取时按「内置默认值 → config.yaml → settings.json」逐层合并，
  未提供过的字段不会被清空。
- api_key 对外一律脱敏（``sk-****1c1``）；前端回传脱敏串或空串时不覆盖已保存值，
  只有提交真实新值才更新，避免「打开设置页点保存把密钥洗成星星」。
- 所有读写都被 try/except 兜住：磁盘不可写时退化为内存默认，不影响主流程。
"""
import json
import threading
from typing import Any, Dict

from .paths import SETTINGS_PATH, load_config

MASK = "****"

# 允许前端提交的字段白名单（同时充当类型模板，用于强制类型转换）
LLM_FIELDS: Dict[str, Any] = {
    "base_url": "https://api.deepseek.com/v1/chat/completions",
    "api_key": "",
    "model": "deepseek-chat",
    "temperature": 0.1,
    "max_tokens": 2000,
    "request_timeout": 120,
}

AGENT_FIELDS: Dict[str, Any] = {
    "max_rounds": 20,
    "max_workers": 3,
    "planner_max_intents": 5,
    "mode": "SRC",
    "require_approval": False,
    "approval_timeout": 180,
    "token_budget": 0,
    "logic_agent": True,
    "chain_review": True,
    "context_compress": True,
    "compress_every": 3,
}

SECTION_FIELDS = {"llm": LLM_FIELDS, "agent": AGENT_FIELDS}

_LOCK = threading.RLock()


# ----------------------------------------------------------------------------
# 基础工具
# ----------------------------------------------------------------------------
def mask_secret(value: Any) -> str:
    """密钥脱敏：``sk-a29b...1c1`` → ``sk-****1c1``；过短则整体遮蔽。"""
    v = "" if value is None else str(value)
    if not v:
        return ""
    if len(v) <= 8:
        return MASK
    return f"{v[:3]}{MASK}{v[-4:]}"


def is_masked(value: Any) -> bool:
    """判断是否为脱敏回显值（前端原样回传时不应覆盖真实密钥）。"""
    return value is None or str(value).strip() == "" or MASK in str(value)


def _coerce(value: Any, template: Any) -> Any:
    """按模板类型强制转换，转换失败则回退模板值。"""
    if isinstance(template, bool):
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in ("1", "true", "yes", "on")
    if isinstance(template, int) and not isinstance(template, bool):
        try:
            return int(value)
        except Exception:
            return template
    if isinstance(template, float):
        try:
            return float(value)
        except Exception:
            return template
    return "" if value is None else str(value)


# ----------------------------------------------------------------------------
# 默认值：内置常量 + config.yaml 推断
# ----------------------------------------------------------------------------
def default_settings() -> Dict[str, Dict[str, Any]]:
    try:
        cfg = load_config() or {}
    except Exception:
        cfg = {}
    if not isinstance(cfg, dict):
        cfg = {}
    llm_cfg = cfg.get("llm") if isinstance(cfg.get("llm"), dict) else {}

    llm = dict(LLM_FIELDS)
    llm["model"] = str(llm_cfg.get("model") or LLM_FIELDS["model"])
    llm["temperature"] = _coerce(llm_cfg.get("temperature"), LLM_FIELDS["temperature"])
    llm["max_tokens"] = _coerce(llm_cfg.get("max_tokens"), LLM_FIELDS["max_tokens"])
    llm["request_timeout"] = _coerce(llm_cfg.get("request_timeout"),
                                     LLM_FIELDS["request_timeout"])
    # 未单独保存过 Key 时，界面显示 config.yaml / 环境变量里那份（脱敏）
    llm["api_key"] = str(cfg.get("api_key") or "")
    return {"llm": llm, "agent": dict(AGENT_FIELDS)}


# ----------------------------------------------------------------------------
# 读
# ----------------------------------------------------------------------------
def load_settings() -> Dict[str, Dict[str, Any]]:
    """返回与默认值合并后的完整设置（含真实 api_key，仅限进程内使用）。"""
    merged = default_settings()
    try:
        if SETTINGS_PATH.exists():
            raw = json.loads(SETTINGS_PATH.read_text(encoding="utf-8") or "{}")
            if isinstance(raw, dict):
                for sec, fields in SECTION_FIELDS.items():
                    got = raw.get(sec)
                    if isinstance(got, dict):
                        for k, v in got.items():
                            if k in fields:
                                merged[sec][k] = _coerce(v, fields[k])
    except Exception:
        pass
    return merged


def public_settings() -> Dict[str, Dict[str, Any]]:
    """对外回显：api_key 脱敏，并附带 api_key_set 便于界面提示是否已配置。"""
    st = load_settings()
    llm = dict(st.get("llm") or {})
    llm["api_key"] = mask_secret(llm.get("api_key"))
    llm["api_key_set"] = bool(st.get("llm", {}).get("api_key"))
    return {"llm": llm, "agent": dict(st.get("agent") or {})}


# ----------------------------------------------------------------------------
# 写
# ----------------------------------------------------------------------------
def save_section(section: str, patch: Dict) -> Dict[str, Dict[str, Any]]:
    """按白名单合并保存某一分区，返回保存后的完整设置（未脱敏）。"""
    fields = SECTION_FIELDS.get(section)
    if not fields:
        raise ValueError(f"未知配置分区: {section}")

    with _LOCK:
        cur = load_settings()
        sec = dict(cur.get(section) or {})
        for k, v in (patch or {}).items():
            if k not in fields:
                continue
            if k == "api_key" and is_masked(v):
                continue  # 脱敏回显值 / 空值：保留原密钥
            sec[k] = _coerce(v, fields[k])
        cur[section] = sec
        try:
            SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
            SETTINGS_PATH.write_text(
                json.dumps(cur, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            pass  # 写盘失败不影响内存态，界面仍可继续使用
        return cur


def llm_kwargs() -> Dict[str, Any]:
    """给 LLMClient 用的配置：settings 中已保存项优先于 config.yaml。"""
    st = load_settings()
    llm = st.get("llm") or {}
    return {
        "api_url": llm.get("base_url") or LLM_FIELDS["base_url"],
        "model": llm.get("model") or LLM_FIELDS["model"],
        "temperature": llm.get("temperature"),
        "max_tokens": llm.get("max_tokens"),
        "request_timeout": llm.get("request_timeout"),
    }
