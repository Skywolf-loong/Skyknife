from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Any
from urllib.parse import unquote

# ----------------------------------------------------------------------------
# 统一落盘目录：所有 Skill 运行时产出的文件都集中到项目根下的
# agent6_data/output/，由子目录区分用途，避免散落在项目各处。
# （与 agent6/paths.py 中的 OUTPUT_DIR 指向同一物理目录，互为主备来源。）
# ----------------------------------------------------------------------------
_ARTIFACT_ROOT = Path(__file__).resolve().parent.parent / "agent6_data" / "output"
ARTIFACT_DIR = _ARTIFACT_ROOT
CRAWLER_CACHE_DIR = _ARTIFACT_ROOT / "crawler_cache"
PORTSCAN_DIR = _ARTIFACT_ROOT / "portscan"
SESSIONS_DIR = _ARTIFACT_ROOT / "sessions"
REPORTS_DIR = _ARTIFACT_ROOT / "reports"
for _d in (ARTIFACT_DIR, CRAWLER_CACHE_DIR, PORTSCAN_DIR, SESSIONS_DIR, REPORTS_DIR):
    try:
        _d.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass


# ----------------------------------------------------------------------------
# 通用参数规范化工具
# LLM 经常把 object / array / integer 类型的参数写成字符串，
# 直接使用会导致 AttributeError（如 'str' object has no attribute 'keys'）。
# 各 Skill 应通过这两个函数读取参数，而不是直接索引。
# ----------------------------------------------------------------------------
def coerce_dict(raw: Any) -> Dict:
    """把 object 类参数从 dict / JSON 串 / query string / 列表 统一成 dict。"""
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        s = raw.strip()
        if not s:
            return {}
        try:
            import json as _json
            d = _json.loads(s)
            if isinstance(d, dict):
                return d
            if isinstance(d, list):
                return {str(x): "1" for x in d}
        except Exception:
            pass
        if "=" in s:                       # a=1&b=2
            out = {}
            for part in s.split("&"):
                if not part:
                    continue
                k, _, v = part.partition("=")
                out[unquote(k)] = unquote(v)
            return out
        return {s: "1"}                    # 单个参数名
    if isinstance(raw, (list, tuple, set)):
        return {str(x): "1" for x in raw}
    return {}


def coerce_list(raw: Any) -> list:
    """把 array 类参数从 list / JSON 串 / 逗号分隔串 统一成 list。"""
    if raw is None:
        return []
    if isinstance(raw, list):
        return raw
    if isinstance(raw, tuple):
        return list(raw)
    if isinstance(raw, str):
        s = raw.strip()
        if not s:
            return []
        try:
            import json as _json
            v = _json.loads(s)
            if isinstance(v, list):
                return v
        except Exception:
            pass
        return [x.strip() for x in s.split(",") if x.strip()]
    return [raw]


class BaseSkill(ABC):
    """所有 Skill 必须继承此基类"""
    name: str = ""                # Skill 唯一名称
    description: str = ""         # 简短描述，供 LLM 参考
    parameters: Dict[str, Any] = {}  # JSON Schema 定义参数结构（可选）

    # ---------- 便捷方法：子类可直接复用 ----------
    @staticmethod
    def dict_param(params: Dict, key: str) -> Dict:
        return coerce_dict((params or {}).get(key))

    @staticmethod
    def list_param(params: Dict, key: str) -> list:
        return coerce_list((params or {}).get(key))

    @staticmethod
    def err(msg: str) -> Dict:
        return {"status": "error", "message": msg}

    def ok(self, data: Any = None, **extra) -> Dict:
        d = {"status": "success", "data": data if data is not None else {}}
        d.update(extra)
        return d

    @abstractmethod
    def execute(self, params: Dict[str, Any], context: Dict) -> Dict:
        """
        执行 Skill，返回统一格式：
        {
            "status": "success" | "error",
            "data": ...,       # 成功时的数据
            "message": ...     # 错误或提示信息
        }
        """
        pass