"""通用工具：JSON 提取（复用 core.utils，带兜底实现）。"""
import json
import re


def _fallback_extract_json(text: str):
    if not isinstance(text, str):
        return None
    # 去掉 ```json ``` 包裹
    m = re.search(r"```(?:json)?\s*(.*?)```", text, re.S)
    if m:
        text = m.group(1)
    try:
        return json.loads(text)
    except Exception:
        pass
    dec = json.JSONDecoder()
    for i, ch in enumerate(text):
        if ch in "{[":
            try:
                obj, _ = dec.raw_decode(text[i:])
                return obj
            except Exception:
                continue
    return None


def extract_json(text: str):
    try:
        import sys
        from pathlib import Path
        root = Path(__file__).resolve().parent.parent
        if str(root) not in sys.path:
            sys.path.insert(0, str(root))
        from core.utils import extract_json as _core  # type: ignore
        obj = _core(text)
        if obj is not None:
            return obj
    except Exception:
        pass
    return _fallback_extract_json(text)
