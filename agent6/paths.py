"""全局路径与配置加载（复用项目根目录的 config.yaml，不新增依赖）。"""
from pathlib import Path

# 项目根目录：agent6/ 的上一级
BASE_DIR = Path(__file__).resolve().parent.parent
PKG_DIR = Path(__file__).resolve().parent

CONFIG_PATH = BASE_DIR / "config.yaml"
DATA_DIR = BASE_DIR / "agent6_data"
DB_PATH = DATA_DIR / "agent6.db"
SETTINGS_PATH = DATA_DIR / "settings.json"
WEBUI_STATIC_DIR = PKG_DIR / "webui" / "static"

# 统一落盘目录：所有 Agent / Skill 运行时产出的文件都集中存到这里，
# 便于清理与归档，避免散落在项目根目录（如旧的 data/、reports/）。
OUTPUT_DIR = DATA_DIR / "output"
REPORTS_DIR = OUTPUT_DIR / "reports"

# 确保数据目录 / 落盘目录存在
DATA_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def load_config() -> dict:
    """读取 config.yaml；无 pyyaml 时回退到极简解析。"""
    if not CONFIG_PATH.exists():
        return {}
    try:
        import yaml
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return _minimal_yaml(CONFIG_PATH)


def _minimal_yaml(path: Path) -> dict:
    """极简 YAML 子集解析，仅在缺 pyyaml 时兜底（仅支持 key: value 一层嵌套）。"""
    data, cur = {}, None
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        if ":" not in line:
            continue
        k, _, v = line.strip().partition(":")
        v = v.strip().strip('"').strip("'")
        if indent == 0:
            if v == "":
                cur = k
                data.setdefault(k, {})
            else:
                data[k] = _coerce(v)
                cur = None
        elif cur:
            data[cur][k] = _coerce(v)
    return data


def _coerce(v: str):
    if v.lower() in ("true", "false"):
        return v.lower() == "true"
    try:
        return int(v)
    except ValueError:
        pass
    try:
        return float(v)
    except ValueError:
        return v
