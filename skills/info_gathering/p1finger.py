"""
P1finger 集成 Skill（v2 - 修复 _parse_output 识别真实输出格式）
调用 P1finger 指纹识别工具，用于 Web 资产的框架 / 中间件 / 组件指纹识别。

可执行文件查找顺序（见 _find_executable）：
  1. 环境变量 P1FINGER_EXE / P1FINGER_HOME（显式指定，优先级最高）
  2. 工程内置目录 tools/p1finger/（随项目携带，推荐）
  3. PATH
  4. 当前工作目录
"""
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional

from skills.base import BaseSkill


P1FINGER_GUIDE = """
P1finger 使用指南：
  - 本地指纹识别: p1finger rule -u <URL>
  - Fofa 查询    : p1finger fofa -u <URL>
  - 列出指纹库   : p1finger finger list
  - 全局参数     : -o <file> / --proxy <url> / --debug
  - 必须带协议，如 http://target.com 或 https://1.2.3.4:8443
"""

# 工程根目录：本文件位于 <root>/skills/info_gathering/
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
# 随项目携带的内置工具目录
_TOOLS_EXE_DIR = _PROJECT_ROOT / "tools" / "p1finger"
_EXE_NAMES = ("p1finger", "p1finger.exe")

# ANSI 色码（P1finger 输出会带色码）
_ANSI_RE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

def _strip_ansi(s: str) -> str:
    return _ANSI_RE.sub('', s) if s else (s or "")


class P1fingerSkill(BaseSkill):
    name = "p1finger"
    description = (
        "红队资产指纹识别工具 P1finger。识别 Web 目标的框架 / 中间件 / CMS 指纹 "
        "（Spring / Shiro / Nginx / ThinkPHP / 若依 / OA / WordPress 等），为后续漏洞验证提供方向。"
        "在信息收集阶段拿到 Web URL 后，**推荐优先调用此工具**。"
        "支持 rule（本地指纹库）和 fofa（Fofa 空间测绘）两种模式。"
        "同一 URL 只需调用一次，指纹不会变化。"
    )
    parameters = {
        "target": {"type": "string", "required": True,
                   "description": "目标 URL，如 http://example.com 或 https://1.2.3.4:8443"},
        "mode": {"type": "string", "default": "rule",
                 "description": "'rule'（本地指纹库，推荐）/ 'fofa'（Fofa 空间测绘）"},
        "output": {"type": "string",
                   "description": "输出文件（.csv 或 .json），可选"},
        "proxy": {"type": "string",
                  "description": "代理，如 socks5://127.0.0.1:1080，可选"},
        "debug": {"type": "boolean", "default": False,
                  "description": "是否输出调试信息"},
        "timeout": {"type": "number", "default": 90,
                    "description": "命令超时（秒）"},
    }

    def _find_executable(self) -> Optional[str]:
        """按固定顺序解析 p1finger 可执行文件，返回绝对路径或 None。

        1. 环境变量 P1FINGER_EXE（完整可执行文件路径）/ P1FINGER_HOME（工具目录）
        2. 工程内置目录 tools/p1finger/（随项目携带）
        3. PATH（shutil.which）
        4. 当前工作目录 ./p1finger(.exe)
        """
        candidates: List[Path] = []

        env_exe = os.environ.get("P1FINGER_EXE", "").strip()
        if env_exe:
            candidates.append(Path(env_exe))
        env_home = os.environ.get("P1FINGER_HOME", "").strip()
        if env_home:
            candidates += [Path(env_home) / n for n in _EXE_NAMES]

        candidates += [_TOOLS_EXE_DIR / n for n in _EXE_NAMES]

        for p in candidates:
            try:
                if p.is_file():
                    return str(p)
            except OSError:
                continue

        for name in _EXE_NAMES:
            found = shutil.which(name)
            if found:
                return found

        for name in _EXE_NAMES:
            p = Path(name)
            if p.is_file():
                return str(p)
        return None

    def _build_command(self, exe: str, params: Dict[str, Any]) -> List[str]:
        mode = str(params.get("mode", "rule")).lower()
        if mode not in ("rule", "fofa"):
            mode = "rule"
        target = str(params["target"]).strip()
        cmd = [exe, mode, "-u", target]
        if params.get("output"):
            cmd += ["-o", str(params["output"])]
        if params.get("proxy"):
            cmd += ["--proxy", str(params["proxy"])]
        if params.get("debug"):
            cmd += ["--debug"]
        return cmd

    def _run(self, cmd: List[str], timeout: float) -> Dict[str, Any]:
        try:
            result = subprocess.run(
                cmd, capture_output=True, timeout=timeout,
                text=False, shell=False,
            )
            output = ""
            for enc in ("utf-8", "gbk", "cp936", "latin-1"):
                try:
                    output = result.stdout.decode(enc, errors="replace")
                    if output.strip():
                        break
                except Exception:
                    continue
            err = ""
            for enc in ("utf-8", "gbk", "cp936", "latin-1"):
                try:
                    err = result.stderr.decode(enc, errors="replace")
                    if err.strip():
                        break
                except Exception:
                    continue
            return {
                "returncode": result.returncode,
                "stdout": output.strip(),
                "stderr": err.strip(),
            }
        except subprocess.TimeoutExpired:
            return {"returncode": -1, "stdout": "", "stderr": f"命令超时（>{timeout}s）"}
        except FileNotFoundError:
            return {"returncode": -1, "stdout": "", "stderr": "未找到 p1finger 可执行文件"}
        except Exception as e:
            return {"returncode": -1, "stdout": "", "stderr": str(e)}

    # v2: 重写 _parse_output，识别 P1finger 真实输出格式
    # 真实格式（ANSI 色码已剥）：
    #   [200] https://example.com/ [Example Site - Home] WordPress
    #   [200] https://x.com/ [title] Nginx PHP WordPress
    # 兜底旧格式：
    #   [+] xxx
    #   命中/匹配/found/hit/fingerprint: xxx
    def _parse_output(self, text: str) -> Dict[str, Any]:
        if not text:
            return {}
        # 先剥 ANSI 色码
        text_clean = _strip_ansi(text)
        parsed: Dict[str, Any] = {"raw": text_clean[:4000]}
        hits: List[str] = []

        for raw_line in text_clean.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            # 格式1（主）：[状态码] URL [标题] 指纹1 指纹2 ...
            # 状态码 100-599，URL 非空，标题在 [] 中，末尾是空格分隔的指纹串
            m1 = re.match(
                r'^\[(\d{3})\]\s+(\S+)\s+\[([^\]]*)\]\s*(.+?)\s*$',
                line,
            )
            if m1:
                fingerprints_str = m1.group(4).strip()
                if fingerprints_str:
                    # 可能包含多个指纹（空格分隔）；每个指纹可能含空格（如 "WordPress 5.1.19"）
                    # 简单策略：整体作为一个 hit 加入，同时按大粒度切分常用产品名
                    # 主指纹串整体加入
                    hits.append(fingerprints_str)
                    # 切分出单个产品名（大写开头的词 + 可能的版本号）
                    # 例："Nginx PHP WordPress 5.1.19" → ["Nginx", "PHP", "WordPress 5.1.19"]
                    for token in self._split_fingerprints(fingerprints_str):
                        if token and token != fingerprints_str:
                            hits.append(token)
                continue

            # 格式2：命中/匹配/found/hit/fingerprint: xxx
            m2 = re.search(r'(?:命中|匹配|found|hit|finger(?:print)?)\s*[:：]\s*(.+)', line, re.I)
            if m2:
                hits.append(m2.group(1).strip())
                continue

            # 格式3：[+] xxx
            m3 = re.match(r'^\s*\[\+\]\s*(.+)', line)
            if m3:
                hits.append(m3.group(1).strip())
                continue

        # 去重（保持顺序）
        seen = set()
        unique_hits = []
        for h in hits:
            if h and h not in seen:
                seen.add(h)
                unique_hits.append(h)

        if unique_hits:
            parsed["matches"] = unique_hits
            parsed["match_count"] = len(unique_hits)
        else:
            parsed["matches"] = []
            parsed["match_count"] = 0
        return parsed

    @staticmethod
    def _split_fingerprints(s: str) -> List[str]:
        """从指纹串中切分出单个产品名（保留产品名+版本）。
        例: "Nginx PHP WordPress 5.1.19" → ["Nginx", "PHP", "WordPress 5.1.19"]
        """
        if not s:
            return []
        # 用空格切分；如果一个 token 后跟版本号，合并
        tokens = s.split()
        result = []
        i = 0
        version_re = re.compile(r'^\d+(?:\.\d+)*')
        while i < len(tokens):
            t = tokens[i]
            # 如果下一个 token 是纯版本号，合并
            if i + 1 < len(tokens) and version_re.match(tokens[i + 1]):
                result.append(f"{t} {tokens[i + 1]}")
                i += 2
            else:
                result.append(t)
                i += 1
        return result

    def execute(self, params: Dict[str, Any], context: Dict) -> Dict:
        target = params.get("target")
        if not target:
            return {"status": "error", "message": "缺少必需参数 'target'"}

        target = str(target).strip()
        if not target.startswith(("http://", "https://")):
            target = "http://" + target
        params = {**params, "target": target}

        cache_key = f"p1finger::{params.get('mode', 'rule')}::{target.lower().rstrip('/')}"
        if cache_key in context:
            return {
                "status": "success",
                "message": "该 URL 已做过 P1finger 指纹识别，复用缓存结果",
                "data": context[cache_key],
                "cached": True,
            }

        exe = self._find_executable()
        if not exe:
            return {
                "status": "error",
                "message": (
                    "未找到 p1finger 可执行文件。请任选其一配置：\n"
                    "  1. 放到工程内置目录 tools/p1finger/（推荐，随项目携带）；\n"
                    "  2. 设置环境变量 P1FINGER_EXE=<可执行文件路径>，"
                    "或 P1FINGER_HOME=<工具目录>；\n"
                    "  3. 安装后加入 PATH。\n"
                    f"shutil.which('p1finger') = {shutil.which('p1finger')}"
                ),
            }

        cmd = self._build_command(exe, params)
        timeout = float(params.get("timeout", 90))
        print(f"[p1finger] 执行: {' '.join(cmd)}")

        run = self._run(cmd, timeout)
        if run["returncode"] != 0 and not run["stdout"]:
            return {
                "status": "error",
                "message": (
                    f"p1finger 执行失败（返回码 {run['returncode']}）："
                    f"{run['stderr'][:500] or '无 stderr 输出'}"
                ),
            }

        parsed = self._parse_output(run["stdout"])
        data = {
            "target": target,
            "mode": params.get("mode", "rule"),
            "matches": parsed.get("matches", []),
            "match_count": parsed.get("match_count", 0),
            "raw_output": _strip_ansi(run["stdout"])[:4000],
            "stderr": _strip_ansi(run["stderr"])[:500] if run["stderr"] else None,
        }

        context[cache_key] = data
        context.setdefault("p1finger_results", []).append(data)

        return {
            "status": "success",
            "message": f"p1finger 指纹识别完成（{data['match_count']} 条命中）",
            "data": data,
        }
