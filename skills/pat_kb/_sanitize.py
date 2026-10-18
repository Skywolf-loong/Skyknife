# -*- coding: utf-8 -*-
"""pat_kb 知识型 Skill 公共工具：懒加载 + 消毒 + 章节切分。

消毒目标（与 claude_red 一致）：
  1) 阻断"下载即执行 / 远程脚本执行 / 根目录删除"等可误执行片段
  2) 把文档里的提示注入载荷标记为"示例·已消毒"，避免成为本 Agent 的真实指令
"""
import re
from pathlib import Path

_CACHE = {}

_SANITIZERS = [
    # 下载即执行：curl|sh / wget|sh / |bash
    (re.compile(r"(\|\s*)(sudo\s+)?(sh|bash|zsh)\b"), r"\1#\2\3  # [消毒] 已阻断下载即执行"),
    # PowerShell IEX
    (re.compile(r"\b(IEX|Invoke-Expression)\s*\("), r"#\1(  # [消毒] 已阻断远程脚本执行"),
    # 根目录删除
    (re.compile(r"(?i)\brm\s+-rf\s+/"), "rm -rf #/  # [消毒] 已阻断根目录删除"),
    # 提示注入（英文，行首或列表项）
    (re.compile(r"(?im)^(\s*(?:[-*>]|\d+[.)])?\s*\[?)(IGNORE\s+(?:ALL\s+)?(?:PREVIOUS|PRIOR)\s+INSTRUCTIONS?\]?[:.]?)"),
     r"\1[提示注入示例·已消毒] "),
    # 提示注入（英文，行内任意位置）
    (re.compile(r"(?i)(ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions?)"),
     r"[提示注入示例·已消毒] \1"),
    (re.compile(r"(?i)\b(disregard\s+(?:all\s+)?(?:previous|prior)\s+instructions)\b"),
     r"[提示注入示例·已消毒] \1"),
    (re.compile(r"(?i)\b(do\s+not\s+tell\s+the\s+user|without\s+asking\s+the\s+user|forget\s+(everything|all\s+previous))\b"),
     r"[提示注入示例·已消毒] \1"),
    (re.compile(r"(?i)\b(system\s+prompt|new\s+instructions?\s*:)\b"),
     r"[提示注入示例·已消毒] \1"),
    # 提示注入（中文，含行内）
    (re.compile(r"(忽略(以上|之前|前面)(的)?(所有)?指令|系统提示词|不要(告诉|让)用户(知道)?)"),
     r"[提示注入示例·已消毒] \1"),
]

_H2_RE = re.compile(r"(?m)^##\s+(.+?)\s*$")


def load_knowledge(path: Path) -> str:
    key = str(path)
    if key not in _CACHE:
        _CACHE[key] = path.read_text(encoding="utf-8", errors="replace")
    return _CACHE[key]


def sanitize_text(text: str) -> str:
    out = text or ""
    for rx, rep in _SANITIZERS:
        out = rx.sub(rep, out)
    return out


def pick_sections(body: str):
    marks = [(m.start(), m.group(1).strip()) for m in _H2_RE.finditer(body)]
    if not marks:
        return []
    out = []
    for i, (pos, title) in enumerate(marks):
        end = marks[i + 1][0] if i + 1 < len(marks) else len(body)
        out.append({"title": title, "text": body[pos:end].strip()})
    return out
