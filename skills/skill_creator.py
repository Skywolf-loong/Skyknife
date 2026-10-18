import ast
import re
from pathlib import Path
from typing import Dict, Any, List, Tuple
from skills.base import BaseSkill

# 黑名单：禁止导入的模块
BLACKLIST_IMPORTS = {
    'os', 'subprocess', 'sys', 'shutil', 'socket', 'ssl',
    'ctypes', 'cffi', 'pickle', 'marshal', 'imp', 'importlib',
    'pdb', 'code', 'codeop', 'pty', 'fcntl', 'resource',
    'winreg', 'msvcrt'
}

# 黑名单：禁止调用的函数/属性
BLACKLIST_ATTRS = {
    'eval', 'exec', 'compile', '__import__', 'execfile',
    'open', 'file', 'input', 'raw_input',
    'system', 'popen', 'spawn', 'fork', 'execl', 'execv',
    'remove', 'unlink', 'rmdir', 'rename', 'chmod', 'chown',
    'mkfifo', 'mknod', 'mount', 'umount'
}

# 允许的第三方库（标准库默认允许，但这里显式列出）
ALLOWED_LIBRARIES = {
    'requests', 'bs4', 'json', 're', 'time', 'datetime',
    'urllib', 'hashlib', 'base64', 'random', 'typing',
    'collections', 'itertools', 'math', 'string',
    'aiohttp', 'yaml', 'xml', 'csv', 'io'
}

class CreateSkillSkill(BaseSkill):
    name = "create_skill"
    description = "安全地创建新的 Skill，自动进行代码审查"
    parameters = {
        "skill_name": {"type": "string", "required": True},
        "description": {"type": "string"},
        "code": {"type": "string", "required": True}
    }

    def execute(self, params: Dict[str, Any], context: Dict) -> Dict:
        skill_name = params.get("skill_name")
        code = params.get("code", "")
        if not skill_name or not code:
            return {"status": "error", "message": "缺少 skill_name 或 code"}

        # 1. 结构验证
        if not self._validate_structure(skill_name, code):
            return {"status": "error", "message": "类名必须与 skill_name 一致，且包含 execute 方法"}

        # 2. 安全审查
        safe, errors = self._security_check(code)
        if not safe:
            return {"status": "error", "message": f"安全审查失败: {', '.join(errors)}"}

        # 3. 检查使用说明
        if not self._has_usage(code):
            return {"status": "error", "message": "类缺少文档字符串或 usage 属性"}

        # 4. 保存到 custom 子目录
        skills_dir = Path("skills") / "custom"
        skills_dir.mkdir(parents=True, exist_ok=True)
        filepath = skills_dir / f"{skill_name}.py"
        if filepath.exists():
            return {"status": "error", "message": f"Skill '{skill_name}' 已存在"}

        # 5. 用户确认
        print(f"\n[创建 Skill] 将保存到 {filepath}")
        print("代码预览（前500字符）：")
        print(code[:500] + ("..." if len(code) > 500 else ""))
        if input("确认保存并加载？(y/N): ").strip().lower() != 'y':
            return {"status": "error", "message": "用户取消"}

        # 6. 写入文件
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(code)
            return {
                "status": "success",
                "message": f"Skill '{skill_name}' 已创建",
                "data": {"file": str(filepath)}
            }
        except Exception as e:
            return {"status": "error", "message": f"保存失败: {e}"}

    def _validate_structure(self, skill_name: str, code: str) -> bool:
        return bool(re.search(rf"class\s+{skill_name}\s*[:\(]", code)) and "def execute" in code

    def _has_usage(self, code: str) -> bool:
        return bool(re.search(r'class\s+\w+\s*[:\(][^:]*?\"\"\"', code, re.DOTALL)) or \
               bool(re.search(r'usage\s*=\s*["\']', code))

    def _security_check(self, code: str) -> Tuple[bool, List[str]]:
        errors = []
        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            return False, [f"语法错误: {e}"]

        for node in ast.walk(tree):
            # 检查导入
            if isinstance(node, ast.Import):
                for alias in node.names:
                    mod = alias.name.split('.')[0]
                    if mod in BLACKLIST_IMPORTS:
                        errors.append(f"禁止导入 {mod}")
                    elif mod not in ALLOWED_LIBRARIES and not mod.startswith('skills.'):
                        errors.append(f"未授权库: {mod}")
            elif isinstance(node, ast.ImportFrom):
                mod = node.module.split('.')[0] if node.module else ''
                if mod in BLACKLIST_IMPORTS:
                    errors.append(f"禁止从 {mod} 导入")
                elif mod and mod not in ALLOWED_LIBRARIES and not mod.startswith('skills.'):
                    errors.append(f"未授权库: {mod}")

            # 检查危险调用
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Attribute):
                    attr = func.attr
                    if attr in BLACKLIST_ATTRS:
                        errors.append(f"禁止调用 {attr}")
                    if isinstance(func.value, ast.Name) and func.value.id in BLACKLIST_IMPORTS:
                        errors.append(f"禁止使用 {func.value.id}.{attr}")
                elif isinstance(func, ast.Name) and func.id in BLACKLIST_ATTRS:
                    errors.append(f"禁止调用 {func.id}")

        return len(errors) == 0, errors
