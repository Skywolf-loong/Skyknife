import os
import importlib
import pkgutil
import sys
from pathlib import Path
from typing import Dict, Type, Any
from skills.base import BaseSkill

class SkillManager:
    def __init__(self, skills_dir: str = "skills", recursive: bool = True):
        self.skills_dir = skills_dir
        self.skills: Dict[str, Type] = {}
        self._candidates = []     # [(skill_name, module_name, class)]
        self._conflicts = []      # [(skill_name, 被跳过的模块)]
        self._source = {}         # {skill_name: 实际采用的模块}
        self._load_skills(skills_dir, recursive)
        self._resolve()

    def conflicts(self):
        """返回加载过程中被跳过的同名 Skill（用于排查重复定义）。"""
        return list(self._conflicts)

    def source_of(self, skill_name: str):
        """返回该 Skill 实际采用的模块来源，便于排查重复定义。"""
        return self._source.get(skill_name)

    def _load_skills(self, directory: str, recursive: bool):
        base_path = Path(directory)
        if not base_path.exists():
            print(f"[警告] Skills 目录 '{directory}' 不存在")
            return

        # 递归遍历
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith(".py") and file != "__init__.py":
                    module_path = Path(root) / file
                    # 转为包路径: skills/info_gathering/dns_enum -> skills.info_gathering.dns_enum
                    rel_path = module_path.relative_to(base_path.parent)  # 相对于 skills 上级
                    module_name = str(rel_path).replace(os.sep, ".").replace(".py", "")
                    self._import_module(module_name)
            if not recursive:
                break

    def _import_module(self, module_name: str):
        """导入模块并收集其中的 Skill 候选（不立即注册，交由 _resolve 裁决同名冲突）。"""
        try:
            module = importlib.import_module(module_name)
            for attr_name in dir(module):
                obj = getattr(module, attr_name)
                if not isinstance(obj, type):
                    continue
                if issubclass(obj, BaseSkill) and obj is not BaseSkill:
                    try:
                        instance = obj()
                        skill_name = getattr(instance, 'name', None)
                    except Exception:
                        skill_name = getattr(obj, 'name', None)
                    if not skill_name:
                        skill_name = obj.__name__.lower()
                    self._candidates.append((skill_name, module_name, obj))
        except Exception as e:
            print(f"[SkillManager] 加载模块 {module_name} 失败: {e}")

    def _resolve(self):
        """
        裁决同名 Skill：优先采用「模块名与技能名一致」的实现。
        例如 auto_discovery.py 内部也定义了 PortScanSkill，若不裁决，
        简化版可能覆盖 skills/info_gathering/port_scan.py 中的完整实现。
        """
        best = {}
        for skill_name, module_name, cls in self._candidates:
            base = module_name.rsplit(".", 1)[-1]
            if base == skill_name:
                score = 0            # 模块名与技能名完全一致：最可信
            elif skill_name in base:
                score = 1
            else:
                score = 2            # 只是被 import 进来的同名类
            prev = best.get(skill_name)
            if prev is None or score < prev[0]:
                if prev is not None:
                    self._conflicts.append((skill_name, prev[1]))
                best[skill_name] = (score, module_name, cls)
            else:
                self._conflicts.append((skill_name, module_name))

        for skill_name, (score, module_name, cls) in best.items():
            self.skills[skill_name] = cls
            self._source[skill_name] = module_name
            print(f"[SkillManager] 已加载 Skill: {skill_name} (来自 {module_name})")

    def get_skill(self, name: str) -> Type:
        return self.skills.get(name)

    def list_skills(self) -> Dict[str, str]:
        result = {}
        for name, cls in self.skills.items():
            try:
                instance = cls()
                desc = getattr(instance, 'description', None)
                if not desc:
                    doc = cls.__doc__
                    if doc:
                        desc = doc.strip().split('\n')[0]
                    else:
                        desc = "（无描述）"
                result[name] = desc
            except Exception:
                result[name] = "（无描述）"
        return result

    def get_skills_info(self) -> Dict[str, Dict]:
        """
        返回 {skill_name: { 'description': ..., 'parameters': {...}, 'required': [...] }}
        用于构建系统提示，让AI了解每个skill的参数。
        """
        info = {}
        for name, cls in self.skills.items():
            try:
                instance = cls()
                desc = getattr(instance, 'description', None)
                if not desc:
                    doc = cls.__doc__
                    if doc:
                        desc = doc.strip().split('\n')[0]
                    else:
                        desc = "（无描述）"
                # 获取参数信息（从实例属性或类属性）
                params = getattr(instance, 'parameters', {})
                if not params:
                    params = getattr(cls, 'parameters', {})
                # 提取必需的参数名
                required = [k for k, v in params.items() if v.get('required', False)]
                info[name] = {
                    'description': desc,
                    'parameters': params,
                    'required': required
                }
            except Exception as e:
                info[name] = {'description': '（加载失败）', 'parameters': {}, 'required': []}
        return info
    
    def execute(self, skill_name: str, params: Dict[str, Any], context: Dict) -> Dict:
        cls = self.get_skill(skill_name)
        if not cls:
            return {"status": "error", "message": f"Skill '{skill_name}' 未找到"}
        instance = cls()
        try:
            return instance.execute(params, context)
        except Exception as e:
            return {"status": "error", "message": f"执行 Skill 时发生错误: {str(e)}"}
