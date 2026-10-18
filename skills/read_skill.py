from pathlib import Path
from typing import Dict, Any
from skills.base import BaseSkill

class ReadSkillSkill(BaseSkill):
    name = "read_skill"
    description = "读取指定 Skill 的源代码，返回文件内容"
    parameters = {
        "skill_name": {"type": "string", "required": True, "description": "Skill 名称（不含 .py）"}
    }

    def execute(self, params: Dict[str, Any], context: Dict) -> Dict:
        skill_name = params.get("skill_name")
        if not skill_name:
            return {"status": "error", "message": "缺少 skill_name"}
        # 搜索 skills 目录下所有子目录中的 .py 文件
        skills_root = Path("skills")
        for py_file in skills_root.rglob(f"{skill_name}.py"):
            if py_file.is_file():
                try:
                    with open(py_file, 'r', encoding='utf-8') as f:
                        code = f.read()
                    return {"status": "success", "data": {"code": code, "file": str(py_file)}}
                except Exception as e:
                    return {"status": "error", "message": f"读取文件失败: {e}"}
        return {"status": "error", "message": f"未找到 Skill: {skill_name}"}