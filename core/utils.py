import json
import re
import hashlib
import difflib

def extract_json(text: str):
    """从文本中提取 JSON 对象（增强鲁棒性）"""
    # 尝试直接解析（若整个文本是 JSON）
    try:
        return json.loads(text)
    except:
        pass

    # 使用正则提取最外层 JSON 对象或数组
    # 匹配以 { 或 [ 开头，以 } 或 ] 结尾的完整片段
    # 使用非贪婪匹配，并考虑嵌套
    # 简单方法：找到第一个 { 或 [，然后计数匹配
    decoder = json.JSONDecoder()
    idx = 0
    while idx < len(text):
        # 跳过非 JSON 起始字符
        while idx < len(text) and text[idx] not in '{[':
            idx += 1
        if idx >= len(text):
            break
        try:
            obj, end = decoder.raw_decode(text, idx)
            if end > idx:
                return obj
        except json.JSONDecodeError:
            # 尝试用正则匹配 { ... } 或 [ ... ]
            match = re.search(r'(\{.*\}|\[.*\])', text[idx:], re.DOTALL)
            if match:
                candidate = match.group(1)
                try:
                    return json.loads(candidate)
                except:
                    pass
            idx += 1
            continue
        idx = end
    return None

def hash_action(action_obj):
    action_type = action_obj.get("action")
    params = action_obj.get("params", {})
    if action_type == "command":
        cmd = params.get("command", "")
        return hashlib.md5(f"{action_type}:{cmd}".encode()).hexdigest()
    elif action_type == "skill":
        skill_name = params.get("skill", "")
        skill_params = params.get("params", {})
        param_str = json.dumps(skill_params, sort_keys=True)
        return hashlib.md5(f"{action_type}:{skill_name}:{param_str}".encode()).hexdigest()
    else:
        return hashlib.md5(json.dumps(action_obj, sort_keys=True).encode()).hexdigest()

def actions_similar(a1, a2):
    """比较两个动作是否语义相似（基于命令/参数文本）"""
    if a1.get('action') != a2.get('action'):
        return False
    if a1['action'] == 'command':
        cmd1 = a1.get('params', {}).get('command', '')
        cmd2 = a2.get('params', {}).get('command', '')
        return difflib.SequenceMatcher(None, cmd1, cmd2).ratio() > 0.8
    elif a1['action'] == 'skill':
        sk1 = a1.get('params', {}).get('skill', '')
        sk2 = a2.get('params', {}).get('skill', '')
        return sk1 == sk2  # 名称相同即视为相似
    return False

def results_similar(r1, r2):
    if not isinstance(r1, dict) or not isinstance(r2, dict):
        return False
    if r1.get('status') != r2.get('status'):
        return False
    data1 = r1.get('data')
    data2 = r2.get('data')
    if data1 is None and data2 is None:
        return True
    if data1 is None or data2 is None:
        return False
    if isinstance(data1, dict) and isinstance(data2, dict):
        if set(data1.keys()) != set(data2.keys()):
            return False
        for k in data1:
            if data1[k] != data2[k]:
                return False
        return True
    return data1 == data2
