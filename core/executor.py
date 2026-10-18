import subprocess
import platform
import shutil
import re

DEFAULT_CMD_TIMEOUT = 20

def _adapt_posix_syntax_for_windows(command: str) -> str:
    """
    把 POSIX 的 shell 语法自动转换为 Windows cmd 等价写法，
    避免因 AI 习惯性使用 2>/dev/null、&& 等导致整条命令失败。
    """
    command = re.sub(r'\s+2\s*>\s*/dev/null', ' 2>nul', command)
    command = re.sub(r'\s*>\s*/dev/null\s*2\s*>&\s*1', ' >nul 2>&1', command)
    command = re.sub(r'\s*>\s*/dev/null', ' >nul', command)
    return command

def execute_command(command: str, timeout: int = DEFAULT_CMD_TIMEOUT) -> str:
    """
    在当前进程执行 Shell 命令，返回输出（含错误）。
    自动处理交互式命令：对 sqlmap 自动添加 --batch 参数。
    """
    # 对 sqlmap 命令自动添加 --batch
    if re.search(r'\bsqlmap\b', command, re.I):
        if '--batch' not in command:
            command = command + ' --batch'

    # Windows 环境适配
    if platform.system() == "Windows":
        original = command
        command = _adapt_posix_syntax_for_windows(command)
        if command != original:
            print(f"[executor] 已把 POSIX 重定向适配为 Windows 写法")

        # 拆分多命令管道：只保留第一部分
        if "||" in command or "&&" in command:
            parts = re.split(r'\|\||&&', command)
            first_cmd = parts[0].strip()
            print(f"[警告] 检测到多命令管道，Windows 下仅执行第一部分: {first_cmd}")
            command = first_cmd

    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            timeout=timeout,
            input='\n'
        )
        output = ""
        if result.stdout:
            output += result.stdout
        if result.stderr:
            output += result.stderr
        if result.returncode != 0:
            output += f"\n[返回码] {result.returncode}"
        return output.strip() or "[执行成功，无输出]"
    except subprocess.TimeoutExpired:
        return f"[错误] 命令执行超时（超过 {timeout} 秒），已强制终止。"
    except Exception as e:
        return f"[执行错误] {e}"

def run_in_new_window(command: str) -> str:
    """在新终端窗口中执行命令（异步），用于长时间任务。"""
    system = platform.system()
    try:
        if system == "Windows":
            if re.search(r'\bsqlmap\b', command, re.I) and '--batch' not in command:
                command = command + ' --batch'
            full_cmd = f'start cmd /k "{command}"'
            subprocess.Popen(full_cmd, shell=True)
            return f"[新窗口] 已在新的命令提示符窗口中执行: {command}"
        elif system == "Linux":
            terminals = [
                ("gnome-terminal", f'gnome-terminal -- bash -c "{command}; exec bash"'),
                ("xterm", f'xterm -e bash -c "{command}; exec bash"'),
                ("konsole", f'konsole -e bash -c "{command}; exec bash"'),
                ("terminator", f'terminator -e bash -c "{command}; exec bash"'),
            ]
            for term, cmd in terminals:
                if shutil.which(term):
                    subprocess.Popen(cmd, shell=True)
                    return f"[新窗口] 已在 {term} 中执行: {command}"
            return "[错误] 未找到可用的终端模拟器。"
        elif system == "Darwin":
            script = f'tell application "Terminal" do script "{command}"'
            subprocess.Popen(["osascript", "-e", script])
            return f"[新窗口] 已在 Terminal.app 中执行: {command}"
        else:
            return "[错误] 不支持的操作系统。"
    except Exception as e:
        return f"[错误] 打开新窗口失败: {e}"

def is_install_command(command: str) -> bool:
    install_keywords = [
        "install", "setup", "下载", "安装", "pip install", "npm install",
        "apt-get install", "yum install", "brew install", "gem install",
        "cargo install", "go get"
    ]
    cmd_lower = command.lower()
    return any(kw in cmd_lower for kw in install_keywords)
