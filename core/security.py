import re

# 危险命令关键词（用于二次确认）
DANGEROUS_KEYWORDS = [
    "rm -rf", "rm -fr", "dd", "mkfs", "shutdown", "reboot",
    "halt", "poweroff", "format", "del /f", "rd /s",
    ":(){ :|:& };:",  # fork bomb
    "chmod 777", "chmod -R 777", "chown",
    "mv", "cp", "curl.*|.*sh", "wget.*|.*sh",  # 下载执行
    "python -c", "perl -e", "bash -i", "nc -e", "ncat -e",
    "mkfifo", ">/dev/tcp", ">/dev/udp",  # 反弹shell
    "sudo", "su", "passwd", "chpasswd", "useradd", "userdel"
]

def is_dangerous(command: str) -> bool:
    """
    判断命令是否危险。为避免误报，对'纯字母短词'（如 su、dd、mv、cp、halt）
    加词边界匹配，对'含空格/符号'的关键词（如 rm -rf、chmod 777）用子串匹配。
    对 PowerShell 的 Format-* cmdlet 做特判，避免与 format 误命中。
    """
    cmd_lower = command.lower()

    SUBSTRING_KEYWORDS = [
        "rm -rf", "rm -fr", "del /f", "rd /s",
        ":(){ :|:& };:", "chmod 777", "chmod -r 777",
        "curl.*|.*sh", "wget.*|.*sh",
        "python -c", "perl -e", "bash -i", "nc -e", "ncat -e",
        ">/dev/tcp", ">/dev/udp", "mkfifo",
    ]
    for kw in SUBSTRING_KEYWORDS:
        if kw in cmd_lower:
            return True

    # format 特判：排除 PowerShell 的 Format-* cmdlet
    if re.search(r'(^|[^\w])format([^\w]|$)', cmd_lower):
        if not re.search(r'\bformat-(list|table|wide|custom|hex)\b', cmd_lower):
            return True

    WORD_KEYWORDS = [
        "dd", "mkfs", "shutdown", "reboot", "halt", "poweroff",
        "chown", "mv", "cp",
        "sudo", "su", "passwd", "chpasswd", "useradd", "userdel",
    ]
    for kw in WORD_KEYWORDS:
        if re.search(r'(^|[^\w])' + re.escape(kw) + r'([^\w]|$)', cmd_lower):
            return True

    return False
