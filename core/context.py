import platform
import sys
import shutil
import subprocess

def get_env_info() -> str:
    """收集当前系统环境信息，返回描述文本"""
    info = []
    info.append(f"操作系统: {platform.system()} {platform.release()} (架构: {platform.machine()})")
    info.append(f"Python 版本: {sys.version.split()[0]}")
    
    pip_path = shutil.which("pip") or shutil.which("pip3")
    if pip_path:
        info.append(f"pip 路径: {pip_path}")
        try:
            result = subprocess.run([pip_path, "--version"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                info.append(f"pip 版本: {result.stdout.strip().split()[1]}")
        except:
            pass
    else:
        info.append("pip: 未找到")
    
    if platform.system() == "Linux":
        for pkg in ["apt", "yum", "dnf", "pacman", "zypper"]:
            if shutil.which(pkg):
                info.append(f"包管理器: {pkg}")
                break
    elif platform.system() == "Darwin":
        if shutil.which("brew"):
            info.append("包管理器: Homebrew")
    elif platform.system() == "Windows":
        if shutil.which("choco"):
            info.append("包管理器: Chocolatey")
        if shutil.which("winget"):
            info.append("包管理器: winget")
    
    try:
        import socket
        socket.create_connection(("8.8.8.8", 53), timeout=3)
        info.append("网络: 连通")
    except:
        info.append("网络: 可能不通")
    
    return "\n".join(info)