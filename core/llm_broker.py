import os
import json
import requests
from typing import List, Dict, Optional
from pathlib import Path
from colorama import Fore, Style, init
import yaml

init(autoreset=True)

BASE_DIR = Path(__file__).parent.parent
CONFIG_FILE = BASE_DIR / "config.yaml"

# 默认值
DEEPSEEK_API_URL = "https://api.deepseek.com/v1/chat/completions"
MODEL = "deepseek-chat"
MAX_TOKENS = 2000
TEMPERATURE = 0.1
REQUEST_TIMEOUT = 120
MAX_RETRIES = 3

_cached_api_key = None
_config = None

def load_config():
    global _config
    if _config is None and CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                _config = yaml.safe_load(f)
        except Exception as e:
            print(f"[警告] 读取配置文件失败: {e}")
    return _config or {}

def get_api_key() -> str:
    global _cached_api_key
    if _cached_api_key:
        return _cached_api_key

    config = load_config()
    # 1. 环境变量
    key = os.environ.get("DEEPSEEK_API_KEY")
    if key:
        _cached_api_key = key
        return key

    # 2. 配置文件
    if config.get("api_key"):
        _cached_api_key = config["api_key"]
        return _cached_api_key

    # 3. 交互输入
    print("\n[提示] 未找到 DeepSeek API Key。")
    print("您可以：")
    print("  1. 设置环境变量 DEEPSEEK_API_KEY")
    print("  2. 在 config.yaml 中配置 api_key")
    print("  3. 现在手动输入（仅本次会话有效）")
    while True:
        key = input("请输入您的 DeepSeek API Key: ").strip()
        if key:
            _cached_api_key = key
            return key
        else:
            print("API Key 不能为空，请重新输入。")

def chat_completion(messages: List[Dict[str, str]], retry: int = None) -> Optional[str]:
    config = load_config()
    llm_cfg = config.get("llm", {})
    model = llm_cfg.get("model", MODEL)
    max_tokens = llm_cfg.get("max_tokens", MAX_TOKENS)
    temperature = llm_cfg.get("temperature", TEMPERATURE)
    request_timeout = llm_cfg.get("request_timeout", REQUEST_TIMEOUT)
    max_retries = llm_cfg.get("max_retries", MAX_RETRIES) if retry is None else retry

    try:
        api_key = get_api_key()
    except Exception as e:
        print(f"[错误] 获取 API Key 失败: {e}")
        return None

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }
    payload = {
        "model": model,
        "messages": messages,
        "max_tokens": max_tokens,
        "temperature": temperature,
        "stream": False
    }

    proxies = {}
    if os.environ.get("HTTP_PROXY"):
        proxies["http"] = os.environ.get("HTTP_PROXY")
    if os.environ.get("HTTPS_PROXY"):
        proxies["https"] = os.environ.get("HTTPS_PROXY")

    try:
        resp = requests.post(
            DEEPSEEK_API_URL,
            headers=headers,
            json=payload,
            timeout=request_timeout,
            proxies=proxies if proxies else None,
            verify=True
        )
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"].strip()

    except requests.exceptions.ConnectionError as e:
        print(f"\n[网络错误] 无法连接到 DeepSeek API 服务器。")
        if proxies:
            print(f"  当前使用的代理: {proxies}")
        else:
            print("  未设置代理，若需要代理请设置 HTTP_PROXY/HTTPS_PROXY 环境变量。")
        if max_retries > 0:
            print(f"  正在重试... (剩余 {max_retries} 次)")
            return chat_completion(messages, max_retries - 1)
        return None

    except requests.exceptions.Timeout as e:
        print(f"\n[超时错误] 请求 DeepSeek API 超时（{request_timeout} 秒）。")
        if max_retries > 0:
            print(f"  正在重试... (剩余 {max_retries} 次)")
            return chat_completion(messages, max_retries - 1)
        return None

    except requests.exceptions.HTTPError as e:
        status_code = e.response.status_code if e.response else "未知"
        print(f"\n[HTTP 错误] 状态码: {status_code}")
        if status_code == 401:
            print("  可能原因：API Key 无效或已过期。")
        elif status_code == 402:
            print("  可能原因：账户余额不足。")
        elif status_code == 429:
            print("  可能原因：请求频率过高。")
        elif status_code in (500, 502, 503):
            print("  可能原因：DeepSeek 服务端临时故障。")
        if max_retries > 0 and status_code in (500, 502, 503, 429):
            print(f"  正在重试... (剩余 {max_retries} 次)")
            return chat_completion(messages, max_retries - 1)
        return None

    except Exception as e:
        print(f"\n[未知错误] {e}")
        return None