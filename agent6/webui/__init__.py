"""Web 可视化工作台（零外部依赖，基于标准库 http.server）。"""
from .server import serve, create_server

__all__ = ["serve", "create_server"]
