"""
SQLite 连接管理 + 表结构（幂等初始化）。

- WAL 模式，允许 WebUI 线程并发读。
- check_same_thread=False + RLock 保证多线程写入安全。
"""
import json
import sqlite3
import threading
import time
from typing import Any, Iterable, Optional

from ..paths import DB_PATH

_SCHEMA = """
-- ============ 资产图（全局共享） ============
CREATE TABLE IF NOT EXISTS assets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT NOT NULL,                 -- root_domain/subdomain/ip/port/service/webapp/endpoint
    key         TEXT NOT NULL UNIQUE,          -- 去重键，如 ip:1.2.3.4  port:1.2.3.4:80
    label       TEXT NOT NULL,
    props       TEXT NOT NULL DEFAULT '{}',
    first_task  TEXT,
    first_seen  REAL,
    last_seen   REAL
);
CREATE INDEX IF NOT EXISTS idx_assets_kind ON assets(kind);

CREATE TABLE IF NOT EXISTS asset_edges (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    src_id  INTEGER NOT NULL,
    dst_id  INTEGER NOT NULL,
    rel     TEXT NOT NULL,                     -- resolves_to/has_port/runs_service/hosts_app/has_endpoint
    props   TEXT NOT NULL DEFAULT '{}',
    UNIQUE(src_id, dst_id, rel)
);

-- ============ 探索图（单任务） ============
CREATE TABLE IF NOT EXISTS nodes (
    id          TEXT PRIMARY KEY,              -- 如 T1-N12
    task_id     TEXT NOT NULL,
    kind        TEXT NOT NULL,                 -- goal/intent/fact/finding/hint
    label       TEXT NOT NULL,
    data        TEXT NOT NULL DEFAULT '{}',
    status      TEXT NOT NULL DEFAULT 'pending', -- pending/running/done/failed/blocked
    parent_id   TEXT,
    asset_ref   TEXT,                          -- 可选：关联资产 key
    created_at  REAL,
    updated_at  REAL
);
CREATE INDEX IF NOT EXISTS idx_nodes_task ON nodes(task_id, kind);
CREATE INDEX IF NOT EXISTS idx_nodes_status ON nodes(task_id, status);

CREATE TABLE IF NOT EXISTS edges (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT NOT NULL,
    src_id  TEXT NOT NULL,
    dst_id  TEXT NOT NULL,
    rel     TEXT NOT NULL,                     -- derives/uses/leads_to/supports
    UNIQUE(task_id, src_id, dst_id, rel)
);
CREATE INDEX IF NOT EXISTS idx_edges_task ON edges(task_id);

-- ============ 探索锚点（Exploration Anchors） ============
-- 把探索图节点锚定到资产图节点，是「资产覆盖度」的唯一权威来源。
-- 对标 ARTEX 的 exploration_anchors(node_id, asset_id)。
CREATE TABLE IF NOT EXISTS exploration_anchors (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id     TEXT NOT NULL,                 -- 探索图节点 id，如 T1-N12
    asset_id    INTEGER NOT NULL,              -- 资产 id（assets.id）
    task_id     TEXT NOT NULL,
    relation    TEXT NOT NULL DEFAULT 'targets', -- targets/found_in/derives_from
    created_at  REAL,
    UNIQUE(node_id, asset_id, relation)
);
CREATE INDEX IF NOT EXISTS idx_anchors_asset ON exploration_anchors(asset_id);
CREATE INDEX IF NOT EXISTS idx_anchors_node ON exploration_anchors(node_id);
CREATE INDEX IF NOT EXISTS idx_anchors_task ON exploration_anchors(task_id);

-- ============ 任务 / 会话 ============
CREATE TABLE IF NOT EXISTS tasks (
    id          TEXT PRIMARY KEY,
    name        TEXT,
    target      TEXT,
    scope       TEXT,
    mode        TEXT,
    status      TEXT NOT NULL DEFAULT 'pending', -- pending/running/paused/done/failed/stopped
    created_at  REAL,
    started_at  REAL,
    finished_at REAL,
    config      TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS events (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT,
    ts      REAL,
    type    TEXT,                              -- task/plan/tool/finding/llm/error
    actor   TEXT,                              -- planner/worker/system
    message TEXT,
    data    TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_events_task ON events(task_id, ts);

CREATE TABLE IF NOT EXISTS tool_calls (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id        TEXT,
    intent_id      TEXT,
    tool           TEXT,
    args           TEXT NOT NULL DEFAULT '{}',
    status         TEXT,
    result_summary TEXT,
    raw            TEXT,
    started_at     REAL,
    finished_at    REAL,
    duration_ms    INTEGER
);
CREATE INDEX IF NOT EXISTS idx_toolcalls_task ON tool_calls(task_id);

-- ============ 审批记录（人在环路历史，HumanGate 决定后落库持久化） ============
CREATE TABLE IF NOT EXISTS approvals (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    approval_id     TEXT,                          -- AP00001，HumanGate 内存自增 id
    task_id         TEXT,
    tool            TEXT,
    args            TEXT NOT NULL DEFAULT '{}',
    risk            TEXT,                          -- high/medium/low
    reason          TEXT,                           -- 申请时的风险说明
    action          TEXT,                           -- approved/rejected/timeout_approved/...
    decision_reason TEXT,                           -- 人工填写的理由
    auto            INTEGER DEFAULT 0,              -- 1=超时自动决定，0=人工决定
    created_at      REAL,                           -- 申请时间
    decided_at      REAL                            -- 决定时间
);
CREATE INDEX IF NOT EXISTS idx_approvals_task ON approvals(task_id, decided_at);

CREATE TABLE IF NOT EXISTS llm_usage (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id           TEXT,
    agent             TEXT,
    model             TEXT,
    prompt_tokens     INTEGER DEFAULT 0,
    completion_tokens INTEGER DEFAULT 0,
    total_tokens      INTEGER DEFAULT 0,
    created_at        REAL
);
CREATE INDEX IF NOT EXISTS idx_usage_task ON llm_usage(task_id);

-- ============ 漏洞 POC / 验证 / 复测留痕（VulnAgent） ============
-- 每次「生成 POC / 执行验证 / 复测 / AI 复测 / AI 误报分析」都落一条，
-- 漏洞详情页按 finding_id 回放历史；最新结论同时写回 nodes.data 供列表展示。
CREATE TABLE IF NOT EXISTS poc_records (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id  TEXT NOT NULL,                    -- nodes.id（漏洞节点，全局唯一）
    task_id     TEXT,                              -- 所属任务（冗余，便于按任务检索）
    kind        TEXT NOT NULL,                     -- gen/verify/retest/ai_retest/ai_analyze/dedup
    poc         TEXT,                              -- POC 定义 JSON
    echo        TEXT,                              -- 执行回显（请求/响应或命令输出原文）
    ok          INTEGER DEFAULT 0,                 -- 本次执行是否命中预期
    verdict     TEXT,                              -- verified/failed/false_positive/fixed/unfixed/unverified
    analysis    TEXT,                              -- AI 分析结论（JSON 或文本）
    created_at  REAL
);
CREATE INDEX IF NOT EXISTS idx_poc_finding ON poc_records(finding_id, created_at);
CREATE INDEX IF NOT EXISTS idx_poc_task ON poc_records(task_id);
"""


class Database:
    def __init__(self, path=None):
        self.path = str(path or DB_PATH)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=NORMAL;")
        self._conn.execute("PRAGMA foreign_keys=ON;")
        self.init_schema()

    def init_schema(self):
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()
            # 向后兼容：补加流量录制字段（旧库无此列时追加）
            for col_sql in (
                "ALTER TABLE tool_calls ADD COLUMN traffic TEXT",
            ):
                try:
                    self._conn.execute(col_sql)
                    self._conn.commit()
                except Exception:
                    pass  # 列已存在则忽略

    # ---------- 通用执行 ----------
    def execute(self, sql: str, params: Iterable = ()) -> sqlite3.Cursor:
        with self._lock:
            cur = self._conn.execute(sql, tuple(params))
            self._conn.commit()
            return cur

    def executemany(self, sql: str, seq) -> sqlite3.Cursor:
        with self._lock:
            cur = self._conn.executemany(sql, seq)
            self._conn.commit()
            return cur

    def query(self, sql: str, params: Iterable = ()) -> list:
        with self._lock:
            cur = self._conn.execute(sql, tuple(params))
            return [dict(r) for r in cur.fetchall()]

    def query_one(self, sql: str, params: Iterable = ()) -> Optional[dict]:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def close(self):
        with self._lock:
            try:
                self._conn.close()
            except Exception:
                pass


# ---------- 便捷 JSON 工具 ----------
def jdump(obj: Any) -> str:
    try:
        return json.dumps(obj, ensure_ascii=False, default=str)
    except Exception:
        return json.dumps({"_unserializable": str(type(obj))}, ensure_ascii=False)


def jload(s: Any, default=None):
    if s is None:
        return default
    if isinstance(s, (dict, list)):
        return s
    try:
        return json.loads(s)
    except Exception:
        return default


# ---------- 全局单例 ----------
_db_singleton: Optional[Database] = None
_db_lock = threading.Lock()


def get_db() -> Database:
    global _db_singleton
    if _db_singleton is None:
        with _db_lock:
            if _db_singleton is None:
                _db_singleton = Database()
    return _db_singleton


def now() -> float:
    return time.time()
