"""
Scout Agent · 数据层

记忆分层设计（核心）
--------------------
1. 站点记忆 (site_memory)   —— 按「站点」隔离，存指纹、接口、技术栈、历史结论
                               同域名永远映射到同一个站点，实现跨会话复用
2. 会话 (sessions)          —— 按域名自动命名；同一站点的多次测试复用同一站点记忆
3. 长期记忆 (user_prefs)    —— 仅存用户偏好（模型、并发、审批策略、报告风格等），
                               **绝不存任何站点探测数据**

数据流：
  域名 → site_key(归一化) → sites 表 → site_memory 读写
  长期偏好 → user_prefs（全局唯一，与站点无关）
"""
from __future__ import annotations

import json
import re
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

__all__ = ["sqlite3"]   # 供 auth.py 捕获唯一约束冲突

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "scout.db"

_local = threading.local()


# --------------------------------------------------------------------------
# 工具
# --------------------------------------------------------------------------
def now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
_PORT_RE = re.compile(r":\d+$")


def normalize_target(raw: str) -> str:
    """把用户输入的各种写法归一化成裸域名（小写、去协议、去端口、去路径、去 www 前缀之外的噪声）。

    >>> normalize_target("https://Shop.Example.com:8443/a/b?x=1")
    'shop.example.com'
    """
    s = (raw or "").strip()
    if not s:
        return ""
    s = _SCHEME_RE.sub("", s)
    s = s.split("/")[0]
    s = s.split("?")[0]
    s = s.split("#")[0]
    s = _PORT_RE.sub("", s)
    s = s.strip().strip(".").lower()
    # 去掉凭据前缀 user:pass@
    if "@" in s:
        s = s.split("@", 1)[1]
    return s


def site_key(domain: str) -> str:
    """站点键：同域名（含子域归属）稳定映射。

    去掉 www. 前缀后作为键，使 www.a.com 与 a.com 共享记忆；
    其余子域（api.a.com / hgt.a.com）保持独立，符合"按站点切分"的要求。
    """
    d = normalize_target(domain)
    if d.startswith("www."):
        d = d[4:]
    return d or "unknown"


def session_name(domain: str) -> str:
    """会话窗口名：按测试域名自动命名，直接取归一化域名。"""
    return normalize_target(domain) or "untitled-target"


def is_private_host(host: str) -> bool:
    """判断是否内网/本机地址——这类目标禁止外网探测。"""
    h = normalize_target(host)
    if h in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        return True
    parts = h.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        a, b = int(parts[0]), int(parts[1])
        if a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168):
            return True
    if h.endswith((".local", ".internal", ".lan")):
        return True
    return False


# --------------------------------------------------------------------------
# 连接管理（线程安全）
# --------------------------------------------------------------------------
def get_conn() -> sqlite3.Connection:
    conn = getattr(_local, "conn", None)
    if conn is None:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(DB_PATH), timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=30000")
        _local.conn = conn
    return conn


@contextmanager
def tx():
    conn = get_conn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def init_db() -> None:
    with tx() as c:
        c.executescript(
            """
            -- 站点：按归一化域名唯一
            CREATE TABLE IF NOT EXISTS sites (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                domain        TEXT NOT NULL UNIQUE,      -- 归一化域名，唯一
                site_key      TEXT NOT NULL UNIQUE,      -- 去 www 后的记忆键
                display_name  TEXT NOT NULL,
                first_seen    TEXT NOT NULL,
                last_seen     TEXT NOT NULL,
                is_private    INTEGER NOT NULL DEFAULT 0,
                notes         TEXT
            );

            -- 会话：按域名自动命名，同站点可多次测试各自留痕
            CREATE TABLE IF NOT EXISTS sessions (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                site_id       INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
                name          TEXT NOT NULL,             -- 自动按域名命名
                title         TEXT NOT NULL,
                status        TEXT NOT NULL DEFAULT 'active',  -- active|paused|closed
                model         TEXT NOT NULL DEFAULT 'scout-pro',
                created_at    TEXT NOT NULL,
                updated_at    TEXT NOT NULL,
                closed_at     TEXT
            );
            CREATE INDEX IF NOT EXISTS ix_sessions_site ON sessions(site_id);

            -- 站点记忆：按站点隔离的长期沉淀（指纹/接口/技术栈/历史结论）
            CREATE TABLE IF NOT EXISTS site_memory (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                site_id       INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
                namespace     TEXT NOT NULL,             -- fingerprint|endpoint|stack|finding|config|history
                key           TEXT NOT NULL,
                value         TEXT NOT NULL,             -- JSON
                confidence    REAL NOT NULL DEFAULT 1.0,
                source        TEXT,
                hit_count     INTEGER NOT NULL DEFAULT 0,
                created_at    TEXT NOT NULL,
                updated_at    TEXT NOT NULL,
                UNIQUE(site_id, namespace, key)
            );
            CREATE INDEX IF NOT EXISTS ix_mem_site ON site_memory(site_id, namespace);

            -- 长期记忆：仅用户偏好，与站点无关，禁止写入站点探测数据
            CREATE TABLE IF NOT EXISTS user_prefs (
                key           TEXT PRIMARY KEY,
                value         TEXT NOT NULL,
                scope         TEXT NOT NULL DEFAULT 'global',
                created_at    TEXT NOT NULL,
                updated_at    TEXT NOT NULL
            );

            -- 对话消息
            CREATE TABLE IF NOT EXISTS messages (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id    INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
                role          TEXT NOT NULL,             -- user|assistant|system
                kind          TEXT NOT NULL DEFAULT 'text',  -- text|plan|run|gate|error
                content       TEXT NOT NULL,             -- JSON
                seq           INTEGER NOT NULL,
                created_at    TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_msg_session ON messages(session_id, seq);

            -- 工具调用记录
            CREATE TABLE IF NOT EXISTS tool_calls (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id    INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
                message_id    INTEGER REFERENCES messages(id) ON DELETE CASCADE,
                tool          TEXT NOT NULL,
                args          TEXT NOT NULL,
                status        TEXT NOT NULL,             -- running|done|failed|awaiting
                result        TEXT,
                error         TEXT,
                attempt       INTEGER NOT NULL DEFAULT 1,
                duration_ms   INTEGER NOT NULL DEFAULT 0,
                created_at    TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_tool_session ON tool_calls(session_id);

            -- 审批门（等待确认的操作）
            CREATE TABLE IF NOT EXISTS approvals (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id    INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
                title         TEXT NOT NULL,
                description   TEXT NOT NULL,
                payload       TEXT NOT NULL,
                risk          TEXT NOT NULL DEFAULT 'medium',
                status        TEXT NOT NULL DEFAULT 'pending',  -- pending|approved|rejected|expired
                options       TEXT NOT NULL,
                decided_at    TEXT,
                created_at    TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_appr_session ON approvals(session_id, status);

            -- 交付产物
            CREATE TABLE IF NOT EXISTS artifacts (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id    INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
                name          TEXT NOT NULL,
                kind          TEXT NOT NULL,             -- md|json|csv|log|html
                content       TEXT NOT NULL,
                size          INTEGER NOT NULL DEFAULT 0,
                created_at    TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_art_session ON artifacts(session_id);

            -- 运行日志（审计）
            CREATE TABLE IF NOT EXISTS run_log (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id    INTEGER,
                level         TEXT NOT NULL,
                message       TEXT NOT NULL,
                created_at    TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_log_session ON run_log(session_id);

            -- 流式事件：SSE 推送 + 断线重连 + 刷新恢复都以它为准
            CREATE TABLE IF NOT EXISTS run_events (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id    INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
                run_id        TEXT NOT NULL,
                seq           INTEGER NOT NULL,
                type          TEXT NOT NULL,
                payload       TEXT NOT NULL,
                created_at    TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_ev_session ON run_events(session_id, id);
            CREATE INDEX IF NOT EXISTS ix_ev_run ON run_events(run_id, seq);

            -- 用户账号
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT NOT NULL UNIQUE,
                display_name  TEXT NOT NULL,
                password_hash TEXT NOT NULL,           -- werkzeug pbkdf2/scrypt
                role          TEXT NOT NULL DEFAULT 'analyst',   -- admin|analyst|viewer
                is_active     INTEGER NOT NULL DEFAULT 1,
                last_login_at TEXT,
                created_at    TEXT NOT NULL,
                updated_at    TEXT NOT NULL
            );

            -- 登录会话（服务端可吊销）
            CREATE TABLE IF NOT EXISTS auth_sessions (
                token_hash    TEXT PRIMARY KEY,       -- sha256(token)，不存明文
                user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                created_at    TEXT NOT NULL,
                expires_at    TEXT NOT NULL,
                last_seen_at  TEXT NOT NULL,
                user_agent    TEXT,
                ip            TEXT
            );
            CREATE INDEX IF NOT EXISTS ix_asess_user ON auth_sessions(user_id);

            -- 注册邀请码（只存哈希，用完即废）
            CREATE TABLE IF NOT EXISTS auth_invites (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                code_hash     TEXT NOT NULL UNIQUE,
                role          TEXT NOT NULL DEFAULT 'analyst',
                note          TEXT,
                max_uses      INTEGER NOT NULL DEFAULT 1,
                used_count    INTEGER NOT NULL DEFAULT 0,
                created_by    INTEGER REFERENCES users(id) ON DELETE SET NULL,
                created_at    TEXT NOT NULL,
                used_at       TEXT
            );

            -- 每用户的 API 配置（LLM 网关等），api_key 加密存储
            CREATE TABLE IF NOT EXISTS user_api_config (
                user_id       INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                llm_base      TEXT NOT NULL DEFAULT '',
                llm_key_enc   TEXT NOT NULL DEFAULT '',  -- Fernet 密文
                llm_model     TEXT NOT NULL DEFAULT 'qwen',
                llm_timeout   INTEGER NOT NULL DEFAULT 60,
                probe_timeout INTEGER NOT NULL DEFAULT 10,
                max_steps     INTEGER NOT NULL DEFAULT 12,
                max_rounds    INTEGER NOT NULL DEFAULT 8,
                verify_ssl    INTEGER NOT NULL DEFAULT 0,
                updated_at    TEXT NOT NULL,
                updated_by    INTEGER
            );
            """
        )
        _migrate()


# --------------------------------------------------------------------------
# 轻量迁移
#
# CREATE TABLE IF NOT EXISTS 对**已存在的表**不会补新列，所以每次给表加字段
# 都必须在这里显式 ALTER 一次。写错了不会破坏数据（重复执行会先查列是否存在）。
# --------------------------------------------------------------------------
_MIGRATIONS = [
    # (表名, 列名, 列定义)
    ("user_api_config", "max_rounds", "INTEGER NOT NULL DEFAULT 8"),
]


def _columns(table: str) -> set:
    return {r[1] for r in get_conn().execute(f"PRAGMA table_info({table})").fetchall()}


def _migrate() -> None:
    for table, col, decl in _MIGRATIONS:
        try:
            if col in _columns(table):
                continue
            with tx() as c:
                c.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
        except Exception as e:                      # 迁移失败不该阻断启动
            log(None, "warn", f"migrate {table}.{col} failed: {e}")


# --------------------------------------------------------------------------
# 站点 + 会话
# --------------------------------------------------------------------------
def get_or_create_site(domain: str) -> Dict[str, Any]:
    """按域名取站点，不存在则创建。同域名必然命中同一条记录。"""
    d = normalize_target(domain)
    k = site_key(d)
    with tx() as c:
        row = c.execute("SELECT * FROM sites WHERE site_key=?", (k,)).fetchone()
        if row is None:
            ts = now()
            cur = c.execute(
                "INSERT INTO sites(domain, site_key, display_name, first_seen, last_seen, is_private)"
                " VALUES(?,?,?,?,?,?)",
                (d, k, k, ts, ts, 1 if is_private_host(d) else 0),
            )
            row = c.execute("SELECT * FROM sites WHERE id=?", (cur.lastrowid,)).fetchone()
        else:
            c.execute("UPDATE sites SET last_seen=?, domain=? WHERE id=?", (now(), d, row["id"]))
            row = c.execute("SELECT * FROM sites WHERE id=?", (row["id"],)).fetchone()
    return dict(row)


def list_sites() -> List[Dict[str, Any]]:
    rows = get_conn().execute(
        "SELECT s.*, COUNT(DISTINCT se.id) AS session_count,"
        " (SELECT COUNT(*) FROM site_memory m WHERE m.site_id=s.id) AS memory_count"
        " FROM sites s LEFT JOIN sessions se ON se.site_id=s.id"
        " GROUP BY s.id ORDER BY s.last_seen DESC"
    ).fetchall()
    return [dict(r) for r in rows]


def create_session(domain: str, title: str = "", model: str = "scout-pro") -> Dict[str, Any]:
    site = get_or_create_site(domain)
    ts = now()
    auto = session_name(domain)
    title = title or f"{auto} 安全测试"
    with tx() as c:
        cur = c.execute(
            "INSERT INTO sessions(site_id, name, title, status, model, created_at, updated_at)"
            " VALUES(?,?,?,?,?,?,?)",
            (site["id"], auto, title, "active", model, ts, ts),
        )
        sid = cur.lastrowid
    return get_session(sid)


def get_session(session_id: int) -> Dict[str, Any]:
    r = get_conn().execute(
        "SELECT se.*, s.domain, s.site_key, s.is_private FROM sessions se"
        " JOIN sites s ON s.id=se.site_id WHERE se.id=?",
        (session_id,),
    ).fetchone()
    if r is None:
        raise KeyError(f"session {session_id} not found")
    return dict(r)


def find_session_by_name(name: str) -> Optional[Dict[str, Any]]:
    """按域名找已有会话——实现「测试同一网站复用同一会话窗口」。"""
    r = get_conn().execute(
        "SELECT se.*, s.domain, s.site_key FROM sessions se"
        " JOIN sites s ON s.id=se.site_id WHERE se.name=? ORDER BY se.updated_at DESC LIMIT 1",
        (session_name(name),),
    ).fetchone()
    return dict(r) if r else None


def get_or_create_session(domain: str, title: str = "", model: str = "scout-pro") -> Dict[str, Any]:
    """核心：同域名 → 同一站点记忆。已有活跃会话则直接复用。"""
    existing = find_session_by_name(domain)
    if existing and existing["status"] == "active":
        touch_session(existing["id"])
        return get_session(existing["id"])
    return create_session(domain, title, model)


def touch_session(session_id: int) -> None:
    with tx() as c:
        c.execute("UPDATE sessions SET updated_at=? WHERE id=?", (now(), session_id))


def list_sessions(limit: int = 100) -> List[Dict[str, Any]]:
    rows = get_conn().execute(
        "SELECT se.*, s.domain, s.site_key FROM sessions se"
        " JOIN sites s ON s.id=se.site_id"
        " ORDER BY se.updated_at DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]


def set_session_status(session_id: int, status: str) -> None:
    with tx() as c:
        closed = now() if status == "closed" else None
        c.execute("UPDATE sessions SET status=?, updated_at=?, closed_at=? WHERE id=?",
                  (status, now(), closed, session_id))


# --------------------------------------------------------------------------
# 站点记忆（按站点隔离）
# --------------------------------------------------------------------------
_SITE_NS = ("fingerprint", "endpoint", "stack", "finding", "config", "history")


def remember(site_id: int, namespace: str, key: str, value: Any,
             confidence: float = 1.0, source: str = "") -> Dict[str, Any]:
    """写入站点记忆。同 namespace+key 覆盖更新并累加命中次数。

    这是「同一网站测试时自动复用历史指纹/接口」的基础。
    """
    if namespace not in _SITE_NS:
        raise ValueError(f"invalid namespace {namespace}")
    ts = now()
    val = json.dumps(value, ensure_ascii=False)
    with tx() as c:
        c.execute(
            """INSERT INTO site_memory(site_id, namespace, key, value, confidence, source,
                                       hit_count, created_at, updated_at)
               VALUES(?,?,?,?,?,?,1,?,?)
               ON CONFLICT(site_id, namespace, key) DO UPDATE SET
                 value=excluded.value, confidence=excluded.confidence,
                 source=excluded.source, hit_count=site_memory.hit_count+1,
                 updated_at=excluded.updated_at""",
            (site_id, namespace, key, val, confidence, source, ts, ts),
        )
    return {"namespace": namespace, "key": key, "value": value, "confidence": confidence}


def recall(site_id: int, namespace: Optional[str] = None,
           limit: int = 200, min_confidence: float = 0.0) -> List[Dict[str, Any]]:
    """读取站点记忆。Agent 每次启动任务前都会调用，把历史指纹/接口注入上下文。"""
    sql = "SELECT * FROM site_memory WHERE site_id=?"
    args: List[Any] = [site_id]
    if namespace:
        sql += " AND namespace=?"
        args.append(namespace)
    if min_confidence > 0:
        sql += " AND confidence>=?"
        args.append(min_confidence)
    sql += " ORDER BY updated_at DESC LIMIT ?"
    args.append(limit)
    rows = get_conn().execute(sql, args).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        try:
            d["value"] = json.loads(d["value"])
        except Exception:
            pass
        out.append(d)
    return out


def forget(site_id: int, namespace: Optional[str] = None, key: Optional[str] = None) -> int:
    sql = "DELETE FROM site_memory WHERE site_id=?"
    args: List[Any] = [site_id]
    if namespace:
        sql += " AND namespace=?"
        args.append(namespace)
    if key:
        sql += " AND key=?"
        args.append(key)
    with tx() as c:
        return c.execute(sql, args).rowcount


def site_profile(site_id: int) -> Dict[str, Any]:
    """汇总某站点的记忆画像，用于注入 Agent 上下文。"""
    mem = recall(site_id, limit=500)
    profile: Dict[str, Any] = {
        "fingerprint": {}, "endpoints": [], "stack": [],
        "findings": [], "config": {}, "history": [],
    }
    for m in mem:
        ns, k, v = m["namespace"], m["key"], m["value"]
        if ns == "fingerprint":
            profile["fingerprint"][k] = {"value": v, "confidence": m["confidence"],
                                         "updated_at": m["updated_at"]}
        elif ns == "endpoint":
            if isinstance(v, dict):
                profile["endpoints"].append({"path": k, **v})
        elif ns == "stack":
            profile["stack"].append(v if not isinstance(v, dict) else v.get("name", k))
        elif ns == "finding":
            if isinstance(v, dict):
                profile["findings"].append({"id": k, **v})
        elif ns == "config":
            profile["config"][k] = v
        elif ns == "history":
            profile["history"].append(v if not isinstance(v, dict) else {"key": k, **v})
    meta = get_conn().execute("SELECT * FROM sites WHERE id=?", (site_id,)).fetchone()
    profile["site"] = dict(meta) if meta else {}
    # 固定输出全部 namespace 的计数（缺失为 0），前端无需判空
    profile["counts"] = {
        "fingerprint": len(profile["fingerprint"]),
        "endpoints": len(profile["endpoints"]),
        "endpoint": len(profile["endpoints"]),
        "stack": len(profile["stack"]),
        "findings": len(profile["findings"]),
        "config": len(profile["config"]),
        "history": len(profile["history"]),
    }
    return profile


# --------------------------------------------------------------------------
# 长期记忆（仅用户偏好）
# --------------------------------------------------------------------------
# 允许进入长期记忆的白名单键——只有偏好类，绝不放站点探测数据
PREF_KEYS = {
    "default_model", "default_skill", "approval_policy", "request_timeout",
    "max_concurrency", "report_style", "report_language", "user_role",
    "default_severity_floor", "rate_limit_rps", "auto_summary", "ui_density",
}


def set_pref(key: str, value: Any) -> Dict[str, Any]:
    """写入用户偏好。白名单外的键直接拒绝——防止站点数据污染长期记忆。"""
    if key not in PREF_KEYS:
        raise ValueError(
            f"'{key}' 不是用户偏好字段，长期记忆仅接受偏好类数据。"
            f"允许字段: {sorted(PREF_KEYS)}"
        )
    val = json.dumps(value, ensure_ascii=False)
    ts = now()
    with tx() as c:
        c.execute(
            "INSERT INTO user_prefs(key, value, scope, created_at, updated_at)"
            " VALUES(?,?,?,?,?)"
            " ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
            (key, val, "global", ts, ts),
        )
    return {"key": key, "value": value}


def get_pref(key: str, default: Any = None) -> Any:
    r = get_conn().execute("SELECT value FROM user_prefs WHERE key=?", (key,)).fetchone()
    if r is None:
        return default
    try:
        return json.loads(r["value"])
    except Exception:
        return default


def all_prefs() -> Dict[str, Any]:
    rows = get_conn().execute("SELECT key, value FROM user_prefs ORDER BY key").fetchall()
    out = {}
    for r in rows:
        try:
            out[r["key"]] = json.loads(r["value"])
        except Exception:
            out[r["key"]] = r["value"]
    return out


def delete_pref(key: str) -> int:
    with tx() as c:
        return c.execute("DELETE FROM user_prefs WHERE key=?", (key,)).rowcount


# --------------------------------------------------------------------------
# 消息 / 工具 / 审批 / 产物
# --------------------------------------------------------------------------
def next_seq(session_id: int) -> int:
    r = get_conn().execute("SELECT COALESCE(MAX(seq),0)+1 AS n FROM messages WHERE session_id=?",
                           (session_id,)).fetchone()
    return int(r["n"])


def add_message(session_id: int, role: str, content: Any, kind: str = "text") -> Dict[str, Any]:
    ts = now()
    with tx() as c:
        seq = next_seq(session_id)
        cur = c.execute(
            "INSERT INTO messages(session_id, role, kind, content, seq, created_at)"
            " VALUES(?,?,?,?,?,?)",
            (session_id, role, kind, json.dumps(content, ensure_ascii=False), seq, ts),
        )
        mid = cur.lastrowid
    touch_session(session_id)
    r = get_conn().execute("SELECT * FROM messages WHERE id=?", (mid,)).fetchone()
    d = dict(r)
    d["content"] = json.loads(d["content"])
    return d


def list_messages(session_id: int, limit: int = 500) -> List[Dict[str, Any]]:
    rows = get_conn().execute(
        "SELECT * FROM messages WHERE session_id=? ORDER BY seq ASC LIMIT ?",
        (session_id, limit),
    ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        try:
            d["content"] = json.loads(d["content"])
        except Exception:
            pass
        out.append(d)
    return out


def add_tool_call(session_id: int, tool: str, args: Dict[str, Any], status: str,
                  result: Any = None, error: str = "", attempt: int = 1,
                  duration_ms: int = 0, message_id: Optional[int] = None) -> int:
    ts = now()
    with tx() as c:
        cur = c.execute(
            "INSERT INTO tool_calls(session_id, message_id, tool, args, status, result, error,"
            " attempt, duration_ms, created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (session_id, message_id, tool, json.dumps(args, ensure_ascii=False), status,
             json.dumps(result, ensure_ascii=False) if result is not None else None,
             error, attempt, duration_ms, ts),
        )
        return int(cur.lastrowid)


def update_tool_call(call_id: int, status: str, result: Any = None,
                     error: str = "", duration_ms: Optional[int] = None) -> None:
    # 固定写全四个字段，用 None 表示"不更新"。
    # 不用 f-string 拼 SET 子句——列名即使只来自硬编码常量，
    # 一旦以后有人加动态列就容易变成注入点。全量 UPDATE 更直白也更安全。
    with tx() as c:
        c.execute(
            "UPDATE tool_calls SET status=?, result=?, error=?, duration_ms=?"
            " WHERE id=?",
            (status,
             json.dumps(result, ensure_ascii=False) if result is not None else None,
             error or None,
             duration_ms,
             call_id))


def list_tool_calls(session_id: int) -> List[Dict[str, Any]]:
    rows = get_conn().execute(
        "SELECT * FROM tool_calls WHERE session_id=? ORDER BY id ASC", (session_id,)
    ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        for f in ("args", "result"):
            try:
                d[f] = json.loads(d[f]) if d[f] else None
            except Exception:
                pass
        out.append(d)
    return out


def create_approval(session_id: int, title: str, description: str, payload: Any,
                    risk: str = "medium", options: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    ts = now()
    opts = options or [
        {"id": "approve", "label": "批准执行", "primary": True},
        {"id": "reject", "label": "拒绝"},
    ]
    with tx() as c:
        cur = c.execute(
            "INSERT INTO approvals(session_id, title, description, payload, risk, status, options, created_at)"
            " VALUES(?,?,?,?,?,?,?,?)",
            (session_id, title, description, json.dumps(payload, ensure_ascii=False),
             risk, "pending", json.dumps(opts, ensure_ascii=False), ts),
        )
        aid = cur.lastrowid
    return get_approval(aid)


def get_approval(approval_id: int) -> Dict[str, Any]:
    r = get_conn().execute("SELECT * FROM approvals WHERE id=?", (approval_id,)).fetchone()
    if r is None:
        raise KeyError(approval_id)
    d = dict(r)
    for f in ("payload", "options"):
        try:
            d[f] = json.loads(d[f])
        except Exception:
            pass
    return d


def decide_approval(approval_id: int, decision: str) -> Dict[str, Any]:
    valid = ("approved", "rejected", "expired")
    if decision not in valid:
        raise ValueError(f"decision must be one of {valid}")
    with tx() as c:
        c.execute("UPDATE approvals SET status=?, decided_at=? WHERE id=?",
                  (decision, now(), approval_id))
    return get_approval(approval_id)


def list_approvals(session_id: int, status: Optional[str] = None) -> List[Dict[str, Any]]:
    sql = "SELECT * FROM approvals WHERE session_id=?"
    args: List[Any] = [session_id]
    if status:
        sql += " AND status=?"
        args.append(status)
    rows = get_conn().execute(sql + " ORDER BY id DESC", args).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        for f in ("payload", "options"):
            try:
                d[f] = json.loads(d[f])
            except Exception:
                pass
        out.append(d)
    return out


def add_artifact(session_id: int, name: str, kind: str, content: str) -> Dict[str, Any]:
    ts = now()
    with tx() as c:
        cur = c.execute(
            "INSERT INTO artifacts(session_id, name, kind, content, size, created_at)"
            " VALUES(?,?,?,?,?,?)",
            (session_id, name, kind, content, len(content.encode("utf-8")), ts),
        )
        aid = cur.lastrowid
    r = get_conn().execute("SELECT id,name,kind,size,created_at FROM artifacts WHERE id=?",
                           (aid,)).fetchone()
    return dict(r)


def list_artifacts(session_id: int) -> List[Dict[str, Any]]:
    rows = get_conn().execute(
        "SELECT id,name,kind,size,created_at FROM artifacts WHERE session_id=? ORDER BY id DESC",
        (session_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def get_artifact(artifact_id: int) -> Dict[str, Any]:
    r = get_conn().execute("SELECT * FROM artifacts WHERE id=?", (artifact_id,)).fetchone()
    if r is None:
        raise KeyError(artifact_id)
    return dict(r)


def log(session_id: Optional[int], level: str, message: str) -> None:
    with tx() as c:
        c.execute("INSERT INTO run_log(session_id, level, message, created_at) VALUES(?,?,?,?)",
                  (session_id, level, message[:4000], now()))


# --------------------------------------------------------------------------
# 流式事件
# --------------------------------------------------------------------------
def emit(session_id: int, run_id: str, type_: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """写一条流式事件。SSE 推送、断线重连、页面刷新恢复都以这张表为准。"""
    ts = now()
    body = json.dumps(payload, ensure_ascii=False)
    with tx() as c:
        r = c.execute("SELECT COALESCE(MAX(seq),0) FROM run_events WHERE run_id=?",
                      (run_id,)).fetchone()
        seq = int(r[0]) + 1
        cur = c.execute(
            "INSERT INTO run_events(session_id, run_id, seq, type, payload, created_at)"
            " VALUES(?,?,?,?,?,?)",
            (session_id, run_id, seq, type_, body, ts))
        eid = int(cur.lastrowid)
    return {"id": eid, "session_id": session_id, "run_id": run_id,
            "seq": seq, "type": type_, "payload": payload, "created_at": ts}


def events_since(session_id: int, after_id: int = 0, run_id: Optional[str] = None,
                 limit: int = 500) -> List[Dict[str, Any]]:
    """拉取 id > after_id 的事件。after_id=0 表示从头回放（用于刷新恢复）。"""
    sql = "SELECT * FROM run_events WHERE session_id=? AND id>?"
    args: List[Any] = [session_id, after_id]
    if run_id:
        sql += " AND run_id=?"
        args.append(run_id)
    sql += " ORDER BY id ASC LIMIT ?"
    args.append(limit)
    rows = get_conn().execute(sql, args).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        try:
            d["payload"] = json.loads(d["payload"])
        except Exception:
            pass
        out.append(d)
    return out


def latest_run_id(session_id: int) -> Optional[str]:
    r = get_conn().execute(
        "SELECT run_id FROM run_events WHERE session_id=? ORDER BY id DESC LIMIT 1",
        (session_id,)).fetchone()
    return r["run_id"] if r else None


def run_status(session_id: int) -> Dict[str, Any]:
    """当前会话的运行态，供前端恢复现场。"""
    row = get_conn().execute(
        "SELECT run_id, MAX(id) AS last_id, COUNT(*) AS n FROM run_events"
        " WHERE session_id=? GROUP BY run_id ORDER BY MAX(id) DESC LIMIT 1",
        (session_id,)).fetchone()
    if row is None:
        return {"running": False, "run_id": None, "last_id": 0, "events": 0}
    rid = row["run_id"]
    done = get_conn().execute(
        "SELECT 1 FROM run_events WHERE run_id=? AND type IN"
        " ('run_done','run_failed','run_interrupted') LIMIT 1", (rid,)).fetchone()
    return {"running": done is None, "run_id": rid,
            "last_id": int(row["last_id"] or 0), "events": int(row["n"] or 0)}


def stats() -> Dict[str, Any]:
    c = get_conn()
    q = lambda sql: c.execute(sql).fetchone()[0]
    return {
        "sites": q("SELECT COUNT(*) FROM sites"),
        "sessions": q("SELECT COUNT(*) FROM sessions"),
        "site_memory": q("SELECT COUNT(*) FROM site_memory"),
        "prefs": q("SELECT COUNT(*) FROM user_prefs"),
        "messages": q("SELECT COUNT(*) FROM messages"),
        "tool_calls": q("SELECT COUNT(*) FROM tool_calls"),
        "artifacts": q("SELECT COUNT(*) FROM artifacts"),
        "pending_approvals": q("SELECT COUNT(*) FROM approvals WHERE status='pending'"),
    }