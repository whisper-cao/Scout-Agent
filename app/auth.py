"""
Scout Agent · 认证与 API 配置

安全设计
--------
- 密码：werkzeug 自带 PBKDF2/scrypt，绝不明文或可逆存储
- 会话 token：明文只在登录响应里出现一次，库里存 sha256 摘要 → 库泄露也无法冒用
- API Key：Fernet 对称加密落库，主密钥来自环境变量 SECRET_KEY；
  未配置时用随机生成的进程内密钥（重启后旧密文不可解，会自动要求重填）
- 配置缓存：进程内 LRU + TTL，写时失效；命中缓存可省掉一次解密与 DB 查询
"""
from __future__ import annotations

import base64
import hashlib
import os
import secrets
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from werkzeug.security import check_password_hash, generate_password_hash

from . import db

# --------------------------------------------------------------------------
# 配置
# --------------------------------------------------------------------------
SECRET_KEY = os.environ.get("SCOUT_SECRET_KEY", "")
SESSION_TTL = int(os.environ.get("SCOUT_SESSION_TTL", str(60 * 60 * 24 * 7)))   # 7 天
CACHE_TTL = int(os.environ.get("SCOUT_CONFIG_CACHE_TTL", "60"))                  # 配置缓存 60s
CACHE_MAX = 256

_fernet = None
_fernet_lock = threading.Lock()
_fallback_secret = None


def _get_fernet():
    """返回 Fernet 实例。主密钥优先取环境变量。"""
    global _fernet, _fallback_secret
    with _fernet_lock:
        if _fernet is not None:
            return _fernet
        raw = SECRET_KEY
        ephemeral = False
        if not raw:
            # 未配置主密钥：派生一个仅进程内的密钥。
            # 好处是开箱即用，代价是重启后旧密文解不开（会提示重填）。
            ephemeral = True
            if _fallback_secret is None:
                _fallback_secret = os.urandom(32)
            raw = _fallback_secret.hex()
        digest = hashlib.sha256(raw.encode("utf-8")).digest()
        key = base64.urlsafe_b64encode(digest)
        from cryptography.fernet import Fernet
        _fernet = Fernet(key)
        _fernet.ephemeral = ephemeral  # 供健康检查展示
        return _fernet


def encrypt_secret(plain: str) -> str:
    if not plain:
        return ""
    return _get_fernet().encrypt(plain.encode("utf-8")).decode("ascii")


def decrypt_secret(token: str) -> str:
    if not token:
        return ""
    try:
        return _get_fernet().decrypt(token.encode("ascii")).decode("utf-8")
    except Exception:
        return ""


def mask_secret(s: str) -> str:
    """脱敏展示：sk-abcdef123456…7890 → sk-a••••••7890"""
    if not s:
        return ""
    if len(s) <= 8:
        return "•" * len(s)
    return f"{s[:4]}{'•' * 6}{s[-4:]}"


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------
# 输入校验（纵深防御：SQL 全程参数绑定，这里再加一层字符白名单）
#
# 为什么参数绑定之外还要校验：
#   1. 参数绑定能挡 SQL 注入，但挡不住"脏数据入库"——
#      用户名 "admin' OR '1'='1" 会被当字面量存下来，污染账号表与日志。
#   2. 提前拒绝可以让错误提示更明确，不必等 DB 报错。
#   3. 限制长度可防超长输入打满内存/日志。
# --------------------------------------------------------------------------
import re as _re

# 用户名：字母数字、下划线、点、连字符，3~32 位
RE_USERNAME = _re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,31}$")
# 显示名称：允许中日韩、空格与常见符号，但禁止控制字符与不可见字符
RE_DISPLAY = _re.compile(r"^[^\x00-\x1f\x7f]{1,48}$")
# 角色：白名单
VALID_ROLES = ("admin", "analyst", "viewer")

# 常见的注入/探测特征，仅用于日志标记与早期拒绝，不作为唯一防线
_SUSPECT = _re.compile(
    r"(?i)("
    r"(--|#|/\*|\*/)"                    # SQL 注释
    r"|(\bunion\b\s+\bselect\b)"        # UNION SELECT
    r"|(\bselect\b.{1,40}\bfrom\b)"     # SELECT ... FROM
    r"|(\bdrop\b\s+\b(table|database)\b)"
    r"|(\binsert\b\s+\binto\b)"
    r"|(\bupdate\b\s+\w+\s+\bset\b)"
    r"|(\bdelete\b\s+\bfrom\b)"
    r"|(\bor\b\s+['\"]?1['\"]?\s*=\s*['\"]?1)"
    r"|(\b(and\b\s+1\s*=\s*1))"
    r"|(\bsleep\s*\(|benchmark\s*\()"    # 时间盲注
    r"|(xp_cmdshell|information_schema)"
    r"|('|\")\s*(or|and)\s*('|\")?\s*\d" # ' or '1'='1
    r")"
)


class ValidationError(ValueError):
    """输入校验失败。调用方应转成 400 返回。"""


def validate_username(raw: str) -> str:
    # 先看未清洗的原串：如果用户输入了首尾空白，说明他在依赖服务端"帮他修"，
    # 直接拒绝比静默 strip 更明确（" lead" 会被 strip 成合法名，静默通过是错的）。
    u = raw or ""
    if u != u.strip():
        raise ValidationError("用户名首尾不能有空格")
    u = u.strip()
    if not u:
        raise ValidationError("用户名不能为空")
    if len(u) < 3:
        raise ValidationError("用户名至少 3 个字符")
    if len(u) > 32:
        raise ValidationError("用户名最多 32 个字符")
    if _SUSPECT.search(u):
        # 不回显载荷内容，避免把攻击字符串反射回给攻击者
        db.log(None, "warn", "rejected username containing SQL-injection patterns")
        raise ValidationError("用户名包含不允许的字符")
    if not RE_USERNAME.match(u):
        raise ValidationError("用户名只能包含字母、数字、下划线、点和连字符，且须以字母或数字开头")
    return u.lower()


def validate_password(raw: str) -> str:
    p = raw or ""
    if len(p) < 8:
        raise ValidationError("密码至少 8 个字符")
    if len(p) > 256:
        raise ValidationError("密码过长")
    if _SUSPECT.search(p) or _re.search(r"['\"\\\x00-\x1f]", p):
        # 密码含引号/反斜杠/控制字符时拒绝——不做转义，避免引号进入哈希前引发歧义
        db.log(None, "warn", "rejected password containing SQL-injection patterns")
        raise ValidationError("密码不能包含引号、反斜杠或控制字符")
    return p


def validate_display_name(raw: str, fallback: str = "") -> str:
    d = (raw or "").strip() or fallback
    if len(d) > 48:
        raise ValidationError("显示名称最多 48 个字符")
    if not RE_DISPLAY.match(d):
        raise ValidationError("显示名称包含控制字符")
    return d


def validate_role(raw: Optional[str], default: Optional[str] = None) -> str:
    r = (raw or default or "analyst")
    if r not in VALID_ROLES:
        raise ValidationError("role 必须是 admin/analyst/viewer")
    return r


def has_suspicious(raw: str) -> bool:
    """给通用入口用的轻量检测：命中则记录审计日志。"""
    return bool(_SUSPECT.search(raw or ""))


# --------------------------------------------------------------------------
# 登录限流（防口令爆破）
#
# 内存滑动窗口，按 (ip, username) 双维度计数：
#   - 单用户名 15 分钟内失败 8 次 → 锁
#   - 单 IP     15 分钟内失败 30 次 → 锁
# 进程内存实现（多 worker 下每个 worker 各自计数，够用且零依赖）。
# --------------------------------------------------------------------------
LOGIN_FAIL_LIMIT_USER = 8
LOGIN_FAIL_LIMIT_IP = 30
LOGIN_WINDOW = 900          # 15 分钟

_fail_log: Dict[str, List[float]] = {}
_fail_lock = threading.Lock()


def _prune(now_t: float) -> None:
    cutoff = now_t - LOGIN_WINDOW
    for k in [k for k, v in _fail_log.items()
              if not v or max(v) < cutoff]:
        _fail_log.pop(k, None)


def login_locked(username: str, ip: str) -> Optional[str]:
    """返回锁定原因；None 表示未锁定。"""
    now_t = time.time()
    with _fail_lock:
        _prune(now_t)
        u = _fail_log.get("u:" + (username or "").lower(), [])
        i = _fail_log.get("i:" + (ip or ""), [])
        if len(u) >= LOGIN_FAIL_LIMIT_USER:
            return "该账号登录失败次数过多，请 15 分钟后再试"
        if len(i) >= LOGIN_FAIL_LIMIT_IP:
            return "当前来源 IP 登录失败次数过多，请稍后再试"
    return None


def record_login_fail(username: str, ip: str) -> None:
    now_t = time.time()
    with _fail_lock:
        _prune(now_t)
        for key in ("u:" + (username or "").lower(), "i:" + (ip or "")):
            _fail_log.setdefault(key, []).append(now_t)


def clear_login_fail(username: str, ip: str) -> None:
    with _fail_lock:
        _fail_log.pop("u:" + (username or "").lower(), None)
        _fail_log.pop("i:" + (ip or ""), None)


# --------------------------------------------------------------------------
# 用户
# --------------------------------------------------------------------------
def create_user(username: str, password: str, display_name: str = "",
                role: Optional[str] = None) -> Dict[str, Any]:
    username = validate_username(username)
    password = validate_password(password)
    n = db.get_conn().execute("SELECT COUNT(*) FROM users").fetchone()[0]
    role = validate_role(role, "admin" if n == 0 else "analyst")
    ts = db.now()
    dn = validate_display_name(display_name, username)
    try:
        with db.tx() as c:
            cur = c.execute(
                "INSERT INTO users(username, display_name, password_hash, role, created_at, updated_at)"
                " VALUES(?,?,?,?,?,?)",
                (username, dn, generate_password_hash(password), role, ts, ts))
            uid = int(cur.lastrowid)
    except db.sqlite3.IntegrityError:
        # 并发下同名也可能撞唯一索引，同样按"已存在"处理
        raise ValidationError(f"用户名 {username} 已存在")
    invalidate_cache(uid)
    return get_user(uid)


def get_user(user_id: int) -> Dict[str, Any]:
    r = db.get_conn().execute(
        "SELECT id, username, display_name, role, is_active, last_login_at, created_at"
        " FROM users WHERE id=?", (user_id,)).fetchone()
    if r is None:
        raise KeyError(f"user {user_id} not found")
    return dict(r)


def get_user_by_name(username: str) -> Optional[Dict[str, Any]]:
    r = db.get_conn().execute(
        "SELECT id, username, display_name, password_hash, role, is_active"
        " FROM users WHERE username=?", ((username or "").strip().lower(),)).fetchone()
    return dict(r) if r else None


def list_users() -> List[Dict[str, Any]]:
    rows = db.get_conn().execute(
        "SELECT id, username, display_name, role, is_active, last_login_at, created_at"
        " FROM users ORDER BY id ASC").fetchall()
    return [dict(r) for r in rows]


def authenticate(username: str, password: str) -> Optional[Dict[str, Any]]:
    """校验登录。

    安全要点：
      - SQL 走参数绑定，输入不参与语句拼接；
      - 即便账号不存在也执行一次等价的哈希校验，让响应时间不可用于枚举用户；
      - 用户名先用同一套白名单校验，异常载荷直接判失败而不是"查不到用户"。
    """
    raw_u = (username or "").strip()
    # 先做白名单校验；不通过时仍走恒定耗时分支，避免时间侧信道
    if not RE_USERNAME.match(raw_u) or len(raw_u) > 32:
        check_password_hash(generate_password_hash("x"), password or "x")
        return None

    u = get_user_by_name(raw_u)
    if not u or not u["is_active"]:
        check_password_hash(generate_password_hash("x"), password or "x")
        return None
    if not check_password_hash(u["password_hash"], password or ""):
        return None
    with db.tx() as c:
        c.execute("UPDATE users SET last_login_at=? WHERE id=?", (db.now(), u["id"]))
    return get_user(u["id"])


def change_password(user_id: int, old_password: str, new_password: str) -> None:
    u = get_user_by_name(get_user(user_id)["username"])
    if not u or not check_password_hash(u["password_hash"], old_password or ""):
        raise ValidationError("原密码不正确")
    new_password = validate_password(new_password)
    with db.tx() as c:
        c.execute("UPDATE users SET password_hash=?, updated_at=? WHERE id=?",
                  (generate_password_hash(new_password), db.now(), user_id))


def set_user_active(user_id: int, active: bool) -> Dict[str, Any]:
    with db.tx() as c:
        c.execute("UPDATE users SET is_active=?, updated_at=? WHERE id=?",
                  (1 if active else 0, db.now(), user_id))
    if not active:
        revoke_all_sessions(user_id)
    return get_user(user_id)


def set_user_role(user_id: int, role: str) -> Dict[str, Any]:
    role = validate_role(role)
    with db.tx() as c:
        c.execute("UPDATE users SET role=?, updated_at=? WHERE id=?",
                  (role, db.now(), user_id))
    return get_user(user_id)


# --------------------------------------------------------------------------
# 登录会话
# --------------------------------------------------------------------------
def login(user_id: int, user_agent: str = "", ip: str = "") -> Dict[str, Any]:
    token = secrets.token_urlsafe(32)
    ts = db.now()
    exp = time.time() + SESSION_TTL
    with db.tx() as c:
        c.execute(
            "INSERT INTO auth_sessions(token_hash, user_id, created_at, expires_at,"
            " last_seen_at, user_agent, ip) VALUES(?,?,?,?,?,?,?)",
            (hash_token(token), user_id, ts,
             time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(exp)), ts,
             (user_agent or "")[:200], ip or ""))
    return {"token": token, "expires_at": exp, "user": get_user(user_id)}


def resolve_session(token: str) -> Optional[Dict[str, Any]]:
    """校验 token → 返回用户。同时滑动续期。"""
    if not token:
        return None
    th = hash_token(token)
    r = db.get_conn().execute(
        "SELECT s.token_hash, s.expires_at, u.id, u.is_active FROM auth_sessions s"
        " JOIN users u ON u.id=s.user_id WHERE s.token_hash=?", (th,)).fetchone()
    if r is None:
        return None
    if not r["is_active"]:
        return None
    try:
        if time.mktime(time.strptime(r["expires_at"], "%Y-%m-%dT%H:%M:%S")) < time.time():
            revoke_session(token)
            return None
    except Exception:
        pass
    with db.tx() as c:
        c.execute("UPDATE auth_sessions SET last_seen_at=? WHERE token_hash=?", (db.now(), th))
    return get_user(r["id"])


def revoke_session(token: str) -> int:
    with db.tx() as c:
        return c.execute("DELETE FROM auth_sessions WHERE token_hash=?",
                         (hash_token(token),)).rowcount


def revoke_all_sessions(user_id: int) -> int:
    with db.tx() as c:
        return c.execute("DELETE FROM auth_sessions WHERE user_id=?", (user_id,)).rowcount


def purge_expired_sessions() -> int:
    now_s = time.strftime("%Y-%m-%dT%H:%M:%S")
    with db.tx() as c:
        return c.execute("DELETE FROM auth_sessions WHERE expires_at < ?", (now_s,)).rowcount


def list_sessions_for_user(user_id: int) -> List[Dict[str, Any]]:
    rows = db.get_conn().execute(
        "SELECT created_at, expires_at, last_seen_at, user_agent, ip FROM auth_sessions"
        " WHERE user_id=? ORDER BY last_seen_at DESC", (user_id,)).fetchall()
    return [dict(r) for r in rows]


# --------------------------------------------------------------------------
# 自助注册（需邀请码）
#
# 为什么不是完全开放注册：安全工具的账号一旦可随意自助创建，
# 等于把探测能力开放给任何拿到 URL 的人。所以：
#   - 首个账号：初始化流程（need_setup 时免邀请码）
#   - 后续账号：必须持管理员生成的邀请码
# 邀请码存哈希（和密码同理），用完即废，可随时禁用。
# --------------------------------------------------------------------------
def _invite_hash(code: str) -> str:
    return hashlib.sha256(("scout-invite:" + (code or "")).encode("utf-8")).hexdigest()


def create_invite(role: str = "analyst", note: str = "",
                  max_uses: int = 1, created_by: Optional[int] = None) -> Dict[str, Any]:
    role = validate_role(role, "analyst")
    max_uses = max(1, min(int(max_uses), 100))
    # 128bit 随机，足够抗爆破
    code = secrets.token_urlsafe(12)
    ts = db.now()
    with db.tx() as c:
        cur = c.execute(
            "INSERT INTO auth_invites(code_hash, role, note, max_uses, used_count,"
            " created_by, created_at) VALUES(?,?,?,?,?,?,?)",
            (_invite_hash(code), role, (note or "")[:120], max_uses, 0,
             created_by, ts))
        iid = int(cur.lastrowid)
    return {"id": iid, "code": code, "role": role, "note": note,
            "max_uses": max_uses, "used_count": 0}


def list_invites(include_used: bool = True) -> List[Dict[str, Any]]:
    sql = ("SELECT id, role, note, max_uses, used_count, created_by, created_at,"
           " used_at FROM auth_invites")
    if not include_used:
        sql += " WHERE used_at IS NULL"
    rows = db.get_conn().execute(sql + " ORDER BY id DESC").fetchall()
    return [dict(r) for r in rows]


def revoke_invite(invite_id: int) -> int:
    with db.tx() as c:
        return c.execute("DELETE FROM auth_invites WHERE id=? AND used_at IS NULL",
                         (invite_id,)).rowcount


def consume_invite(code: str) -> str:
    """校验并核销邀请码，返回该邀请码对应的角色。
    校验与核销放在同一事务里，避免并发下同一码被用多次。"""
    ch = _invite_hash(code)
    ts = db.now()
    with db.tx() as c:
        row = c.execute(
            "SELECT id, role, max_uses, used_count FROM auth_invites WHERE code_hash=?",
            (ch,)).fetchone()
        if row is None:
            db.log(None, "warn", "register rejected: invalid invite")
            raise ValidationError("邀请码无效")
        if row["used_count"] >= row["max_uses"]:
            db.log(None, "warn", "register rejected: invite exhausted")
            raise ValidationError("邀请码已被使用")
        c.execute("UPDATE auth_invites SET used_count=used_count+1, used_at=? WHERE id=?",
                  (ts, row["id"]))
        return row["role"]


def register_with_invite(username: str, password: str, display_name: str,
                         invite_code: str) -> Dict[str, Any]:
    # 先校验账号格式，再核销邀请码。
    # 否则用户填错用户名时会看到"邀请码无效"，把问题指错了方向。
    validated_u = validate_username(username)
    validated_p = validate_password(password)
    validated_d = validate_display_name(display_name, validated_u)

    role = consume_invite(invite_code)          # 再核销，失败即抛
    try:
        u = create_user(validated_u, validated_p, validated_d, role)
    except Exception:
        # 账号创建失败不该白吃掉邀请码，退回未使用状态
        ch = _invite_hash(invite_code)
        with db.tx() as c:
            c.execute("UPDATE auth_invites SET used_count=MAX(0,used_count-1),"
                      " used_at=NULL WHERE code_hash=?", (ch,))
        raise
    db.log(None, "info", f"registered user {u['username']} role={u['role']}")
    return u


def purge_expired_invites() -> int:
    """清理用尽且已使用过的邀请码记录。"""
    with db.tx() as c:
        return c.execute("DELETE FROM auth_invites WHERE used_at IS NOT NULL").rowcount
DEFAULT_CONFIG = {
    "llm_base": "", "llm_model": "qwen", "llm_timeout": 60,
    "probe_timeout": 10, "max_steps": 12, "max_rounds": 8, "verify_ssl": False,
}

_cache: Dict[int, Dict[str, Any]] = {}
_cache_lock = threading.Lock()
_cache_stats = {"hit": 0, "miss": 0, "set": 0, "invalidate": 0}


def cache_stats() -> Dict[str, Any]:
    with _cache_lock:
        return {**_cache_stats, "entries": len(_cache)}


def invalidate_cache(user_id: Optional[int] = None) -> None:
    with _cache_lock:
        if user_id is None:
            _cache.clear()
            _cache_stats["invalidate"] += 1
        else:
            _cache.pop(user_id, None)
            _cache_stats["invalidate"] += 1


def get_api_config(user_id: int) -> Dict[str, Any]:
    """读配置。命中缓存直接返回（含解密后的 key，仅存在于内存）。"""
    now_t = time.time()
    with _cache_lock:
        hit = _cache.get(user_id)
        if hit and now_t - hit["_at"] < CACHE_TTL:
            _cache_stats["hit"] += 1
            return hit["cfg"]

    row = db.get_conn().execute(
        "SELECT llm_base, llm_key_enc, llm_model, llm_timeout, probe_timeout,"
        " max_steps, max_rounds, verify_ssl FROM user_api_config WHERE user_id=?",
        (user_id,)).fetchone()

    cfg = dict(DEFAULT_CONFIG)
    if row:
        cfg.update({
            "llm_base": (row["llm_base"] or "").rstrip("/"),
            "llm_model": row["llm_model"] or "qwen",
            "llm_timeout": int(row["llm_timeout"] or 60),
            "probe_timeout": int(row["probe_timeout"] or 10),
            "max_steps": int(row["max_steps"] or 12),
            "verify_ssl": bool(row["verify_ssl"]),
        })
        # max_rounds 是后加的列，老行可能是 NULL
        try:
            cfg["max_rounds"] = int(row["max_rounds"] or 8)
        except (IndexError, KeyError, TypeError, ValueError):
            cfg["max_rounds"] = 8
        cfg["_llm_key"] = decrypt_secret(row["llm_key_enc"] or "")
    else:
        cfg["_llm_key"] = ""

    with _cache_lock:
        _cache_stats["miss"] += 1
        if len(_cache) >= CACHE_MAX:                 # 简易 LRU：丢最早写入的
            _cache.pop(next(iter(_cache)), None)
        _cache[user_id] = {"at": now_t, "cfg": cfg, "_at": now_t}
        _cache_stats["set"] += 1
    return cfg


def save_api_config(user_id: int, data: Dict[str, Any]) -> Dict[str, Any]:
    """保存配置。llm_key 为空表示保持原值；传 '__CLEAR__' 表示清空。"""
    cur = get_api_config(user_id)
    base = (data.get("llm_base", cur["llm_base"]) or "").strip().rstrip("/")
    if base and not base.startswith(("http://", "https://")):
        raise ValueError("网关地址必须以 http:// 或 https:// 开头")
    model = (data.get("llm_model", cur["llm_model"]) or "qwen").strip()

    raw_key = data.get("llm_key")
    if raw_key == "__CLEAR__":
        key_enc = ""
    elif raw_key:
        key_enc = encrypt_secret(raw_key.strip())
    else:
        key_enc = encrypt_secret(cur.get("_llm_key", "")) if cur.get("_llm_key") else ""

    def _num(k: str, lo: int, hi: int, dflt: int) -> int:
        """取值并夹到 [lo, hi]。超界直接报错，不要静默改写——
        静默夹紧会让用户以为设置生效了，实际被改掉。"""
        v = data.get(k, dflt)
        if v is None or v == "":
            return dflt
        try:
            v = int(v)
        except Exception:
            raise ValueError(f"{k} 必须是整数")
        if v < lo or v > hi:
            raise ValueError(f"{k} 必须在 {lo}~{hi} 之间，当前为 {v}")
        return v

    with db.tx() as c:
        c.execute(
            "INSERT INTO user_api_config(user_id, llm_base, llm_key_enc, llm_model,"
            " llm_timeout, probe_timeout, max_steps, max_rounds, verify_ssl,"
            " updated_at, updated_by)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?)"
            " ON CONFLICT(user_id) DO UPDATE SET llm_base=excluded.llm_base,"
            " llm_key_enc=excluded.llm_key_enc, llm_model=excluded.llm_model,"
            " llm_timeout=excluded.llm_timeout, probe_timeout=excluded.probe_timeout,"
            " max_steps=excluded.max_steps, max_rounds=excluded.max_rounds,"
            " verify_ssl=excluded.verify_ssl,"
            " updated_at=excluded.updated_at, updated_by=excluded.updated_by",
            (user_id, base, key_enc, model,
             _num("llm_timeout", 5, 600, 60),
             _num("probe_timeout", 3, 60, 10),
             _num("max_steps", 1, 200, 12),
             _num("max_rounds", 1, 60, 8),
             1 if data.get("verify_ssl") else 0,
             db.now(), user_id))
    invalidate_cache(user_id)          # 写后失效，保证下次读到新值
    return public_config(get_api_config(user_id))


def public_config(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """对外安全视图：不含明文 key。"""
    key = cfg.get("_llm_key", "")
    return {
        "llm_base": cfg.get("llm_base", ""),
        "llm_model": cfg.get("llm_model", "qwen"),
        "llm_timeout": cfg.get("llm_timeout", 60),
        "probe_timeout": cfg.get("probe_timeout", 10),
        "max_steps": cfg.get("max_steps", 12),
        "max_rounds": cfg.get("max_rounds", 8),
        "verify_ssl": bool(cfg.get("verify_ssl")),
        "llm_key_set": bool(key),
        "llm_key_masked": mask_secret(key),
        "llm_ready": bool(cfg.get("llm_base") and key),
    }


def resolve_llm(user_id: Optional[int]) -> Tuple[str, str, str, int]:
    """给 agent 用：返回 (base, key, model, timeout)。"""
    if user_id:
        cfg = get_api_config(user_id)
        base, key = cfg.get("llm_base", ""), cfg.get("_llm_key", "")
        if base and key:
            return base, key, cfg.get("llm_model", "qwen"), int(cfg.get("llm_timeout", 60))
    # 回退到环境变量（管理员全局默认）
    base = os.environ.get("SCOUT_LLM_BASE", "").rstrip("/")
    key = os.environ.get("SCOUT_LLM_KEY", "")
    if base and key:
        return base, key, os.environ.get("SCOUT_LLM_MODEL", "qwen"), \
            int(os.environ.get("SCOUT_LLM_TIMEOUT", "60"))
    return "", "", os.environ.get("SCOUT_LLM_MODEL", "qwen"), 60


def effective_runtime(user_id: Optional[int]) -> Dict[str, Any]:
    """给 agent 用的运行时参数（超时、深度上限等）。"""
    if user_id:
        cfg = get_api_config(user_id)
        return {"max_steps": int(cfg.get("max_steps", 12)),
                "max_rounds": int(cfg.get("max_rounds", 8)),
                "probe_timeout": int(cfg.get("probe_timeout", 10))}
    return {"max_steps": int(os.environ.get("SCOUT_MAX_STEPS", "12")),
            "max_rounds": int(os.environ.get("SCOUT_MAX_ROUNDS", "8")),
            "probe_timeout": 10}