"""
Scout Agent · Flask API
"""
from __future__ import annotations

import json
import os
import threading
import time
from typing import Any, Dict

from flask import Flask, g, jsonify, request, send_file, Response

from . import agent, auth, db, skills, tools
from . import tools_ext          # noqa: F401  注册扩展工具到全局注册表
from . import autonomous, intel

app = Flask(__name__, static_folder="static", static_url_path="/static")
app.config["JSON_AS_ASCII"] = False
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024

COOKIE_NAME = "scout_token"

# 无需登录即可访问的路径（健康检查、静态资源、登录接口、首用户注册）
PUBLIC = ("/api/auth/register", "/api/auth/login", "/api/auth/bootstrap",
          "/api/auth/status", "/api/health")


def _extract_token() -> str:
    """取 token。优先 Authorization 头，其次 Cookie；
    EventSource 不能自定义头，所以 SSE 还允许 ?token= 查询参数。"""
    h = request.headers.get("Authorization", "")
    if h.startswith("Bearer "):
        return h[7:].strip()
    ck = request.cookies.get(COOKIE_NAME)
    if ck:
        return ck
    return (request.args.get("token") or "").strip()


def current_user() -> Optional[Dict[str, Any]]:
    tok = _extract_token()
    return auth.resolve_session(tok) if tok else None


def require_auth(fn):
    """API 守卫。未登录统一 401。

    注意 functools.wraps 保留原函数名——Flask 以函数名作为 endpoint，
    全部命名成 wrapper 会触发 "View function mapping is overwriting"。
    """
    from functools import wraps
    @wraps(fn)
    def wrapper(*a, **kw):
        u = current_user()
        if not u:
            resp = jsonify({"ok": False, "error": "未登录或登录已过期",
                            "need_login": True})
            resp.status_code = 401
            return resp
        g.user = u            # noqa: F841  (Flask g)
        return fn(*a, **kw)
    return wrapper


def require_admin(fn):
    """管理员守卫。wraps 保证 endpoint 名唯一。"""
    from functools import wraps
    @wraps(fn)
    def wrapper(*a, **kw):
        u = current_user()
        if not u:
            resp = jsonify({"ok": False, "error": "未登录或登录已过期",
                            "need_login": True})
            resp.status_code = 401
            return resp
        if u.get("role") != "admin":
            return fail("需要管理员权限", 403)
        g.user = u            # noqa: F841
        return fn(*a, **kw)
    return wrapper


def ok(data: Any = None, **kw):
    payload = {"ok": True}
    if data is not None:
        payload["data"] = data
    payload.update(kw)
    return jsonify(payload)


def fail(msg: str, code: int = 400, **kw):
    payload = {"ok": False, "error": msg}
    payload.update(kw)
    return jsonify(payload), code


# 说明：不要用 @app.errorhandler(Exception) 兜底——
# 它会把静态文件 404、模板缺失等基础错误也吞成 500，掩盖真实原因。
# 这里只处理业务异常，其余交给 Flask 默认处理。


# --------------------------------------------------------------------------
# 认证
# --------------------------------------------------------------------------
@app.get("/api/auth/status")
def api_auth_status():
    """登录态探测。首次部署时用来看是否需要初始化管理员。"""
    n = db.get_conn().execute("SELECT COUNT(*) FROM users").fetchone()[0]
    u = current_user()
    return ok({
        "need_setup": n == 0,
        "user_count": n,
        "user": u,
        "cache": auth.cache_stats(),
        "secret_persistent": bool(auth.SECRET_KEY),
    })


@app.post("/api/auth/register")
def api_register():
    """注册。

    两段式：
      - 系统未初始化（need_setup）：首个管理员，免邀请码；
      - 已初始化：必须携带管理员签发的邀请码。
    输入一律走 auth 的白名单校验，SQL 全程参数绑定。
    """
    d = request.get_json(force=True, silent=True) or {}
    ip = request.remote_addr or ""
    n = db.get_conn().execute("SELECT COUNT(*) FROM users").fetchone()[0]

    if n > 0:
        # 限流：同一 IP 的注册尝试也计数，避免用来爆破邀请码
        reason = auth.login_locked("__register__", ip)
        if reason:
            return fail(reason, 429)

    try:
        if n == 0:
            u = auth.create_user(d.get("username", ""), d.get("password", ""),
                                 d.get("display_name", ""))
            note = "已创建管理员账号，请登录"
        else:
            code = (d.get("invite_code") or "").strip()
            if not code:
                return fail("注册需要邀请码，请向管理员申请")
            u = auth.register_with_invite(
                d.get("username", ""), d.get("password", ""),
                d.get("display_name", ""), code)
            note = "注册成功，请登录"
    except auth.ValidationError as e:
        if n > 0:
            auth.record_login_fail("__register__", ip)
        return fail(str(e), 400)
    except ValueError as e:
        return fail(str(e), 400)

    if n > 0:
        auth.clear_login_fail("__register__", ip)
    return ok({"user": u, "note": note})


@app.post("/api/auth/login")
def api_login():
    d = request.get_json(force=True, silent=True) or {}
    username = (d.get("username") or "").strip()
    password = d.get("password") or ""
    ip = request.remote_addr or ""

    # 防爆破：先看是否已锁
    reason = auth.login_locked(username, ip)
    if reason:
        return fail(reason, 429)

    u = auth.authenticate(username, password)
    if not u:
        auth.record_login_fail(username, ip)
        # 载荷像注入时记审计日志（不记录原文）
        if auth.has_suspicious(username):
            db.log(None, "warn", "login rejected: username with SQL-injection patterns")
        return fail("用户名或密码错误", 401)

    auth.clear_login_fail(username, ip)
    s = auth.login(u["id"], request.headers.get("User-Agent", ""), ip)
    resp = ok({"user": u, "expires_at": s["expires_at"]})
    # HttpOnly + SameSite，避免脚本读取与跨站携带
    resp.set_cookie(COOKIE_NAME, s["token"], httponly=True, samesite="Lax",
                    max_age=auth.SESSION_TTL, path="/")
    return resp


@app.post("/api/auth/logout")
@require_auth
def api_logout():
    auth.revoke_session(_extract_token())
    resp = ok({"logged_out": True})
    resp.delete_cookie(COOKIE_NAME, path="/")
    return resp


@app.get("/api/auth/me")
@require_auth
def api_me():
    return ok({
        "user": g.user,
        "config": auth.public_config(auth.get_api_config(g.user["id"])),
        "runtime": auth.effective_runtime(g.user["id"]),
        "cache": auth.cache_stats(),
        "my_sessions": auth.list_sessions_for_user(g.user["id"])[:5],
    })


# ---------- API 配置 ----------
@app.get("/api/config")
@require_auth
def api_config_get():
    return ok({
        "config": auth.public_config(auth.get_api_config(g.user["id"])),
        "runtime": auth.effective_runtime(g.user["id"]),
        "cache": auth.cache_stats(),
    })


@app.post("/api/config")
@require_auth
def api_config_set():
    d = request.get_json(force=True, silent=True) or {}
    try:
        c = auth.save_api_config(g.user["id"], d)
    except ValueError as e:
        return fail(str(e))
    db.log(None, "info", f"user {g.user['username']} updated api config")
    return ok({"config": c, "runtime": auth.effective_runtime(g.user["id"]),
               "cache": auth.cache_stats()})


@app.post("/api/config/test")
@require_auth
def api_config_test():
    """实测网关连通性——不泄露密钥内容。"""
    import urllib.error
    import urllib.request as _rq

    base, key, model, timeout = auth.resolve_llm(g.user["id"])
    if not base:
        return fail("尚未配置网关地址", 400)
    url = f"{base}/models"
    req = _rq.Request(url, headers={"Authorization": f"Bearer {key}"})
    t0 = time.time()
    try:
        with _rq.urlopen(req, timeout=min(timeout, 15)) as r:
            body = r.read(2048)
            dt = int((time.time() - t0) * 1000)
            return ok({"reachable": True, "status": r.status,
                       "elapsed_ms": dt,
                       "hint": _model_names(body, model)})
    except urllib.error.HTTPError as e:
        # 地址可达但鉴权/路由有问题——这是最有价值的诊断信息
        return ok({"reachable": True, "status": e.code,
                   "hint": f"地址可达但返回 HTTP {e.code}，请检查 API Key 或接口路径"})
    except Exception as e:
        dt = int((time.time() - t0) * 1000)
        return ok({"reachable": False, "elapsed_ms": dt,
                   "hint": f"无法连接：{type(e).__name__}",
                   "detail": str(e)[:160]})


def _model_names(body: bytes, fallback: str) -> str:
    try:
        j = json.loads(body.decode("utf-8", "replace"))
        names = [m.get("id") for m in (j.get("data") or []) if isinstance(m, dict)]
        if names:
            shown = "、".join(names[:5])
            return f"可用模型：{shown}"
    except Exception:
        pass
    return f"当前模型：{fallback}"


@app.post("/api/auth/password")
@require_auth
def api_change_password():
    d = request.get_json(force=True, silent=True) or {}
    try:
        auth.change_password(g.user["id"], d.get("old_password", ""),
                             d.get("new_password", ""))
    except ValueError as e:
        return fail(str(e))
    return ok({"changed": True})


# ---------- 用户管理（管理员） ----------
@app.get("/api/users")
@require_auth
@require_admin
def api_users():
    return ok(auth.list_users())


@app.post("/api/users")
@require_auth
@require_admin
def api_create_user():
    d = request.get_json(force=True, silent=True) or {}
    try:
        u = auth.create_user(d.get("username", ""), d.get("password", ""),
                             d.get("display_name", ""), d.get("role"))
    except ValueError as e:
        return fail(str(e))
    return ok({"user": u})


@app.post("/api/users/<int:uid>/active")
@require_auth
@require_admin
def api_set_active(uid: int):
    d = request.get_json(force=True, silent=True) or {}
    if uid == g.user["id"] and not d.get("active", True):
        return fail("不能禁用自己的账号", 400)
    return ok(auth.set_user_active(uid, bool(d.get("active", True))))


@app.post("/api/users/<int:uid>/role")
@require_auth
@require_admin
def api_set_role(uid: int):
    d = request.get_json(force=True, silent=True) or {}
    try:
        return ok(auth.set_user_role(uid, d.get("role", "analyst")))
    except ValueError as e:
        return fail(str(e))


@app.post("/api/users/<int:uid>/revoke")
@require_auth
@require_admin
def api_revoke(uid: int):
    return ok({"revoked": auth.revoke_all_sessions(uid)})


# ---------- 邀请码 ----------
@app.get("/api/invites")
@require_admin
def api_invites():
    return ok({"invites": auth.list_invites()})


@app.post("/api/invites")
@require_admin
def api_create_invite():
    d = request.get_json(force=True, silent=True) or {}
    try:
        inv = auth.create_invite(d.get("role", "analyst"), d.get("note", ""),
                                 int(d.get("max_uses", 1)), g.user["id"])
    except auth.ValidationError as e:
        return fail(str(e), 400)
    except Exception:
        return fail("max_uses 必须是整数", 400)
    # 明文 code 只在这一次返回，之后库里只有哈希、无法再取回
    return ok({"invite": inv,
               "notice": "邀请码仅显示这一次，请立即复制给使用者"})


@app.delete("/api/invites/<int:iid>")
@require_admin
def api_revoke_invite(iid: int):
    return ok({"deleted": auth.revoke_invite(iid)})


@app.post("/api/auth/cache/flush")
@require_auth
@require_admin
def api_cache_flush():
    auth.invalidate_cache(None)
    return ok({"cache": auth.cache_stats()})


# --------------------------------------------------------------------------
# 系统
# --------------------------------------------------------------------------
@app.get("/api/health")
def health():
    return ok({
        "status": "healthy",
        "db": str(db.DB_PATH),
        "llm_configured": agent.llm_available(),
        "tools": len(tools.list_tools()),
        "skills": len(skills.list_skills()),
        "stats": db.stats(),
    })


@app.get("/api/stats")
@require_auth
def api_stats():
    return ok(db.stats())


@app.get("/api/tools")
@require_auth
def api_tools():
    return ok(tools.list_tools())


@app.get("/api/tools/specs")
@require_auth
def api_tool_specs():
    """返回 OpenAI function schema——前端可展示模型实际能调什么。"""
    return ok(autonomous.tool_specs())


@app.get("/api/intel/cve/<cve_id>")
@require_auth
def api_intel_cve(cve_id: str):
    try:
        return ok(intel.lookup_cve(cve_id))
    except intel.IntelError as e:
        return fail(str(e), 404)


@app.post("/api/intel/scan")
@require_auth
def api_intel_scan():
    d = request.get_json(force=True, silent=True) or {}
    text = (d.get("text") or "")
    mx = max(1, min(int(d.get("max", 3)), 8))
    return ok(intel.batch_lookup([text], max_n=mx))


@app.get("/api/skills")
@require_auth
def api_skills():
    return ok(skills.list_skills())


# --------------------------------------------------------------------------
# 站点（项目隔离单元）
# --------------------------------------------------------------------------
@app.get("/api/sites")
@require_auth
def api_sites():
    return ok(db.list_sites())


@app.get("/api/sites/<int:site_id>/memory")
@require_auth
def api_site_memory(site_id: int):
    ns = request.args.get("namespace")
    mem = db.recall(site_id, namespace=ns, limit=500)
    return ok(mem)


@app.get("/api/sites/<int:site_id>/profile")
@require_auth
def api_site_profile(site_id: int):
    return ok(db.site_profile(site_id))


@app.delete("/api/sites/<int:site_id>/memory")
@require_auth
def api_forget(site_id: int):
    ns = request.args.get("namespace")
    n = db.forget(site_id, namespace=ns)
    return ok({"deleted": n})


# --------------------------------------------------------------------------
# 会话（按域名自动命名 + 同域名复用）
# --------------------------------------------------------------------------
@app.get("/api/sessions")
@require_auth
def api_sessions():
    return ok(db.list_sessions(limit=int(request.args.get("limit", 100))))


@app.post("/api/sessions")
@require_auth
def api_create_session():
    d = request.get_json(force=True, silent=True) or {}
    target = d.get("target", "")
    title = d.get("title", "")
    model = d.get("model", db.get_pref("default_model", "scout-pro"))

    extracted = agent.extract_target(target + " " + title)
    if not extracted:
        return fail("需要提供 target（域名）")

    reuse = bool(d.get("reuse", True))
    if reuse:
        sess = db.get_or_create_session(extracted, title, model)
        sess["reused"] = True
    else:
        sess = db.create_session(extracted, title, model)
        sess["reused"] = False

    site = db.get_or_create_site(extracted)
    sess["memory"] = db.site_profile(site["id"])
    return ok(sess)


@app.post("/api/sessions/resolve")
@require_auth
def api_resolve_session():
    """只按域名解析会话——前端输入域名即可拿到对应窗口与记忆。"""
    d = request.get_json(force=True, silent=True) or {}
    domain = agent.extract_target(d.get("target", ""))
    if not domain:
        return fail("需要提供 target")
    sess = db.get_or_create_session(domain, d.get("title", ""),
                                    d.get("model", "scout-pro"))
    site = db.get_or_create_site(domain)
    return ok({"session": sess, "memory": db.site_profile(site["id"])})


@app.get("/api/sessions/<int:sid>")
@require_auth
def api_get_session(sid: int):
    sess = db.get_session(sid)
    site = db.get_or_create_site(sess["domain"])
    return ok({"session": sess, "memory": db.site_profile(site["id"])})


@app.get("/api/sessions/<int:sid>/detail")
@require_auth
def api_session_detail(sid: int):
    sess = db.get_session(sid)
    site = db.get_or_create_site(sess["domain"])
    return ok({
        "session": sess,
        "memory": db.site_profile(site["id"]),
        "messages": db.list_messages(sid),
        "tool_calls": db.list_tool_calls(sid),
        "approvals": db.list_approvals(sid),
        "artifacts": db.list_artifacts(sid),
        "owner": g.user["username"],
    })


@app.post("/api/sessions/<int:sid>/close")
@require_auth
def api_close_session(sid: int):
    db.set_session_status(sid, "closed")
    return ok({"session_id": sid, "status": "closed"})


@app.post("/api/sessions/<int:sid>/rename")
@require_auth
def api_rename_session(sid: int):
    d = request.get_json(force=True, silent=True) or {}
    title = (d.get("title") or "").strip()
    if not title:
        return fail("title 不能为空")
    with db.tx() as c:
        c.execute("UPDATE sessions SET title=?, updated_at=? WHERE id=?",
                  (title, db.now(), sid))
    return ok(db.get_session(sid))


# --------------------------------------------------------------------------
# 运行任务（异步 + SSE 流式）
# --------------------------------------------------------------------------
@app.post("/api/sessions/<int:sid>/run")
@require_auth
def api_run(sid: int):
    """启动任务，立即返回 run_id；执行过程通过 SSE 实时推送。"""
    d = request.get_json(force=True, silent=True) or {}
    text = (d.get("input") or "").strip()
    if not text:
        return fail("input 不能为空")
    try:
        db.get_session(sid)
    except KeyError:
        return fail(f"session {sid} 不存在", 404)

    run_id = f"run-{int(time.time() * 1000)}-{sid}"

    auth_uid = (g.user or {}).get("id")
    db.log(sid, "info", f"run started by uid={auth_uid}")

    def worker():
        try:
            agent.run_task(sid, text, run_id=run_id,
                            user_id=auth_uid)
        except Exception as e:
            try:
                db.emit(sid, run_id, "run_failed",
                        {"error": f"{type(e).__name__}: {e}"})
                db.log(sid, "error", f"run {run_id} crashed: {e}")
            except Exception:
                pass

    t = threading.Thread(target=worker, daemon=True, name=f"scout-run-{sid}")
    t.start()
    return ok({"run_id": run_id, "status": "started", "session_id": sid})


@app.get("/api/sessions/<int:sid>/stream")
@require_auth
def api_stream(sid: int):
    """SSE 流。after=事件 id 续传；run_id 可限定某一次执行。"""
    try:
        db.get_session(sid)
    except KeyError:
        return fail(f"session {sid} 不存在", 404)

    after = int(request.args.get("after", 0))
    run_id = request.args.get("run_id") or None
    idle_timeout = int(request.args.get("timeout", 900))

    def gen():
        cursor = after
        deadline = time.time() + idle_timeout
        # 先把断线期间的事件补齐
        while True:
            batch = db.events_since(sid, after_id=cursor, run_id=run_id, limit=200)
            for e in batch:
                cursor = e["id"]
                yield (f"id: {e['id']}\n"
                       f"event: {e['type']}\n"
                       f"data: {json.dumps(e, ensure_ascii=False)}\n\n")
            if batch:
                deadline = time.time() + idle_timeout
                continue
            # 告诉前端当前进度，前端据此恢复状态
            st = db.run_status(sid)
            yield (f"event: __ping__\n"
                   f"data: {json.dumps(st, ensure_ascii=False)}\n\n")
            if not st["running"] and (run_id is None or st["run_id"] == run_id):
                yield f"event: __eof__\ndata: {json.dumps(st, ensure_ascii=False)}\n\n"
                return
            if time.time() > deadline:
                yield "event: __timeout__\ndata: {}\n\n"
                return
            time.sleep(0.4)

    return Response(gen(), mimetype="text/event-stream", headers={
        "Cache-Control": "no-cache, no-transform",
        "X-Accel-Buffering": "no",      # 关闭 nginx 缓冲，保证实时
        "Connection": "keep-alive",
    })


@app.get("/api/sessions/<int:sid>/events")
@require_auth
def api_events(sid: int):
    """拉取历史事件（页面刷新后恢复现场，不依赖 SSE 重连）。"""
    after = int(request.args.get("after", 0))
    run_id = request.args.get("run_id") or None
    limit = min(int(request.args.get("limit", 500)), 2000)
    return ok(db.events_since(sid, after_id=after, run_id=run_id, limit=limit))


@app.get("/api/sessions/<int:sid>/status")
@require_auth
def api_run_status(sid: int):
    return ok(db.run_status(sid))


@app.get("/api/sessions/<int:sid>/messages")
@require_auth
def api_messages(sid: int):
    return ok(db.list_messages(sid))


# --------------------------------------------------------------------------
# 自主决策模式（LLM 选工具）
# --------------------------------------------------------------------------
@app.post("/api/sessions/<int:sid>/autonomous")
@require_auth
def api_autonomous(sid: int):
    """自主决策执行：模型自己决定调哪个工具、调几次、看到结果后下一步做什么。

    未配置 LLM 网关时自动降级为确定性工作流，功能不缺失。
    """
    d = request.get_json(force=True, silent=True) or {}
    text = (d.get("input") or "").strip()
    if not text:
        return fail("input 不能为空")
    try:
        session = db.get_session(sid)
    except KeyError:
        return fail(f"session {sid} 不存在", 404)

    run_id = f"auto-{int(time.time() * 1000)}-{sid}"
    uid = (g.user or {}).get("id")
    db.add_message(sid, "user", {"text": text})

    def ev(t: str, p: Dict[str, Any]) -> None:
        try:
            db.emit(sid, run_id, t, p)
        except Exception:
            pass

    def worker():
        try:
            dec = autonomous.run_autonomous(sid, text, run_id, uid, emit=ev)
            _finish_autonomous(sid, dec, run_id, session)
        except Exception as e:
            try:
                db.emit(sid, run_id, "run_failed",
                        {"error": f"{type(e).__name__}: {str(e)[:200]}"})
                db.log(sid, "error", f"autonomous {run_id} crashed: {e}")
            except Exception:
                pass

    threading.Thread(target=worker, daemon=True,
                     name=f"scout-auto-{sid}").start()
    return ok({"run_id": run_id, "status": "started", "mode": "autonomous",
               "session_id": sid})


def _finish_autonomous(session_id: int, dec, run_id: str, session: Dict[str, Any]) -> None:
    """收尾：落报告、发结论事件。"""
    def ev(t: str, p: Dict[str, Any]) -> None:
        try:
            db.emit(session_id, run_id, t, p)
        except Exception:
            pass

    db.add_message(session_id, "assistant", {"steps": dec.steps}, kind="run")
    ev("run_finished_steps", {"steps": dec.steps})

    v = dec.verdict
    site = db.get_or_create_site(session["domain"])
    findings = [{
        "title": f"{x.get('cve')} 前置条件核查",
        "severity": "high" if x.get("verdict") == "AFFECTED" else "info",
        "status": x.get("verdict"),
    } for x in (v.get("cve_checks") or [])]
    for x in (v.get("intel") or []):
        findings.append({"title": f"{x.get('cve')} 情报 CVSS {x.get('cvss')}",
                         "severity": "high" if x.get("kev") else "medium",
                         "status": "情报已获取，未验证前置条件"})

    md = tools.render_report(session, db.site_profile(site["id"]),
                             [{"cve": x.get("cve"), "verdict": x.get("verdict"),
                               "component": "-", "conclusion": x.get("conclusion")}
                              for x in (v.get("cve_checks") or [])],
                             findings)
    if dec.degraded:
        md = md.replace("## 一、测试范围与方法",
                        "> 本次由预设工作流执行（未配置 LLM 网关），工具调用路径固定。\n\n"
                        "## 一、测试范围与方法", 1)
    art = db.add_artifact(session_id, f"{session['name']}-安全测试报告.md", "md", md)

    label = v.get("label") or "需人工确认"
    done_n = sum(1 for s in dec.steps if s.get("status") == "done")
    # 优先用模型自己的结论文本（dec.summary），它才是真正的分析。
    # 只有拿不到时才退回拼接一行结论 —— 否则会把已经渲染过的
    # markdown 正文再用纯文本重复一遍，而模型的依据就丢了。
    summary = (dec.summary or "").strip()
    if not summary:
        reason = v.get("reason") or ""
        summary = f"**{label}**。{reason}。共执行 {done_n} 个工具调用、{dec.rounds} 轮决策。"
        if dec.degraded:
            summary += "（未配置 LLM，走的是固定工作流）"
    db.add_message(session_id, "assistant",
                   {"text": summary, "artifacts": [art],
                    "verdict_label": label})
    db.log(session_id, "info",
           f"autonomous done: {done_n} tools, {dec.rounds} rounds, {v.get('verdict')}")
    ev("artifact", art)
    ev("verdict", v)
    if not dec.summary:
        # 降级或模型没给正文时，这里补推一条，前端才有结论文本可显示
        ev("agent_text", {"text": summary, "llm": False})
    ev("run_done", {"status": "done", "verdict": v.get("verdict"),
                    "label": label, "report_id": art["id"],
                    "degraded": dec.degraded, "rounds": dec.rounds,
                    "tools_used": done_n})


# --------------------------------------------------------------------------
# 审批
# --------------------------------------------------------------------------
@app.get("/api/sessions/<int:sid>/approvals")
@require_auth
def api_approvals(sid: int):
    return ok(db.list_approvals(sid, request.args.get("status")))


@app.get("/api/approvals/<int:aid>")
@require_auth
def api_approval(aid: int):
    return ok(db.get_approval(aid))


@app.post("/api/approvals/<int:aid>/decide")
@require_auth
def api_decide(aid: int):
    d = request.get_json(force=True, silent=True) or {}
    approved = bool(d.get("approved"))
    try:
        result = agent.resume_after_approval(aid, approved)
    except KeyError:
        return fail(f"approval {aid} 不存在", 404)
    return ok(result)


# --------------------------------------------------------------------------
# 工具（供直接调用与调试）
# --------------------------------------------------------------------------
@app.post("/api/tools/<name>")
@require_auth
def api_call_tool(name: str):
    d = request.get_json(force=True, silent=True) or {}
    try:
        result = tools.execute(name, d.get("args") or {})
        return ok(result)
    except tools.NeedsApproval as na:
        return fail("该操作需要人工确认", 409, needs_approval=True,
                    title=na.title, description=na.description,
                    payload=na.payload, risk=na.risk)
    except KeyError:
        return fail(f"未知工具 {name}", 404)
    except Exception as e:
        return fail(f"{type(e).__name__}: {e}", 500)


# --------------------------------------------------------------------------
# 产物
# --------------------------------------------------------------------------
@app.get("/api/sessions/<int:sid>/artifacts")
@require_auth
def api_artifacts(sid: int):
    return ok(db.list_artifacts(sid))


@app.get("/api/artifacts/<int:aid>")
@require_auth
def api_artifact(aid: int):
    art = db.get_artifact(aid)
    return ok({k: v for k, v in art.items() if k != "content"} | {"content": art["content"]})


@app.get("/api/artifacts/<int:aid>/download")
@require_auth
def api_artifact_dl(aid: int):
    art = db.get_artifact(aid)
    import io
    buf = io.BytesIO(art["content"].encode("utf-8"))
    return send_file(buf, mimetype="text/plain; charset=utf-8",
                     as_attachment=True, download_name=art["name"])


# --------------------------------------------------------------------------
# 长期记忆（仅用户偏好）
# --------------------------------------------------------------------------
@app.get("/api/prefs")
@require_auth
def api_prefs_get():
    return ok({"values": db.all_prefs(), "allowed_keys": sorted(db.PREF_KEYS)})


@app.post("/api/prefs")
@require_auth
def api_prefs_set():
    d = request.get_json(force=True, silent=True) or {}
    key = d.get("key")
    if not key:
        return fail("key 不能为空")
    try:
        r = db.set_pref(key, d.get("value"))
    except ValueError as e:
        return fail(str(e))
    return ok(r)


@app.delete("/api/prefs/<key>")
@require_auth
def api_pref_del(key: str):
    n = db.delete_pref(key)
    return ok({"deleted": n})


# --------------------------------------------------------------------------
# 前端静态页
# --------------------------------------------------------------------------
def _send_page(name: str) -> Response:
    with open(os.path.join(app.root_path, "templates", name), encoding="utf-8") as f:
        return Response(f.read(), mimetype="text/html")


@app.get("/")
def index():
    # 未登录直接跳登录页；SSE 之类无 Cookie 的场景仍可用 ?token= 兜底
    if not current_user():
        return _send_page("login.html")
    return _send_page("index.html")


@app.get("/login")
def page_login():
    return _send_page("login.html")


@app.get("/favicon.ico")
def favicon():
    svg = ("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'>"
           "<rect width='24' height='24' rx='6' fill='#0d7d72'/>"
           "<g fill='none' stroke='#fff' stroke-width='2' stroke-linecap='round'>"
           "<circle cx='11' cy='11' r='6'/><path d='M15.6 15.6L20 20'/></g></svg>")
    return Response(svg, mimetype="image/svg+xml")


def bootstrap():
    """建表并写入默认用户偏好。gunicorn 下由 __main__ 钩子在 worker 启动前调用。"""
    db.init_db()
    defaults = {
        "default_model": os.environ.get("SCOUT_DEFAULT_MODEL", "scout-pro"),
        "default_skill": "web_recon",
        "approval_policy": "require-confirmation",
        "request_timeout": 10,
        "max_concurrency": 4,
        "report_style": "markdown",
        "report_language": "zh-CN",
        "user_role": "security-engineer",
        "default_severity_floor": "low",
        "rate_limit_rps": 2,
        "auto_summary": True,
        "ui_density": "comfortable",
    }
    for k, v in defaults.items():
        if db.get_pref(k) is None:
            try:
                db.set_pref(k, v)
            except Exception:
                pass
    auth.purge_expired_sessions()
    auth.purge_expired_invites()
    # 预热配置缓存：容器启动时把有配置的用户读进内存，避免首个请求慢
    try:
        for r in db.get_conn().execute("SELECT user_id FROM user_api_config").fetchall():
            auth.get_api_config(r["user_id"])
    except Exception:
        pass


# gunicorn 导入本模块时即完成初始化（每个 worker 都会执行，幂等）
bootstrap()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), threaded=True)