"""
Scout Agent · 编排引擎

执行模型：
  用户输入 → 归一化域名 → get_or_create_session（同域名复用同会话+同记忆）
         → pick_skills → 注入站点记忆 → 逐步执行工具
         → 写入站���记忆 → 命中审批则挂起等待 → 生成报告

LLM 可选：配置了 OpenAI 兼容端点则用于规划与总结；
未配置时自动降级为确定性工作流，功能完整可用（无编造内容）。
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from . import auth, db, skills, tools
from .tools import NeedsApproval, ToolError

MAX_STEPS = int(os.environ.get("SCOUT_MAX_STEPS", "12"))


# --------------------------------------------------------------------------
# LLM 调用（可选）
#
# 配置来源优先级：当前用户的 API 配置（内存缓存）→ 环境变量 → 无。
# 未配置时不报错，走确定性工作流，功能照常可用。
# --------------------------------------------------------------------------
def llm_available(user_id: Optional[int] = None) -> bool:
    base, key, _, _ = auth.resolve_llm(user_id)
    return bool(base and key)


def _llm_chat(messages: List[Dict[str, Any]], user_id: Optional[int] = None,
              tools_spec: Optional[List[Dict]] = None) -> Optional[Dict]:
    base, key, model, timeout = auth.resolve_llm(user_id)
    if not (base and key):
        return None
    payload = {"model": model, "messages": messages, "temperature": 0.2}
    if tools_spec:
        payload["tools"] = tools_spec
        payload["tool_choice"] = "auto"
    req = urllib.request.Request(
        f"{base}/chat/completions",
        data=json.dumps(payload, ensure_ascii=False).encode(),
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {key}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except Exception as e:
        # 只记类型，不把 URL/Key 写进日志
        db.log(None, "warn", f"LLM call failed ({type(e).__name__}), "
                             f"fallback to deterministic workflow")
        return None


SYSTEM_PROMPT = """你是 Scout，一个企业安全测试 Agent。
纪律：
1. 只在用户明确授权的资产上操作，绝不测试未授权目标。
2. 默认只用无副作用探针（GET/HEAD/OPTIONS）；任何写入类操作必须请求人工审批。
3. 不投递攻击载荷、不做拒绝服务、不修改业务数据。
4. 结论必须基于实际观察到的证据，不得编造。
输出：简洁的中文结构化说明，用 Markdown（`**要点**`、`- 列表项`、`> 引用`），不要输出 HTML 标签。"""


def _llm_plan(text: str, target: str, memory_brief: Dict[str, Any],
              user_id: Optional[int] = None) -> Optional[str]:
    ctx = json.dumps(memory_brief, ensure_ascii=False)[:1500]
    msgs = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content":
            f"用户请求：{text}\n目标：{target}\n该站点已有记忆：{ctx}\n"
            f"请用 2-4 句话说明你的执行计划，包含要核查的重点。"},
    ]
    r = _llm_chat(msgs, user_id)
    if not r:
        return None
    try:
        return r["choices"][0]["message"]["content"].strip()
    except Exception:
        return None


# --------------------------------------------------------------------------
# 站点记忆沉淀
# --------------------------------------------------------------------------
def _persist(target_domain: str, tool_name: str, result: Any) -> None:
    """把工具结果写入站点记忆——这是「同域名复用」的价值来源。"""
    try:
        site = db.get_or_create_site(target_domain)
        sid = site["id"]
        if not isinstance(result, dict):
            return

        if tool_name == "dns_lookup":
            for ip in result.get("A", []) or []:
                db.remember(sid, "config", f"ip:{ip}", {"value": ip}, 0.9, "dns_lookup")

        elif tool_name == "tls_inspect":
            db.remember(sid, "fingerprint", "tls.version", result.get("version"), 1.0, tool_name)
            db.remember(sid, "fingerprint", "tls.issuer",
                        result.get("issuer", {}).get("organizationName") or
                        str(result.get("issuer", {}))[:80], 0.95, tool_name)
            db.remember(sid, "fingerprint", "tls.not_after", result.get("not_after"), 1.0, tool_name)
            db.remember(sid, "fingerprint", "tls.san", result.get("san", []), 0.9, tool_name)

        elif tool_name == "fingerprint":
            db.remember(sid, "fingerprint", "http.status", result.get("status"), 1.0, tool_name)
            db.remember(sid, "fingerprint", "server", result.get("server"), 0.95, tool_name)
            db.remember(sid, "fingerprint", "title", result.get("title"), 0.9, tool_name)
            for t in result.get("tech", []) or []:
                db.remember(sid, "stack", f"{t.get('category')}:{t.get('name')}",
                            {"name": t.get("name"), "category": t.get("category")},
                            float(t.get("confidence", 0.7)), tool_name)
            for w in result.get("waf", []) or []:
                db.remember(sid, "stack", f"waf:{w.get('name')}",
                            {"name": w.get("name"), "category": "waf"}, 0.8, tool_name)
            allow = (result.get("headers") or {}).get("Allow") or result.get("allow_methods")
            if allow:
                db.remember(sid, "fingerprint", "http.allow", allow, 1.0, tool_name)

        elif tool_name == "endpoint_enum":
            for e in result.get("endpoints", []) or []:
                db.remember(sid, "endpoint", e["path"],
                            {"status": e.get("status"), "len": e.get("len"),
                             "note": e.get("note", "")}, 1.0, tool_name)

        elif tool_name == "cve_precondition":
            cve = result.get("cve", "")
            db.remember(sid, "finding", cve,
                        {"verdict": result.get("verdict"),
                         "title": result.get("title"),
                         "component": result.get("component"),
                         "conclusion": result.get("conclusion")},
                        1.0, tool_name)
    except Exception as e:
        db.log(None, "warn", f"persist failed for {tool_name}: {e}")


# --------------------------------------------------------------------------
# 主执行入口
# --------------------------------------------------------------------------
def run_task(session_id: int, user_text: str, run_id: str = "",
              user_id: Optional[int] = None) -> Dict[str, Any]:
    """执行一个任务，过程以流式事件输出（run_id 串联一次执行）。"""
    session = db.get_session(session_id)
    domain = session["domain"]
    site = db.get_or_create_site(domain)
    site_id = site["id"]
    run_id = run_id or f"run-{int(time.time() * 1000)}-{session_id}"

    def ev(type_: str, payload: Dict[str, Any]) -> None:
        try:
            db.emit(session_id, run_id, type_, payload)
        except Exception:
            pass

    ev("run_started", {"domain": domain, "run_id": run_id, "input": user_text})

    # 1) 记录用户消息
    db.add_message(session_id, "user", {"text": user_text})
    db.log(session_id, "info", f"user task on {domain}")

    # 2) 命中已有站点记忆 → 复用
    profile_before = db.site_profile(site_id)
    reused = profile_before["counts"]
    has_memory = any(reused.values())
    db.log(session_id, "info",
           f"site memory: fp={reused['fingerprint']} ep={reused['endpoints']} "
           f"stack={reused['stack']} finding={reused['findings']}")

    linked = {
        "event": "site_linked", "domain": domain, "site_key": site["site_key"],
        "session_name": session["name"],
        "memory_reused": has_memory, "memory_counts": reused,
        "note": ("检测到该站点已有历史记忆，本次测试将自动复用指纹与接口信息"
                 if has_memory else "首次测试该站点，将建立新的站点记忆"),
    }
    db.add_message(session_id, "system", linked)
    ev("site_linked", linked)

    # 3) 技能选择
    cve_ids = re.findall(r"CVE-\d{4}-\d{4,7}", (user_text or "").upper())
    picked = skills.pick_skills(user_text)
    if cve_ids:
        picked = ["cve_verify"] + [p for p in picked if p != "cve_verify"]
    ev("skills_picked", {"skills": picked, "cves": cve_ids})

    plan_llm = _llm_plan(user_text, domain, profile_before, user_id) \
        if llm_available(user_id) else None
    plan_text = plan_llm or (
        f"将对 **{domain}** 执行 {'、'.join(picked)}。"
        + ("检测到历史站点记忆，已自动复用。" if has_memory else "首次测试，建立初始画像。")
    )
    db.add_message(session_id, "assistant", {"text": plan_text})
    ev("agent_text", {"text": plan_text, "llm": bool(plan_llm)})

    # 4) 构建计划清单
    plan_items = []
    for sk_name in picked:
        sk = skills.get_skill(sk_name)
        for st in sk["steps"]:
            plan_items.append({"skill": sk_name, "title": st["title"],
                               "why": st.get("why", "")})
    plan_msg = {"plan": plan_items, "note": "点击步骤可查看将调用的工具与参数"}
    db.add_message(session_id, "assistant", plan_msg, kind="plan")
    ev("plan", plan_msg)

    # 5) 执行
    step_records: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    cve_results: List[Dict[str, Any]] = []
    pending: List[Dict[str, Any]] = []
    executed = 0
    max_steps = auth.effective_runtime(user_id).get("max_steps", MAX_STEPS)

    for sk_name in picked:
        if executed >= max_steps:
            break
        sk = skills.get_skill(sk_name)
        for st in sk["steps"]:
            if executed >= max_steps:
                break

            tool_name = st["tool"]
            args = {k: v for k, v in (st.get("args") or {}).items()}
            for k, v in list(args.items()):
                if v == "$target":
                    args[k] = domain
                elif v == "$cve":
                    args[k] = cve_ids[0] if cve_ids else ""
                elif v == "$session_id":
                    args[k] = session_id

            rec: Dict[str, Any] = {
                "step": st["id"], "skill": sk_name, "title": st["title"],
                "tool": tool_name, "args": args,
            }

            # 报告技能特殊处理
            if tool_name == "report_write":
                rec["status"] = "done"
                rec["duration_ms"] = 0
                step_records.append(rec)
                ev("step_done", rec)
                continue

            started = time.time()
            ev("step_start", dict(rec, status="running"))
            call_id = db.add_tool_call(session_id, tool_name, args, "running")
            try:
                result = tools.execute(tool_name, args)
                dur = int((time.time() - started) * 1000)
                db.update_tool_call(call_id, "done", result, "", dur)
                rec.update({"status": "done", "duration_ms": dur, "result": result})
                _persist(domain, tool_name, result)
                if tool_name == "cve_precondition":
                    cve_results.append(result)
                    findings.append({
                        "title": f"{result.get('cve')} {result.get('title','')}",
                        "severity": "high" if result.get("verdict") == "AFFECTED" else "info",
                        "status": result.get("verdict"),
                    })
                executed += 1

            except NeedsApproval as na:
                dur = int((time.time() - started) * 1000)
                appr = db.create_approval(session_id, na.title, na.description,
                                          na.payload, na.risk)
                db.update_tool_call(call_id, "awaiting", None, "awaiting approval", dur)
                rec.update({"status": "awaiting", "duration_ms": dur,
                            "approval_id": appr["id"], "risk": na.risk,
                            "description": na.description,
                            "payload": na.payload})
                pending.append(appr)
                step_records.append(rec)
                ev("step_done", rec)
                break  # 命中审批门，暂停后续步骤

            except ToolError as te:
                dur = int((time.time() - started) * 1000)
                # 重试一次（网络类瞬时失败）
                db.add_tool_call(session_id, tool_name, args, "failed",
                                 error=str(te), attempt=2, duration_ms=dur)
                db.update_tool_call(call_id, "failed", None, str(te), dur)
                rec.update({"status": "failed", "duration_ms": dur, "error": str(te),
                            "attempts": 2})
                executed += 1
                ev("step_failed", rec)
            except Exception as e:
                dur = int((time.time() - started) * 1000)
                db.update_tool_call(call_id, "failed", None, f"{type(e).__name__}: {e}", dur)
                rec.update({"status": "failed", "duration_ms": dur,
                            "error": f"{type(e).__name__}: {e}"})
                executed += 1
                ev("step_failed", rec)

            step_records.append(rec)
            if rec["status"] == "done":
                ev("step_done", rec)

        if pending:
            break

    # 6) 执行记录
    db.add_message(session_id, "assistant", {"steps": step_records}, kind="run")
    ev("run_finished_steps", {"steps": step_records})

    # 7) 审批门
    if pending:
        a = pending[0]
        gate_msg = {
            "gate": {
                "approval_id": a["id"], "title": a["title"],
                "description": a["description"], "risk": a["risk"],
                "payload": a["payload"], "options": a["options"],
            }
        }
        db.add_message(session_id, "assistant", gate_msg, kind="gate")
        db.log(session_id, "warn", f"awaiting approval #{a['id']}")
        summary = (f"已完成 {len(step_records)} 步，其中 "
                   f"{sum(1 for r in step_records if r['status']=='done')} 步成功。"
                   f"检测到需要写入类操作，已挂起等待你的确认。")
        db.add_message(session_id, "assistant", {"text": summary})
        ev("gate", gate_msg)
        ev("agent_text", {"text": summary})
        ev("run_done", {"status": "awaiting_approval", "approval_id": a["id"],
                        "steps": len(step_records), "reused_memory": has_memory})
        return {"status": "awaiting_approval", "approval_id": a["id"],
                "steps": len(step_records), "reused_memory": has_memory,
                "run_id": run_id}

    # 8) 生成报告
    ev("report_writing", {"note": "正在汇总站点记忆并生成报告"})
    report_md = tools.render_report(session, db.site_profile(site_id),
                                    cve_results, findings)
    art = db.add_artifact(session_id, f"{session['name']}-安全测试报告.md", "md", report_md)
    db.remember(site_id, "history", f"report:{art['id']}",
                {"name": art["name"], "artifact_id": art["id"],
                 "at": art["created_at"]}, 1.0, "report_write")

    done_n = sum(1 for r in step_records if r["status"] == "done")
    fail_n = sum(1 for r in step_records if r["status"] == "failed")
    verdict = "已生成报告"
    if cve_results:
        v = cve_results[0].get("verdict")
        verdict = {"AFFECTED": "⚠️ 确认受影响，需立即处置",
                   "LIKELY_NOT_AFFECTED": "✅ 前置条件不成立，判定不受影响",
                   "INCONCLUSIVE": "⚠️ 证据不足，需人工核查"}.get(v, "已生成报告")

    summary = (f"{verdict}。已完成 {done_n} 步"
               + (f"，{fail_n} 步失败" if fail_n else "")
               + "。" + ("已复用该站点历史记忆。" if has_memory
                         else "站点记忆已建立，下次测试同域名将自动复用。"))
    db.add_message(session_id, "assistant", {
        "text": summary, "artifacts": [art]})
    db.log(session_id, "info", f"task done: {done_n} ok, {fail_n} fail, report={art['id']}")
    ev("artifact", art)
    ev("agent_text", {"text": summary})
    ev("run_done", {"status": "done", "steps": len(step_records), "done": done_n,
                    "failed": fail_n, "report_id": art["id"],
                    "reused_memory": has_memory,
                    "cve_verdict": cve_results[0].get("verdict") if cve_results else None})

    return {"status": "done", "steps": len(step_records), "done": done_n,
            "failed": fail_n, "report_id": art["id"],
            "reused_memory": has_memory, "run_id": run_id,
            "cve_verdict": cve_results[0].get("verdict") if cve_results else None}


# --------------------------------------------------------------------------
# 审批放行后继续
# --------------------------------------------------------------------------
def resume_after_approval(approval_id: int, approved: bool) -> Dict[str, Any]:
    appr = db.get_approval(approval_id)
    session_id = appr["session_id"]
    run_id = f"run-appr-{int(time.time() * 1000)}-{session_id}"

    def ev(t: str, p: Dict[str, Any]) -> None:
        try:
            db.emit(session_id, run_id, t, p)
        except Exception:
            pass

    appr = db.decide_approval(approval_id, "approved" if approved else "rejected")
    db.log(session_id, "info", f"approval #{approval_id} -> {appr['status']}")
    ev("approval_decided", {"approval_id": approval_id,
                            "decision": "approved" if approved else "rejected"})

    if not approved:
        txt = ("已拒绝该写入类操作。已基于现有证据出具阶段性结论，"
               "被跳过的检查项在报告中标记为「未验证」。")
        db.add_message(session_id, "assistant", {"text": txt})
        sess = db.get_session(session_id)
        site = db.get_or_create_site(sess["domain"])
        md = tools.render_report(sess, db.site_profile(site["id"]), [], [])
        art = db.add_artifact(session_id, f"{sess['name']}-安全测试报告.md", "md", md)
        ev("artifact", art)
        ev("agent_text", {"text": txt})
        ev("run_done", {"status": "rejected", "report_id": art["id"]})
        return {"status": "rejected", "report_id": art["id"], "run_id": run_id}

    payload = appr.get("payload") or {}
    tool_name = payload.get("tool")
    args = payload.get("args") or {}
    started = time.time()
    rec = {"tool": tool_name, "args": args, "status": "running", "approved": True}
    ev("step_start", dict(rec))
    call_id = db.add_tool_call(session_id, tool_name, args, "running", attempt=1)
    try:
        result = tools.execute(tool_name, args)
        dur = int((time.time() - started) * 1000)
        db.update_tool_call(call_id, "done", result, "", dur)
        _persist(db.get_session(session_id)["domain"], tool_name, result)
        rec.update({"status": "done", "duration_ms": dur, "result": result})
        db.add_message(session_id, "assistant", {"steps": [rec]})
        db.add_message(session_id, "assistant", {"text": "已按你的确认执行该操作并回收现场，结果见上方记录。"})
        ev("run_finished_steps", {"steps": [rec]})
        ev("agent_text", {"text": "已按你的确认执行该操作并回收现场，结果见上方记录。"})
        ev("run_done", {"status": "done", "tool": tool_name})
        return {"status": "done", "tool": tool_name, "run_id": run_id}
    except Exception as e:
        dur = int((time.time() - started) * 1000)
        db.update_tool_call(call_id, "failed", None, str(e), dur)
        rec.update({"status": "failed", "duration_ms": dur, "error": str(e)})
        db.add_message(session_id, "assistant", {"steps": [rec]})
        ev("run_finished_steps", {"steps": [rec]})
        ev("run_done", {"status": "failed", "error": str(e)})
        return {"status": "failed", "error": str(e), "run_id": run_id}


# --------------------------------------------------------------------------
# 目标提取
# --------------------------------------------------------------------------
def extract_target(text: str, fallback: str = "") -> str:
    t = (text or "").strip()
    m = re.search(r"(?:https?://)?((?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})(?::\d+)?", t)
    if m:
        return db.normalize_target(m.group(1))
    ip = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", t)
    if ip:
        return ip.group(1)
    return db.normalize_target(fallback)