"""
Scout Agent · 内置技能

技能 = 一段可复用的工作流定义，声明：
  - 触发条件
  - 分步计划
  - 每步调用哪个工具
  - 是否需要审批
Agent 会根据用户意图挑选技能，把历史站点记忆注入每一步。
"""
from __future__ import annotations

from typing import Any, Dict, List

SKILLS: Dict[str, Dict[str, Any]] = {
    "web_recon": {
        "name": "web_recon",
        "title": "Web 资产被动侦察",
        "description": "对目标做指纹识别与端点收集，全部使用无副作用探针，"
                       "结果沉淀到站点记忆供复用。",
        "tags": ["recon", "fingerprint"],
        "steps": [
            {"id": "dns", "title": "解析 DNS 记录", "tool": "dns_lookup",
             "args": {"target": "$target"}, "why": "确认解析与同站资产归并"},
            {"id": "tls", "title": "读取 TLS 证书", "tool": "tls_inspect",
             "args": {"target": "$target"}, "why": "取签发者、SAN、有效期作为指纹"},
            {"id": "fp", "title": "被动指纹识别", "tool": "fingerprint",
             "args": {"target": "$target"}, "why": "判定服务器/框架/WAF，不发攻击载荷"},
            {"id": "enum", "title": "端点枚举", "tool": "endpoint_enum",
             "args": {"target": "$target"}, "why": "只读 GET 收集存在的接口"},
        ],
    },
    "cve_verify": {
        "name": "cve_verify",
        "title": "漏洞告警复现与前置条件核查",
        "description": "针对指定 CVE 排查触发前置条件，输出可确认/不可确认/需人工核查结论。",
        "tags": ["cve", "recon"],
        "steps": [
            {"id": "pre", "title": "前置条件排查", "tool": "cve_precondition",
             "args": {"target": "$target", "cve": "$cve"},
             "why": "仅用无副作用探针确认触发条件是否成立"},
        ],
    },
    "owasp_top10": {
        "name": "owasp_top10",
        "title": "OWASP Top 10 覆盖检查",
        "description": "按 A01–A10 逐项检查常见风险面，只读探测。",
        "tags": ["web", "check"],
        "steps": [
            {"id": "fp", "title": "指纹与防护基线", "tool": "fingerprint",
             "args": {"target": "$target"}, "why": "确认 WAF 与应用栈，决定后续检查深度"},
            {"id": "enum", "title": "敏感端点发现", "tool": "endpoint_enum",
             "args": {"target": "$target"},
             "why": "覆盖 A05 安全配置错误 / A01 访问控制相关暴露面"},
        ],
    },
    "report": {
        "name": "report",
        "title": "生成交付报告",
        "description": "汇总站点记忆与核查结果，产出 Markdown 报告。",
        "tags": ["report"],
        "steps": [
            {"id": "write", "title": "生成报告", "tool": "report_write",
             "args": {"session_id": "$session_id"}, "why": "沉淀可交付成果"},
        ],
    },
}


def list_skills() -> List[Dict[str, Any]]:
    return [{"name": s["name"], "title": s["title"], "description": s["description"],
             "tags": s["tags"], "step_count": len(s["steps"])} for s in SKILLS.values()]


def get_skill(name: str) -> Dict[str, Any]:
    if name not in SKILLS:
        raise KeyError(name)
    return SKILLS[name]


def pick_skills(text: str) -> List[str]:
    """按意图粗匹配技能。这是无 LLM 时的确定性兜底。"""
    t = (text or "").lower()
    picked = []
    cve_hits = [c for c in ("CVE-2025-24813", "CVE-2022-22965", "CVE-2021-44228",
                            "spring4shell", "log4shell", "tomcat") if c.lower() in t]
    if cve_hits or "复现" in t or "告警" in t or "漏洞" in t:
        picked.append("cve_verify")
    if any(w in t for w in ("渗透", "侦察", "指纹", "测绘", "暴露面", "枚举", "测试")):
        picked.append("web_recon")
    if any(w in t for w in ("owasp", "top10", "top 10", "常见风险")):
        picked.append("owasp_top10")
    if any(w in t for w in ("报告", "report", "总结", "输出")):
        picked.append("report")
    if not picked:
        picked = ["web_recon"]
    # 去重保序
    seen, out = set(), []
    for p in picked:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out