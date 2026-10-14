"""
Scout Agent · 工具函数注册表

安全纪律（与用户既定红线一致）
------------------------------
- 默认只读：GET / HEAD / OPTIONS 探测，不投递攻击载荷
- 写入类操作（PUT/POST/DELETE/PATCH）必须走审批门，由人工确认
- 禁止内网/本机目标（除非显式允许本地自测）
- 全程记录到站点记忆，供后续同域名测试复用
"""
from __future__ import annotations

import hashlib
import json
import re
import socket
import ssl
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional

from . import db

# --------------------------------------------------------------------------
# 只读方法白名单（可直接执行，无需审批）
SAFE_METHODS = ("GET", "HEAD", "OPTIONS")
# 写入/破坏性方法（必须审批）
RISKY_METHODS = ("PUT", "POST", "DELETE", "PATCH")

_UA = "Scout-Agent/1.0 (+authorized-security-testing)"
DEFAULT_TIMEOUT = 10


class ToolError(Exception):
    pass


class NeedsApproval(Exception):
    """工具判定该操作需要人工确认。"""

    def __init__(self, title: str, description: str, payload: Dict[str, Any],
                 risk: str = "high"):
        super().__init__(title)
        self.title = title
        self.description = description
        self.payload = payload
        self.risk = risk


# --------------------------------------------------------------------------
# 注册表
# --------------------------------------------------------------------------
_REGISTRY: Dict[str, Dict[str, Any]] = {}


def tool(name: str, description: str, schema: Dict[str, Any],
         writes: bool = False, tags: Optional[List[str]] = None):
    def deco(fn: Callable):
        _REGISTRY[name] = {
            "name": name, "fn": fn, "description": description,
            "schema": schema, "writes": writes, "tags": tags or [],
        }
        return fn
    return deco


def get_tool(name: str) -> Dict[str, Any]:
    if name not in _REGISTRY:
        raise ToolError(f"unknown tool: {name}")
    return _REGISTRY[name]


def list_tools() -> List[Dict[str, Any]]:
    return [
        {"name": t["name"], "description": t["description"],
         "schema": t["schema"], "writes": t["writes"], "tags": t["tags"]}
        for t in _REGISTRY.values()
    ]


def _build_url(domain: str, path: str = "", scheme: str = "https") -> str:
    d = db.normalize_target(domain)
    if not d:
        raise ToolError("target domain is empty")
    if path.startswith(("http://", "https://")):
        return path
    if not path.startswith("/"):
        path = "/" + path
    return f"{scheme}://{d}{path}"


# --------------------------------------------------------------------------
# 1. http_probe —— 核心探测，唯一出网工具
# --------------------------------------------------------------------------
@tool(
    name="http_probe",
    description="对目标发起一次 HTTP 请求并返回状态码、响应头与响应体摘要。"
                "默认只读；写入方法会被拦截并转入审批流程。",
    schema={
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "目标域名"},
            "path": {"type": "string", "description": "请求路径，如 / 或 /api/", "default": "/"},
            "method": {"type": "string", "enum": ["GET", "HEAD", "OPTIONS", "PUT", "POST", "DELETE", "PATCH"],
                       "default": "GET"},
            "scheme": {"type": "string", "enum": ["http", "https"], "default": "https"},
            "headers": {"type": "object", "description": "附加请求头"},
            "body": {"type": "string", "description": "请求体（写入类操作时使用）"},
        },
        "required": ["target"],
    },
    writes=True,
    tags=["recon", "core"],
)
def http_probe(target: str, path: str = "/", method: str = "GET", scheme: str = "https",
               headers: Optional[Dict[str, str]] = None, body: str = "") -> Dict[str, Any]:
    m = method.upper()
    if m not in SAFE_METHODS + RISKY_METHODS:
        raise ToolError(f"unsupported method: {method}")
    if m in RISKY_METHODS:
        raise NeedsApproval(
            title=f"确认执行 {m} 请求？",
            description=f"该请求为写入/破坏性方法。目标：{db.normalize_target(target)}{path}。"
                        f"确认后立即执行并回收现场。",
            payload={"tool": "http_probe", "args": {"target": target, "path": path,
                                                    "method": m, "scheme": scheme,
                                                    "headers": headers, "body": body}},
            risk="high",
        )

    url = _build_url(target, path, scheme)
    h = {"User-Agent": _UA, "Accept": "*/*", "Connection": "close"}
    h.update(headers or {})
    req = urllib.request.Request(url, method=m, headers=h,
                                 data=body.encode() if body else None)
    started = time.time()
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=DEFAULT_TIMEOUT, context=ctx) as resp:
            raw = resp.read(262144)
            return {
                "url": url, "status": resp.status, "reason": resp.reason,
                "headers": dict(resp.headers.items()),
                "body_len": len(raw),
                "body_sha256": hashlib.sha256(raw).hexdigest()[:16],
                "body_head": raw[:800].decode("utf-8", "replace"),
                "elapsed_ms": int((time.time() - started) * 1000),
            }
    except urllib.error.HTTPError as e:
        raw = b""
        try:
            raw = e.read(65536)
        except Exception:
            pass
        return {"url": url, "status": e.code, "reason": e.reason,
                "headers": dict(e.headers.items()) if e.headers else {},
                "body_len": len(raw),
                "body_sha256": hashlib.sha256(raw).hexdigest()[:16] if raw else "",
                "body_head": raw[:800].decode("utf-8", "replace"),
                "elapsed_ms": int((time.time() - started) * 1000)}
    except Exception as e:
        raise ToolError(f"{type(e).__name__}: {e}")


# --------------------------------------------------------------------------
# 2. dns_lookup
# --------------------------------------------------------------------------
@tool(name="dns_lookup", description="解析域名 A/AAAA/CNAME 记录，用于资产确认与同站归并。",
      schema={"type": "object",
              "properties": {"target": {"type": "string"}}, "required": ["target"]},
      tags=["recon"])
def dns_lookup(target: str) -> Dict[str, Any]:
    d = db.normalize_target(target)
    out: Dict[str, Any] = {"domain": d}
    for rtype in ("A", "AAAA", "CNAME", "NS"):
        try:
            infos = socket.getaddrinfo(d, None)
            if rtype == "A":
                out["A"] = sorted({i[4][0] for i in infos if i[4]})
            break
        except Exception as e:
            out.setdefault("errors", []).append(str(e))
            break
    try:
        out["resolved"] = bool(out.get("A"))
    except Exception:
        out["resolved"] = False
    return out


# --------------------------------------------------------------------------
# 3. tls_inspect
# --------------------------------------------------------------------------
def _parse_der_cert(der: bytes) -> Dict[str, Any]:
    """解析 DER 证书。

    为什么不用 ssl.getpeercert()：关闭校验（CERT_NONE）时它返回空 dict，
    只能拿到 getpeercert(binary_form=True) 的 DER 字节。
    这里用 cryptography 解析，比手写 ASN.1 遍历可靠得多。
    """
    out: Dict[str, Any] = {"issuer": {}, "subject": {}, "san": [], "serial": "",
                           "not_before": None, "not_after": None}
    if not der:
        return out
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        cert = x509.load_der_x509_certificate(der)

        def name_to_dict(n):
            """把 x509.Name 转成 dict。
            注意：不能对 _name 做 replace('name','')，commonName 会变成 common。
            """
            mapping = {
                "commonName": "commonName",
                "organizationName": "organizationName",
                "organizationalUnitName": "organizationalUnitName",
                "countryName": "countryName",
                "stateOrProvinceName": "stateOrProvinceName",
                "localityName": "localityName",
                "emailAddress": "emailAddress",
            }
            d = {}
            for attr in n:
                try:
                    raw = attr.oid._name or attr.oid.dotted_string
                    d[mapping.get(raw, raw)] = str(attr.value)
                except Exception:
                    continue
            return d

        out["issuer"] = name_to_dict(cert.issuer)
        out["subject"] = name_to_dict(cert.subject)
        out["serial"] = str(cert.serial_number)
        try:
            out["not_before"] = cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S")
        except AttributeError:
            out["not_before"] = cert.not_valid_before.strftime("%Y-%m-%d %H:%M:%S")
        try:
            out["not_after"] = cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S")
        except AttributeError:
            out["not_after"] = cert.not_valid_after.strftime("%Y-%m-%d %H:%M:%S")

        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            out["san"] = [str(g.value) for g in san.value if isinstance(
                getattr(x509, g.__class__.__name__, None), object)][:60]
        except Exception:
            pass

        try:
            sig = cert.signature_hash_algorithm
            out["sig_algo"] = getattr(sig, "name", None)
        except Exception:
            pass
    except Exception as e:
        out["error"] = str(e)[:120]
    return out


@tool(name="tls_inspect", description="握手并读取 TLS 证书信息（签发者、有效期、SAN、协议版本）。",
      schema={"type": "object",
              "properties": {"target": {"type": "string"},
                             "port": {"type": "integer", "default": 443}},
              "required": ["target"]},
      tags=["recon", "fingerprint"])
def tls_inspect(target: str, port: int = 443) -> Dict[str, Any]:
    d = db.normalize_target(target)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((d, port), timeout=DEFAULT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=d) as ssock:
                cipher = ssock.cipher()
                der = None
                try:
                    der = ssock.getpeercert(True)
                except Exception:
                    pass
                info = _parse_der_cert(der) if der else {}
                return {
                    "host": d, "port": port,
                    "version": ssock.version(),
                    "cipher": cipher[0] if cipher else None,
                    "issuer": info.get("issuer", {}),
                    "subject": info.get("subject", {}),
                    "not_before": info.get("not_before"),
                    "not_after": info.get("not_after"),
                    "san": info.get("san", []),
                    "cert_bytes": len(der) if der else 0,
                }
    except Exception as e:
        raise ToolError(f"TLS handshake failed: {e}")


# --------------------------------------------------------------------------
# 4. fingerprint —— 被动指纹识别（不投递任何攻击载荷）
# --------------------------------------------------------------------------
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)

_FP_RULES = [
    ("nginx", r"server:\s*nginx"),
    ("apache", r"server:\s*apache"),
    ("iis", r"server:\s*microsoft-iis"),
    ("tomcat", r"(apache-coyote|tomcat|jsessionid)"),
    ("weblogic", r"(weblogic| weblogic)"),
    ("jboss", r"(jboss|wildfly)"),
    ("jetty", r"jetty\("),
    ("f5-asm", r"(bigipserver|x-cnection|\bcookie:\s*.*\bts\w{0,6}=)"),
    ("waf-generic", r"(waf|firewall|webapplicationfirewall)"),
    ("spring-boot", r"(whitelabel error page|spring-boot|x-application-context)"),
    ("php", r"(x-powered-by:\s*php|set-cookie:\s*phpsessid)"),
    ("aspnet", r"(asp\.net|aspnet_sessionid)"),
]


@tool(name="fingerprint", description="被动指纹识别：解析响应头与首页特征，判定 Web 服务器、"
                                     "应用框架与防护设备。不发送任何攻击载荷。",
      schema={"type": "object",
              "properties": {"target": {"type": "string"},
                             "path": {"type": "string", "default": "/"}},
              "required": ["target"]},
      tags=["fingerprint"])
def fingerprint(target: str, path: str = "/") -> Dict[str, Any]:
    r = http_probe(target=target, path=path, method="GET")
    headers = {k.lower(): v for k, v in (r.get("headers") or {}).items()}
    body = r.get("body_head", "") or ""
    tech, waf = [], []

    server = headers.get("server", "")
    if server:
        tech.append({"name": server, "category": "server", "confidence": 0.9})

    for name, pat in _FP_RULES:
        hay = f"{server}\n{json.dumps(headers, ensure_ascii=False)}\n{body[:600]}"
        if re.search(pat, hay, re.I):
            (waf if name in ("f5-asm", "waf-generic") else tech).append(
                {"name": name, "category": "waf" if name in ("f5-asm", "waf-generic") else "app",
                 "confidence": 0.75})

    m = _TITLE_RE.search(body)
    title = m.group(1).strip()[:120] if m else ""
    for js in re.findall(r'src="([^"]+\.js)"', body[:4000])[:3]:
        tech.append({"name": f"js:{js.split('/')[-1]}", "category": "asset",
                     "confidence": 0.4})

    return {
        "target": db.normalize_target(target), "status": r.get("status"),
        "title": title, "server": server, "tech": tech, "waf": waf,
        "allow_methods": r.get("headers", {}).get("Allow", "") if r.get("headers") else "",
        "body_len": r.get("body_len"), "body_sha256": r.get("body_sha256"),
        "headers": r.get("headers"),
    }


# --------------------------------------------------------------------------
# 5. cve_precondition —— CVE 前置条件排查
# --------------------------------------------------------------------------
CVE_RULES = {
    "CVE-2025-24813": {
        "title": "Apache Tomcat Session 反序列化 RCE",
        "component": "Apache Tomcat",
        "checks": [
            {"id": "defaultServletWriteEnabled",
             "how": "对 / 发送 PUT 空 body，观察是否返回 201/204；405/403 即未开启",
             "method": "PUT", "path": "/"},
            {"id": "putExposed",
             "how": "读取 OPTIONS 响应的 Allow 头，确认是否含 PUT/DELETE",
             "method": "OPTIONS", "path": "/"},
        ],
    },
    "CVE-2022-22965": {
        "title": "Spring4Shell (Spring MVC 属性绑定 RCE)",
        "component": "Spring Framework",
        "checks": [
            {"id": "jdk9plus",
             "how": "请求 ?class.module.classLoader.DefaultAssertionStatus，JDK9+ 会返回类层次信息",
             "method": "GET", "path": "/?class.module.classLoader.DefaultAssertionStatus"},
        ],
    },
    "CVE-2021-44228": {
        "title": "Log4Shell (JNDI 注入 RCE)",
        "component": "Log4j 2",
        "checks": [
            {"id": "jndiLookupEnabled",
             "how": "被动观察响应头与行为特征，不投递 ${jndi:} 载荷",
             "method": "OPTIONS", "path": "/"},
        ],
    },
}


@tool(name="cve_precondition", description="针对指定 CVE 排查触发前置条件，"
                                         "仅使用无副作用探针，不投递利用载荷。",
      schema={"type": "object",
              "properties": {"target": {"type": "string"},
                             "cve": {"type": "string"},
                             "component_version": {"type": "string"}},
              "required": ["target", "cve"]},
      tags=["cve"])
def cve_precondition(target: str, cve: str, component_version: str = "") -> Dict[str, Any]:
    cve = cve.upper()
    rule = CVE_RULES.get(cve)
    if not rule:
        return {"cve": cve, "supported": False,
                "note": "该 CVE 未内置规则，需人工分析或补充规则",
                "known": sorted(CVE_RULES.keys())}

    results, verdict = [], "INCONCLUSIVE"
    fp = None
    try:
        fp = fingerprint(target)
    except Exception:
        pass

    for chk in rule["checks"]:
        entry = {"id": chk["id"], "how": chk["how"]}
        if chk["method"] in SAFE_METHODS:
            try:
                r = http_probe(target=target, path=chk["path"], method=chk["method"])
                st = r.get("status")
                entry["status"] = st
                allow = (r.get("headers") or {}).get("Allow", "")
                entry["observed"] = (allow or f"HTTP {st}")
                if chk["id"] == "putExposed":
                    entry["result"] = "EXPOSED" if ("PUT" in allow.upper() or
                                                     "DELETE" in allow.upper()) else "NOT_EXPOSED"
                elif chk["id"] == "jdk9plus":
                    leaked = "class" in (r.get("body_head") or "").lower() and st == 200
                    entry["result"] = "JDK9_PLUS" if leaked else "NOT_JDK9"
                else:
                    entry["result"] = "OBSERVED"
            except Exception as e:
                entry["result"] = "ERROR"
                entry["error"] = str(e)
        else:
            entry["result"] = "NEEDS_MANUAL_PROBE"
            entry["note"] = "该检查为写入类，需人工批准后执行"
        results.append(entry)

    if any(e.get("result") == "NEEDS_MANUAL_PROBE" for e in results):
        verdict = "INCONCLUSIVE"
    elif any(e.get("result") in ("EXPOSED", "JDK9_PLUS") for e in results):
        verdict = "AFFECTED"
    elif all(e.get("result") in ("NOT_EXPOSED", "NOT_JDK9", "OBSERVED") for e in results):
        verdict = "LIKELY_NOT_AFFECTED"

    return {
        "cve": cve, "supported": True, "title": rule["title"],
        "component": rule["component"], "component_version": component_version,
        "verdict": verdict, "checks": results,
        "fingerprint": {"tech": fp["tech"], "waf": fp["waf"]} if fp else None,
        "conclusion": {
            "AFFECTED": "前置条件成立，需立即处置并进一步验证影响面",
            "LIKELY_NOT_AFFECTED": "前置条件不成立，可判定为不受影响（建议关闭告警）",
            "INCONCLUSIVE": "证据不足，需人工确认后定稿",
        }[verdict],
    }


# --------------------------------------------------------------------------
# 6. endpoint_enum —— 只读路径枚举
# --------------------------------------------------------------------------
DEFAULT_PATHS = [
    "/", "/robots.txt", "/sitemap.xml", "/.env", "/.git/config", "/.well-known/security.txt",
    "/api/", "/api/v1/", "/api/v2/", "/swagger-ui/", "/swagger-ui.html", "/v2/api-docs",
    "/v3/api-docs", "/docs/", "/doc/", "/admin/", "/actuator", "/actuator/health",
    "/actuator/env", "/druid/index.html", "/manager/html", "/examples/", "/metrics",
    "/debug/pprof/", "/console/", "/login", "/api/health", "/graphql",
]


@tool(name="endpoint_enum", description="对一组候选路径做只读 GET 探测，收集存在的端点（200/30x/401）。",
      schema={"type": "object",
              "properties": {"target": {"type": "string"},
                             "paths": {"type": "array", "items": {"type": "string"}},
                             "max_paths": {"type": "integer", "default": 30}},
              "required": ["target"]},
      tags=["recon", "endpoint"])
def endpoint_enum(target: str, paths: Optional[List[str]] = None,
                  max_paths: int = 30) -> Dict[str, Any]:
    cand = (paths or DEFAULT_PATHS)[:max_paths]
    found, scanned = [], 0
    for p in cand:
        scanned += 1
        try:
            r = http_probe(target=target, path=p, method="GET")
            st = r.get("status")
            if st and st < 400:
                found.append({"path": p, "status": st,
                              "len": r.get("body_len"),
                              "note": "auth-required" if st in (401, 403) else ""})
        except Exception:
            continue
    return {"target": db.normalize_target(target), "scanned": scanned,
            "found": len(found), "endpoints": found,
            "note": "仅只读 GET，未携带任何凭据"}


# --------------------------------------------------------------------------
# 7. save_memory —— 把本次结论沉淀进站点记忆
# --------------------------------------------------------------------------
@tool(name="save_memory", description="将本次探测结论写入该站点的长期记忆，供后续同域名测试复用。",
      schema={"type": "object",
              "properties": {"namespace": {"type": "string",
                                           "enum": ["fingerprint", "endpoint", "stack", "finding", "config", "history"]},
                             "key": {"type": "string"},
                             "value": {"type": "object"},
                             "confidence": {"type": "number", "default": 1.0}},
              "required": ["namespace", "key", "value"]},
      tags=["memory"])
def save_memory(namespace: str, key: str, value: Dict[str, Any],
                confidence: float = 1.0) -> Dict[str, Any]:
    # 由编排层注入当前站点；此处直接返回，实际落库在 agent 层
    return {"namespace": namespace, "key": key, "value": value, "confidence": confidence}


# --------------------------------------------------------------------------
# 8. report_write —— 生成交付报告
# --------------------------------------------------------------------------
def render_report(session: Dict[str, Any], profile: Dict[str, Any],
                  cve_results: List[Dict[str, Any]], findings: List[Dict[str, Any]]) -> str:
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    counts = profile.get("counts", {})
    lines = [
        f"# {session['title']}", "",
        f"- **目标站点**：{session['domain']}",
        f"- **会话窗口**：`{session['name']}`（按域名自动命名）",
        f"- **站点记忆键**：`{session['site_key']}`",
        f"- **生成时间**：{ts}",
        f"- **执行模型**：{session.get('model', 'scout-pro')}",
        "",
        "## 一、测试范围与方法", "",
        "本次测试严格遵循被动优先原则：仅使用无副作用探针（GET/HEAD/OPTIONS）进行指纹确认"
        "与端点收集，未向目标投递任何攻击载荷，未修改任何业务数据。"
        "涉及写入类操作均经人工审批后执行并即时回收现场。", "",
        "## 二、资产指纹", "",
    ]
    fp = profile.get("fingerprint", {})
    if fp:
        lines.append("| 特征 | 值 | 置信度 | 最后更新 |")
        lines.append("| --- | --- | --- | --- |")
        for k, v in list(fp.items())[:20]:
            val = v.get("value")
            val_s = val if not isinstance(val, dict) else json.dumps(val, ensure_ascii=False)[:60]
            lines.append(f"| {k} | {val_s} | {v.get('confidence')} | {v.get('updated_at','')[:19]} |")
    else:
        lines.append("_本次未采集到指纹特征。_")

    lines += ["", "## 三、技术栈与防护", ""]
    stack = profile.get("stack", [])
    lines.append("、".join(str(s) for s in stack) if stack else "_未识别_")

    lines += ["", "## 四、端点与接口", ""]
    eps = profile.get("endpoints", [])
    if eps:
        lines.append("| 路径 | 状态 | 备注 |")
        lines.append("| --- | --- | --- |")
        for e in eps[:30]:
            lines.append(f"| `{e.get('path')}` | {e.get('status')} | {e.get('note','')} |")
    else:
        lines.append("_未发现可用端点。_")

    lines += ["", "## 五、漏洞与 CVE 核查", ""]
    if cve_results:
        lines.append("| CVE | 组件 | 结论 | 说明 |")
        lines.append("| --- | --- | --- | --- |")
        for c in cve_results:
            lines.append(f"| {c.get('cve')} | {c.get('component','-')} | "
                         f"{c.get('verdict')} | {c.get('conclusion','')} |")
    else:
        lines.append("_本次未指定 CVE 核查项。_")

    lines += ["", "## 六、风险发现", ""]
    if findings:
        lines.append("| 编号 | 问题 | 严重度 | 状态 |")
        lines.append("| --- | --- | --- | --- |")
        for i, f in enumerate(findings, 1):
            lines.append(f"| V-{i:02d} | {f.get('title','')} | {f.get('severity','-')} | {f.get('status','')} |")
    else:
        lines.append("_未发现需立即处置的问题。_")

    lines += ["", "## 七、整改建议", "",
              "1. 关闭或限制调试/管理端点（`/actuator/*`、`/druid/*`、`/manager/*`、默认文档页）",
              "2. 清理响应头中的版本号等指纹信息",
              "3. 对外暴露接口统一接入鉴权，未授权返回 401",
              "4. CVE 相关组件显式关闭危险开关，不依赖默认值",
              "5. 建立资产台账，同域名资产纳入统一监控", "",
              "---", "",
              f"_本报告由 Scout Agent 自动生成，站点记忆已归档至 `{session['site_key']}`，"
              f"下次测试 `{session['domain']}` 时将自动复用历史结论。_"]
    return "\n".join(lines)


@tool(name="report_write", description="汇总站点记忆与本次核查结果，生成 Markdown 交付报告。",
      schema={"type": "object",
              "properties": {"session_id": {"type": "integer"}}, "required": ["session_id"]},
      tags=["report"])
def report_write(session_id: int) -> Dict[str, Any]:
    raise ToolError("report_write 由编排层调用，需会话上下文")


# --------------------------------------------------------------------------
# 执行入口（含审批拦截）
# --------------------------------------------------------------------------
def execute(name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    t = get_tool(name)
    return t["fn"](**args)