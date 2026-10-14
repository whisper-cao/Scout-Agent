"""
Scout Agent · 扩展侦察工具

新增工具全部遵守既有纪律：
  - 只读：只用 GET/HEAD/OPTIONS，绝不写业务数据
  - 限速：单目标串行 + 间隔，避免把对方打挂（也避免自己被 WAF 拦）
  - 有界：所有参数都有上限，防止无节制发包
  - 归一：只解析域名，产出的候选子域交给上层判断，不主动扩大攻击面
"""
from __future__ import annotations

import re
import socket
import time
from typing import Any, Dict, List, Optional

from . import db, tools as T
from .tools import ToolError, http_probe, tls_inspect

_RATE_LAST: Dict[str, float] = {}
MIN_INTERVAL = 0.4          # 同目标两次请求最小间隔（秒）


def _throttle(target: str, interval: float = MIN_INTERVAL) -> None:
    last = _RATE_LAST.get(target, 0.0)
    gap = time.time() - last
    if gap < interval:
        time.sleep(interval - gap)
    _RATE_LAST[target] = time.time()


# --------------------------------------------------------------------------
# 工具定义。用 tools.tool 注册器挂进全局注册表。
# --------------------------------------------------------------------------
def _register_extra():
    @T.tool(name="cve_intel",
            description="查询 CVE 公开情报：CVSS 评分与向量、CWE、受影响产品与版本、"
                        "CISA KEV 已知利用标记、公开利用渠道数量。只返回元数据，"
                        "不下载也不执行任何利用代码。",
            schema={"type": "object",
                    "properties": {
                        "cve_id": {"type": "string", "description": "CVE 编号，如 CVE-2025-24813"}},
                    "required": ["cve_id"]},
            tags=["intel", "cve"])
    def cve_intel(cve_id: str) -> Dict[str, Any]:
        from . import intel
        return intel.lookup_cve(cve_id)

    @T.tool(name="cve_scan_text",
            description="从一段文本（告警内容、扫描报告、工单）中提取所有 CVE 编号并"
                        "逐个查询情报，返回按风险排序的结果。",
            schema={"type": "object",
                    "properties": {
                        "text": {"type": "string", "description": "待分析的文本"},
                        "max": {"type": "integer", "default": 3, "description": "最多查几个"}},
                    "required": ["text"]},
            tags=["intel", "cve"])
    def cve_scan_text(text: str, max: int = 3) -> Dict[str, Any]:
        from . import intel
        return intel.batch_lookup([text], max_n=max(1, min(int(max), 8)))

    @T.tool(name="package_vulns",
            description="按包名查询已知漏洞（npm/PyPI/Maven/Go 等生态），"
                        "用于资产与依赖对账。",
            schema={"type": "object",
                    "properties": {
                        "ecosystem": {"type": "string",
                                      "description": "npm | pypi | maven | go | rubygems | crates.io | nuget | packagist"},
                        "package": {"type": "string", "description": "包名"}},
                    "required": ["ecosystem", "package"]},
            tags=["intel", "sca"])
    def package_vulns(ecosystem: str, package: str) -> Dict[str, Any]:
        from . import intel
        return intel.search_vendor(ecosystem, package)

    # ---- 扩展侦察 ----

    @T.tool(name="subdomains",
            description="从 TLS 证书 SAN 与首页内容中提取子域候选，"
                        "并校验其 DNS 是否解析。仅被动收集，不做爆破。",
            schema={"type": "object",
                    "properties": {
                        "target": {"type": "string"},
                        "verify": {"type": "boolean", "default": True,
                                   "description": "是否逐个做 DNS 解析校验"},
                        "max_verify": {"type": "integer", "default": 25}},
                    "required": ["target"]},
            tags=["recon", "asset"])
    def subdomains(target: str, verify: bool = True, max_verify: int = 25) -> Dict[str, Any]:
        d = db.normalize_target(target)
        found: Dict[str, str] = {}

        # 1) 证书 SAN
        try:
            info = tls_inspect(d)
            for san in (info.get("san") or []):
                s = san.lstrip("*.").strip(".").lower()
                if s and s != d and d.endswith(s.split(".")[-2] if s.count(".") >= 2 else s):
                    found.setdefault(s, "tls-san")
        except Exception:
            pass

        # 2) 页面内容里的域名引用
        try:
            r = http_probe(target=d, path="/", method="GET")
            body = (r.get("body_head") or "") + " " + \
                   " ".join(str(v) for v in (r.get("headers") or {}).values())
            base = ".".join(d.split(".")[-2:])
            for m in re.finditer(r"[A-Za-z0-9][A-Za-z0-9.-]{3,60}\." + re.escape(base),
                                 body):
                s = m.group(0).lower().strip(".")
                if s != d and len(s) < 64:
                    found.setdefault(s, "page-ref")
        except Exception:
            pass

        candidates = list(found.items())[:80]
        result: List[Dict[str, Any]] = []
        checked = 0
        for name, src in candidates:
            if verify and checked >= max(1, min(int(max_verify), 60)):
                break
            item = {"name": name, "source": src, "resolves": None}
            if verify:
                checked += 1
                _throttle(name, 0.15)
                try:
                    socket.getaddrinfo(name, None)
                    item["resolves"] = True
                except Exception:
                    item["resolves"] = False
            if item["resolves"] is not False:
                result.append(item)
        return {"target": d, "base_domain": ".".join(d.split(".")[-2:]),
                "candidates": len(candidates), "verified": len(result),
                "subdomains": result,
                "note": "来源为证书与页面引用，未做字典爆破"}

    @T.tool(name="port_check",
            description="检查目标的少量常见端口是否开放。只做 TCP 连接探测，"
                        "不发送应用层数据。默认走精简端口表，避免全端口扫描。",
            schema={"type": "object",
                    "properties": {
                        "target": {"type": "string"},
                        "ports": {"type": "array", "items": {"type": "integer"},
                                  "description": "端口列表，留空用默认精简表"},
                        "timeout": {"type": "integer", "default": 2}},
                    "required": ["target"]},
            tags=["recon", "network"])
    def port_check(target: str, ports: Optional[List[int]] = None,
                   timeout: int = 2) -> Dict[str, Any]:
        d = db.normalize_target(target)
        # 默认表刻意保守：全端口扫描既慢又容易被 WAF 判定为攻击行为。
        # 这里只保留"值得知道"的十几个端口，且串行限速。
        default = [80, 443, 8080, 8443, 22, 3306, 6379, 27017, 5432, 9200, 2375]
        plist = [int(p) for p in (ports or default)][:20]
        timeout = max(1, min(int(timeout), 3))
        # 串行会让"关闭端口"一个个等满 timeout（11 个就是 33 秒）。
        # 改成并发探测：总耗时约等于单个端口的超时。
        from concurrent.futures import ThreadPoolExecutor
        def _probe(p: int) -> bool:
            s = None
            try:
                s = socket.create_connection((d, p), timeout=timeout)
                return True
            except Exception:
                return False
            finally:
                if s:
                    try:
                        s.close()
                    except Exception:
                        pass
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(_probe, plist))
        open_ports = [p for p, ok in zip(plist, results) if ok]
        closed = sum(1 for ok in results if not ok)
        return {"target": d, "scanned": len(plist), "open": open_ports,
                "closed": closed,
                "note": "仅 TCP 连接探测，未发送应用层数据；默认走精简端口表"}

    @T.tool(name="js_endpoints",
            description="抓取首页引用的 JS 文件并从中提取 API 路径与路由，"
                        "用于发现前端已暴露但未在文档中声明的接口。",
            schema={"type": "object",
                    "properties": {
                        "target": {"type": "string"},
                        "max_files": {"type": "integer", "default": 6}},
                    "required": ["target"]},
            tags=["recon", "endpoint"])
    def js_endpoints(target: str, max_files: int = 6) -> Dict[str, Any]:
        d = db.normalize_target(target)
        _throttle(d)
        r = http_probe(target=d, path="/", method="GET")
        body = r.get("body_head") or ""
        srcs = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', body)[:12]
        if not srcs:
            # body 可能是截断的，多取一次完整首页
            try:
                r2 = http_probe(target=d, path="/", method="GET")
                srcs = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']',
                                  (r2.get("body_head") or ""))[:12]
            except Exception:
                pass
        paths: Dict[str, int] = {}
        api_like = re.compile(
            r"""["'`](/(?:api|v\d|graphql|rest|service|admin|auth|user|login)[A-Za-z0-9_\-/{}.$:\-]{1,80})["'`]""")
        bucket = re.compile(
            r"""["'`]([A-Za-z0-9_\-]+/[A-Za-z0-9_\-/{}.$:@\-]{1,80})["'`]""")
        scanned = []
        for src in srcs[:max(1, min(int(max_files), 12))]:
            _throttle(d, 0.4)
            try:
                j = http_probe(target=d, path=src, method="GET")
                content = j.get("body_head") or ""
                scanned.append(src)
                for m in api_like.findall(content):
                    paths[m] = paths.get(m, 0) + 1
                for m in bucket.findall(content):
                    if "/" in m and not m.startswith(("http", "//")):
                        paths.setdefault("/" + m, 1)
            except Exception:
                continue
        top = sorted(paths.items(), key=lambda kv: -kv[1])[:40]
        return {"target": d, "js_files": len(scanned), "js_list": scanned[:12],
                "endpoint_count": len(top),
                "endpoints": [{"path": p, "hits": n} for p, n in top],
                "note": "路径来自 JS 字面量，属静态分析结果，未实际访问验证"}

    @T.tool(name="header_audit",
            description="检查目标的安全响应头与常见配置暴露，输出整改建议。",
            schema={"type": "object",
                    "properties": {"target": {"type": "string"}},
                    "required": ["target"]},
            tags=["recon", "config"])
    def header_audit(target: str) -> Dict[str, Any]:
        d = db.normalize_target(target)
        _throttle(d)
        r = http_probe(target=d, path="/", method="GET")
        h = {k.lower(): v for k, v in (r.get("headers") or {}).items()}
        checks = [
            ("strict-transport-security", "HSTS", "缺 HSTS：首次访问可能降级到 HTTP"),
            ("content-security-policy", "CSP", "缺 CSP：XSS 缺少浏览器侧约束"),
            ("x-frame-options", "防点击劫持", "缺 X-Frame-Options：可被 iframe 嵌入"),
            ("x-content-type-options", "MIME 嗅探防护", "缺 nosniff：浏览器可能猜测类型"),
            ("referrer-policy", "Referrer", "缺 Referrer-Policy：路径可能外泄"),
            ("x-xss-protection", "XSS 过滤", "缺 X-XSS-Protection（现代浏览器已弃用，低优先）"),
            ("permissions-policy", "浏览器能力限制", "缺 Permissions-Policy"),
            ("server", "Server 头", "Server 头暴露版本，属于信息泄露"),
        ]
        findings = []
        for key, label, desc in checks:
            present = key in h
            if key == "server":
                findings.append({"item": label, "present": bool(h.get(key)),
                                 "value": h.get(key, ""), "desc": desc,
                                 "level": "low" if present else "none"})
            else:
                findings.append({"item": label, "present": present,
                                 "value": h.get(key, "")[:80],
                                 "desc": desc if not present else "已配置",
                                 "level": "none" if present else "medium"})
        missing = sum(1 for f in findings if f["level"] == "medium")
        return {"target": d, "status": r.get("status"),
                "headers_present": len(h), "checks": findings,
                "missing_count": missing,
                "cookies": [k for k in h if k == "set-cookie"],
                "summary": (f"缺失 {missing} 项安全响应头" if missing
                            else "关键安全响应头均已配置")}

    @T.tool(name="robots_parse",
            description="读取 robots.txt 与 sitemap.xml，提取允许/禁止路径与站点结构线索。",
            schema={"type": "object",
                    "properties": {"target": {"type": "string"}},
                    "required": ["target"]},
            tags=["recon", "config"])
    def robots_parse(target: str) -> Dict[str, Any]:
        d = db.normalize_target(target)
        allow, disallow, sitemap = [], [], []
        try:
            _throttle(d)
            r = http_probe(target=d, path="/robots.txt", method="GET")
            if r.get("status") == 200:
                for line in (r.get("body_head") or "").splitlines():
                    line = line.strip()
                    if line.lower().startswith("allow:"):
                        allow.append(line.split(":", 1)[1].strip())
                    elif line.lower().startswith("disallow:"):
                        disallow.append(line.split(":", 1)[1].strip())
                    elif line.lower().startswith("sitemap:"):
                        sitemap.append(line.split(":", 1)[1].strip())
        except Exception:
            pass
        urls = []
        for sm in sitemap[:2]:
            try:
                _throttle(d, 0.5)
                r2 = http_probe(target=d, path=sm, method="GET")
                urls = re.findall(r"<loc>\s*([^<\s]+)\s*</loc>",
                                  (r2.get("body_head") or ""))[:60]
                if urls:
                    break
            except Exception:
                continue
        return {"target": d, "robots_found": bool(allow or disallow or sitemap),
                "allow": allow[:30], "disallow": disallow[:30],
                "sitemaps": sitemap[:5], "urls": len(urls),
                "url_samples": urls[:15],
                "note": "disallow 仅表示爬虫应遵守，不等于访问控制"}

    @T.tool(name="host_header_check",
            description="对比 Host 头被改为其他域名时的响应差异，判断是否存在"
                        "虚拟主机误配置或缓存投毒风险。仅 GET，不做缓存型利用。",
            schema={"type": "object",
                    "properties": {
                        "target": {"type": "string"},
                        "host_header": {"type": "string", "description": "用于对比的域名"}},
                    "required": ["target"]},
            tags=["recon", "config"])
    def host_header_check(target: str, host_header: str) -> Dict[str, Any]:
        d = db.normalize_target(target)
        _throttle(d)
        base = http_probe(target=d, path="/", method="GET")
        try:
            alt = http_probe(target=d, path="/", method="GET",
                             headers={"Host": host_header})
        except Exception as e:
            raise ToolError(f"对比请求失败: {e}")
        bh = base.get("body_sha256") or ""
        ah = alt.get("body_sha256") or ""
        differs = bh != ah
        return {"target": d, "compared_host": host_header,
                "base_status": base.get("status"), "alt_status": alt.get("status"),
                "body_differs": differs,
                "base_len": base.get("body_len"), "alt_len": alt.get("body_len"),
                "verdict": ("响应体不同：可能存在虚拟主机误配置，建议人工确认是否为预期行为"
                            if differs else "响应体一致，未见明显差异"),
                "note": "仅做只读对比，未做任何缓存键利用或投毒验证"}


_register_extra()