"""
Scout Agent · CVE 情报查询

边界（重要）
------------
本模块只查询**公开漏洞情报元数据**：CVSS、CWE、受影响版本、已知利用状态、
公开披露时间线、参考链接。**不下载、不解析、不执行任何利用代码（PoC）**。

"是否有公开利用"这类信号来自权威源的标记字段（如 CISA KEV），
以及参考链接中已被分类为 exploit/poc 的条目——**只作为风险评级依据**，
供分析师判断"这条告警有多紧急"，而不是给 Agent 提供可直接运行的武器。

数据源优先级：
  1. NVD 2.0   —— 最完整，含 CWE / CVSS / KEV / affected
  2. CIRCL     —— 补充欧洲视角，部分条目更快
  3. OSV       —— 补充生态包（npm/pypi/maven/go）影响面
"""
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

UA = "Scout-Agent/1.0 (authorized security testing)"
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CIRCL = "https://cve.circl.lu/api/cve"
OSV = "https://api.osv.dev/v1/vulns"

# NVD 无 Key 时的限速建议：6 请求 / 30 秒
_last_nvd: List[float] = []
NVD_MIN_INTERVAL = 5.2

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
# 参考链接里指向利用代码的域名特征——只做标记，不取内容
POC_HINTS = (
    "exploit-db.com", "packetstormsecurity.com", "github.com", "gitlab.com",
    "metasploit.com", "seebug.org", "vuldb.com", "cisa.gov", "nvd.nist.gov",
    "githubusercontent.com", "0day.rip", "poc-in-github",
)
POC_NEGATIVE = ("security-advisories", "advisory", "changelog", "release-notes")


class IntelError(Exception):
    pass


def extract_cve_ids(text: str) -> List[str]:
    """从任意文本抽出 CVE 编号（去重、保序、大写）。"""
    out = []
    for m in CVE_RE.findall(text or ""):
        c = m.upper()
        if c not in out:
            out.append(c)
    return out


def _get_json(url: str, timeout: int = 20, throttle_nvd: bool = False) -> Dict[str, Any]:
    if throttle_nvd:
        now_t = time.time()
        if _last_nvd:
            gap = now_t - _last_nvd[-1]
            if gap < NVD_MIN_INTERVAL:
                time.sleep(NVD_MIN_INTERVAL - gap)
        _last_nvd.append(time.time())
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        raise IntelError(f"HTTP {e.code}: {url.split('?')[0]}")
    except Exception as e:
        raise IntelError(f"{type(e).__name__}: {str(e)[:100]}")


def _score_from_metrics(metrics: Dict[str, Any]) -> Dict[str, Any]:
    """从 NVD metrics 里挑一份 CVSS 向量。优先 v3.1 → v3.0 → v4.0 → v2.0。"""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr:
            d = arr[0].get("cvssData") or {}
            return {
                "version": d.get("version"),
                "vector": d.get("vectorString"),
                "base_score": d.get("baseScore"),
                "severity": d.get("baseSeverity") or arr[0].get("baseSeverity"),
            }
    return {"version": None, "vector": None, "base_score": None, "severity": None}


def _affected_from_nvd(configs: List[Dict[str, Any]], limit: int = 12) -> List[str]:
    out: List[str] = []
    for cfg in configs or []:
        for node in cfg.get("nodes", []) or []:
            for m in node.get("cpeMatch", []) or []:
                criteria = m.get("criteria", "")
                if criteria and criteria not in out:
                    out.append(criteria)
                if len(out) >= limit:
                    return out
    return out


def _describe_references(refs: List[Dict[str, Any]], limit: int = 12) -> Dict[str, Any]:
    """把参考链接分类。只记录 URL 与标签，不抓取内容。"""
    poc_flagged, advisories, others = [], [], []
    for r in refs or []:
        url = r.get("url") or ""
        low = url.lower()
        tags = r.get("tags") or []
        is_poc_tag = "Exploit" in tags or "Third Party Advisory" in tags
        looks_poc = any(h in low for h in POC_HINTS) and \
            not any(n in low for n in POC_NEGATIVE)
        item = {"url": url[:200], "source": r.get("source", "")[:60],
                "tags": tags[:3]}
        if is_poc_tag or looks_poc:
            poc_flagged.append(item)
        elif "Vendor Advisory" in tags or r.get("source", "").lower().startswith("security@"):
            advisories.append(item)
        else:
            others.append(item)
    return {
        "total": len(refs or []),
        "exploit_related": len(poc_flagged),
        "exploit_refs": poc_flagged[:limit],
        "vendor_advisories": advisories[:limit],
        "other_count": max(0, len(refs or []) - len(poc_flagged) - len(advisories)),
        "note": "仅标记公开披露渠道，不下载也不执行其中内容",
    }


def lookup_cve(cve_id: str) -> Dict[str, Any]:
    """查单个 CVE 的完整情报。返回统一结构，标明数据来源。"""
    cve = (cve_id or "").upper().strip()
    if not CVE_RE.fullmatch(cve):
        raise IntelError(f"不是合法的 CVE 编号: {cve_id!r}")

    sources: List[str] = []
    data: Dict[str, Any] = {}
    errors: List[str] = []

    # --- NVD ---
    try:
        j = _get_json(f"{NVD}?cveId={cve}", throttle_nvd=True)
        vulns = j.get("vulnerabilities") or []
        if vulns:
            v = vulns[0].get("cve") or {}
            descs = v.get("descriptions") or []
            desc = next((d.get("value") for d in descs if d.get("lang") == "en"), "")
            weaknesses = []
            for w in v.get("weaknesses") or []:
                for d in w.get("description") or []:
                    val = d.get("value")
                    if val and val not in weaknesses:
                        weaknesses.append(val)
            data = {
                "id": cve,
                "summary": desc[:600],
                "published": v.get("published"),
                "last_modified": v.get("lastModified"),
                "status": v.get("vulnStatus"),
                "cvss": _score_from_metrics(v.get("metrics") or {}),
                "cwe": weaknesses[:8],
                "affected": _affected_from_nvd(v.get("configurations") or []),
                "references": _describe_references(v.get("references") or []),
                "kev": bool(v.get("cisaExploitAdd")),
                "cisa_action_due": v.get("cisaActionDue"),
                "cisa_required_action": (v.get("cisaRequiredAction") or "")[:300] or None,
                "tags": v.get("cveTags") or [],
            }
            sources.append("nvd")
    except IntelError as e:
        errors.append(f"nvd: {e}")

    # --- CIRCL（补充/兜底）---
    if not data:
        try:
            j = _get_json(f"{CIRCL}/{cve}")
            containers = j.get("containers") or {}
            cna = containers.get("cna") or {}
            descs = cna.get("descriptions") or []
            data = {
                "id": cve,
                "summary": (descs[0].get("value", "")[:600] if descs else ""),
                "published": (j.get("cveMetadata") or {}).get("datePublished"),
                "last_modified": (j.get("cveMetadata") or {}).get("dateUpdated"),
                "status": (j.get("cveMetadata") or {}).get("state"),
                "cvss": {}, "cwe": [],
                "affected": [p.get("product") for p in (cna.get("affected") or [])][:12],
                "references": _describe_references(
                    [{"url": r.get("url", ""), "tags": ["Exploit"] if "exploit" in
                      r.get("url", "").lower() else []}
                     for r in (cna.get("references") or [])]),
                "kev": False,
            }
            sources.append("circl")
        except IntelError as e:
            errors.append(f"circl: {e}")

    if not data:
        raise IntelError(f"{cve} 未在任何源查到" + (f"（{'; '.join(errors)}）" if errors else ""))

    # --- OSV（补包生态影响面）---
    try:
        osv = _get_json(f"{OSV}/{cve}")
        pkgs = []
        for a in (osv.get("affected") or [])[:10]:
            pkg = a.get("package") or {}
            eco = (pkg.get("ecosystem") or "").lower()
            name = pkg.get("name") or ""
            if name:
                pkgs.append(f"{eco}:{name}")
        if pkgs:
            data["affected_packages"] = pkgs
            sources.append("osv")
    except Exception:
        pass   # OSV 只是补充，失败不影响主流程

    data["sources"] = sources
    if errors:
        data["source_errors"] = errors

    # --- 风险评级（基于权威标记，不含主观判断）---
    score = (data.get("cvss") or {}).get("base_score")
    band = "unknown"
    if isinstance(score, (int, float)):
        band = ("critical" if score >= 9.0 else "high" if score >= 7.0
                else "medium" if score >= 4.0 else "low")
    data["risk"] = {
        "band": band,
        "cvss": score,
        "known_exploited": bool(data.get("kev")),
        "exploit_refs": (data.get("references") or {}).get("exploit_related", 0),
        "basis": "CVSS 分级 + CISA KEV 标记 + 公开利用渠道数量",
    }
    return data


def search_vendor(ecosystem: str, package: str) -> Dict[str, Any]:
    """按包名查已知漏洞（OSV），用于资产与依赖对账。"""
    eco = (ecosystem or "").lower().strip()
    if eco not in ("npm", "pypi", "maven", "golang", "go", "rubygems", "crates.io", "nuget", "packagist"):
        raise IntelError(f"不支持的生态: {ecosystem}")
    body = json.dumps({
        "package": {"name": package, "ecosystem": {"npm": "npm", "pypi": "PyPI",
                                                     "maven": "Maven", "go": "Go",
                                                     "golang": "Go", "rubygems": "RubyGems",
                                                     "crates.io": "crates.io",
                                                     "nuget": "NuGet",
                                                     "packagist": "Packagist"}.get(eco, eco)},
        "version": "",
    }).encode()
    req = urllib.request.Request(
        f"{OSV}/query", data=body,
        headers={"Content-Type": "application/json", "User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            j = json.loads(r.read().decode("utf-8", "replace"))
    except Exception as e:
        raise IntelError(f"OSV 查询失败: {type(e).__name__}")
    vulns = []
    for v in (j.get("vulns") or [])[:30]:
        vulns.append({"id": v.get("id"),
                      "aliases": (v.get("aliases") or [])[:3],
                      "summary": (v.get("summary") or "")[:200],
                      "severity": _osv_severity(v)})
    return {"ecosystem": eco, "package": package, "count": len(vulns),
            "vulns": vulns,
            "note": "包名匹配为精确匹配；如需按版本精确匹配请提供版本号"}


def _osv_severity(v: Dict[str, Any]) -> Optional[float]:
    for s in (v.get("severity") or []):
        sc = s.get("score")
        if isinstance(sc, str) and sc.replace(".", "", 1).isdigit():
            try:
                return float(sc)
            except ValueError:
                pass
    for a in (v.get("affected") or []):
        for d in (a.get("database_specific") or {}).items():
            pass
    return None


def batch_lookup(cve_ids: List[str], max_n: int = 5) -> Dict[str, Any]:
    """批量查询，逐个之间留间隔避免触发 NVD 限流。"""
    ids = [c for c in (x or "").upper() for x in extract_cve_ids(c)][:max_n]
    if not ids:
        return {"queried": [], "results": [], "note": "未识别到 CVE 编号"}
    out = []
    for i, c in enumerate(ids):
        if i:
            time.sleep(1.0)
        try:
            out.append({"cve": c, "ok": True, "intel": lookup_cve(c)})
        except IntelError as e:
            out.append({"cve": c, "ok": False, "error": str(e)})
    ok_n = sum(1 for r in out if r["ok"])
    return {"queried": out, "ok": ok_n, "failed": len(out) - ok_n}