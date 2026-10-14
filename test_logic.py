"""本地逻辑测试：域名归一、会话复用、记忆隔离、长期偏好白名单。"""
import os, sys, tempfile, pathlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
tmp = pathlib.Path(tempfile.mkdtemp()) / "t.db"
from app import db
db.DB_PATH = tmp
db.init_db()

ok = True
def chk(label, cond, extra=""):
    global ok
    print(f"  {'✅' if cond else '❌'} {label}{('  ' + str(extra)) if extra else ''}")
    if not cond: ok = False

print("== 1. 域名归一化 ==")
cases = [
    ("https://Shop.Example.com:8443/a/b?x=1", "shop.example.com"),
    ("http://a.example.com", "a.example.com"),
    ("  API.example.com  ", "api.example.com"),
    ("example.com.", "example.com"),
    ("user:pw@shop.example.com:80", "shop.example.com"),
]
for inp, want in cases:
    got = db.normalize_target(inp)
    chk(f"{inp[:38]:<38} -> {got}", got == want, f"(期望 {want})")

print("\n== 2. 会话名按域名自动命名 ==")
chk("session_name('https://shop.example.com/x')", db.session_name("https://shop.example.com/x") == "shop.example.com")
chk("www 与裸域共享记忆键", db.site_key("www.a.com") == db.site_key("a.com"))
chk("不同子域记忆键独立", db.site_key("hgt.a.com") != db.site_key("ab.a.com"))

print("\n== 3. 同域名复用同一会话 ==")
s1 = db.get_or_create_session("shop.example.com", "首次测试")
s2 = db.get_or_create_session("https://SHOP.example.com/path", "再次测试")
chk("同域名返回同一 session_id", s1["id"] == s2["id"], f"({s1['id']} == {s2['id']})")
chk("会话名自动取域名", s1["name"] == "shop.example.com")
s3 = db.get_or_create_session("other.example.com", "另一站")
chk("不同域名得到不同会话", s3["id"] != s1["id"])
chk("site_id 隔离", s3["site_id"] != s1["site_id"])

print("\n== 4. 站点记忆隔离与复用 ==")
sid = db.get_or_create_site("shop.example.com")["id"]
db.remember(sid, "fingerprint", "server", "nginx", 0.95, "test")
db.remember(sid, "endpoint", "/admin/", {"status": 401}, 1.0, "test")
db.remember(sid, "finding", "CVE-2025-24813", {"verdict": "LIKELY_NOT_AFFECTED"}, 1.0, "test")

sid2 = db.get_or_create_site("other.example.com")["id"]
prof1 = db.site_profile(sid)
prof2 = db.site_profile(sid2)
chk("A 站有记忆", prof1["counts"]["fingerprint"] == 1, prof1["counts"])
chk("B 站记忆独立为空", prof2["counts"]["fingerprint"] == 0 and prof2["counts"]["endpoint"] == 0)
chk("A 站接口已沉淀", prof1["counts"]["endpoint"] == 1)
chk("A 站结论已沉淀", prof1["counts"]["findings"] == 1)

db.remember(sid, "fingerprint", "server", "nginx/1.24", 0.9, "test2")
chk("重复写入覆盖而非新增", db.site_profile(sid)["counts"]["fingerprint"] == 1)
row = db.recall(sid, "fingerprint")[0]
chk("hit_count 累加", row["hit_count"] == 2, f"(hit={row['hit_count']})")
chk("值已更新", row["value"] == "nginx/1.24")

print("\n== 5. 长期记忆只存偏好 ==")
db.set_pref("default_model", "scout-pro")
db.set_pref("approval_policy", "require-confirmation")
chk("偏好写入成功", db.get_pref("default_model") == "scout-pro")
try:
    db.set_pref("site_fingerprint", {"x": 1})
    chk("非偏好键被拒绝", False, "!!! 不该写进去")
except ValueError as e:
    chk("非偏好键被拒绝", True)
for bad in ("fingerprint", "endpoint", "secret", "token"):
    try:
        db.set_pref(bad, "x"); chk(f"拒绝 {bad}", False, "!!! ")
    except ValueError:
        chk(f"拒绝 '{bad}'", True)

print("\n== 6. 私有地址识别 ==")
for h, want in [("localhost", True), ("127.0.0.1", True), ("192.168.1.1", True),
                ("172.16.5.4", True), ("10.0.0.1", True), ("svc.local", True),
                ("example.com", False), ("8.8.8.8", False)]:
    chk(f"{h:<16} private={want}", db.is_private_host(h) == want)

print("\n== 7. 消息/工具/审批链路 ==")
m1 = db.add_message(s1["id"], "user", {"text": "测试"})
m2 = db.add_message(s1["id"], "assistant", {"text": "回复"}, kind="text")
chk("消息 seq 递增", m2["seq"] == m1["seq"] + 1, f"({m1['seq']} -> {m2['seq']})")
cid = db.add_tool_call(s1["id"], "http_probe", {"target": "shop.example.com"}, "running")
db.update_tool_call(cid, "done", {"status": 200}, "", 120)
tc = db.list_tool_calls(s1["id"])
chk("工具记录状态更新", tc[-1]["status"] == "done" and tc[-1]["duration_ms"] == 120)
ap = db.create_approval(s1["id"], "确认写入", "描述", {"tool": "http_probe"}, "high")
db.decide_approval(ap["id"], "approved")
chk("审批状态流转", db.get_approval(ap["id"])["status"] == "approved")
art = db.add_artifact(s1["id"], "报告.md", "md", "# 标题\n内容")
chk("产物已保存", art["size"] > 0, f"({art['size']}B)")

print("\n== 8. 统计 ==")
st = db.stats()
chk("统计可用", st["sites"] >= 2 and st["sessions"] >= 2, st)

print("\n" + ("=" * 46))
print("结果:", "✅ 全部通过" if ok else "❌ 存在失败项")
sys.exit(0 if ok else 1)