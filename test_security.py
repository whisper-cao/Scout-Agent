"""注册 + 登录 安全回归测试：SQL 注入纵深防御 / 邀请码 / 限流。"""
import pathlib
import sys
import tempfile

sys.path.insert(0, '.')
from app import auth, db            # noqa: E402

# 必须先改 DB_PATH 再 import server（模块级 bootstrap 会建表）
db.DB_PATH = pathlib.Path(tempfile.mkdtemp()) / 'sec.db'

from app import server as S         # noqa: E402

auth.invalidate_cache()
c = S.app.test_client()
ok = True


def chk(label, cond, extra=""):
    global ok
    print(f"  {'PASS' if cond else 'FAIL'}  {label}" + (f"  {extra}" if extra else ""))
    ok = ok and bool(cond)


INJECT = [
    "admin' OR '1'='1",
    "admin'; DROP TABLE users;--",
    "' UNION SELECT 1,2,3,4,5,6,7--",
    "admin'--",
    "' OR 1=1--",
    "1; UPDATE users SET role='admin'--",
    "admin\x00",
    "') OR ('1'='1",
    "admin' AND SLEEP(5)--",
    "admin'/**/UNION/**/SELECT/**/password_hash/**/FROM/**/users--",
    "' OR 'x'='x' /*",
    "'; SELECT sql FROM sqlite_master--",
]

print("== 1. 登录：注入载荷全部拒绝 ==")
for p in INJECT:
    r = c.post('/api/auth/login', json={"username": p, "password": "whatever"})
    chk(f"{p[:40]:<42} → {r.status_code}", r.status_code == 401, r.status_code)

print("\n== 2. 表结构完好 ==")
tabs = [x[0] for x in db.get_conn().execute(
    "SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
chk("users 表存在", "users" in tabs)
chk("auth_invites 表存在", "auth_invites" in tabs)
chk("表数量 >= 15", len(tabs) >= 15, len(tabs))

print("\n== 3. 首个账号：初始化注册（免邀请码）==")
r = c.post('/api/auth/register',
           json={"username": "admin", "password": "Adm1n@2026x", "display_name": "管理员"})
chk("注册成功", r.get_json().get('ok'), r.get_json().get('error'))
chk("角色为 admin", r.get_json()['data']['user']['role'] == 'admin')

print("\n== 4. 后续注册：必须邀请码 ==")
r = c.post('/api/auth/register', json={"username": "bob", "password": "Bob@123456"})
chk("无邀请码被拒", r.status_code == 400, r.get_json().get('error'))

r = c.post('/api/auth/register',
           json={"username": "bob", "password": "Bob@123456", "invite_code": "fake-code"})
chk("错误邀请码被拒", r.status_code == 400, r.get_json().get('error'))

print("\n== 5. 注册时用户名注入被白名单拦下 ==")
c.post('/api/auth/login', json={"username": "admin", "password": "Adm1n@2026x"})
inv = c.post('/api/invites', json={"note": "for test", "max_uses": 3}).get_json()['data']['invite']
code = inv['code']
for p in INJECT[:6]:
    r = c.post('/api/auth/register',
               json={"username": p, "password": "Passw0rd@x", "invite_code": code})
    rejected = r.status_code == 400
    chk(f"拒绝 {p[:36]:<38}", rejected, r.get_json().get('error', '')[:26])
# 邀请码没被这些失败消耗掉
chk("邀请码未被无效注册消耗",
    c.post('/api/auth/register',
           json={"username": "gooduser", "password": "Passw0rd@x", "invite_code": code}).get_json().get('ok'))

print("\n== 6. 密码含引号/注入特征被拒 ==")
for p in ["pass' OR '1'='1", 'pw"--', "with\\slash"]:
    r = c.post('/api/auth/register',
               json={"username": "u" + str(abs(hash(p)) % 999), "password": p, "invite_code": code})
    chk(f"拒绝密码 {p[:22]:<24}", r.status_code == 400, r.get_json().get('error', '')[:22])

print("\n== 7. 正常注册（有效邀请码）==")
r = c.post('/api/auth/register',
           json={"username": "analyst01", "password": "Analyst@2026",
                 "display_name": "分析师一号", "invite_code": code})
chk("注册成功", r.get_json().get('ok'), r.get_json().get('error'))
chk("角色取自邀请码", r.get_json()['data']['user']['role'] == 'analyst', r.get_json()['data']['user']['role'])

print("\n== 8. 邀请码用完即废 ==")
inv2 = c.post('/api/invites', json={"note": "single", "max_uses": 1}).get_json()['data']['invite']
c2 = inv2['code']
chk("第 1 次可用", c.post('/api/auth/register',
    json={"username": "u_one", "password": "Passw0rd@x", "invite_code": c2}).get_json().get('ok'))
r = c.post('/api/auth/register',
           json={"username": "u_two", "password": "Passw0rd@x", "invite_code": c2})
chk("第 2 次被拒", r.status_code == 400, r.get_json().get('error'))

print("\n== 9. 账号校验失败时邀请码退回 ==")
inv3 = c.post('/api/invites', json={"note": "refund", "max_uses": 1}).get_json()['data']['invite']
c3 = inv3['code']
r = c.post('/api/auth/register',
           json={"username": "BAD NAME!", "password": "Passw0rd@x", "invite_code": c3})
chk("非法用户名被拒", r.status_code == 400, r.get_json().get('error'))
r = c.post('/api/auth/register',
           json={"username": "recovered", "password": "Passw0rd@x", "invite_code": c3})
chk("邀请码已退回可再用", r.get_json().get('ok'), r.get_json().get('error'))

print("\n== 10. 用户名白名单边界（每个用例用独立邀请码，避免被上一个用例耗尽）==")
for bad in ["ab", "user@host", "用户中文", "a" * 33, " lead", "-lead", "drop'table"]:
    ic = c.post('/api/invites', json={"note": "t", "max_uses": 1}).get_json()['data']['invite']['code']
    r = c.post('/api/auth/register',
               json={"username": bad, "password": "Passw0rd@x", "invite_code": ic})
    err = r.get_json().get('error', '')
    # 关键：必须是"用户名不合法"，而不是"邀请码用完了"
    chk(f"拒绝 {bad[:16]:<18}", r.status_code == 400 and "邀请码" not in err, err[:30])
for good in ["a.b_c-d", "user01", "A_b"]:
    ic = c.post('/api/invites', json={"note": "t", "max_uses": 1}).get_json()['data']['invite']['code']
    r = c.post('/api/auth/register',
               json={"username": good + "z", "password": "Passw0rd@x", "invite_code": ic})
    chk(f"接受 {good:<12}", r.get_json().get('ok') is True, r.get_json().get('error', '')[:26])

print("\n== 11. 登录限流 ==")
auth._fail_log.clear()
for i in range(9):
    r = c.post('/api/auth/login', json={"username": "analyst01", "password": f"wrong{i}"})
chk("连续失败后被锁", r.status_code == 429, r.get_json().get('error', '')[:32])
r = c.post('/api/auth/login', json={"username": "analyst01", "password": "Analyst@2026"})
chk("正确密码也被锁（防爆破）", r.status_code == 429)
auth._fail_log.clear()
r = c.post('/api/auth/login', json={"username": "analyst01", "password": "Analyst@2026"})
chk("解锁后可登录", r.get_json().get('ok') is not None)

print("\n== 12. 现有账号仍可登录 ==")
r = c.post('/api/auth/login', json={"username": "admin", "password": "Adm1n@2026x"})
chk("管理员可登录", r.get_json().get('ok') is not None)

print("\n== 13. 数据完整性 ==")
n_users = db.get_conn().execute("SELECT COUNT(*) FROM users").fetchone()[0]
n_inv = db.get_conn().execute("SELECT COUNT(*) FROM auth_invites").fetchone()[0]
chk(f"用户数 {n_users}", n_users > 0)
chk(f"邀请码记录 {n_inv}", n_inv > 0)
bad = db.get_conn().execute(
    "SELECT COUNT(*) FROM users WHERE username LIKE '%''%' OR username LIKE '%--%'").fetchone()[0]
chk("库中无含引号/注释的用户名", bad == 0, f"count={bad}")
hashes = [r[0] for r in db.get_conn().execute("SELECT code_hash FROM auth_invites")]
chk("邀请码只存哈希", all(len(x) == 64 for x in hashes))
chk("哈希非明文", not any(c3 in x for x in hashes))

print()
print("=" * 52)
print("结果:", "全部通过" if ok else "存在失败")
sys.exit(0 if ok else 1)