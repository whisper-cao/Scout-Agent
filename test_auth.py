"""认证 + API 配置缓存 的接口级回归测试。"""
import pathlib
import sys
import tempfile

sys.path.insert(0, '.')
from app import auth, db            # noqa: E402

# 必须在 import server 之前改 DB_PATH，否则模块级 bootstrap() 已经建过表
db.DB_PATH = pathlib.Path(tempfile.mkdtemp()) / 's.db'

from app import server as S         # noqa: E402

auth.invalidate_cache()
c = S.app.test_client()

ok = True


def chk(label, cond, extra=""):
    global ok
    print(f"  {'PASS' if cond else 'FAIL'}  {label}" + (f"  {extra}" if extra else ""))
    ok = ok and bool(cond)


print("== 1. 未登录拦截 ==")
for p in ['/api/sites', '/api/sessions', '/api/tools', '/api/prefs',
          '/api/auth/me', '/api/config', '/api/skills']:
    chk(f"{p} → 401", c.get(p).status_code == 401)

print("== 2. 公开接口 ==")
chk("health 200", c.get('/api/health').status_code == 200)
d = c.get('/api/auth/status').get_json()['data']
chk("提示需要初始化", d['need_setup'] is True)

print("== 3. 首个用户自动成为管理员 ==")
r = c.post('/api/auth/register', json={"username": "admin", "password": "admin12345",
                                      "display_name": "管理员"})
chk("注册成功", r.get_json().get('ok'), r.get_json().get('error'))
chk("角色为 admin", r.get_json()['data']['user']['role'] == 'admin')
# 邀请码制：初始化后不再"关闭注册"，而是改为"必须持邀请码"。
# 无码注册应被拒（400/403），而不是静默成功。
_r = c.post('/api/auth/register', json={"username": "x", "password": "xxxxxx12"})
chk("初始化后无邀请码不可注册", _r.status_code in (400, 403),
    f"{_r.status_code} {_r.get_json().get('error', '')}")

print("== 4. 登录 ==")
chk("错误密码 401", c.post('/api/auth/login',
                    json={"username": "admin", "password": "bad"}).status_code == 401)
r = c.post('/api/auth/login', json={"username": "admin", "password": "admin12345"})
chk("登录成功", r.get_json().get('ok'))
ck = r.headers.get('Set-Cookie', '')
chk("下发 Cookie", 'scout_token' in ck)
chk("Cookie HttpOnly", 'HttpOnly' in ck)
chk("Cookie SameSite", 'SameSite' in ck)

print("== 5. 登录后可访问 ==")
for p in ['/api/sites', '/api/sessions', '/api/tools', '/api/skills',
          '/api/auth/me', '/api/config']:
    chk(f"{p} → 200", c.get(p).status_code == 200)

print("== 6. API 配置保存与脱敏 ==")
r = c.post('/api/config', json={"llm_base": "http://gw.test:8000/v1/",
                                "llm_key": "sk-testkey-1234", "llm_model": "qwen3",
                                "max_steps": 20})
body = r.get_data(as_text=True)
cfg = r.get_json()['data']['config']
chk("保存成功", cfg['llm_ready'] is True)
chk("响应中无明文 Key", 'sk-testkey-1234' not in body)
chk("返回脱敏 Key", cfg['llm_key_masked'].startswith('sk-t'), cfg['llm_key_masked'])
chk("base 去掉尾斜杠", cfg['llm_base'] == 'http://gw.test:8000/v1')
chk("max_steps 生效", r.get_json()['data']['runtime']['max_steps'] == 20)

print("== 7. 缓存命中 ==")
h0 = auth.cache_stats()['hit']
for _ in range(4):
    c.get('/api/config')
st = auth.cache_stats()
chk("连续读命中缓存", st['hit'] >= h0 + 4, st)

print("== 8. 改配置后缓存失效 ==")
c.post('/api/config', json={"llm_model": "qwen-max"})
chk("模型已更新", c.get('/api/config').get_json()['data']['config']['llm_model'] == 'qwen-max')

print("== 9. 输入校验 ==")
for bad, label in [({"llm_base": "ftp://x"}, "非 http 协议"),
                   ({"llm_timeout": "abc"}, "超时非数字"),
                   ({"max_steps": 9999}, "步数越界")]:
    chk(f"拒绝{label}", c.post('/api/config', json=bad).status_code == 400)

print("== 10. 管理员接口 ==")
chk("普通用户看到 users 被拒或为空", c.get('/api/users').status_code in (200, 403))

print("== 11. 登出 ==")
chk("登出成功", c.post('/api/auth/logout').get_json().get('ok'))
c.set_cookie('scout_token', '', path='/')
chk("登出后 401", c.get('/api/sites').status_code == 401)

print("== 12. 第二用户隔离 ==")
c.post('/api/auth/login', json={"username": "admin", "password": "admin12345"})
r = c.post('/api/users', json={"username": "analyst", "password": "analyst123",
                              "display_name": "分析师"})
chk("管理员创建用户", r.get_json().get('ok'), r.get_json().get('error'))
c.post('/api/auth/logout')
c.post('/api/auth/login', json={"username": "analyst", "password": "analyst123"})
cfg2 = c.get('/api/config').get_json()['data']['config']
chk("新用户无配置", cfg2['llm_ready'] is False, cfg2)
chk("新用户看不到他人 Key", 'sk-testkey' not in c.get('/api/config').get_data(as_text=True))
chk("新用户权限为 analyst", c.get('/api/auth/me').get_json()['data']['user']['role'] == 'analyst')
chk("非管理员访问 users → 403", c.get('/api/users').status_code == 403)

print()
print("=" * 48)
print("结果:", "全部通过" if ok else "存在失败")
sys.exit(0 if ok else 1)