/* 登录 / 注册页逻辑
   - 首次部署：无邀请码，创建管理员
   - 已初始化：需邀请码注册；可与登录页互相切换
   - 后端对用户名/密码做白名单校验，SQL 全程参数绑定 */
(function () {
  'use strict';
  const $ = (s) => document.querySelector(s);
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  const form = $('#auth-form'), errBox = $('#auth-err'), note = $('#auth-note');
  const btn = $('#f-submit'), switchBtn = $('#auth-switch');
  let mode = 'login';
  let initialized = false;

  function showErr(m) { errBox.textContent = m; errBox.hidden = false; }
  function hideErr() { errBox.hidden = true; errBox.textContent = ''; }
  function setNote(kind, html) {
    if (!html) { note.hidden = true; note.innerHTML = ''; return; }
    note.dataset.kind = kind || '';
    note.innerHTML = html;
    note.hidden = false;
  }

  function setMode(m) {
    mode = m;
    hideErr();
    const reg = m === 'register';
    $('#f-pw2-wrap').classList.toggle('hidden', !reg);
    $('#f-dn-wrap').classList.toggle('hidden', !reg);
    // 首账号免邀请码；系统已初始化则必须填
    $('#f-inv-wrap').classList.toggle('hidden', !reg || !initialized);
    $('#f-inv').required = reg && initialized;
    $('#f-pw2').required = reg;
    btn.textContent = reg
      ? (initialized ? '注册账号' : '创建管理员账号')
      : '登录';
    $('#f-pw').setAttribute('autocomplete', reg ? 'new-password' : 'current-password');
    $('#f-pw').placeholder = reg ? '至少 8 位' : '请输入密码';

    const foot = $('#auth-foot-text');
    if (foot) foot.textContent = reg
      ? (initialized ? '需要有效邀请码才能注册' : '创建后将自动成为系统管理员')
      : '';
    switchBtn.hidden = !initialized;
    switchBtn.textContent = reg ? '已有账号？返回登录' : '没有账号？用邀请码注册';
    if (reg && !initialized) setNote('',
      `<svg class="ic"><use href="#i-lock"></use></svg>
       <span>首次使用，请创建管理员账号。创建后注册入口将自动改为邀请码模式。</span>`);
    else if (!reg && !initialized) setNote('', '');
  }

  $('#f-eye').addEventListener('click', () => {
    const i = $('#f-pw');
    i.type = i.type === 'password' ? 'text' : 'password';
    $('#f-eye').style.color = i.type === 'text' ? 'var(--c-accent)' : '';
  });
  switchBtn.addEventListener('click', () => setMode(mode === 'login' ? 'register' : 'login'));

  async function api(path, opts) {
    const o = Object.assign({ headers: { 'Content-Type': 'application/json' } }, opts || {});
    if (o.body) o.body = JSON.stringify(o.body);
    const r = await fetch('/api' + path, o);
    let j = null;
    try { j = await r.json(); } catch (e) {}
    return { status: r.status, json: j };
  }

  async function boot() {
    const { json } = await api('/auth/status');
    const d = (json && json.data) || {};
    initialized = !d.need_setup;
    if (d.need_setup) {
      setMode('register');
      $('#f-user').value = 'admin';
    } else {
      setMode('login');
      if (!d.secret_persistent) {
        setNote('warn', `<svg class="ic"><use href="#i-alert"></use></svg>
          <span>未配置 <code>SCOUT_SECRET_KEY</code>，重启后已保存的 API Key 将无法解密，
          需要重新填写。建议在 .env 中设置该环境变量。</span>`);
      }
    }
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideErr();
    const u = $('#f-user').value.trim();
    const p = $('#f-pw').value;
    if (mode === 'register' && p !== $('#f-pw2').value) {
      return showErr('两次输入的密码不一致');
    }
    btn.disabled = true;
    const old = btn.textContent;
    btn.textContent = mode === 'register' ? '提交中…' : '登录中…';
    try {
      const path = mode === 'register' ? '/auth/register' : '/auth/login';
      const body = mode === 'register' ? {
        username: u, password: p,
        display_name: $('#f-dn').value.trim(),
        invite_code: $('#f-inv').value.trim(),
      } : { username: u, password: p };
      const { status, json } = await api(path, { method: 'POST', body });
      if (!json || !json.ok) {
        showErr((json && json.error) || ('请求失败 (' + status + ')'));
        btn.disabled = false; btn.textContent = old;
        return;
      }
      if (mode === 'register') {
        // 注册成功不直接登录，回登录页让用户自己输密码
        setMode('login');
        $('#f-user').value = u;
        showErr('');
        errBox.hidden = true;
        setNote('', `<svg class="ic"><use href="#i-check"></use></svg>
          <span>注册成功，请用该账号登录。</span>`);
        $('#f-pw').value = ''; $('#f-pw2').value = ''; $('#f-inv').value = '';
        btn.disabled = false; btn.textContent = '登录';
        return;
      }
      location.href = '/';
    } catch (err) {
      showErr('网络错误：' + err.message);
      btn.disabled = false; btn.textContent = old;
    }
  });

  boot().catch(() => setMode('login'));
})();