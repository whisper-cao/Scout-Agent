/* ==========================================================================
   账号与 API 配置面板
   ========================================================================== */
(function () {
  'use strict';
  const $  = (s, r) => (r || document).querySelector(s);
  const $$ = (s, r) => Array.prototype.slice.call((r || document).querySelectorAll(s));
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  const box = $('#acct-box');
  let me = null, cfg = null, rt = null, cache = null, users = [], invites = [];

  async function api(path, opts) {
    const o = Object.assign({ headers: { 'Content-Type': 'application/json' } }, opts || {});
    if (o.body && typeof o.body !== 'string') o.body = JSON.stringify(o.body);
    const r = await fetch('/api' + path, o);
    if (r.status === 401) { location.href = '/login'; throw new Error('登录已过期'); }
    let j = null;
    try { j = await r.json(); } catch (e) {}
    if (!r.ok || (j && j.ok === false)) throw new Error((j && j.error) || ('HTTP ' + r.status));
    return j;
  }

  function toast(msg) {
    const t = document.getElementById('toast');
    const tx = document.getElementById('toast-text');
    if (!t) return;
    tx.textContent = msg; t.hidden = false;
    clearTimeout(t._t);
    t._t = setTimeout(() => { t.hidden = true; }, 2400);
  }

  function initials(u) {
    const s = (u.display_name || u.username || '?').trim();
    return s.slice(0, 2).toUpperCase();
  }
  const ROLE_CN = { admin: '管理员', analyst: '分析师', viewer: '只读' };

  /* ---------- 渲染 ---------- */
  function render() {
    if (!me) { box.innerHTML = ''; return; }
    const c = cfg || {};
    box.innerHTML = `
      <div class="acct-card">
        <div class="acct-head">
          <span class="acct-av">${esc(initials(me))}</span>
          <div style="flex:1;min-width:0">
            <div class="acct-name">${esc(me.display_name || me.username)}</div>
            <div class="acct-role">${esc(me.username)} · ${esc(ROLE_CN[me.role] || me.role)}</div>
          </div>
          <button class="ur-btn" id="btn-logout" title="退出登录" aria-label="退出登录">
            <svg class="ic"><use href="#i-log-out"></use></svg></button>
        </div>
      </div>

      <div class="acct-card">
        <div class="acct-head" style="margin-bottom:9px">
          <span class="acct-name" style="font-size:11.5px">LLM 网关配置</span>
        </div>

        <div class="cfg-state" data-s="${c.llm_ready ? 'on' : 'off'}">
          <svg class="ic"><use href="#${c.llm_ready ? 'i-check' : 'i-alert'}"></use></svg>
          <span>${c.llm_ready
            ? '已接入模型，规划与总结将走推理'
            : '未接入模型，当前使用确定性工作流（工具照常执行）'}</span>
        </div>

        <div class="cfg-row">
          <span class="cfg-l">网关地址 <span class="cfg-hint">Base URL，需含 /v1</span></span>
          <input class="cfg-in" id="c-base" value="${esc(c.llm_base || '')}"
                 placeholder="http://gateway:8000/v1">
        </div>

        <div class="cfg-row">
          <span class="cfg-l">API Key <span class="cfg-hint">${c.llm_key_set
            ? '已保存 ' + esc(c.llm_key_masked) + '，留空则不修改' : '尚未配置'}</span></span>
          <input class="cfg-in" id="c-key" type="password" autocomplete="new-password"
                 placeholder="${c.llm_key_set ? '留空保持不变' : 'sk-...'}">
        </div>

        <div class="cfg-row">
          <span class="cfg-l">模型名</span>
          <input class="cfg-in" id="c-model" value="${esc(c.llm_model || '')}" placeholder="qwen">
        </div>

        <div class="cfg-grid2">
          <div class="cfg-row">
            <span class="cfg-l">LLM 超时 <span class="cfg-hint">秒</span></span>
            <input class="cfg-in mono-sq" id="c-llmto" type="number" min="5" max="600"
                   value="${c.llm_timeout || 60}">
          </div>
          <div class="cfg-row">
            <span class="cfg-l">探测超时 <span class="cfg-hint">秒</span></span>
            <input class="cfg-in mono-sq" id="c-probeto" type="number" min="3" max="60"
                   value="${c.probe_timeout || 10}">
          </div>
        </div>

        <div class="cfg-row">
          <span class="cfg-l">单次最大步数 <span class="cfg-hint">1~200</span></span>
          <input class="cfg-in mono-sq" id="c-steps" type="number" min="1" max="200"
                 value="${c.max_steps || 12}">
        </div>

        <div class="cfg-row">
          <span class="cfg-l">最大决策轮数 <span class="cfg-hint">1~60</span></span>
          <input class="cfg-in mono-sq" id="c-rounds" type="number" min="1" max="60"
                 value="${c.max_rounds || 12}">
        </div>

        <div class="cfg-tip">
          探测深度由这两个值决定：<b>轮数</b>是模型思考→取证的循环次数，
          <b>步数</b>是单轮内允许的工具调用总数。数值越大越 thorough，
          但耗时与目标站点的请求量也线性上升。
        </div>

        <div class="cfg-acts">
          <button class="btn btn-primary" id="c-save">保存</button>
          <button class="btn" id="c-test">测试连通</button>
        </div>
        <div class="cfg-test" id="c-test-out" hidden></div>

        <div class="cfg-cache" id="c-cache"></div>
      </div>

      <div class="acct-card">
        <div class="acct-head" style="margin-bottom:9px">
          <span class="acct-name" style="font-size:11.5px">修改密码</span>
        </div>
        <div class="cfg-row">
          <input class="cfg-in mono-sq" id="c-oldpw" type="password"
                 placeholder="当前密码" autocomplete="current-password">
        </div>
        <div class="cfg-row">
          <input class="cfg-in mono-sq" id="c-newpw" type="password"
                 placeholder="新密码（至少 8 位）" autocomplete="new-password">
        </div>
        <div class="cfg-acts"><button class="btn" id="c-pw">更新密码</button></div>
      </div>

      ${me.role === 'admin' ? `<div class="acct-card">
        <div class="acct-head" style="margin-bottom:9px">
          <span class="acct-name" style="font-size:11.5px">注册邀请码</span>
          <span class="nav-count" style="margin-left:auto" id="inv-count">${invites.length}</span>
        </div>
        <p class="cfg-hint" style="margin:-4px 0 8px;line-height:1.55">
          自助注册需要邀请码。生成后明文只显示一次，请立即复制给使用者。</p>
        <div class="cfg-grid2" style="grid-template-columns:1fr 76px">
          <input class="cfg-in mono-sq" id="ni-role" placeholder="备注（选填）">
          <select class="cfg-in" id="ni-num">
            <option value="1">1 次</option><option value="3">3 次</option>
            <option value="10">10 次</option>
          </select>
        </div>
        <div class="cfg-acts" style="margin-bottom:8px">
          <button class="btn btn-primary" id="ni-add">生成邀请码</button>
        </div>
        <div id="inv-list"></div>
      </div>

      <div class="acct-card">
        <div class="acct-head" style="margin-bottom:9px">
          <span class="acct-name" style="font-size:11.5px">用户管理</span>
          <span class="nav-count" style="margin-left:auto">${users.length}</span>
        </div>
        <div class="cfg-grid2" style="margin-bottom:8px">
          <input class="cfg-in mono-sq" id="nu-user" placeholder="用户名">
          <input class="cfg-in mono-sq" id="nu-pw" type="password" placeholder="初始密码">
        </div>
        <div class="cfg-acts" style="margin-bottom:8px">
          <button class="btn btn-primary" id="nu-add">添加用户</button>
        </div>
        <div id="user-list"></div>
      </div>` : ''}
    `;
    renderCache();
    renderUsers();
    renderInvites();
    bind();
  }

  function renderCache() {
    const n = $('#c-cache');
    if (!n || !cache) return;
    n.innerHTML = `<span>配置缓存</span>
      <span>命中 <b>${cache.hit}</b></span>
      <span>回源 <b>${cache.miss}</b></span>
      <span>条目 <b>${cache.entries}</b></span>`;
  }

  function renderUsers() {
    const n = $('#user-list');
    if (!n || me.role !== 'admin') return;
    n.innerHTML = users.map((u) => `<div class="user-row${u.is_active ? '' : ' ur-off'}">
        <span class="ur-name" title="${esc(u.username)}">${esc(u.display_name || u.username)}</span>
        <span class="ur-role" data-r="${esc(u.role)}">${esc(ROLE_CN[u.role] || u.role)}</span>
        <button class="ur-btn" data-toggle-user="${u.id}" data-active="${u.is_active ? 1 : 0}"
          title="${u.is_active ? '禁用' : '启用'}">
          <svg class="ic"><use href="#i-${u.is_active ? 'x' : 'check'}"></use></svg></button>
        <button class="ur-btn" data-revoke-user="${u.id}" title="强制下线">
          <svg class="ic"><use href="#i-log-out"></use></svg></button>
      </div>`).join('') || '<div style="font-size:11px;color:var(--c-ink-4);padding:4px">暂无其他用户</div>';
  }

  function renderInvites() {
    const n = $('#inv-list');
    if (!n || me.role !== 'admin') return;
    const cnt = $('#inv-count');
    if (cnt) cnt.textContent = invites.length;
    n.innerHTML = invites.length ? invites.map((i) => {
      const used = i.used_count >= i.max_uses;
      return `<div class="user-row${used ? ' ur-off' : ''}">
          <span class="ur-name" title="${esc(i.note || '')}">${esc(i.note || ('#' + i.id))}</span>
          <span class="ur-role" data-r="${esc(i.role)}">${esc(ROLE_CN[i.role] || i.role)}</span>
          <span style="font-size:10px;color:var(--c-ink-4);margin-left:auto">
            ${i.used_count}/${i.max_uses}</span>
          ${used ? '' : `<button class="ur-btn" data-del-invite="${i.id}" title="作废">
            <svg class="ic"><use href="#i-trash"></use></svg></button>`}
        </div>`;
    }).join('') : '<div style="font-size:11px;color:var(--c-ink-4);padding:4px">暂无邀请码，点击上方生成</div>';
  }

  async function loadInvites() {
    if (!me || me.role !== 'admin') return;
    try { invites = (await api('/invites')).data.invites || []; renderInvites(); }
    catch (e) { /* 非管理员忽略 */ }
  }

  async function makeInvite() {
    const note = $('#ni-role').value.trim();
    const n = parseInt($('#ni-num').value, 10) || 1;
    try {
      const r = await api('/invites', { method: 'POST', body: { note, max_uses: n } });
      const inv = r.data.invite;
      await loadInvites();
      // 明文只此一次，直接弹出来让用户复制
      navigator.clipboard?.writeText(inv.code).catch(() => {});
      toast('邀请码已生成并复制：' + inv.code);
      $('#ni-role').value = '';
    } catch (e) { toast('生成失败：' + e.message); }
  }

  /* ---------- 交互 ---------- */
  function bind() {
    $('#btn-logout')?.addEventListener('click', doLogout);
    $('#c-save')?.addEventListener('click', saveCfg);
    $('#c-test')?.addEventListener('click', testCfg);
    $('#c-pw')?.addEventListener('click', changePw);
    $('#nu-add')?.addEventListener('click', addUser);
    $('#ni-add')?.addEventListener('click', makeInvite);

    $('#inv-list')?.addEventListener('click', async (e) => {
      const d = e.target.closest('[data-del-invite]');
      if (!d) return;
      if (!confirm('作废该邀请码？')) return;
      try {
        await api('/invites/' + d.dataset.delInvite, { method: 'DELETE' });
        await loadInvites();
        toast('已作废');
      } catch (err) { toast('操作失败：' + err.message); }
    });

    $('#user-list')?.addEventListener('click', async (e) => {
      const t = e.target.closest('[data-toggle-user]');
      const r = e.target.closest('[data-revoke-user]');
      try {
        if (t) {
          const on = t.dataset.active === '1';
          if (!on && !confirm('禁用该账号会强制其下线，确认？')) return;
          await api('/users/' + t.dataset.toggleUser + '/active', { method: 'POST', body: { active: on } });
          toast(on ? '已禁用' : '已启用');
          await loadUsers();
        } else if (r) {
          await api('/users/' + r.dataset.revokeUser + '/revoke', { method: 'POST' });
          toast('已强制下线该账号的所有会话');
        }
      } catch (err) { toast('操作失败：' + err.message); }
    });
  }

  async function loadMe() {
    const r = await api('/auth/me');
    me = r.data.user; cfg = r.data.config; rt = r.data.runtime; cache = r.data.cache;
    const av = $('#tb-avatar');
    if (av) { av.textContent = initials(me); av.title = me.display_name || me.username; }
  }

  async function loadUsers() {
    if (!me || me.role !== 'admin') return;
    try { users = (await api('/users')).data || []; renderUsers(); } catch (e) { /* 非管理员忽略 */ }
    await loadInvites();
  }

  async function saveCfg() {
    const body = {
      llm_base: $('#c-base').value.trim(),
      llm_model: $('#c-model').value.trim() || 'qwen',
      llm_timeout: $('#c-llmto').value,
      probe_timeout: $('#c-probeto').value,
      max_steps: $('#c-steps').value,
      max_rounds: $('#c-rounds').value,
    };
    const k = $('#c-key').value.trim();
    if (k) body.llm_key = k;                 // 留空 = 不修改
    try {
      const r = await api('/config', { method: 'POST', body });
      cfg = r.data.config; rt = r.data.runtime; cache = r.data.cache;
      $('#c-key').value = '';
      render();
      toast(cfg.llm_ready ? '已保存，配置已缓存生效' : '已保存（未填网关与 Key，仍用确定性工作流）');
    } catch (e) { toast('保存失败：' + e.message); }
  }

  async function testCfg() {
    const out = $('#c-test-out');
    out.hidden = false; out.dataset.s = 'wait';
    out.textContent = '正在测试网关连通性…（最多 20 秒）';
    const t = setTimeout(() => {
      if (out.dataset.s === 'wait') out.textContent = '仍在等待网关响应，请确认地址从服务器可达…';
    }, 6000);
    try {
      const r = await api('/config/test', { method: 'POST' });
      const d = r.data;
      out.dataset.s = d.reachable ? 'ok' : 'err';
      out.textContent = d.reachable
        ? `连通正常（HTTP ${d.status}，${d.elapsed_ms}ms）· ${d.hint}`
        : `无法连通：${d.hint}${d.detail ? ' — ' + d.detail : ''}`;
    } catch (e) {
      out.dataset.s = 'err';
      out.textContent = '测试失败：' + e.message;
    } finally { clearTimeout(t); }
  }

  async function changePw() {
    const o = $('#c-oldpw').value, n = $('#c-newpw').value;
    if (!o || !n) return toast('请填写当前密码与新密码');
    try {
      await api('/auth/password', { method: 'POST', body: { old_password: o, new_password: n } });
      $('#c-oldpw').value = ''; $('#c-newpw').value = '';
      toast('密码已更新');
    } catch (e) { toast('修改失败：' + e.message); }
  }

  async function addUser() {
    const u = $('#nu-user').value.trim(), p = $('#nu-pw').value;
    if (!u || !p) return toast('请填写用户名与初始密码');
    try {
      await api('/users', { method: 'POST', body: { username: u, password: p } });
      $('#nu-user').value = ''; $('#nu-pw').value = '';
      await loadUsers();
      toast('已创建用户，请提醒其首次登录后修改密码');
    } catch (e) { toast('创建失败：' + e.message); }
  }

  async function doLogout() {
    try { await api('/auth/logout', { method: 'POST' }); } catch (e) { /* 已失效也跳登录 */ }
    location.href = '/login';
  }

  /* 定时刷新缓存统计，让"缓存生效"可观测 */
  setInterval(async () => {
    if (!me) return;
    try {
      const r = await api('/config');
      cache = r.data.cache; cfg = r.data.config;
      renderCache();
    } catch (e) { /* 忽略 */ }
  }, 15000);

  /* 先拿身份，再取列表，最后一次性渲染——
     否则 renderUsers() 执行时 users 还是空数组，面板会一直空白。 */
  loadMe()
    .then(() => loadUsers())
    .then(render)
    .catch(() => {});
})();