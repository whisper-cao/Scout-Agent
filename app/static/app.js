/* ==========================================================================
   Scout Agent · 前端逻辑（对接真实 API）
   核心：输入域名 → 后端按域名归一 → 同域名复用同会话 + 同站点记忆
   ========================================================================== */
(function () {
  'use strict';

  const $  = (s, r) => (r || document).querySelector(s);
  const $$ = (s, r) => Array.prototype.slice.call((r || document).querySelectorAll(s));
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  // Markdown 渲染入口。ScoutMD 缺失时回退为纯文本 —— 宁可显示源码，
  // 也不能因为渲染器没加载就把未转义的 HTML 塞进 DOM。
  const md = (t) => (window.ScoutMD && t)
    ? window.ScoutMD.render(t)
    : '<p class="md-p">' + esc(t || '') + '</p>';

  const el = {
    conn: $('#conn'), connText: $('#conn-text'),
    crumbSite: $('#crumb-site'),
    taskTitle: $('#task-title'), statusPill: $('#status-pill'), taskMeta: $('#task-meta'),
    targetInput: $('#target-input'), targetHint: $('#target-hint'), btnOpen: $('#btn-open'),
    siteList: $('#site-list'), sessList: $('#sess-list'), prefList: $('#pref-list'),
    skillList: $('#skill-list'), fnList: $('#fn-list'),
    blkSites: $('#blk-sites'), blkSess: $('#blk-sessions'),
    blkPrefs: $('#blk-prefs'), blkTools: $('#blk-tools'),
    thread: $('#thread'), stageScroll: $('#stage-scroll'),
    input: $('#input'), btnSend: $('#btn-send'), btnSkill: $('#btn-skill'),
    scopeTag: $('#scope-tag'),
    rrSub: $('#rr-sub'), rrBody: $('#rr-body'), memTabs: $('#memory-tabs'),
    btnForget: $('#btn-forget'), btnCloseRight: $('#btn-close-right'),
    btnOpenRight: $('#btn-open-right'), reopenRight: $('#reopen-right'),
    body: $('#body'),
    toast: $('#toast'), toastText: $('#toast-text'),
  };

  const state = {
    sessionId: null,
    siteId: null,
    site: null,          // 当前站点
    memory: null,        // 当前站点记忆画像
    sites: [],
    sessions: [],
    prefs: {},
    tools: [],
    skillsList: [],
    memTab: 'fingerprint',
    rightOpen: true,
    running: false,
    mode: 'autonomous',
    toolCount: 0,
  };

  /* ---------------- API ---------------- */
  async function api(path, opts) {
    const o = Object.assign({ headers: { 'Content-Type': 'application/json' } }, opts || {});
    if (o.body && typeof o.body !== 'string') o.body = JSON.stringify(o.body);
    const r = await fetch('/api' + path, o);
    // 会话失效统一跳登录，避免后续请求连环 401
    if (r.status === 401) {
      let j = null; try { j = await r.json(); } catch (e) {}
      if (j && j.need_login) { location.href = '/login'; throw new Error('登录已过期'); }
    }
    let j = null;
    try { j = await r.json(); } catch (e) { /* 非 JSON */ }
    if (!r.ok) {
      const msg = (j && (j.error || j.description)) || ('HTTP ' + r.status);
      throw new Error(msg);
    }
    return j;
  }

  function setConn(s, text) {
    el.conn.dataset.s = s;
    el.connText.textContent = text;
  }

  let toastTimer;
  function toast(msg, ms) {
    el.toastText.textContent = msg;
    el.toast.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { el.toast.hidden = true; },
                          ms || 2600);
  }

  /* ---------------- 站点记忆渲染（右栏） ---------------- */
  const NS_META = {
    fingerprint: { label: '指纹', ic: '#i-target' },
    stack:       { label: '技术栈', ic: '#i-db' },
    endpoint:    { label: '接口', ic: '#i-link' },
    finding:     { label: '漏洞结论', ic: '#i-alert' },
    config:      { label: '配置', ic: '#i-shield' },
    history:     { label: '历史', ic: '#i-clock' },
  };

  function confLevel(c) { return c >= 0.9 ? 'high' : c >= 0.6 ? 'mid' : 'low'; }

  function renderMemory() {
    const m = state.memory;
    if (!m) {
      el.rrSub.textContent = '未选择站点';
      el.memTabs.innerHTML = '';
      el.rrBody.innerHTML = empty('db', '未选择站点', '在左侧输入域名后，<br>该站点的指纹与接口会沉淀在这里');
      return;
    }
    const c = m.counts || {};
    el.rrSub.textContent = `${m.site.domain} · ${m.site.site_key}`;

    const tabs = Object.keys(NS_META).filter((k) => (c[k] || 0) > 0);
    if (!tabs.includes(state.memTab)) state.memTab = tabs[0] || 'fingerprint';

    el.memTabs.innerHTML = tabs.map((k) =>
      `<button class="ftab${k === state.memTab ? ' is-on' : ''}" data-ns="${k}">
        <svg class="ic"><use href="${NS_META[k].ic}"></use></svg>
        <span>${NS_META[k].label} ${c[k]}</span>
      </button>`).join('');

    if (!tabs.length) {
      el.rrBody.innerHTML = empty('db', '暂无站点记忆',
        '执行一次任务后，<br>指纹、接口与结论会自动沉淀到这里');
      return;
    }
    el.rrBody.innerHTML = renderMemGroup(state.memTab);
  }

  function empty(ic, t, d) {
    return `<div class="rr-empty"><div class="rr-empty-ic"><svg class="ic"><use href="#${ic}"></use></svg></div>
      <div class="rr-empty-t">${esc(t)}</div><div class="rr-empty-d">${d}</div></div>`;
  }

  function short(v, n) {
    n = n || 90;
    if (v == null) return '';
    if (typeof v === 'object') { try { v = JSON.stringify(v); } catch (e) { v = String(v); } }
    v = String(v);
    return v.length > n ? v.slice(0, n) + '…' : v;
  }

  function memItem(key, value, conf, updated) {
    return `<div class="mem-item">
      <div class="mem-k">${esc(key)}</div>
      <div class="mem-v">${esc(short(value))}</div>
      <div class="mem-meta">
        ${conf != null ? `<span class="mem-conf" data-c="${confLevel(conf)}">置信度 ${conf}</span>` : ''}
        ${updated ? `<span>${esc(String(updated).slice(0, 16).replace('T', ' '))}</span>` : ''}
      </div>
    </div>`;
  }

  function renderMemGroup(ns) {
    const m = state.memory || {};
    const meta = NS_META[ns] || { label: ns };
    let items = '';

    if (ns === 'fingerprint') {
      const fp = m.fingerprint || {};
      items = Object.keys(fp).map((k) =>
        memItem(k, fp[k].value, fp[k].confidence, fp[k].updated_at)).join('');
    } else if (ns === 'stack') {
      items = (m.stack || []).map((s) => memItem(typeof s === 'string' ? s : s.name,
        typeof s === 'string' ? '已识别组件' : s.category, 0.8)).join('');
    } else if (ns === 'endpoint') {
      items = (m.endpoints || []).map((e) =>
        memItem(e.path, `HTTP ${e.status}${e.len ? ' · ' + e.len + 'B' : ''}${e.note ? ' · ' + e.note : ''}`, 1)).join('');
    } else if (ns === 'finding') {
      items = (m.findings || []).map((f) =>
        memItem(f.id, `${f.verdict || ''} ${f.conclusion || ''}`.trim(), 1)).join('');
    } else if (ns === 'config') {
      items = Object.keys(m.config || {}).map((k) => memItem(k, m.config[k].value, m.config[k].confidence)).join('');
    } else if (ns === 'history') {
      items = (m.history || []).map((h) => memItem(h.name || h.key,
        `${h.at || ''}`, 1)).join('');
    }

    if (!items) items = empty('db', '该分类暂无数据', '');
    return `<div class="mem-group">
      <div class="mem-h"><svg class="ic"><use href="${meta.ic}"></use></svg>${meta.label}</div>
      ${items}
    </div>`;
  }

  el.memTabs.addEventListener('click', (e) => {
    const b = e.target.closest('[data-ns]');
    if (b) { state.memTab = b.dataset.ns; renderMemory(); }
  });

  /* ---------------- 左栏 ---------------- */
  function renderSites() {
    if (!state.sites.length) {
      el.siteList.innerHTML = `<li style="padding:12px 9px;font-size:11.5px;color:var(--c-ink-4)">
        暂无站点。输入域名开始第一次测试。</li>`;
      return;
    }
    el.siteList.innerHTML = state.sites.map((s) => {
      const on = s.id === state.siteId;
      const hasMem = s.memory_count > 0;
      return `<li><button class="site-item${on ? ' is-active' : ''}${hasMem ? ' has-memory' : ''}" data-site="${s.id}">
        <span class="si-row">
          <span class="si-name" title="${esc(s.site_key)}">${esc(s.site_key)}</span>
          ${hasMem ? `<span class="si-tag" data-k="mem">${s.memory_count} 条</span>` : ''}
        </span>
        <span class="si-sub">
          <span>会话 <b>${s.session_count}</b></span>
          <span>${esc(String(s.last_seen || '').slice(5, 16).replace('T', ' '))}</span>
        </span>
      </button></li>`;
    }).join('');
  }

  function renderSessions() {
    if (!state.sessions.length) {
      el.sessList.innerHTML = `<li style="padding:12px 9px;font-size:11.5px;color:var(--c-ink-4)">
        暂无会话</li>`;
      return;
    }
    el.sessList.innerHTML = state.sessions.map((s) => {
      const on = s.id === state.sessionId;
      return `<li><button class="sess-item${on ? ' is-active' : ''}" data-sess="${s.id}" data-s="${esc(s.status)}">
        <span class="ss-name" title="${esc(s.title)}">${esc(s.title)}</span>
        <span class="ss-sub">
          <span class="ss-badge" data-s="${esc(s.status)}">${s.status === 'active' ? '进行中' : '已关闭'}</span>
          <span>${esc(String(s.updated_at || '').slice(5, 16).replace('T', ' '))}</span>
        </span>
      </button></li>`;
    }).join('');
  }

  function renderPrefs() {
    const keys = Object.keys(state.prefs).sort();
    if (!keys.length) { el.prefList.innerHTML = ''; return; }
    el.prefList.innerHTML = keys.map((k) =>
      `<li class="pref-item"><span class="pref-k">${esc(k)}</span>
       <span class="pref-dots"></span>
       <span class="pref-v" title="${esc(short(state.prefs[k], 40))}">${esc(short(state.prefs[k], 22))}</span></li>`).join('');
  }

  function renderTools() {
    el.skillList.innerHTML = state.skillsList.map((s) =>
      `<li class="tool-item"><div class="tool-t"><svg class="ic"><use href="#i-book"></use></svg>${esc(s.title)}</div>
       <div class="tool-d">${esc(s.description)}</div>
       <div class="tool-tags">${(s.tags || []).map((t) => `<span class="tool-tag">${esc(t)}</span>`).join('')}
       <span class="tool-tag">${s.step_count} 步</span></div></li>`).join('');
    el.fnList.innerHTML = state.tools.map((t) =>
      `<li class="tool-item"><div class="tool-t"><svg class="ic"><use href="#i-terminal"></use></svg>${esc(t.name)}</div>
       <div class="tool-d">${esc(t.description)}</div>
       <div class="tool-tags">${(t.tags || []).map((x) => `<span class="tool-tag">${esc(x)}</span>`).join('')}
       ${t.writes ? '<span class="tool-tag" data-k="write">需审批</span>' : ''}</div></li>`).join('');
  }

  function renderCounts() {
    const c = state.memory ? state.memory.counts : {};
    $('#c-sites').textContent = state.sites.length;
    $('#c-sessions').textContent = state.sessions.length;
    $('#c-prefs').textContent = Object.keys(state.prefs).length;
    $('#s-sites').textContent = state.sites.length;
    $('#s-sessions').textContent = state.sessions.length;
    $('#s-mem').textContent = (c.fingerprint || 0) + (c.endpoint || 0) + (c.stack || 0) + (c.findings || 0);
  }

  /* ---------------- 中栏：消息渲染 ---------------- */
  function linkBar(ev) {
    const cnt = ev.memory_counts || {};
    const pills = Object.keys(cnt).filter((k) => cnt[k] > 0)
      .map((k) => `<span class="lc">${esc(NS_META[k] ? NS_META[k].label : k)} ${cnt[k]}</span>`).join('');
    return `<div class="link-bar">
      <svg class="ic"><use href="#${ev.memory_reused ? 'i-link' : 'i-target'}"></use></svg>
      <div class="link-bar-body">
        <div class="link-bar-t">会话窗口 <code style="font-family:var(--ff-mono)">${esc(ev.session_name)}</code> · 记忆键 <code style="font-family:var(--ff-mono)">${esc(ev.site_key)}</code></div>
        <div class="link-bar-d">${esc(ev.note)}</div>
        ${pills ? `<div class="link-counts">${pills}</div>` : ''}
      </div>
    </div>`;
  }

  function renderMessages(msgs) {
    if (!msgs.length) {
      el.thread.innerHTML = `<div class="sec-mark"><span class="sec-label">
        <svg class="ic"><use href="#i-spark"></use></svg>开始</span></div>
        <div style="text-align:center;padding:30px 12px 8px">
          <div style="font-size:13.5px;color:var(--c-ink-2);line-height:1.7">
            在左侧输入目标域名开始安全测试。<br>
            <span style="font-size:12px;color:var(--c-ink-4)">
            同一域名会自动复用同一会话窗口与历史站点记忆。</span>
          </div>
        </div>`;
      return;
    }
    el.thread.innerHTML = msgs.map(renderMsg).join('');
    el.stageScroll.scrollTop = el.stageScroll.scrollHeight;
  }

  function renderMsg(m) {
    const c = m.content || {};
    if (m.role === 'user') {
      return `<article class="msg msg-user">
        <div class="avatar-msg me">AN</div>
        <div class="msg-body">
          <div class="msg-head"><span class="msg-who">analyst</span>
            <span class="msg-role">安全运维</span>
            <span class="msg-time">${esc(String(m.created_at || '').slice(11, 16))}</span></div>
          <div class="bubble-user">${esc(c.text || '')}</div>
        </div></article>`;
    }
    if (m.kind === 'run') return renderRun(c);
    if (m.kind === 'plan') return renderPlan(c);
    if (m.kind === 'gate') return renderGate(c);
    if (c.event === 'site_linked') return linkBar(c);

    const arts = (c.artifacts || []).map((a) =>
      `<div class="mem-item" style="margin-top:8px"><div class="mem-k">${esc(a.name)}</div>
       <div class="mem-meta"><span>${a.size} B</span>
       <button class="btn" style="height:22px;padding:0 7px;font-size:11px;margin-left:auto"
         data-art-view="${a.id}"><svg class="ic"><use href="#i-eye"></use></svg>预览</button>
       <button class="btn" style="height:22px;padding:0 7px;font-size:11px"
         data-art="${a.id}"><svg class="ic"><use href="#i-download"></use></svg>下载</button></div></div>`).join('');

    return `<article class="msg msg-agent">
      <div class="avatar-msg ai"><svg viewBox="0 0 24 24" width="15" height="15" fill="none"
        stroke="currentColor" stroke-width="2.1" stroke-linecap="round"><circle cx="11" cy="11" r="6.2"/><path d="M15.6 15.6L21 21"/></svg></div>
      <div class="msg-body">
        <div class="msg-head"><span class="msg-who">Scout</span>
          ${c.thinking ? '<span class="msg-role">决策中</span>' : ''}
          <span class="msg-time">${esc(String(m.created_at || '').slice(11, 16))}</span></div>
        <div class="agent-text md">${md(c.text || '')}</div>
        ${arts}
      </div></article>`;
  }

  function renderPlan(c) {
    const items = c.plan || [];
    return `<div class="sec-mark"><span class="sec-label">
      <svg class="ic"><use href="#i-list"></use></svg>执行计划</span>
      <span class="sec-count">${items.length} 步</span></div>
      <div class="plan">${items.map((it, i) => `<div class="plan-row">
        <span class="plan-idx">${i + 1}</span>
        <span class="plan-txt">${esc(it.title)}<br><span style="color:var(--c-ink-4);font-size:11.5px">${esc(it.why || '')}</span></span>
        <span class="plan-badge" data-s="${esc(it.skill)}">${esc(it.skill)}</span>
      </div>`).join('')}</div>`;
  }

  function renderRun(c) {
    const steps = c.steps || [];
    const done = steps.filter((s) => s.status === 'done').length;
    const fail = steps.filter((s) => s.status === 'failed').length;
    const wait = steps.filter((s) => s.status === 'awaiting').length;
    return `<div class="sec-mark"><span class="sec-label">
        <svg class="ic"><use href="#i-terminal"></use></svg>执行记录</span>
        <span class="sec-count">${steps.length} 次工具调用</span></div>
      <div class="run" data-open="true">
        <div class="run-head">
          <svg class="ic run-head-ic"><use href="#i-terminal"></use></svg>
          <span class="run-title">tool trace</span>
          <span class="run-stats">
            <span class="rs" data-s="done"><svg class="ic"><use href="#i-check"></use></svg>${done} 成功</span>
            ${fail ? `<span class="rs" data-s="fail"><svg class="ic"><use href="#i-x"></use></svg>${fail} 失败</span>` : ''}
            ${wait ? `<span class="rs" data-s="wait"><svg class="ic"><use href="#i-clock"></use></svg>${wait} 待确认</span>` : ''}
          </span>
          <button class="run-toggle" data-toggle-run><span class="run-toggle-text">收起</span>
            <svg class="ic"><use href="#i-chev-down"></use></svg></button>
        </div>
        <div class="run-body">${steps.map(renderStep).join('')}</div>
      </div>`;
  }

  function renderStep(s) {
    const map = {
      done:     { ic: '#i-check', t: '成功' },
      failed:   { ic: '#i-x',     t: '失败' },
      running:  { ic: '#i-ring',  t: '执行中' },
      awaiting: { ic: '#i-clock', t: '待确认' },
    };
    const sk = s.status === 'failed' ? 'fail' : s.status === 'awaiting' ? 'wait'
      : s.status === 'running' ? 'run' : 'done';
    const b = map[s.status] || map.done;

    const detail = s.result || s.error
      ? `<div class="kv">${esc(s.result ? JSON.stringify(s.result, null, 2) : s.error)}</div>` : '';
    const appr = s.status === 'awaiting'
      ? `<div class="retry" style="border-color:var(--c-wait-line);border-left-color:var(--c-wait);background:var(--c-wait-bg)">
           <div class="retry-head" style="color:var(--c-wait);border-bottom-color:var(--c-wait-line)">
             <svg class="ic"><use href="#i-clock"></use></svg><span>已挂起，等待人工确认</span></div>
           <div style="padding:8px 10px;font-size:11.5px;color:var(--c-ink-2);line-height:1.6">${esc(s.description || '')}</div>
         </div>` : '';
    const retry = (s.attempts && s.attempts > 1)
      ? `<div class="retry"><div class="retry-head"><svg class="ic"><use href="#i-refresh"></use></svg>
           <span>失败后重试记录</span><span class="retry-why">已重试 ${s.attempts} 次</span></div>
           <div class="attempts"><div class="att"><span class="att-n">#1</span>
           <span class="att-msg">${esc(s.error || '')}</span><span class="att-t">失败</span></div>
           <div class="att"><span class="att-n">#2</span><span class="att-msg">重试后仍失败，已停止</span>
           <span class="att-t">重试</span></div></div></div>` : '';

    const hasBody = detail || appr || retry;
    return `<div class="step" data-s="${sk}" data-open="${hasBody ? 'true' : 'false'}">
      <div class="step-rail"><span class="step-mark"><svg class="ic"><use href="${b.ic}"></use></svg></span></div>
      <div class="step-main">
        <div class="step-top">
          <span class="step-name">${esc(s.tool || '')}</span>
          <span class="step-title">${esc(s.title || '')}</span>
          <span class="step-badge" data-s="${sk}"><svg class="ic"><use href="${b.ic}"></use></svg>${b.t}</span>
          <span class="step-dur">${s.duration_ms != null ? s.duration_ms + 'ms' : ''}</span>
        </div>
        ${hasBody ? `<div class="step-more"><button class="step-expand" data-toggle-step>
          <span class="step-expand-text">收起详情</span><svg class="ic"><use href="#i-chev-down"></use></svg>
          </button></div>` : ''}
        <div class="step-detail">${detail}${retry}${appr}</div>
      </div></div>`;
  }

  function renderGate(c) {
    const g = c.gate || {};
    const p = g.payload || {};
    const cmd = [p.tool].concat(Object.entries(p.args || {})
      .map(([k, v]) => `${k}=${typeof v === 'object' ? JSON.stringify(v) : v}`)).join('  ');
    return `<div class="gate">
      <div class="gate-head">
        <span class="gate-tag"><svg class="ic"><use href="#i-clock"></use></svg>需人工确认</span>
        <span class="gate-title">${esc(g.title || '')}</span>
      </div>
      <div class="gate-body">
        <p class="gate-desc">${esc(g.description || '')}</p>
        <div class="gate-cmd">${esc(cmd)}</div>
        <div class="gate-risk">
          <div class="gate-risk-row"><svg class="ic"><use href="#i-alert"></use></svg>
            <span>风险等级：<b>${esc(g.risk || 'high')}</b>，属写入/破坏性操作</span></div>
          <div class="gate-risk-row"><svg class="ic"><use href="#i-alert"></use></svg>
            <span>执行后 Scout 会立即回收现场并记录结果</span></div>
        </div>
        <div class="gate-acts">
          <button class="btn btn-primary" data-approve="1" data-id="${g.approval_id}">批准执行</button>
          <button class="btn" data-approve="0" data-id="${g.approval_id}">拒绝</button>
          <span class="gate-note">风险等级 ${esc(g.risk || 'high')}</span>
        </div>
      </div></div>`;
  }

  /* 展开/收起 */
  el.thread.addEventListener('click', (e) => {
    const rb = e.target.closest('[data-toggle-run]');
    if (rb) {
      const run = rb.closest('.run');
      const open = run.dataset.open !== 'true';
      run.dataset.open = String(open);
      $('.run-toggle-text', rb).textContent = open ? '收起' : '展开';
      return;
    }
    const sb = e.target.closest('[data-toggle-step]');
    if (sb) {
      const st = sb.closest('.step');
      const open = st.dataset.open !== 'true';
      st.dataset.open = String(open);
      $('.step-expand-text', sb).textContent = open ? '收起详情' : '展开详情';
      return;
    }
    const ab = e.target.closest('[data-approve]');
    if (ab) {
      const id = ab.dataset.id;
      const okd = ab.dataset.approve === '1';
      ab.disabled = true;
      decideApproval(id, okd);
      return;
    }
    // 预览：markdown 报告渲染后阅读
    const pv = e.target.closest('[data-art-view]');
    if (pv) { openArtifact(pv.dataset.artView); return; }
    const art = e.target.closest('[data-art]');
    if (art) window.open('/api/artifacts/' + art.dataset.art + '/download', '_blank');
  });

  /* Markdown 报告预览弹层 */
  async function openArtifact(aid) {
    let box = $('#art-modal');
    if (!box) {
      box = document.createElement('div');
      box.id = 'art-modal';
      box.className = 'art-modal';
      box.innerHTML = `<div class="art-backdrop"></div>
        <div class="art-panel" role="dialog" aria-modal="true" aria-label="报告预览">
          <div class="art-head">
            <div class="art-name" id="art-name">报告</div>
            <div class="art-acts">
              <a class="btn" id="art-dl"><svg class="ic"><use href="#i-download"></use></svg>下载</a>
              <button class="btn btn-icon" id="art-close" aria-label="关闭">
                <svg class="ic"><use href="#i-x"></use></svg></button>
            </div>
          </div>
          <div class="agent-text md art-body" id="art-body"></div>
        </div>`;
      el.thread.parentElement.appendChild(box);
      box.querySelector('.art-backdrop').addEventListener('click', closeArtifact);
      box.querySelector('#art-close').addEventListener('click', closeArtifact);
      document.addEventListener('keydown', (ev) => {
        if (ev.key === 'Escape') closeArtifact();
      });
    }
    const body = box.querySelector('#art-body');
    body.innerHTML = '<div class="skel"><div class="skel-bar"></div>'
      + '<span class="skel-txt">正在载入报告…</span></div>';
    box.classList.add('open');
    try {
      const r = await api('/artifacts/' + aid);
      const d = r.data;
      box.querySelector('#art-name').textContent = d.name || '报告';
      box.querySelector('#art-dl').setAttribute('href', '/api/artifacts/' + aid + '/download');
      body.innerHTML = md(d.content || '');
      body.scrollTop = 0;
    } catch (e) {
      body.innerHTML = '<p class="md-p" style="color:var(--c-fail)">载入失败：'
        + esc(e.message) + '</p>';
    }
  }

  function closeArtifact() {
    const box = $('#art-modal');
    if (box) box.classList.remove('open');
  }

  /* ---------------- 数据加载 ---------------- */
  async function loadAll() {
    try {
      const [sites, sessions, prefs, tools, sk] = await Promise.all([
        api('/sites'), api('/sessions'), api('/prefs'), api('/tools'), api('/skills'),
      ]);
      state.sites = sites.data || [];
      state.sessions = sessions.data || [];
      state.prefs = (prefs.data || {}).values || {};
      state.tools = tools.data || [];
      state.toolCount = state.tools.filter((t) =>
        !['report_write', 'save_memory'].includes(t.name)).length;
      state.skillsList = sk.data || [];
      renderSites(); renderSessions(); renderPrefs(); renderTools(); renderCounts();
    } catch (e) { setConn('down', 'API 异常'); toast('加载失败：' + e.message); }
  }

  async function loadSession(sid) {
    try {
      const r = await api('/sessions/' + sid + '/detail');
      const d = r.data;
      state.sessionId = sid;
      state.siteId = d.session.site_id;
      state.memory = d.memory;
      el.taskTitle.textContent = d.session.title;
      el.crumbSite.textContent = d.session.site_key;
      el.taskMeta.textContent = d.session.name + ' · ' + (d.session.model || 'scout-pro');
      el.scopeTag.hidden = false;
      $('span', el.scopeTag).textContent = d.session.domain;
      renderMessages(d.messages || []);
      renderMemory(); renderSites(); renderSessions(); renderCounts();
      // 若刷新时任务仍在跑，重连 SSE 从中断处续播
      try {
        const st = await api('/sessions/' + sid + '/status');
        if (st.data && st.data.running) {
          state.running = true;
          el.btnSend.disabled = true;
          setConn('busy', '执行中');
          el.statusPill.dataset.s = 'running';
          $('.sp-text', el.statusPill).textContent = '执行中';
          startStream(sid, st.data.run_id, 0);
          toast('检测到未完成的任务，已续接实时输出');
        }
      } catch (e) { /* 忽略 */ }
      return d;
    } catch (e) { toast('加载会话失败：' + e.message); }
  }

  /* ---------------- 打开站点 ---------------- */
  async function openTarget(forceNew) {
    const raw = el.targetInput.value.trim();
    if (!raw) { el.targetInput.focus(); return; }
    setConn('busy', '解析中');
    try {
      const r = await api('/sessions/resolve', {
        method: 'POST',
        body: { target: raw, reuse: !forceNew },
      });
      const sess = r.data.session;
      const mem = r.data.memory;
      const c = mem.counts || {};
      const total = c.fingerprint + c.endpoint + c.stack + c.findings;

      if (total > 0) {
        el.targetHint.textContent = `已复用该站点记忆：指纹 ${c.fingerprint} · 接口 ${c.endpoint} · 结论 ${c.findings}`;
        el.targetHint.dataset.s = 'hit';
      } else {
        el.targetHint.textContent = '首次测试该域名，将建立新的站点记忆';
        el.targetHint.dataset.s = 'new';
      }
      setConn('up', '已连接');
      await loadAll();
      await loadSession(sess.id);
      toast(total > 0
        ? `已接入 ${sess.name}，复用 ${total} 条历史记忆`
        : `已创建会话窗口 ${sess.name}`);
    } catch (e) {
      setConn('down', '异常');
      el.targetHint.textContent = '解析失败：' + e.message;
      el.targetHint.dataset.s = '';
      toast('打开失败：' + e.message);
    }
  }

  el.btnOpen.addEventListener('click', () => openTarget(false));
  el.targetInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); openTarget(false); }
  });

  el.siteList.addEventListener('click', async (e) => {
    const b = e.target.closest('[data-site]');
    if (!b) return;
    const id = +b.dataset.site;
    const sess = state.sessions.find((s) => s.site_id === id && s.status === 'active')
      || state.sessions.find((s) => s.site_id === id);
    if (sess) await loadSession(sess.id);
    else { state.siteId = id; toast('该站点暂无会话'); }
  });

  el.sessList.addEventListener('click', async (e) => {
    const b = e.target.closest('[data-sess]');
    if (b) await loadSession(+b.dataset.sess);
  });

  /* ---------------- 发送任务 ---------------- */
  /* ================= 流式渲染（SSE） ================= */
  let es = null;

  function closeStream() {
    if (es) { try { es.close(); } catch (e) {} es = null; }
    state.running = false;
  }

  /* 增量容器：工具轨迹，事件到达即追加 */
  function ensureTrace() {
    const sk = document.getElementById('live-skel');
    if (sk) sk.remove();
    let box = $('#live-trace');
    if (box) return box;
    box = document.createElement('div');
    box.className = 'run live';
    box.id = 'live-trace';
    box.dataset.open = 'true';
    box.innerHTML = `<div class="run-head">
        <svg class="ic run-head-ic"><use href="#i-terminal"></use></svg>
        <span class="run-title">tool trace</span>
        <span class="run-stats" id="live-stats"></span>
        <span class="live-tag" id="live-tag"><i></i>实时</span>
      </div><div class="run-body" id="live-body"></div>`;
    el.thread.appendChild(box);
    return box;
  }

  function upsertStep(rec) {
    const body = $('#live-body');
    if (!body) return;
    const key = rec.step + '|' + rec.tool;
    let row = body.querySelector(`[data-key="${CSS.escape(key)}"]`);
    if (!row) {
      const tmp = document.createElement('div');
      tmp.innerHTML = renderStep(Object.assign({}, rec, { status: 'running' }));
      row = tmp.firstElementChild;
      row.dataset.key = key;
      row.classList.add('fresh');
      body.appendChild(row);
    } else {
      const old = row.querySelector('.step-detail');
      const keep = old ? old.innerHTML : '';
      tmpSet(row, renderStep(rec));
      if (keep) {
        const d = row.querySelector('.step-detail');
        if (d) d.innerHTML = keep;
      }
    }
    refreshStats();
    scrollIfNear();
  }

  function tmpSet(node, html) {
    const t = document.createElement('div');
    t.innerHTML = html;
    node.replaceWith(t.firstElementChild);
  }

  function scrollIfNear() {
    const s = el.stageScroll;
    if (s.scrollHeight - s.scrollTop - s.clientHeight < 220) {
      s.scrollTop = s.scrollHeight;
    }
  }

  function addBlock(html, id) {
    const sk = document.getElementById('live-skel');
    if (sk) sk.remove();
    const t = document.createElement('div');
    t.innerHTML = html;
    const node = t.firstElementChild;
    if (id) node.id = id;
    el.thread.appendChild(node);
    scrollIfNear();
    return node;
  }

  function onEvent(e) {
    let d;
    try { d = JSON.parse(e.data); } catch (err) { return; }
    const p = d.payload || {};

    switch (e.type) {
      case 'site_linked':
        addBlock(linkBar(p), 'live-link');
        break;
      case 'agent_text': {
        // thinking=true 是决策过程中的中间自述，不是最终结论。
        // 两者都渲染 markdown，但视觉上必须能区分 ——
        // 否则用户会看到好几段以"## 结论"开头的重复内容。
        const th = !!p.thinking;
        // 兜底：过滤内部控制指令。曾出现模型把 system 里的预算提醒
        // 原样抄回正文的情况，用户界面不该看到 "[系统] 还剩 N 轮"。
        const raw = String(p.text || '')
          .replace(/\[系统\][^\n]*/g, '')
          .replace(/\n{3,}/g, '\n\n')
          .trim();
        if (!raw) break;
        addBlock(`<article class="msg msg-agent${th ? ' msg-think' : ''}">
          <div class="avatar-msg ai"><svg viewBox="0 0 24 24" width="15" height="15" fill="none"
            stroke="currentColor" stroke-width="2.1" stroke-linecap="round"><circle cx="11" cy="11" r="6.2"/><path d="M15.6 15.6L21 21"/></svg></div>
          <div class="msg-body">
            <div class="msg-head"><span class="msg-who">Scout</span>
              ${th ? '<span class="msg-role">决策中</span>' : ''}
              <span class="msg-time">${String(d.created_at || '').slice(11, 16)}</span></div>
            <div class="agent-text md">${md(raw)}</div>
          </div></article>`);
        break;
      }
      case 'plan':
        addBlock(renderPlan(p), 'live-plan');
        break;
      case 'step_start':
      case 'step_done':
      case 'step_failed':
        ensureTrace();
        upsertStep(p);
        break;
      case 'run_finished_steps': {
        const body = $('#live-body');
        if (body && p.steps) {
          // 终态快照，补齐失败重试展示
          p.steps.forEach((st) => upsertStep(st));
          refreshStats();
        }
        break;
      }
      case 'gate':
        addBlock(renderGate(p), 'live-gate');
        break;
      case 'artifact': {
        addBlock(`<article class="msg msg-agent">
          <div class="avatar-msg ai"><svg viewBox="0 0 24 24" width="15" height="15" fill="none"
            stroke="currentColor" stroke-width="2.1" stroke-linecap="round"><circle cx="11" cy="11" r="6.2"/><path d="M15.6 15.6L21 21"/></svg></div>
          <div class="msg-body">
            <div class="agent-text"><div class="mem-item" style="margin-top:0">
              <div class="mem-k">${esc(p.name)}</div>
              <div class="mem-meta"><span>${p.size} B</span>
                <button class="btn" style="height:22px;padding:0 7px;font-size:11px;margin-left:auto"
                  data-art-view="${p.id}"><svg class="ic"><use href="#i-eye"></use></svg>预览</button>
                <button class="btn" style="height:22px;padding:0 7px;font-size:11px"
                  data-art="${p.id}"><svg class="ic"><use href="#i-download"></use></svg>下载</button>
              </div></div></div>
          </div></article>`);
        break;
      }
      case 'autonomous_start': {
        const n = document.getElementById('live-skel');
        if (n) n.remove();
        const d = p || {};
        const chip = document.createElement('div');
        chip.className = 'round-chip';
        chip.id = 'live-round';
        chip.innerHTML = d.degraded
          ? `<svg class="ic"><use href="#i-alert"></use></svg>未配置 LLM，已降级为固定工作流`
          : `<svg class="ic"><use href="#i-ring"></use></svg>第 1 轮决策 · 可选工具 ${(d.tools || []).length} 个`;
        el.thread.appendChild(chip);
        break;
      }
      case 'llm_thinking': {
        const chip = document.getElementById('live-round');
        if (chip) {
          // 把剩余预算一起显示出来：用户改大了轮数/步数后能立刻看到效果，
          // 也能理解"为什么到这里就停了"。
          const left = [];
          if (p.rounds_left != null) left.push(`还剩 ${p.rounds_left} 轮`);
          if (p.steps_left != null) left.push(`${p.steps_left} 次调用`);
          chip.innerHTML = `<svg class="ic"><use href="#i-ring"></use></svg>`
            + `第 ${p.round} 轮决策中…`
            + (left.length ? ` · ${left.join(' / ')}` : '');
        }
        break;
      }
      case 'llm_error': {
        const chip = document.getElementById('live-round');
        if (chip) {
          chip.classList.add('done');
          chip.innerHTML = `<svg class="ic"><use href="#i-alert"></use></svg>${esc(p.note || '模型调用失败')}`;
        }
        toast('模型调用失败，已基于现有证据收尾');
        break;
      }
      case 'budget_exhausted': {
        // 预算耗尽不是错误，但结论可能是半程的 —— 必须让用户知道
        const chip = document.getElementById('live-round');
        const txt = `已达深度上限（${p.rounds}/${p.max_rounds} 轮 · `
                  + `${p.steps}/${p.max_steps} 次调用）`;
        if (chip) {
          chip.classList.add('done');
          chip.innerHTML = `<svg class="ic"><use href="#i-clock"></use></svg>`
            + `探索深度已用尽`;
        }
        toast(txt + '，可在「账号与 API」调大后重试', 5200);
        break;
      }
      case 'verdict': {
        const v = p || {};
        const ic = v.verdict === 'AFFECTED' ? 'i-alert'
                 : v.verdict === 'LIKELY_NOT_AFFECTED' ? 'i-check' : 'i-clock';
        const n = v.evidence_count || 0;
        const intel = (v.intel || []).map((x) =>
          `${x.cve} CVSS ${x.cvss}${x.kev ? ' KEV' : ''}`).join(' · ');
        const line = document.createElement('div');
        line.className = 'verdict-line';
        line.dataset.v = v.verdict || 'INCONCLUSIVE';
        // 判定理由已由模型正文完整给出，正文里不重复展示；
        // 但仍要可查，所以挂到 title 上供悬停查看。
        if (v.reason) line.title = String(v.reason);
        // 判定理由已由模型正文（或降级摘要）完整给出，这里只放判定标签与证据计数，
        // 否则同一句话会在气泡和结论条里各出现一次。
        line.innerHTML = `<svg class="ic"><use href="#${ic}"></use></svg>
          <div style="flex:1;min-width:0">
            <div><b>${esc(v.label || '需人工确认')}</b></div>
            <div class="verdict-evi">证据 ${n} 项${intel ? ' · 情报: ' + esc(intel) : ''}${
              (v.errors || []).length ? ' · 失败 ' + v.errors.length + ' 项' : ''}</div>
          </div>`;
        el.thread.appendChild(line);
        const chip = document.getElementById('live-round');
        if (chip) { chip.classList.add('done'); }
        break;
      }
      case 'run_done':
      case 'run_failed':
        finishRun(p);
        break;
    }
  }

  function refreshStats() {
    const body = $('#live-body');
    const s = $('#live-stats');
    if (!body || !s) return;
    const rows = $$('.step', body);
    const done = rows.filter((r) => r.dataset.s === 'done').length;
    const fail = rows.filter((r) => r.dataset.s === 'fail').length;
    const wait = rows.filter((r) => r.dataset.s === 'wait').length;
    s.innerHTML = `<span class="rs" data-s="done"><svg class="ic"><use href="#i-check"></use></svg>${done} 成功</span>`
      + (fail ? `<span class="rs" data-s="fail"><svg class="ic"><use href="#i-x"></use></svg>${fail} 失败</span>` : '')
      + (wait ? `<span class="rs" data-s="wait"><svg class="ic"><use href="#i-clock"></use></svg>${wait} 待确认</span>` : '');
  }

  function finishRun(p) {
    closeStream();
    const tag = $('#live-tag');
    if (tag) tag.classList.add('done');
    refreshStats();
    el.btnSend.disabled = false;
    setConn('up', '已连接');
    el.statusPill.dataset.s = 'running';
    $('.sp-text', el.statusPill).textContent = '就绪';
    loadAll().then(() => {
      if (state.sessionId) refreshMemoryAndHeader(state.sessionId);
    });
    if (p.status === 'awaiting_approval') toast('检测到写入类操作，已挂起等待确认');
    else if (p.verdict) {
      toast(`${p.label || '已完成'} · ${p.tools_used || 0} 次工具调用`
            + (p.degraded ? '（固定流程）' : `（${p.rounds || 0} 轮自主决策）`));
    } else if (p.reused_memory) toast(`执行完成，共 ${p.done || 0} 步成功`);
    else if (p.status === 'done') toast('执行完成，报告已生成');
    else if (p.status === 'failed') toast('执行失败：' + (p.error || ''));
  }

  async function refreshMemoryAndHeader(sid) {
    try {
      const r = await api('/sessions/' + sid + '/detail');
      state.memory = r.data.memory;
      renderMemory();
      renderCounts();
    } catch (e) { /* 忽略 */ }
  }

  function startStream(sid, runId, afterId) {
    closeStream();
    const q = '/sessions/' + sid + '/stream?run_id=' + encodeURIComponent(runId)
            + '&after=' + (afterId || 0) + '&timeout=900';
    es = new EventSource('/api' + q);
    ['site_linked', 'agent_text', 'plan', 'step_start', 'step_done', 'step_failed',
     'run_finished_steps', 'gate', 'artifact', 'run_done', 'run_failed',
     'autonomous_start', 'llm_thinking', 'llm_error', 'verdict',
     'budget_exhausted'].forEach((t) => {
      es.addEventListener(t, onEvent);
    });
    es.addEventListener('error', () => {
      // EventSource 自带重连；这里只在明确关闭时兜底
      if (es && es.readyState === EventSource.CLOSED) {
        closeStream();
        el.btnSend.disabled = false;
      }
    });
    return es;
  }

  /* ---------------- 模式切换（自主决策 / 固定流程） ---------------- */
  function setMode(m) {
    state.mode = (m === 'workflow') ? 'workflow' : 'autonomous';
    $$('#mode-switch .ms-btn').forEach((b) => {
      const on = b.dataset.mode === state.mode;
      b.classList.toggle('is-on', on);
      b.setAttribute('aria-checked', String(on));
    });
  }
  $$('#mode-switch .ms-btn').forEach((b) =>
    b.addEventListener('click', () => {
      setMode(b.dataset.mode);
      toast(state.mode === 'autonomous'
        ? '自主决策：由模型自己选择工具与顺序'
        : '固定流程：按预设工作流依次执行');
    }));

  async function send() {
    const text = el.input.value.trim();
    if (!text) return;
    if (!state.sessionId) { toast('请先在左侧输入目标域名'); el.targetInput.focus(); return; }
    if (state.running) { toast('当前任务仍在执行'); return; }

    el.input.value = '';
    autosize();
    state.running = true;
    el.btnSend.disabled = true;
    setConn('busy', '执行中');
    el.statusPill.dataset.s = 'running';
    $('.sp-text', el.statusPill).textContent = '执行中';

    // 清掉上一次的实时块与历史对话，让本次执行从干净状态开始渲染
    el.thread.innerHTML = '';
    ['live-trace', 'live-link', 'live-plan', 'live-gate'].forEach((i) => {
      const n = document.getElementById(i); if (n) n.remove();
    });
    const sk = document.createElement('div');
    sk.className = 'skel'; sk.id = 'live-skel';
    sk.innerHTML = `<div class="skel-bar"></div><span class="skel-txt">${
      state.mode === 'autonomous' ? '模型正在规划下一步…' : 'Scout 正在分析…'}</span>`;
    el.thread.appendChild(sk);

    // 模式标识条
    const note = document.createElement('div');
    note.className = 'mode-note';
    note.dataset.m = state.mode === 'autonomous' ? 'auto' : 'flow';
    note.innerHTML = state.mode === 'autonomous'
      ? `<svg class="ic"><use href="#i-spark"></use></svg><span><b>自主决策模式</b>
         —— 模型根据每次工具返回的结果自己决定下一步查什么，可调 <b>${state.toolCount || 15}</b> 个工具。</span>`
      : `<svg class="ic"><use href="#i-list"></use></svg><span><b>固定流程模式</b>
         —— 按预设工作流依次执行，路径确定、结果可预期。</span>`;
    el.thread.appendChild(note);

    addBlock(`<article class="msg msg-user">
      <div class="avatar-msg me">AN</div>
      <div class="msg-body">
        <div class="msg-head"><span class="msg-who">analyst</span>
          <span class="msg-role">安全运维</span>
          <span class="msg-time">${new Date().toTimeString().slice(0, 5)}</span></div>
        <div class="bubble-user">${esc(text)}</div>
      </div></article>`);

    const auto = state.mode === 'autonomous';
    try {
      const r = await api('/sessions/' + state.sessionId + (auto ? '/autonomous' : '/run'),
                          { method: 'POST', body: { input: text } });
      const runId = r.data.run_id || r.data.status;
      startStream(state.sessionId, runId, 0);
    } catch (e) {
      toast('启动失败：' + e.message);
      state.running = false;
      el.btnSend.disabled = false;
      setConn('up', '已连接');
      el.statusPill.dataset.s = 'running';
      $('.sp-text', el.statusPill).textContent = '就绪';
    }
  }

  el.btnSend.addEventListener('click', send);
  el.input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); }
  });
  function autosize() {
    el.input.style.height = 'auto';
    el.input.style.height = Math.min(el.input.scrollHeight, 168) + 'px';
  }
  el.input.addEventListener('input', autosize);

  el.btnSkill.addEventListener('click', () => {
    const names = state.skillsList.map((s) => s.name).join('、');
    toast('内置技能：' + names);
  });

  /* ---------------- 审批 ---------------- */
  async function decideApproval(id, okd) {
    setConn('busy', '执行审批');
    try {
      const r = await api('/approvals/' + id + '/decide', { method: 'POST', body: { approved: okd } });
      const runId = (r.data || {}).run_id;
      // 审批后继续的动作同样流式展示
      if (runId) {
        const g = document.getElementById('live-gate');
        if (g) g.remove();
        startStream(state.sessionId, runId, 0);
      }
      await refreshMemoryAndHeader(state.sessionId);
      toast(okd ? '已批准，正在执行并回收现场' : '已拒绝该操作');
    } catch (e) { toast('审批失败：' + e.message); }
    finally { if (!state.running) setConn('up', '已连接'); }
  }

  /* ---------------- 右栏开关 ---------------- */
  function setRight(open) {
    state.rightOpen = open;
    el.body.classList.toggle('no-right', !open);
    el.reopenRight.hidden = open;
  }
  el.btnCloseRight.addEventListener('click', () => setRight(false));
  el.btnOpenRight.addEventListener('click', () => setRight(true));
  el.reopenRight.addEventListener('click', () => setRight(true));

  el.btnForget.addEventListener('click', async () => {
    if (!state.siteId) { toast('未选择站点'); return; }
    const m = state.memory; const c = (m && m.counts) || {};
    const total = Object.values(c).reduce((a, b) => a + b, 0);
    if (!total) { toast('该站点暂无记忆可清空'); return; }
    if (!confirm(`确认清空 ${m.site.site_key} 的全部站点记忆（${total} 条）？\n长期用户偏好不受影响。`)) return;
    try {
      await api('/sites/' + state.siteId + '/memory', { method: 'DELETE' });
      await loadSession(state.sessionId);
      toast('已清空该站点记忆');
    } catch (e) { toast('清空失败：' + e.message); }
  });

  /* ---------------- 左侧 tab ---------------- */
  $$('.nav-item[data-tab]').forEach((b) => b.addEventListener('click', () => {
    $$('.nav-item[data-tab]').forEach((x) => x.classList.remove('is-active'));
    b.classList.add('is-active');
    const t = b.dataset.tab;
    el.blkSites.classList.toggle('hidden', t !== 'sites');
    el.blkSess.classList.toggle('hidden', t !== 'sessions');
    el.blkPrefs.classList.toggle('hidden', t !== 'prefs');
    const acct = $('#blk-account');
    if (acct) acct.classList.toggle('hidden', t !== 'account');
    el.blkTools.classList.toggle('hidden', t !== 'tools');
  }));

  $('#btn-settings')?.addEventListener('click', () => {
    const b = $('.nav-item[data-tab="account"]');
    if (b) b.click();
  });

  /* ---------------- 启动 ---------------- */
  (async function boot() {
    try {
      const h = await api('/health');
      setConn('up', h.data.llm_configured ? '已连接 · LLM' : '已连接');
      await loadAll();
      // 自动接入最近会话
      const last = state.sessions.find((s) => s.status === 'active') || state.sessions[0];
      if (last) { await loadSession(last.id); el.targetInput.value = last.domain; }
    } catch (e) {
      setConn('down', '连接失败');
      toast('无法连接后端：' + e.message);
    }
  })();
})();