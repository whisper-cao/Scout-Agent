/* ==========================================================================
   md.js —— 轻量 Markdown 渲染器（自包含，无外部依赖）

   为什么自己写而不是引 marked / CDN：
   - 这是部署在内网的安全工具，不能依赖外部 CDN 可达性
   - AI 输出不可信，必须严格「先转义、再解析」，杜绝 HTML 注入

   支持：标题、有序/无序/任务列表（可嵌套）、引用、分割线、代码块、行内代码、
        粗体、斜体、删除线、链接、表格、自动链接、段落与硬换行
   ========================================================================== */
(function (g) {
  'use strict';

  var ESC_MAP = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return ESC_MAP[c]; });
  }

  /* 控制字符：防止 "java&#9;script:" 这类协议绕过 */
  var CONTROL_RE = /[\x00-\x1f\x7f]/g;

  /* URL 白名单：只放行可导航协议，杜绝 javascript: / data: 伪协议 */
  function safeUrl(u) {
    var s = String(u == null ? '' : u).replace(CONTROL_RE, '').trim();
    if (/^(https?:\/\/|mailto:)/i.test(s)) return s;
    if (/^[#\/]/.test(s)) return s;
    return '';
  }

  /* ---------- 行内解析（输入必须已转义） ---------- */
  var PH = String.fromCharCode(1);   // 占位符，正常文本不会出现该字符

  function inline(escaped) {
    var codes = [];
    // 1) 先摘出行内代码，其内部不再做任何解析
    var s = escaped.replace(/`([^`\n]+)`/g, function (_, c) {
      codes.push(c);
      return PH + (codes.length - 1) + PH;
    });

    // 2) 图片：仅允许同源相对路径，远程图降级为纯文本（防外连与跟踪）
    s = s.replace(/!\[([^\]]*)\]\(([^)\s]+)[^)]*\)/g, function (_, alt, url) {
      var u = safeUrl(url);
      return (u && !/^(https?:)?\/\//i.test(u))
        ? '<img src="' + esc(u) + '" alt="' + alt + '" loading="lazy">'
        : alt;
    });

    // 3) 链接
    s = s.replace(/\[([^\]]+)\]\(([^)\s]+)[^)]*\)/g, function (_, txt, url) {
      var u = safeUrl(url);
      return u
        ? '<a href="' + esc(u) + '" target="_blank" rel="noopener noreferrer">' + txt + '</a>'
        : txt;
    });

    // 4) 裸链接自动识别
    s = s.replace(/(^|[\s(])((?:https?:\/\/)[^\s<>"')]+)/g, function (_, pre, url) {
      return pre + '<a href="' + esc(url) + '" target="_blank" rel="noopener noreferrer">' + esc(url) + '</a>';
    });

    // 5) 强调
    s = s.replace(/\*\*\*([^*\n]+)\*\*\*/g, '<strong><em>$1</em></strong>');
    s = s.replace(/\*\*([^*\n]+)\*\*/g, '<strong>$1</strong>');
    s = s.replace(/(^|[^*\w])\*([^*\n]+)\*(?![*\w])/g, '$1<em>$2</em>');
    s = s.replace(/(^|[^_\w])__([^_\n]+)__(?![_\w])/g, '$1<strong>$2</strong>');
    s = s.replace(/(^|[^_\w])_([^_\n]+)_(?![_\w])/g, '$1<em>$2</em>');
    s = s.replace(/~~([^~\n]+)~~/g, '<del>$1</del>');

    // 6) 硬换行（行尾两空格）
    s = s.replace(/ {2,}\n/g, '<br>\n');

    // 7) 还原行内代码：PH 总是成对出现，奇数段是占位索引
    var seg = s.split(PH);
    var rebuilt = '';
    for (var k = 0; k < seg.length; k++) {
      if (k % 2 === 1 && /^\d+$/.test(seg[k])) {
        var ci = +seg[k];
        rebuilt += '<code>' + (codes[ci] || '') + '</code>';
      } else {
        rebuilt += seg[k];
      }
    }
    return rebuilt;
  }

  /* ---------- 块级解析 ---------- */
  var RE_H = /^(#{1,6})\s+(.*)$/;
  var RE_UL = /^(\s*)([-*+])\s+(.*)$/;
  var RE_OL = /^(\s*)(\d{1,3})[.)]\s+(.*)$/;
  var RE_HR = /^\s*([-*_])(\s*\1){2,}\s*$/;
  var RE_QUOTE = /^\s*>\s?(.*)$/;
  var RE_FENCE = /^\s*(```+|~~~+)\s*([A-Za-z0-9_+-]*)\s*$/;

  function indentOf(s) { var m = s.match(/^\s*/); return m ? m[0].replace(/\t/g, '  ').length : 0; }
  function isListLine(l) { return RE_OL.test(l) || RE_UL.test(l); }

  /* 递归解析列表（支持嵌套 + 任务列表）
     注意：i 必须通过 st.i 传递并原地推进。若按值传参，render 里的 i 不会前进，
     外层 while 会反复解析同一行，导致字符串无限累积直至 OOM。 */
  function parseList(lines, st, baseIndent) {
    var i = st.i;
    var ordered = RE_OL.test(lines[i]);
    var tag = ordered ? 'ol' : 'ul';
    var open = '<' + tag;
    if (ordered) {
      var n = parseInt(lines[i].match(RE_OL)[2], 10);
      if (n !== 1) open += ' start="' + n + '"';
    }
    open += '>';
    var close = '</' + tag + '>';
    var out = open;
    var guard = 0;

    while (i < lines.length) {
      if (++guard > 20000) break;      // 防御：任何解析异常都不允许死循环
      var line = lines[i];

      if (!line.trim()) {
        var j = i + 1;
        while (j < lines.length && !lines[j].trim()) j++;
        if (j >= lines.length) { i = j; break; }
        if (!isListLine(lines[j])) break;
        if (indentOf(lines[j]) < baseIndent) break;
        i = j;
        continue;
      }

      if (!isListLine(line)) {
        // 缩进更深且已有条目 → 视为上一条的 lazy continuation
        if (indentOf(line) > baseIndent && /<li>[\s\S]*?<\/li>$/.test(out)) {
          out = out.replace(/<\/li>$/, '<br>' + inline(esc(line.trim())) + '</li>');
          i++;
          continue;
        }
        break;
      }

      var isO = RE_OL.test(line);
      var ind = indentOf(line);

      if (ind < baseIndent) break;

      if (ind > baseIndent) {
        st.i = i;                        // 必须先同步，否则子调用会从列表起点重来
        var before = i;
        var sub = parseList(lines, st, ind);
        i = st.i;
        if (i <= before) { i = before + 1; break; }   // 子解析没前进 → 兜底退出
        // 把子列表塞进上一个 <li> 内部
        var lastLi = out.lastIndexOf('<li>');
        var endLi = lastLi >= 0 ? out.indexOf('</li>', lastLi) : -1;
        if (lastLi >= 0 && endLi >= 0) {
          out = out.slice(0, endLi) + sub.html + out.slice(endLi);
        } else {
          out += sub.html;
        }
        continue;
      }

      if (isO !== ordered) break;

      var content = isO ? line.match(RE_OL)[3] : line.match(RE_UL)[3];
      var tm = content.match(/^\[([ xX])\]\s+(.*)$/);
      if (tm) {
        // 任务列表的 checkbox 由代码生成，不能再交给 inline() 转义，
        // 只对用户文本部分做解析
        var checked = tm[1].toLowerCase() === 'x' ? ' checked' : '';
        out += '<li class="md-task"><input type="checkbox" disabled' + checked +
               '><span>' + inline(esc(tm[2])) + '</span></li>';
        i++;
        continue;
      }
      out += '<li>' + inline(esc(content)) + '</li>';
      i++;
    }

    st.i = i;
    return { html: out + close, i: i };
  }

  function isTableSep(line) {
    return line.indexOf('-') >= 0 && /^[|\s:|-]+$/.test(line);
  }

  function splitRow(line) {
    var s = line.trim().replace(/^\|/, '').replace(/\|$/, '');
    var cells = [], cur = '', inCode = false;
    for (var i = 0; i < s.length; i++) {
      var ch = s[i];
      if (ch === '`') inCode = !inCode;
      if (ch === '|' && !inCode) { cells.push(cur); cur = ''; continue; }
      cur += ch;
    }
    cells.push(cur);
    return cells.map(function (c) { return c.trim(); });
  }

  function alignOf(c) {
    var l = c.charAt(0) === ':';
    var r = c.charAt(c.length - 1) === ':';
    if (l && r) return ' style="text-align:center"';
    if (r) return ' style="text-align:right"';
    return '';
  }

  function render(md) {
    if (md == null) return '';
    var raw = String(md).replace(/\r\n?/g, '\n');
    if (!raw.trim()) return '';

    var lines = raw.split('\n');
    var out = [], i = 0;
    var budget = lines.length + 200;   // 总步数上限：任何解析异常都不允许死循环

    while (i < lines.length) {
      if (--budget < 0) break;
      var line = lines[i];

      // 代码块
      var f = line.match(RE_FENCE);
      if (f) {
        var fence = f[1], lang = f[2] || '';
        var buf = [];
        i++;
        while (i < lines.length && lines[i].trim().indexOf(fence[0]) !== 0) { buf.push(lines[i]); i++; }
        i++;
        out.push('<pre class="md-pre"' + (lang ? ' data-lang="' + esc(lang) + '"' : '') +
                 '><code>' + esc(buf.join('\n')) + '</code></pre>');
        continue;
      }

      if (!line.trim()) { i++; continue; }
      if (RE_HR.test(line)) { out.push('<hr class="md-hr">'); i++; continue; }

      // 标题
      var h = line.match(RE_H);
      if (h) {
        var lv = h[1].length;
        out.push('<h' + lv + ' class="md-h md-h' + lv + '">' +
                 inline(esc(h[2].replace(/\s+#+\s*$/, ''))) + '</h' + lv + '>');
        i++; continue;
      }

      // 表格
      if (line.indexOf('|') >= 0 && i + 1 < lines.length && isTableSep(lines[i + 1])) {
        var head = splitRow(line);
        var aligns = splitRow(lines[i + 1]).map(alignOf);
        i += 2;
        var t = '<div class="md-table-wrap"><table class="md-table"><thead><tr>';
        head.forEach(function (c, k) { t += '<th' + (aligns[k] || '') + '>' + inline(esc(c)) + '</th>'; });
        t += '</tr></thead><tbody>';
        while (i < lines.length && lines[i].trim() && lines[i].indexOf('|') >= 0) {
          var row = splitRow(lines[i]);
          t += '<tr>';
          for (var k = 0; k < head.length; k++) {
            t += '<td' + (aligns[k] || '') + '>' + inline(esc(row[k] || '')) + '</td>';
          }
          t += '</tr>';
          i++;
        }
        out.push(t + '</tbody></table></div>');
        continue;
      }

      // 引用
      if (RE_QUOTE.test(line)) {
        var q = [];
        while (i < lines.length && RE_QUOTE.test(lines[i])) { q.push(lines[i].match(RE_QUOTE)[1]); i++; }
        out.push('<blockquote class="md-quote">' + render(q.join('\n')) + '</blockquote>');
        continue;
      }

      // 列表（用 st 传递索引，保证 i 原地推进）
      if (isListLine(line)) {
        var lr = parseList(lines, { i: i }, indentOf(line));
        out.push(lr.html);
        i = lr.i;
        continue;
      }

      // 段落
      var para = [line];
      i++;
      while (i < lines.length && lines[i].trim() &&
             !RE_H.test(lines[i]) && !RE_HR.test(lines[i]) &&
             !RE_FENCE.test(lines[i]) && !RE_QUOTE.test(lines[i]) &&
             !isListLine(lines[i]) &&
             !(lines[i].indexOf('|') >= 0 && i + 1 < lines.length && isTableSep(lines[i + 1]))) {
        para.push(lines[i]); i++;
      }
      out.push('<p class="md-p">' + inline(esc(para.join('\n'))).replace(/\n/g, '<br>\n') + '</p>');
    }

    return out.join('');
  }

  /* 表格单元格内的换行要保留为 <br>，这里补一个带换行的表格解析入口 */
  g.ScoutMD = { render: render, escape: esc, inline: inline, safeUrl: safeUrl };
})(window);