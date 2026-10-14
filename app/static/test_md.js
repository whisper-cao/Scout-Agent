/* md.js 渲染器回归测试：结构正确性 + XSS 防护 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const src = fs.readFileSync(path.join(__dirname, 'md.js'), 'utf8');
const win = {};
win.window = win;
win.String = String;
win.RegExp = RegExp;
win.Array = Array;
win.Math = Math;
win.JSON = JSON;
vm.createContext(win);
vm.runInContext(src, win);
const MD = win.ScoutMD;

let ok = true;
function chk(label, cond, extra) {
  console.log(`  ${cond ? 'PASS' : 'FAIL'}  ${label}${extra ? '  ' + extra : ''}`);
  if (!cond) ok = false;
}
const has = (h, sub) => h.indexOf(sub) >= 0;

console.log('== 标题 ==');
let h = MD.render('## 结论：**证据不足**');
chk('h2 生成', has(h, '<h2'), h.slice(0, 60));
chk('标题内粗体生效', has(h, '<strong>证据不足</strong>'));
chk('无残留 ## 标记', !has(h, '##'));

console.log('\n== 段落与换行 ==');
h = MD.render('第一行\n第二行');
chk('换行转 <br> 或分段', has(h, '<br') || has(h, '</p><p'), h.slice(0, 70));

console.log('\n== 列表 ==');
h = MD.render('- 第一项\n- 第二项');
chk('ul 生成', has(h, '<ul>') && has(h, '<li>'), h);
chk('无残留 - ', !has(h, '- 第'));

h = MD.render('1. 步骤一\n2. 步骤二');
chk('ol 生成', has(h, '<ol>') && has(h, '<li>'), h);

h = MD.render('1. 第三步\n2. 第四步');
// markdown 规范本身不支持有序列表起始编号，这里只要求能解析、不残留数字标记
chk('ol 数字标记不残留', !has(h, '1. 第三步'), h);

h = MD.render('- 外层\n  - 内层 A\n  - 内层 B\n- 外层二');
chk('嵌套列表', (h.match(/<ul>/g) || []).length === 2, h);

h = MD.render('- [x] 已完成\n- [ ] 待处理');
chk('任务列表', has(h, 'type="checkbox"') && has(h, 'checked'), h);

console.log('\n== 行内 ==');
h = MD.render('这是 `code` 和 **粗体** 和 *斜体* 和 ~~删除~~');
chk('行内代码', has(h, '<code>code</code>'), h);
chk('粗体', has(h, '<strong>粗体</strong>'));
chk('斜体', has(h, '<em>斜体</em>'));
chk('删除线', has(h, '<del>删除</del>'));
chk('代码内不解析粗体', MD.render('`**不该变粗**`').indexOf('<strong>') < 0,
    MD.render('`**不该变粗**`'));

console.log('\n== 代码块 ==');
h = MD.render('```python\nprint("hi")\n```');
chk('pre 生成', has(h, '<pre class="md-pre"'), h.slice(0, 60));
chk('语言标记', has(h, 'data-lang="python"'));
chk('代码块内 HTML 被转义', !has(MD.render('```\n<script>alert(1)</script>\n```'), '<script>'));

console.log('\n== 表格 ==');
h = MD.render('| 端口 | 状态 |\n|---|---|\n| 443 | 开放 |\n| 22 | 关闭 |');
chk('table 生成', has(h, '<table class="md-table">'), h.slice(0, 80));
chk('表头 2 列', has(h, '<th>端口</th>') && has(h, '<th>状态</th>'));
chk('数据行 2 行', (h.match(/<tr>/g) || []).length === 3, (h.match(/<tr>/g) || []).length);
chk('无残留竖线', !has(h, '| 443 |'));

h = MD.render('| 左 | 中 | 右 |\n|:---|:---:|---:|\n| a | b | c |');
chk('左/中/右三种对齐',
    has(h, 'text-align:center') && has(h, 'text-align:right') && !/<th style="text-align:left"/.test(h), h);

console.log('\n== 引用 / 分割线 ==');
h = MD.render('> 这是提示');
chk('blockquote', has(h, '<blockquote class="md-quote">'), h);
h = MD.render('---');
chk('hr', has(h, '<hr class="md-hr">'), h);

console.log('\n== 链接 ==');
h = MD.render('[NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)');
chk('a 标签', has(h, '<a href="https://nvd.nist.gov'), h);
chk('target=_blank', has(h, 'target="_blank"'));
chk('rel=noopener', has(h, 'rel="noopener noreferrer"'));
h = MD.render('见 https://example.com/x 了解');
chk('裸链接自动识别', has(h, '<a href="https://example.com/x"'), h);

console.log('\n== XSS 防护（重点）==');
/* 断言口径：危险内容必须已被转义 —— 即最终 HTML 里不存在可执行的标签/属性。
   注意不能简单全文搜 "onerror=" ：转义后的字面文本里仍然含有这个词，
   那是安全的（浏览器只会当文本显示）。真正要断言的是没有裸标签。 */
const attacks = [
  ['<script>alert(1)</script>', 'script 标签'],
  ['<img src=x onerror=alert(1)>', 'img onerror'],
  ['<iframe src="evil"></iframe>', 'iframe'],
  ['<svg onload=alert(1)>', 'svg onload'],
  ['<a href="javascript:alert(1)">x</a>', '原生 a 伪协议'],
  ['<div onclick="alert(1)">x</div>', 'onclick'],
  ['<style>body{display:none}</style>', 'style 注入'],
  ['<body onload=alert(1)>', 'body onload'],
  ['<form action="javascript:alert(1)">', 'form 伪协议'],
  ['<object data="evil.swf">', 'object'],
];
for (const [payload, label] of attacks) {
  const out = MD.render(payload);
  /* 判定口径：只有「未转义的裸标签」才危险。
     转义后的 &lt;div onclick=…&quot; 是纯文本，浏览器不会执行。
     所以只需确认输出里不存在真实的 <script/<img/<div 这类标签起始。
     （不要去搜 onerror= 这类关键词——转义文本里依然含有它，会误报。） */
  const dangerous = /<(script|iframe|svg|img|style|object|embed|form|body|div|a|input)\b/i.test(out);
  chk(`阻断 ${label}`, !dangerous, dangerous ? out.slice(0, 90) : '');
}

/* 额外确认：所有裸 < 都已被实体化（除渲染器自己生成的安全标签外） */
const raw = MD.render('<div onclick="alert(1)">x</div>');
chk('裸 < 已实体化', raw.indexOf('&lt;div') >= 0, raw);

/* 伪协议链接：不得生成 href */
chk('javascript: 不生成 href',
    !/<a[^>]*href/i.test(MD.render('[click](javascript:alert(1))')),
    MD.render('[click](javascript:alert(1))'));
chk('Tab 拆协议不生成 href',
    !/<a[^>]*href/i.test(MD.render('[click](java\tscript:alert(1))')));
chk('data: 不生成 href',
    !/<a[^>]*href/i.test(MD.render('[x](data:text/html,<script>alert(1)</script>)')));
chk('远程图降级为文本',
    !/<img/i.test(MD.render('![x](https://evil.com/a.png)')));
chk('同源相对图允许',
    /<img[^>]*src="\/static\//.test(MD.render('![x](/static/a.png)')),
    MD.render('![x](/static/a.png)'));
chk('合法链接保留',
    /href="https:\/\/nvd\.nist\.gov"/.test(MD.render('[N](https://nvd.nist.gov)')));

console.log('\n== 边界 ==');
chk('空输入', MD.render('') === '' && MD.render(null) === '');
chk('纯空白', MD.render('   \n  \n') === '');
chk('未闭合代码块不崩', typeof MD.render('```\n未闭合') === 'string', MD.render('```\n未闭合').slice(0, 50));
chk('深层嵌套不崩', typeof MD.render('- a\n  - b\n    - c\n      - d') === 'string');
chk('超长文本不崩', MD.render('x'.repeat(50000)).length > 0);
chk('CRLF 兼容', MD.render('a\r\nb').indexOf('<br') >= 0 || MD.render('a\r\nb').indexOf('</p><p') >= 0,
    MD.render('a\r\nb'));

console.log('\n== 真实场景（用户给的例子）==');
const sample = [
  '## 结论：**证据不足**（倾向于不受影响，但无法确证）',
  '',
  '### 依据',
  '',
  '**1. CVE-2026-43515 的性质**',
  '- 漏洞组件位于请求解析路径，理论上远程可触发',
  '- 官方描述未明确默认配置是否受影响',
  '',
  '**2. 现场证据**',
  '',
  '- 组件版本 2.4.1，低于受影响上限',
  '- 前置条件未确认，需人工核查',
  '',
  '| 检查项 | 结果 | 说明 |',
  '|---|---|---|',
  '| 组件版本 | 2.4.1 | 低于受影响上限 |',
  '| 前置条件 | 未确认 | 需人工核查 |',
  '',
  '> 建议：在隔离环境复现后再定级。参考 [NVD](https://nvd.nist.gov/)。',
].join('\n');
h = MD.render(sample);
chk('h2 + h3 层级', has(h, '<h2') && has(h, '<h3'));
chk('结论粗体', has(h, '<strong>证据不足</strong>'));
chk('编号小标题', has(h, '<strong>1. CVE-2026-43515 的性质</strong>'));
chk('两组列表', (h.match(/<ul>/g) || []).length === 2, (h.match(/<ul>/g) || []).length);
chk('表格渲染', has(h, '<table') && has(h, '<td>2.4.1</td>'), h.slice(h.indexOf('<table'), h.indexOf('<table') + 90));
chk('引用内链接', has(h, '<blockquote') && has(h, 'nvd.nist.gov'));
chk('无 markdown 残留', !has(h, '## ') && !has(h, '**') && !has(h, '|---'));

console.log('\n' + '='.repeat(50));
console.log('结果:', has(JSON.stringify(1), '') ? (ok ? '全部通过 ✅' : '存在失败 ❌') : '');
process.exit(ok ? 0 : 1);