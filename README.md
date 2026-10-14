<div align="center">

# Scout Agent

**LLM 驱动的自主决策安全测试 Agent**

用自然语言下达任务，Agent 自行决定调用哪些工具、查到什么程度、什么时候收尾。
每一步推理与工具调用实时可见。

仅用于**已获授权**的资产。

</div>

---

## 它做什么

> 以下为真实运行记录的节选（略作缩写）：

```
你：评估 example.com 的技术栈，并核查 CVE-2022-22965 是否受影响

Scout：先摸清目标技术栈与暴露面，再核查 Spring4Shell 的前置条件。
      指纹显示这是 Cloudflare 边缘返回的静态示例页…
      前置条件探针返回 NOT_JDK9，但这条结果可能被边缘层污染，需要交叉验证…
      所有路径响应体长度均为 577 字节、同一 SHA256，说明是 CDN 兜底页…

      ## 结论
      **证据不足** —— 无法判定是否受影响；关键在于源站是否可达。
```

模型自己排了取证顺序、自己发现了 CDN 缓存可能污染探针结果、
自己做了 SHA256 交叉验证，最后诚实地说「证据不足」而不是硬下结论。

## 核心特性

| | |
|---|---|
| **自主决策** | ReAct 循环，LLM 自行选择工具与参数，无预设编排。未配置模型时自动降级为固定流程，功能不缺失 |
| **实时渲染** | SSE 推送，执行过程逐行渲染；断线可续传，刷新页面自动回放 |
| **站点记忆** | 按归一化域名隔离。`www.a.com` 与 `a.com` 共享记忆，其他子域独立 |
| **CVE 情报** | 接入 NVD / CIRCL / OSV，含 CVSS、CWE、受影响版本、**CISA KEV** 标记 |
| **安全闸门** | 写入类操作强制人工审批，Agent 无法自行放行 |
| **自带 Markdown 渲染** | 自研渲染器，不依赖任何 CDN |
| **零外部前端依赖** | 原生 JS，无构建步骤 |

## 安全边界

这套东西**不是**用来乱扫的，设计上有明确约束：

- **只读为主** —— 默认仅 GET / HEAD / OPTIONS；写入类方法（PUT/POST/DELETE）被拦截并转入审批队列
- **不投递利用载荷** —— 不做拒绝服务、不修改业务数据、不做子域爆破、不做全端口扫描
- **CVE 只查元数据** —— CVSS / CWE / 受影响版本 / KEV 标记。**不下载、不解析、不执行任何利用代码**；「是否存在公开利用」这个信号只用于给告警定优先级
- **SQL 全部参数化** —— 所有用户输入走 `?` 绑定；SQL 里拼接的只有代码内的硬编码片段（表名、列名常量），不接受任何外部输入
- **输入白名单** —— 用户名限 `^[A-Za-z0-9][A-Za-z0-9._-]{2,31}$`，注入载荷在输入层即被拒绝；密码拒引号与控制字符
- **注册走邀请码** —— 首个账号免码（初始化），之后必须持码且角色由码决定。安全工具的账号不能自助创建
- **登录限流** —— 15 分钟内按用户 8 次 / 按 IP 30 次；账号不存在时也跑等价哈希校验，响应时间不可用于枚举
- **凭据加密存储** —— API Key 用 Fernet 加密落库，接口永不返回明文
- **主密钥必需** —— 未配置 `SCOUT_SECRET_KEY` 时，已保存的 Key 重启后无法解密

> ⚠️ **使用前请确认你对目标资产有合法授权。**
> 未授权使用本工具进行测试可能违反法律与合同约定，责任由使用者承担。

## 快速开始

```bash
git clone <repo-url> && cd scout-agent
chmod +x deploy.sh
./deploy.sh              # 交互式：自动生成主密钥、可改端口
./deploy.sh --yes        # 全默认，非交互（适合 CI）
```

脚本会完成：环境检查 → 生成 `.env` 与主密钥 → 构建镜像 → 启动 →
轮询健康检查 → 输出访问地址。

**只想手动来：**

```bash
cp .env.example .env
# 生成主密钥并填入 SCOUT_SECRET_KEY（不带这步，已保存的 API Key 重启后无法解密）
sed -i "s|^SCOUT_SECRET_KEY=.*|SCOUT_SECRET_KEY=$(python3 -c 'import secrets;print(secrets.token_urlsafe(48))')|" .env
docker compose up -d --build
```

访问 `http://<服务器IP>:80`。首次打开会引导创建管理员账号（该账号免邀请码），
之后新增账号需管理员在界面上生成邀请码。

> ⚠️ **请立即备份 `.env` 中的 `SCOUT_SECRET_KEY`** —— 换了它，所有已加密的
> API Key 全部失效。`.gitignore` 已默认忽略 `.env`。

### 卸载

```bash
./deploy.sh --uninstall    # 停止并删除容器与数据卷（不可恢复）
```

### 部署到多台 / 同机多实例

容器名由 `COMPOSE_PROJECT_NAME` 决定，`deploy.sh` 会根据**目录名**自动派生，
所以把项目 clone 到不同目录就能并存多个实例，互不冲突：

```bash
COMPOSE_PROJECT_NAME=scout-a ./deploy.sh --yes   # 显式指定项目名
```

### 前置要求

Docker Engine + Docker Compose V2。注意是 `docker compose`（V2），
不是已停止维护的 `docker-compose`。

### 接上模型

界面内：登录 → 左栏「账号与 API」→ 填网关地址、API Key、模型名 → 测试连通。

支持任何 OpenAI 兼容端点。不配置也能用 —— Agent 会走确定性固定流程。

### 可调项

| 项 | 默认 | 范围 | 说明 |
|---|---|---|---|
| 最大决策轮数 | 12 | 1~60 | 思考→取证的循环次数。升级前创建的配置默认 8 |
| 单次最大步数 | 12 | 1~200 | 单轮内允许的工具调用总数 |

深度越大越 thorough，耗时与目标站点的请求量也线性上升。

## 工具集（17 个）

**核心侦察**
`http_probe` `dns_lookup` `tls_inspect` `fingerprint` `endpoint_enum`

**CVE 情报**
`cve_intel` 单个 CVE 完整情报（含 KEV） ·
`cve_scan_text` 从告警文本批量提取 CVE 并逐个查询 ·
`cve_precondition` 无副作用地排查触发前置条件 ·
`package_vulns` 按包名查 OSV（npm/PyPI/Maven/Go）

**扩展侦察**
`subdomains` 证书与页面提取子域（不爆破） ·
`port_check` 精简端口表连通性（不全扫） ·
`js_endpoints` 从 JS 提取 API 路径 ·
`header_audit` 安全响应头检查 ·
`robots_parse` robots 与 sitemap 解析 ·
`host_header_check` Host 头误配置比对（不做投毒）

**记忆与报告**
`save_memory` 写入站点长期记忆 · `report_write` 生成 Markdown 交付报告

其中 `http_probe` 在使用写入方法时会转入审批流程。

## 架构

```
server.py      接入层    路由 · 鉴权 · SSE
   ↓
autonomous.py  编排层    ReAct 循环 · 工具选择 · 预算控制
   ↓
tools.py       能力层    工具注册表（唯一出网点）
skills.py      能力层    固定工作流定义（降级路径）
intel.py       能力层    CVE 情报聚合
   ↓
db.py          数据层    14 张表 · 站点记忆 · 迁移
auth.py        数据层    用户 · 邀请码 · 配置缓存
```

四层单向依赖，约 7400 行。技能与工具分离：技能是「什么时候做什么」，工具是「怎么做」——加新工具不改工作流，加工作流不碰底层。

## 技术栈

Flask 3 · SQLite · gunicorn（gthread）· nginx · 原生 JS
仅 4 个 Python 依赖：Flask / gunicorn / requests / cryptography

## 开发

```bash
python test_logic.py        # 工具与工作流
python test_auth.py         # 登录鉴权
python test_security.py     # 注入防护
node app/static/test_md.js  # Markdown 渲染器
```

## License

仅供授权范围内的安全测试与研究使用。请阅读并遵守你的组织政策与当地法律。