#!/usr/bin/env bash
# =============================================================================
# Scout Agent 一键部署
#
#   ./deploy.sh              交互式（首次部署会问几个问题）
#   ./deploy.sh --yes        全部用默认值，非交互
#   ./deploy.sh --uninstall  停止并移除容器与数据卷（数据不可恢复）
#
# 幂等：重复执行会保留已有配置与数据，只重建镜像。
# =============================================================================
set -euo pipefail

C_G=$'\033[32m'; C_Y=$'\033[33m'; C_R=$'\033[31m'; C_B=$'\033[34m'; C_0=$'\033[0m'
die()  { echo "${C_R}✗ $*${C_0}" >&2; exit 1; }
info() { echo "${C_B}▸${C_0} $*"; }
ok()   { echo "${C_G}✓${C_0} $*"; }
warn() { echo "${C_Y}!${C_0} $*"; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

# Compose 项目名：决定容器/网络/数据卷的名称前缀。
# 不设置的话 compose 会用目录名，同名目录在不同机器上没问题，
# 但同一台机器上部署两份会互相抢容器 —— 显式从目录名派生更可控。
PROJECT_BASE="$(basename "$HERE" | tr -c 'a-zA-Z0-9_-' '-' | sed 's/-\{1,\}/-/g; s/^-//; s/-$//')"
PROJECT_BASE="${PROJECT_BASE:-scout}"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-$PROJECT_BASE}"

ASSUME_YES=0
ACTION=install
for a in "$@"; do
  case "$a" in
    -y|--yes)    ASSUME_YES=1 ;;
    --uninstall) ACTION=uninstall ;;
    -h|--help)   sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)           die "未知参数：$a（试试 --help）" ;;
  esac
done

# ---------- 卸载 ----------
if [ "$ACTION" = uninstall ]; then
  warn "即将停止并移除 Scout Agent 的容器与数据"
  warn "数据卷 scout-data 中的数据库会被一并删除，且不可恢复"
  if [ "$ASSUME_YES" -ne 1 ]; then
    read -r -p "确认继续？输入 yes： " ans
    [ "$ans" = "yes" ] || { echo "已取消"; exit 0; }
  fi
  docker compose down -v --remove-orphans 2>/dev/null || true
  ok "已卸载。.env 文件保留，如需彻底删除请手动 rm -rf .env data"
  exit 0
fi

# ---------- 前置检查 ----------
info "检查环境"
command -v docker >/dev/null 2>&1 || die "未找到 docker，请先安装 Docker Engine"
command -v curl   >/dev/null 2>&1 || die "未找到 curl"
docker compose version >/dev/null 2>&1 \
  || die "docker compose 不可用（需要 Docker Compose V2，不是 docker-compose）"
docker info >/dev/null 2>&1 || die "无法连接 Docker 守护进程，请检查服务是否运行、当前用户是否有权限"
ok "docker $(docker --version | sed 's/.*version //' | cut -d, -f1) · compose 可用"

# ---------- 配置文件 ----------
if [ ! -f .env ]; then
  info "生成 .env"
  cp .env.example .env
  KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))' 2>/dev/null \
      || head -c 48 /dev/urandom | base64 | tr -d '\n=')"
  # 用 sed 替换而非 echo >>：.env.example 里已存在空的 SCOUT_SECRET_KEY= 行，
  # 追加会造成重复定义
  if grep -q '^SCOUT_SECRET_KEY=' .env; then
    sed -i "s|^SCOUT_SECRET_KEY=.*|SCOUT_SECRET_KEY=$KEY|" .env
  else
    printf '\nSCOUT_SECRET_KEY=%s\n' "$KEY" >> .env
  fi
  ok "已生成主密钥（务必备份，丢失后已保存的 API Key 无法解密）"
else
  if grep -qE '^SCOUT_SECRET_KEY=.+' .env; then
    ok ".env 已存在且主密钥已配置，保留原值"
  else
    warn ".env 中主密钥为空，正在生成"
    KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))' 2>/dev/null \
        || head -c 48 /dev/urandom | base64 | tr -d '\n=')"
    sed -i "s|^SCOUT_SECRET_KEY=.*|SCOUT_SECRET_KEY=$KEY|" .env
    ok "已生成主密钥"
  fi
fi

# ---------- 可选：交互式改端口 ----------
if [ "$ASSUME_YES" -ne 1 ]; then
  CUR_PORT="$(grep -E '^\s*-\s*"?[0-9]+:80' docker-compose.yml \
            | head -1 | sed -E 's/^[^-]*-[[:space:]]*"?([0-9]+):80.*/\1/')"
  CUR_PORT="${CUR_PORT:-80}"
  read -r -p "对外端口 [$CUR_PORT]： " ans_port
  if [ -n "$ans_port" ] && [ "$ans_port" != "$CUR_PORT" ]; then
    if printf '%s' "$ans_port" | grep -qE '^[0-9]+$' && [ "$ans_port" -ge 1 ] && [ "$ans_port" -le 65535 ]; then
      sed -i -E "s|(\"${CUR_PORT}:80\")|\"${ans_port}:80\"|" docker-compose.yml
      ok "端口已改为 $ans_port"
    else
      die "端口不合法"
    fi
  fi
fi

# ---------- 构建启动 ----------
info "构建镜像（首次约 1~3 分钟，取决于网络）"
docker compose build

info "启动服务"
docker compose up -d

# ---------- 健康检查 ----------
# 注意：不要用 `tr -d ':80'` 提取端口 —— tr 按字符集删除，
# 会把 "18080:80" 里的 0 和 8 一起削掉（得到 "1"）。
# 也不能用 `s/.*"?([0-9]+):80"?.*/\1/` —— 前导 `.*` 贪婪匹配会吃掉
# 1808 只剩 0。要用 `^[^-]*-` 锚定列表符号，强制从第一个数字开始捕获。
PORT="$(grep -E '^\s*-\s*"?[0-9]+:80' docker-compose.yml \
        | head -1 | sed -E 's/^[^-]*-[[:space:]]*"?([0-9]+):80.*/\1/')"
PORT="${PORT:-80}"
info "等待服务就绪（检查 http://127.0.0.1:$PORT/api/health）"

HEALTHY=0
for i in $(seq 1 30); do
  if curl -fsS --max-time 3 "http://127.0.0.1:$PORT/api/health" >/dev/null 2>&1; then
    HEALTHY=1; break
  fi
  sleep 2
done

if [ "$HEALTHY" -eq 1 ]; then
  ok "服务已就绪"
  info "compose 项目名：${COMPOSE_PROJECT_NAME}（容器/数据卷以此为前缀）"
else
  warn "健康检查未通过，最近日志："
  docker compose logs --tail=20
  die "部署未成功，请检查上面的日志"
fi

# ---------- 结果 ----------
IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
[ -n "$IP" ] || IP="<服务器IP>"

echo
echo "${C_G}────────────────────────────────────────${C_0}"
echo "${C_G} 部署完成${C_0}"
echo
echo "  本机访问：http://127.0.0.1:$PORT"
echo "  远程访问：http://$IP:$PORT"
echo
echo "  ${C_Y}下一步${C_0}：浏览器打开上面的地址"
echo "  首次访问会引导创建管理员账号（该账号免邀请码）"
echo "  之后新增账号需要管理员在界面上生成邀请码"
echo
echo "  ${C_B}常用命令${C_0}"
echo "    docker compose logs -f      查看日志"
echo "    docker compose restart      重启"
echo "    docker compose down         停止（保留数据）"
echo "    ./deploy.sh --uninstall     彻底卸载（数据不可恢复）"
echo
echo "  ${C_Y}注意${C_0}：请立即备份 .env 中的 SCOUT_SECRET_KEY"
echo "  更换它会导致所有已保存的 API Key 无法解密。"
echo "${C_G}────────────────────────────────────────${C_0}"