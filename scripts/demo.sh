#!/usr/bin/env bash
# 出站探测 API 演示脚本（compose 环境内或本地裸机均可运行）。
#
# 用法（compose 内，目标为标准 80/443 端口）：
#   ./scripts/demo.sh
# 本地裸机演示（目标监听 8080/8443）：
#   PROBE_BASE=http://127.0.0.1:8001 DNS_CTRL=http://127.0.0.1:8054 \
#     HTTP_PORT=8080 HTTPS_PORT=8443 ./scripts/demo.sh
#
# 前置：docker compose up -d --build 已就绪。
set -euo pipefail

BASE="${PROBE_BASE:-http://127.0.0.1:8000}"
DNS_CTRL="${DNS_CTRL:-http://127.0.0.1:8053}"
# compose 内目标使用标准 80/443；本地裸机可用 HTTP_PORT/HTTPS_PORT 覆盖
HPORT="${HTTP_PORT:+:${HTTP_PORT}}"
SPORT="${HTTPS_PORT:+:${HTTPS_PORT}}"
TARGET_REQ_PORT="${HTTP_PORT:-8080}"

# probe_url "<描述>" "<url>" [method]
probe_url() {
  local desc="$1" url="$2" method="${3:-GET}"
  local body
  body="$(jq -n --arg u "$url" --arg m "$method" '{url:$u, method:$m}')"
  echo
  echo "================================================================"
  echo "▶ ${desc}"
  echo "  POST ${BASE}/api/v1/probe  ${body}"
  curl -sS -X POST "${BASE}/api/v1/probe" \
    -H 'Content-Type: application/json' \
    -d "$body" | jq .
}

switch_profile() {
  local profile="$1"
  echo "--- 切换本地 DNS profile -> ${profile}"
  curl -sS -X POST "${DNS_CTRL}/profiles/switch" \
    -H 'Content-Type: application/json' \
    -d "$(jq -n --arg p "$profile" '{profile:$p}')" | jq -r '.active'
}

echo "### 0. 当前策略"
curl -sS "${BASE}/api/v1/policy" | jq .

# 1) 允许的目标（HTTP + HTTPS，证书按原域名验证）
switch_profile allowed
probe_url "允许的 HTTP 目标" "http://allowed.demo.test${HPORT}/"
probe_url "允许的 HTTPS 目标（受信演示 CA，按原域名校验）" \
  "https://https.allowed.demo.test${SPORT}/secure"

# 2) 禁止目标：被白名单拦截，目标收不到请求
probe_url "禁止网段目标（必须 blocked，且 request_sent=false）" \
  "http://forbidden.demo.test${HPORT}/secret"

# 3) 检查后换址：allowed -> swapped，同名域名换到禁区
switch_profile swapped
probe_url "检查后换址（DNS rebinding）：同名域名解析到禁区，连接前拦截" \
  "http://swapped.demo.test${HPORT}/"

# 4) 混合解析：一次应答含允许+禁止地址，整体拒绝
switch_profile mixed
probe_url "混合 A 记录（允许+禁止地址同时返回）：整体拒绝" \
  "http://multi-a.demo.test${HPORT}/"

# 5) 跳转：正常跳转、跳禁区拦截、非 HTTP 协议、3 次上限
switch_profile allowed
probe_url "正常跳转到允许目标" \
  "http://redirect-ok.demo.test${HPORT}/redirect-allowed"
probe_url "跳转到禁止网段：第二跳拦截，禁区零请求" \
  "http://allowed.demo.test${HPORT}/redirect-forbidden"
probe_url "跳转到非 HTTP(S) 协议：拒绝" \
  "http://allowed.demo.test${HPORT}/redirect-scheme"

switch_profile loop
probe_url "跳转链超过 3 次上限：第 5 跳未连接即拦截" \
  "http://loop1.demo.test${HPORT}/loop/1"
switch_profile allowed

# 6) 仅 IPv4 / 入口校验
probe_url "IPv6 字面量：拒绝" "http://[2001:db8::1]/"
probe_url "非 HTTP(S) scheme：拒绝" "ftp://allowed.demo.test${HPORT}/"
probe_url "URL 携带 userinfo：拒绝" "http://u:p@allowed.demo.test${HPORT}/"

# 7) HTTP/1.1 响应完整性（原始可控目标，默认端口 8090）
RAWPORT="${RAW_PORT:-8090}"
probe_url "保活目标：完整响应后连接保持，探测应立即完成（不等读取超时）" \
  "http://raw.demo.test:${RAWPORT}/keepalive"
probe_url "保活目标上的 302：响应完整即及时跟随跳转" \
  "http://raw.demo.test:${RAWPORT}/keepalive-redirect"
probe_url "断流目标：Content-Length 未收齐即断开，必须报错（不得报可达）" \
  "http://raw.demo.test:${RAWPORT}/truncated"
probe_url "分块响应：读到终止块即完成（连接保持也不等待）" \
  "http://raw.demo.test:${RAWPORT}/chunked"
probe_url "分块格式错误：必须报错" \
  "http://raw.demo.test:${RAWPORT}/chunked-bad"
probe_url "长度信息冲突（Content-Length + Transfer-Encoding）：必须报错" \
  "http://raw.demo.test:${RAWPORT}/conflict"
probe_url "无长度头：正文以连接关闭为界" \
  "http://raw.demo.test:${RAWPORT}/no-length"
probe_url "HEAD 保活目标：完整响应头即结束" \
  "http://raw.demo.test:${RAWPORT}/keepalive" HEAD
probe_url "204 无正文响应：完整响应头即结束" \
  "http://raw.demo.test:${RAWPORT}/status/204"

echo
echo "### 验证禁止目标从未收到探测请求（应返回空列表）:"
curl -sS "http://127.0.0.1:${TARGET_REQ_PORT}/_requests" \
  | jq '[.[] | select(.host=="forbidden.demo.test")]'

echo
echo "演示完成。交互式文档: ${BASE}/docs"
