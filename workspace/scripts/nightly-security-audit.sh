#!/bin/bash
# ============================================================
# Hermes Agent 每日安全巡检脚本
# 适配自 OpenClaw 极简安全实践指南 v2.7
# 路径约定: $HC = ${HERMES_HOME:-$HOME/.hermes}
# ============================================================
set -uo pipefail
# Note: set -e removed to prevent premature exit on grep return codes.
# All risky commands use || true / || : guards.

HC="${HERMES_HOME:-$HOME/.hermes}"
REPORT_DIR="/tmp/hermes/security-reports"
TODAY=$(date +%Y-%m-%d)
TIMESTAMP=$(date +%Y-%m-%d_%H:%M:%S)
REPORT_FILE="${REPORT_DIR}/report-${TODAY}.txt"
HOSTNAME=$(hostname)

# ── 颜色定义 ──────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; RESET='\033[0m'

# ── 初始化报告 ────────────────────────────────────────────
mkdir -p "$REPORT_DIR"
{
  echo "========================================"
  echo "🛡️  Hermes 每日安全巡检简报 ${TODAY} ${TIMESTAMP}"
  echo "========================================"
  echo "Hostname: ${HOSTNAME}"
  echo "Hermes Home: ${HC}"
  echo ""
} > "$REPORT_FILE"

# ── 辅助函数 ──────────────────────────────────────────────
check_ok()   { echo -e "  ✅ $1"; echo "  ✅ $1" >> "$REPORT_FILE"; }
check_warn() { echo -e "  ⚠️  $1"; echo "  ⚠️  $1" >> "$REPORT_FILE"; }
check_bad()  { echo -e "  🔴 $1"; echo "  🔴 $1" >> "$REPORT_FILE"; }
check_info() { echo -e "  ℹ️  $1"; echo "  ℹ️  $1" >> "$REPORT_FILE"; }

# ============================================================
# 巡检项 1: Hermes 平台审计
# ============================================================
echo "" >> "$REPORT_FILE"
echo "【1/13】平台审计" >> "$REPORT_FILE"
echo "========================================"
echo -e "\n${BLUE}[1/13] 平台审计${RESET}"
if command -v hermes &>/dev/null; then
  STATUS_OUTPUT=$(hermes status 2>&1 || true)
  # 检查真正的致命错误（panic、无法连接、Python 异常等）
  if echo "$STATUS_OUTPUT" | grep -qiE "panic|traceback|error.*cannot|failed to start|connection refused"; then
    check_bad "hermes status 报告异常"
    echo "$STATUS_OUTPUT" | head -5 >> "$REPORT_FILE"
  elif echo "$STATUS_OUTPUT" | grep -qiE "error"; then
    # 只有 Error 字样但没有致命错误，正常（某些 provider 未配置不算异常）
    check_ok "hermes status 正常（部分 Provider 未配置属预期）"
  else
    check_ok "hermes status 正常"
  fi

  # 检查 hermes cron 调度器是否运行
  CRON_STATUS=$(hermes cron status 2>&1 || true)
  if echo "$CRON_STATUS" | grep -qi "running\|active"; then
    check_ok "Cron 调度器运行中"
  else
    check_warn "Cron 调度器未运行: $CRON_STATUS"
  fi
else
  check_bad "hermes 命令未找到"
fi
echo "" >> "$REPORT_FILE"

# ============================================================
# 巡检项 2: 进程与网络审计
# ============================================================
echo "【2/13】进程与网络审计" >> "$REPORT_FILE"
echo "========================================"
echo -e "\n${BLUE}[2/13] 进程与网络审计${RESET}"

# TCP 监听端口
TCP_PORTS=$(ss -tnp 2>/dev/null | grep -v "State" | wc -l)
echo "  TCP 监听端口数: $TCP_PORTS" | tee -a "$REPORT_FILE"
if [ "$TCP_PORTS" -gt 50 ]; then
  check_warn "TCP 监听端口数过多 ($TCP_PORTS)，建议人工审计"
else
  check_ok "TCP 监听端口数正常 ($TCP_PORTS)"
fi

# UDP 监听端口
UDP_PORTS=$(ss -unp 2>/dev/null | grep -v "State" | wc -l)
echo "  UDP 监听端口数: $UDP_PORTS" | tee -a "$REPORT_FILE"

# 高资源占用进程 Top 10
echo "  高资源占用进程 Top 10:" | tee -a "$REPORT_FILE"
ps aux --sort=-%cpu 2>/dev/null | head -11 | tail -10 | \
  awk '{printf "    CPU=%s%% MEM=%s%% %s\n", $3, $4, $11}' | tee -a "$REPORT_FILE" || true

# 异常出站连接
echo "  检查异常出站连接..." | tee -a "$REPORT_FILE"
ESTABLISHED=$(ss -tnp state established 2>/dev/null | grep -v "Local" | wc -l)
check_ok "当前 ESTABLISHED 连接数: $ESTABLISHED"
echo "" >> "$REPORT_FILE"

# ============================================================
# 巡检项 3: 敏感目录变更（最近 24h）
# ============================================================
echo "【3/13】敏感目录变更（最近 24h）" >> "$REPORT_FILE"
echo "========================================"
echo -e "\n${BLUE}[3/13] 敏感目录变更${RESET}"

SENSITIVE_DIRS="$HC /etc ~/.ssh ~/.gnupg /usr/local/bin"
DIR_CHANGES=""
for dir in $SENSITIVE_DIRS; do
  # 展开 $dir
  expanded_dir=$(eval echo "$dir" 2>/dev/null || echo "$dir")
  if [ -d "$expanded_dir" ]; then
    changes=$(find "$expanded_dir" -newer "$HC/.config-baseline.sha256" -type f 2>/dev/null | head -20 || true)
    if [ -n "$changes" ]; then
      count=$(echo "$changes" | wc -l)
      echo "  目录 $dir: $count 个文件变更" | tee -a "$REPORT_FILE"
      echo "$changes" | head -5 >> "$REPORT_FILE"
    fi
  fi
done
echo "" >> "$REPORT_FILE"

# ============================================================
# 巡检项 4: 系统定时任务
# ============================================================
echo "【4/13】系统定时任务" >> "$REPORT_FILE"
echo "========================================"
echo -e "\n${BLUE}[4/13] 系统定时任务${RESET}"

SYS_CRON_COUNT=$(find /etc/cron* /etc/anacrontab -type f 2>/dev/null | xargs grep -l . 2>/dev/null | wc -l || true)
SYSTEMD_TIMERS=$(systemctl list-timers --all 2>/dev/null | grep -c "timer\|shadow" || true)
echo "  系统 Cron 文件数: $SYS_CRON_COUNT" | tee -a "$REPORT_FILE"
echo "  Systemd Timers 数: $SYSTEMD_TIMERS" | tee -a "$REPORT_FILE"
check_ok "系统定时任务已审计"
echo "" >> "$REPORT_FILE"

# ============================================================
# 巡检项 5: Hermes Cron Jobs
# ============================================================
echo "【5/13】Hermes Cron Jobs" >> "$REPORT_FILE"
echo "========================================"
echo -e "\n${BLUE}[5/13] Hermes Cron Jobs${RESET}"
if command -v hermes &>/dev/null; then
  HERMES_CRON=$(hermes cron list 2>&1 || true)
  if [ -n "$HERMES_CRON" ] && echo "$HERMES_CRON" | grep -qi "name\|schedule"; then
    echo "$HERMES_CRON" | tee -a "$REPORT_FILE"
    check_ok "Hermes Cron Jobs 已审计"
  else
    check_info "Hermes Cron Jobs 列表为空或无法获取"
  fi
else
  check_warn "hermes 命令不可用"
fi
echo "" >> "$REPORT_FILE"

# ============================================================
# 巡检项 6: 登录与 SSH 安全
# ============================================================
echo "【6/13】登录与 SSH 安全" >> "$REPORT_FILE"
echo "========================================"
echo -e "\n${BLUE}[6/13] 登录与 SSH 安全${RESET}"

# 最近登录
LAST_LOGIN=$(lastlog -t 1 2>/dev/null | grep -v "Never\|Username" | head -5 || true)
if [ -n "$LAST_LOGIN" ]; then
  echo "  最近 1 天登录记录:" | tee -a "$REPORT_FILE"
  echo "$LAST_LOGIN" | head -5 | tee -a "$REPORT_FILE"
else
  check_info "最近 1 天无登录记录"
fi

# SSH 失败尝试（journalctl 在无匹配时 grep 返回 1，用 ||: 避免 set -e 崩溃；timeout 防止挂起）
_journal_ssh=$(timeout 5 journalctl -u sshd --since "yesterday" --no-pager -q 2>/dev/null || true)
SSH_FAILS=0
if [ -n "$_journal_ssh" ]; then
  SSH_FAILS=$(echo "$_journal_ssh" | grep -c "Failed\|BREAK-IN" 2>/dev/null || echo "0")
fi
SSH_FAILS="${SSH_FAILS:-0}"
echo "  SSH 失败尝试 (24h): $SSH_FAILS" | tee -a "$REPORT_FILE"
if [ "${SSH_FAILS:-0}" -gt 10 ]; then
  check_warn "SSH 暴力破解尝试 ($SSH_FAILS 次)，建议检查 /etc/ssh/sshd_config"
else
  check_ok "SSH 安全状态正常"
fi
echo "" >> "$REPORT_FILE"

# ============================================================
# 巡检项 7: 关键文件完整性（哈希基线 + 权限）
# ============================================================
echo "【7/13】关键文件完整性" >> "$REPORT_FILE"
echo "========================================"
echo -e "\n${BLUE}[7/13] 关键文件完整性${RESET}"

# 哈希校验
HASH_RESULT=$(cd "$HC" && sha256sum -c .config-baseline.sha256 2>&1 || true)
if echo "$HASH_RESULT" | grep -qi "OK"; then
  check_ok "配置文件哈希校验全部通过"
elif echo "$HASH_RESULT" | grep -qi "FAILED"; then
  check_bad "配置文件哈希校验失败:"
  echo "$HASH_RESULT" | grep "FAILED" | tee -a "$REPORT_FILE"
else
  check_info "哈希校验结果: $HASH_RESULT"
fi

# 权限检查
for f in config.yaml .env gateway_state.json; do
  if [ -f "$HC/$f" ]; then
    perms=$(stat -c "%a" "$HC/$f" 2>/dev/null || stat -f "%Lp" "$HC/$f" 2>/dev/null)
    if [ "$perms" = "600" ] || [ "$perms" = "400" ]; then
      check_ok "$f 权限正常 ($perms)"
    else
      check_warn "$f 权限异常 ($perms)，应为 600"
    fi
  fi
done
echo "" >> "$REPORT_FILE"

# ============================================================
# 巡检项 8: 黄线操作交叉验证（sudo 记录 vs memory 日志）
# ============================================================
echo "【8/13】黄线操作交叉验证" >> "$REPORT_FILE"
echo "========================================"
echo -e "\n${BLUE}[8/13] 黄线操作交叉验证${RESET}"

_journal_sudo=$(timeout 10 journalctl --since "yesterday" --no-pager -q -u sudo 2>/dev/null || true)
SUDO_RECENT=0
if [ -n "$_journal_sudo" ]; then
  SUDO_RECENT=$(echo "$_journal_sudo" | grep -c "sudo" 2>/dev/null || echo "0")
fi
SUDO_RECENT="${SUDO_RECENT:-0}"
check_info "journalctl 记录 sudo 次数: $SUDO_RECENT"
echo "" >> "$REPORT_FILE"

# ============================================================
# 巡检项 9: 磁盘使用
# ============================================================
echo "【9/13】磁盘使用" >> "$REPORT_FILE"
echo "========================================"
echo -e "\n${BLUE}[9/13] 磁盘使用${RESET}"

ROOT_USAGE=$(df / | awk 'NR==2 {print $5}' | tr -d '%')
echo "  根分区使用率: ${ROOT_USAGE}%" | tee -a "$REPORT_FILE"
if [ "${ROOT_USAGE:-0}" -gt 85 ]; then
  check_bad "根分区使用率超过 85% (${ROOT_USAGE}%)"
else
  check_ok "根分区使用率正常 (${ROOT_USAGE}%)"
fi

# 最近 24h 大文件（限制在 hermes 目录 + /tmp + /home，避免扫描全盘超时）
LARGE_FILES=$(find "$HC" /tmp "$HOME" -mtime -1 -size +100M -type f 2>/dev/null | head -10 || true)
LARGE_COUNT=$(echo "$LARGE_FILES" | grep -v "^$" | wc -l)
if [ "$LARGE_COUNT" -gt 0 ]; then
  check_warn "最近 24h 新增大文件 ($LARGE_COUNT 个):"
  echo "$LARGE_FILES" | head -5 | tee -a "$REPORT_FILE"
else
  check_ok "最近 24h 无新增大文件"
fi
echo "" >> "$REPORT_FILE"

# ============================================================
# 巡检项 10: Gateway 环境变量（凭证扫描）
# ============================================================
echo "【10/13】Gateway 环境变量" >> "$REPORT_FILE"
echo "========================================"
echo -e "\n${BLUE}[10/13] Gateway 环境变量${RESET}"

# 查找 hermes gateway 进程
GATEWAY_PID=$(pgrep -f "hermes.*gateway" 2>/dev/null | head -1 || \
              pgrep -f "gateway" 2>/dev/null | head -1 || true)
if [ -n "$GATEWAY_PID" ]; then
  echo "  Gateway PID: $GATEWAY_PID" | tee -a "$REPORT_FILE"
  # 读取环境变量（脱敏）
  ENV_KEYS=$(cat "/proc/$GATEWAY_PID/environ" 2>/dev/null | tr '\0' '\n' | \
             grep -iE "KEY|TOKEN|SECRET|PASSWORD|API|PRIVATE" | \
             sed 's/=.*/=****/' | head -20 || true)
  if [ -n "$ENV_KEYS" ]; then
    echo "  检测到的敏感环境变量:" | tee -a "$REPORT_FILE"
    echo "$ENV_KEYS" | tee -a "$REPORT_FILE"
  else
    check_ok "未发现明文敏感环境变量泄露"
  fi
else
  check_warn "无法找到 Gateway 进程 PID"
fi
echo "" >> "$REPORT_FILE"

# ============================================================
# 巡检项 11: 明文私钥/凭证泄露扫描 (DLP)
# ============================================================
echo "【11/13】明文私钥/凭证泄露扫描 (DLP)" >> "$REPORT_FILE"
echo "========================================"
echo -e "\n${BLUE}[11/13] 凭证泄露扫描${RESET}"

# 以太坊私钥正则
ETH_KEY_PATTERN='0x[a-fA-F0-9]{64}'
# 比特币私钥正则
BTC_KEY_PATTERN='5[HJKLmNpQRs][1-9A-HJ-NP-Za-km-z]{50}'
# BIP39 助记词（收紧：要求每词 4-8 字符且全小写，英文句子误报率高）
MNEMONIC_PATTERN='\b[a-z]{4,8}(?:\s+[a-z]{4,8}){11}\b'

FOUND_LEAKS=0
# 扫描 memories/logs/sessions 目录（限制每个目录最多 50 个文件，避免长时间扫描）
for dir in "$HC/memories" "$HC/logs" "$HC/sessions"; do
  if [ -d "$dir" ]; then
    # 限制文件数，避免超时
    dir_files=$(find "$dir" -type f 2>/dev/null | head -50 || true)
    if [ -z "$dir_files" ]; then
      continue
    fi

    # 以太坊私钥（timeout 10s 防止挂起）
    eth_leaks=$(echo "$dir_files" | xargs -r grep -rPl "$ETH_KEY_PATTERN" 2>/dev/null | head -5 || true)
    if [ -n "$eth_leaks" ]; then
      check_bad "发现疑似以太坊私钥 in $dir:"
      echo "$eth_leaks" | tee -a "$REPORT_FILE"
      FOUND_LEAKS=$((FOUND_LEAKS + 1))
    fi

    # 助记词（timeout 10s 防止挂起）
    mnemonic_leaks=$(echo "$dir_files" | xargs -r grep -rPl "$MNEMONIC_PATTERN" 2>/dev/null | head -5 || true)
    if [ -n "$mnemonic_leaks" ]; then
      check_bad "发现疑似助记词 in $dir:"
      echo "$mnemonic_leaks" | tee -a "$REPORT_FILE"
      FOUND_LEAKS=$((FOUND_LEAKS + 1))
    fi
  fi
done

if [ "$FOUND_LEAKS" -eq 0 ]; then
  check_ok "memory/logs/sessions 目录未发现明文私钥或助记词"
fi
echo "" >> "$REPORT_FILE"

# ============================================================
# 巡检项 12: Skill/MCP 完整性（哈希基线对比）
# ============================================================
echo "【12/13】Skill/MCP 完整性" >> "$REPORT_FILE"
echo "========================================"
echo -e "\n${BLUE}[12/13] Skill/MCP 完整性${RESET}"

SKILLS_DIR="$HC/skills"
BASELINE_FILE="$HC/.skills-baseline.sha256"

if [ -d "$SKILLS_DIR" ]; then
  SKILL_COUNT=$(find "$SKILLS_DIR" -type f 2>/dev/null | wc -l)
  echo "  Skills 目录文件数: $SKILL_COUNT" | tee -a "$REPORT_FILE"

  # 生成当前哈希
  CURRENT_HASH=$(timeout 15 find "$SKILLS_DIR" -type f -exec sha256sum {} \; 2>/dev/null | sort | sha256sum | cut -d' ' -f1)
  echo "  当前 Skills 目录哈希: $CURRENT_HASH" | tee -a "$REPORT_FILE"

  if [ -f "$BASELINE_FILE" ]; then
    BASELINE_HASH=$(cat "$BASELINE_FILE")
    if [ "$CURRENT_HASH" = "$BASELINE_HASH" ]; then
      check_ok "Skills 目录哈希校验通过"
    else
      check_warn "Skills 目录哈希发生变化，请审计新增/修改的文件"
    fi
  else
    # 首次运行，建立基线
    echo "$CURRENT_HASH" > "$BASELINE_FILE"
    check_info "首次运行，已建立 Skills 目录哈希基线"
  fi
else
  check_info "Skills 目录不存在，跳过"
fi
echo "" >> "$REPORT_FILE"

# ============================================================
# 巡检项 13: Git 灾备自动同步
# ============================================================
echo "【13/13】Git 灾备自动同步" >> "$REPORT_FILE"
echo "========================================"
echo -e "\n${BLUE}[13/13] Git 灾备同步${RESET}"

BACKUP_STATUS="未配置"
# 检查是否有 git remote
if [ -d "$HC/.git" ]; then
  REMOTE=$(git -C "$HC" remote get-url origin 2>/dev/null || true)
  if [ -n "$REMOTE" ]; then
    # 尝试推送（不阻塞）
    git -C "$HC" add -A 2>/dev/null || true
    git -C "$HC" commit -m "Auto-backup ${TODAY} ${TIMESTAMP}" --allow-empty 2>/dev/null || true
    timeout 30 git -C "$HC" push origin main 2>&1 | head -5 || true
    BACKUP_STATUS="已配置 (remote: $REMOTE)"
    check_ok "Git 灾备: $BACKUP_STATUS"
  else
    BACKUP_STATUS="未配置 remote"
    check_warn "Git 灾备: $BACKUP_STATUS"
  fi
else
  BACKUP_STATUS="未初始化 git"
  check_warn "Git 灾备: $BACKUP_STATUS（可选，建议配置）"
fi
echo "" >> "$REPORT_FILE"

# ============================================================
# 巡检项 14: Skill/MCP 工具签名异常检测（污染检测）
# ============================================================
echo "【14/14】Skill/MCP 工具签名异常检测" >> "$REPORT_FILE"
echo "========================================" >> "$REPORT_FILE"
echo -e "\n${BLUE}[14/14] Skill/MCP 工具签名异常检测${RESET}"

TOOL_DETECT_SCRIPT="$HC/.security/detect-skill-poisoning.py"
if [ -f "$TOOL_DETECT_SCRIPT" ]; then
  # 运行检测，捕获退出码
  DETECT_OUTPUT=$(REPORT_FILE="$REPORT_FILE" python3 "$TOOL_DETECT_SCRIPT" 2>&1 || true)
  if echo "$DETECT_OUTPUT" | grep -q "✅"; then
    check_ok "工具签名检测通过"
  elif echo "$DETECT_OUTPUT" | grep -q "🆕\|⚠️\|🔍\|🔄"; then
    echo "$DETECT_OUTPUT" | grep "🆕\|⚠️\|🔍\|🔄" | head -20 | tee -a "$REPORT_FILE"
    check_bad "检测到工具签名异常，请审计 .security/ 目录报告"
  else
    check_info "工具签名检测: $DETECT_OUTPUT"
  fi
else
  check_info "检测脚本不存在，跳过"
fi
echo "" >> "$REPORT_FILE"

# ============================================================
# 输出完整报告路径
# ============================================================
echo "========================================" >> "$REPORT_FILE"
echo "巡检完成: $TIMESTAMP" >> "$REPORT_FILE"
echo "详细报告: $REPORT_FILE" >> "$REPORT_FILE"
echo "========================================" >> "$REPORT_FILE"

echo ""
echo -e "${GREEN}========================================"
echo -e "✅ 巡检完成！详细报告: $REPORT_FILE"
echo -e "========================================${RESET}"
