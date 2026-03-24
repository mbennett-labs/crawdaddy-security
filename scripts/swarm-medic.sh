#!/bin/bash
# QSL Swarm Medic — Autonomous Repair Agent
# Runs every 5 minutes via cron
# Detects → Diagnoses → Fixes → Reports

ALARM="/home/ubuntu/crawdaddy-security/scripts/alarm.sh"
LOG="/home/ubuntu/crawdaddy-security/logs/medic.log"
TIMESTAMP=$(date -u '+%Y-%m-%d %H:%M UTC')

log() { echo "[$TIMESTAMP] $1" >> "$LOG"; }
alarm() { bash "$ALARM" "$1" "$2"; }
dedup_alarm() {
  local check_id="$1" severity="$2" message="$3"
  local dedup_file="/tmp/medic-${check_id}-last-alarm"
  local now=$(date +%s)
  if [ -f "$dedup_file" ]; then
    local last=$(cat "$dedup_file")
    if [ $(( now - last )) -lt 1800 ]; then
      log "SKIP: $check_id alarm suppressed ($(( now - last ))s ago, min 1800s)"
      return 0
    fi
  fi
  echo "$now" > "$dedup_file"
  alarm "$severity" "$message"
}
fixed() {
  log "FIXED: $1"
  bash "$ALARM" "WARNING" "Swarm Medic fixed: $1"
}

log "=== Medic cycle start ==="

# ─────────────────────────────────────────
# CHECK 0 — Credential health
# ─────────────────────────────────────────

# Test ACP API key (seller reads from config.json LITE_AGENT_API_KEY)
ACP_KEY=$(python3 -c "import json; \
  d=json.load(open('$HOME/.openclaw/virtuals-acp/config.json')); \
  print(d.get('LITE_AGENT_API_KEY',''))" 2>/dev/null)

if [ -n "$ACP_KEY" ]; then
  ACP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "x-api-key: $ACP_KEY" \
    "https://claw-api.virtuals.io/acp/me" 2>/dev/null)
  if [ "$ACP_STATUS" = "401" ] || [ "$ACP_STATUS" = "403" ]; then
    dedup_alarm "acp-key" "CRITICAL" \
"ACP API key EXPIRED (HTTP $ACP_STATUS) — CrawDaddy cannot receive jobs.
Renew at: https://app.virtuals.io/settings/api-keys
Update BOTH: ~/.openclaw/virtuals-acp/config.json (LITE_AGENT_API_KEY) + ~/.openclaw/openclaw.json"
  else
    log "OK: ACP API key valid (HTTP $ACP_STATUS)"
  fi
fi

# Test Telegram bot token (from selarix.env)
source ~/.selarix.env 2>/dev/null
if [ -n "$BOT_TOKEN" ]; then
  TG_STATUS=$(curl -s \
    "https://api.telegram.org/bot$BOT_TOKEN/getMe" | \
    python3 -c "import sys,json; \
    d=json.load(sys.stdin); print('OK' if d.get('ok') else 'DEAD')" \
    2>/dev/null)
  if [ "$TG_STATUS" = "DEAD" ]; then
    log "CRITICAL: Telegram bot token invalid — alarms going to email only"
    echo -e "Subject: QSL SWARM ALARM CRITICAL\n\nTelegram bot token expired. Alarms silent. Renew at BotFather." | \
      sendmail michael@quantumshieldlabs.dev 2>/dev/null
  else
    log "OK: Telegram bot token valid"
  fi
fi

# Test Anthropic API key (ContentBot)
ANTHROPIC_KEY=$(grep "ANTHROPIC_API_KEY" \
  ~/.contentbot.env ~/.env 2>/dev/null | \
  head -1 | cut -d'=' -f2)
if [ -n "$ANTHROPIC_KEY" ]; then
  ANTH_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "x-api-key: $ANTHROPIC_KEY" \
    -H "anthropic-version: 2023-06-01" \
    "https://api.anthropic.com/v1/models" 2>/dev/null)
  if [ "$ANTH_STATUS" = "401" ]; then
    dedup_alarm "anthropic-key" "WARNING" \
      "Anthropic API key invalid — ContentBot will fail. Renew at console.anthropic.com"
  else
    log "OK: Anthropic API key valid (HTTP $ANTH_STATUS)"
  fi
fi

# ─────────────────────────────────────────
# CHECK 1 — CrawDaddy seller process
# ─────────────────────────────────────────
if ! pgrep -f "seller.ts" > /dev/null; then
  log "FAILURE: seller.ts not running — attempting restart"
  cd ~/.openclaw/virtuals-acp
  nohup npx tsx src/seller/runtime/seller.ts \
    >> logs/seller.log 2>&1 &
  sleep 8
  if pgrep -f "seller.ts" > /dev/null; then
    fixed "CrawDaddy seller restarted successfully"
  else
    dedup_alarm "seller-dead" "CRITICAL" \
      "CrawDaddy seller DEAD — auto-restart FAILED. Manual intervention required."
  fi
else
  log "OK: seller.ts running"
fi

# ─────────────────────────────────────────
# CHECK 2 — Seller errors + job rejections (30-min dedup)
# ─────────────────────────────────────────
SELLER_LOG=$(ls -t ~/.openclaw/virtuals-acp/logs/*.log 2>/dev/null | head -1)
if [ -f "$SELLER_LOG" ]; then
  # Check for seller errors (403, syntax, type errors)
  ERRORS=$(grep -cE "SyntaxError|TransformError|Cannot find|TypeError|Forbidden|statusCode.*403|Failed to resolve" \
    "$SELLER_LOG" 2>/dev/null)

  # Check for job rejections
  REJECTIONS=$(grep -c "accept=false" "$SELLER_LOG" 2>/dev/null)

  if [ "$ERRORS" -gt 0 ]; then
    log "FAILURE: $ERRORS seller errors in log"
    dedup_alarm "seller-errors" "CRITICAL" \
      "CrawDaddy seller has $ERRORS errors — latest: $(tail -100 "$SELLER_LOG" | grep -E 'Error|Forbidden' | tail -1 | head -c 200)"
  else
    log "OK: no seller errors"
  fi

  if [ "$REJECTIONS" -gt 2 ]; then
    log "WARNING: $REJECTIONS job rejections in log"
    dedup_alarm "seller-rejections" "CRITICAL" \
      "CrawDaddy rejecting jobs — $REJECTIONS total. Revenue lost. Check handlers.ts"
  fi
fi

# ─────────────────────────────────────────
# CHECK 3 — ResearchBot service
# ─────────────────────────────────────────
if ! systemctl is-active researchbot.service > /dev/null 2>&1; then
  log "FAILURE: researchbot down — restarting"
  sudo systemctl restart researchbot.service
  sleep 5
  if systemctl is-active researchbot.service > /dev/null 2>&1; then
    fixed "ResearchBot restarted"
  else
    dedup_alarm "researchbot" "WARNING" "ResearchBot down and failed to restart"
  fi
else
  log "OK: researchbot running"
fi

# ─────────────────────────────────────────
# CHECK 4 — Conway credits
# ─────────────────────────────────────────
CREDITS=$(sqlite3 ~/.automaton/state.db \
  "SELECT json_extract(value,'$.creditsCents') \
   FROM kv WHERE key='last_known_balance';" 2>/dev/null)
if [ -n "$CREDITS" ]; then
  if [ "$CREDITS" -lt 50 ]; then
    dedup_alarm "conway-credits" "CRITICAL" \
      "Conway credits CRITICAL: $(echo "$CREDITS" | awk '{printf "%.2f", $1/100}') — Bastion will die soon. Add credits NOW."
  elif [ "$CREDITS" -lt 150 ]; then
    dedup_alarm "conway-credits" "WARNING" \
      "Conway credits low: $(echo "$CREDITS" | awk '{printf "%.2f", $1/100}') — add credits soon"
  fi
  log "OK: Conway credits $CREDITS cents"
fi

# ─────────────────────────────────────────
# CHECK 5 — Bastion lock integrity
# ─────────────────────────────────────────
if systemctl is-active bastion.service > /dev/null 2>&1; then
  LOCK=$(ls ~/.automaton/bastion-unlocked 2>/dev/null)
  if [ -z "$LOCK" ]; then
    log "FAILURE: Bastion running without unlock token — stopping"
    sudo systemctl stop bastion.service
    dedup_alarm "bastion-lock" "CRITICAL" \
      "Bastion was running WITHOUT unlock token — auto-stopped. Something re-enabled it. Investigate."
  fi
fi

# ─────────────────────────────────────────
# CHECK 6 — Dashboard collector freshness
# ─────────────────────────────────────────
LAST_COLLECT=$(stat -c %Y \
  ~/qsl-dashboard/public/data/status.json 2>/dev/null)
NOW=$(date +%s)
if [ -n "$LAST_COLLECT" ]; then
  AGE=$(( (NOW - LAST_COLLECT) / 60 ))
  if [ "$AGE" -gt 15 ]; then
    log "FAILURE: dashboard stale ${AGE}min — forcing collect"
    bash ~/qsl-dashboard/scripts/collect_status.sh
    fixed "Dashboard collector forced after ${AGE}min stale"
  else
    log "OK: dashboard updated ${AGE}min ago"
  fi
fi

# ─────────────────────────────────────────
# CHECK 7 — EC2 disk space
# ─────────────────────────────────────────
DISK=$(df / | tail -1 | awk '{print $5}' | tr -d '%')
if [ "$DISK" -gt 85 ]; then
  dedup_alarm "disk-space" "CRITICAL" "EC2 disk at ${DISK}% — approaching full. Clean up logs."
elif [ "$DISK" -gt 75 ]; then
  dedup_alarm "disk-space" "WARNING" "EC2 disk at ${DISK}% — monitor closely"
fi
log "OK: disk at ${DISK}%"

# ─────────────────────────────────────────
# CHECK 8 — Openclaw gateway
# ─────────────────────────────────────────
if ! pgrep -f "openclaw" > /dev/null; then
  log "FAILURE: openclaw gateway not running"
  dedup_alarm "openclaw-gw" "CRITICAL" \
    "OpenClaw gateway is DOWN — CrawDaddy cannot receive jobs. Manual restart required."
else
  log "OK: openclaw gateway running"
fi

# ─────────────────────────────────────────
# CHECK 9 — SN61 miner on Hostinger
# ─────────────────────────────────────────
if [ -f ~/.ssh/id_ed25519 ]; then
  MINER_STATUS=$(ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
    -i ~/.ssh/id_ed25519 root@69.62.69.140 \
    'docker inspect --format="{{.State.Status}}" \
     miner-agent-miner-1 2>/dev/null' 2>/dev/null)
  if [ -n "$MINER_STATUS" ] && [ "$MINER_STATUS" != "running" ]; then
    dedup_alarm "sn61-miner" "WARNING" \
      "SN61 miner container on Hostinger is $MINER_STATUS — check docker"
  elif [ -z "$MINER_STATUS" ]; then
    log "WARNING: could not reach Hostinger or miner container missing"
  else
    log "OK: Hostinger miner running"
  fi
else
  log "SKIP: no SSH key for Hostinger — CHECK 9 disabled"
fi

log "=== Medic cycle complete ==="
