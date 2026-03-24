#!/bin/bash
# QSL Swarm Medic — Autonomous Repair Agent
# Runs every 5 minutes via cron
# Detects → Diagnoses → Fixes → Reports

ALARM="/home/ubuntu/crawdaddy-security/scripts/alarm.sh"
LOG="/home/ubuntu/crawdaddy-security/logs/medic.log"
TIMESTAMP=$(date -u '+%Y-%m-%d %H:%M UTC')

log() { echo "[$TIMESTAMP] $1" >> "$LOG"; }
alarm() { bash "$ALARM" "$1" "$2"; }
fixed() {
  log "FIXED: $1"
  bash "$ALARM" "WARNING" "Swarm Medic fixed: $1"
}

log "=== Medic cycle start ==="

# ─────────────────────────────────────────
# CHECK 0 — Credential health
# ─────────────────────────────────────────

# Test ACP API key
ACP_KEY=$(cat ~/.openclaw/openclaw.json 2>/dev/null | \
  python3 -c "import sys,json; d=json.load(sys.stdin); \
  print(d.get('skills',{}).get('entries',{}).get('virtuals-protocol-acp',{}) \
  .get('env',{}).get('ACP_API_KEY',''))" 2>/dev/null)

if [ -n "$ACP_KEY" ]; then
  ACP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "x-api-key: $ACP_KEY" \
    "https://api.virtuals.io/api/v2/sellers/me" 2>/dev/null)
  if [ "$ACP_STATUS" = "401" ] || [ "$ACP_STATUS" = "403" ]; then
    alarm "CRITICAL" \
"ACP API key EXPIRED (HTTP $ACP_STATUS) — CrawDaddy cannot receive jobs.
Renew at: https://app.virtuals.io/settings/api-keys
Paste new key in: ~/.openclaw/openclaw.json"
  else
    log "OK: ACP API key valid (HTTP $ACP_STATUS)"
  fi
fi

# Test Telegram bot token (hardcoded in alarm.sh)
BOT_TOKEN=$(grep "^BOT_TOKEN=" /home/ubuntu/crawdaddy-security/scripts/alarm.sh 2>/dev/null | head -1 | cut -d'"' -f2)
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
    alarm "WARNING" \
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
    alarm "CRITICAL" \
      "CrawDaddy seller DEAD — auto-restart FAILED. Manual intervention required."
  fi
else
  log "OK: seller.ts running"
fi

# ─────────────────────────────────────────
# CHECK 2 — Seller rejecting jobs
# ─────────────────────────────────────────
SELLER_LOG=$(ls -t ~/.openclaw/virtuals-acp/logs/*.log 2>/dev/null | head -1)
if [ -f "$SELLER_LOG" ]; then
  # Check for syntax/transform errors in last 30 min
  ERRORS=$(grep -E "SyntaxError|TransformError|Cannot find|TypeError" \
    "$SELLER_LOG" | \
    awk -v cutoff="$(date -u -d '30 minutes ago' '+%Y-%m-%dT%H:%M')" \
    '$0 > cutoff' | wc -l)
  if [ "$ERRORS" -gt 0 ]; then
    log "FAILURE: $ERRORS errors in seller log (last 30min)"
    alarm "CRITICAL" \
      "CrawDaddy seller has $ERRORS errors in last 30min — possible handlers.ts issue. Check seller.log"
  else
    log "OK: no seller errors in last 30min"
  fi

  # Check for job rejections
  REJECTIONS=$(grep "accept=false" "$SELLER_LOG" | \
    grep "$(date '+%Y-%m-%d')" | wc -l)
  if [ "$REJECTIONS" -gt 2 ]; then
    alarm "CRITICAL" \
      "CrawDaddy rejecting jobs — $REJECTIONS today. Revenue lost. Check handlers.ts"
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
    alarm "WARNING" "ResearchBot down and failed to restart"
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
    alarm "CRITICAL" \
      "Conway credits CRITICAL: $(echo "$CREDITS" | awk '{printf "%.2f", $1/100}') — Bastion will die soon. Add credits NOW."
  elif [ "$CREDITS" -lt 150 ]; then
    alarm "WARNING" \
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
    alarm "CRITICAL" \
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
  alarm "CRITICAL" "EC2 disk at ${DISK}% — approaching full. Clean up logs."
elif [ "$DISK" -gt 75 ]; then
  alarm "WARNING" "EC2 disk at ${DISK}% — monitor closely"
fi
log "OK: disk at ${DISK}%"

# ─────────────────────────────────────────
# CHECK 8 — Openclaw gateway
# ─────────────────────────────────────────
if ! pgrep -f "openclaw" > /dev/null; then
  log "FAILURE: openclaw gateway not running"
  alarm "CRITICAL" \
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
    alarm "WARNING" \
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
