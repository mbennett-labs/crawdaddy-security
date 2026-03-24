#!/bin/bash
# Conway Spending Watchdog — stops Bastion if burn rate exceeds $0.50/hr
# Runs every 30 minutes via cron: */30 * * * *

LOG="/home/ubuntu/crawdaddy-security/logs/conway-watchdog.log"
STATE_DB="/home/ubuntu/.automaton/state.db"
RATE_FILE="/home/ubuntu/crawdaddy-security/logs/.conway-watchdog-last-balance"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
BOT_TOKEN="REDACTED_TOKEN_1"
CHAT_ID="REDACTED_CHAT_ID"
MAX_SPEND_PER_30MIN_CENTS=25  # $0.25 per 30 min = $0.50/hr
ALARM="/home/ubuntu/crawdaddy-security/scripts/alarm.sh"

notify() {
  curl -s "https://api.telegram.org/bot${BOT_TOKEN}/sendMessage" \
    -d "chat_id=${CHAT_ID}" \
    -d "text=$1" > /dev/null
}

# Read current balance from state.db
if [ ! -f "$STATE_DB" ]; then
  echo "[$TIMESTAMP] ERROR: state.db not found at $STATE_DB" >> "$LOG"
  exit 1
fi

CURRENT_CENTS=$(sqlite3 "$STATE_DB" \
  "SELECT json_extract(value, '$.creditsCents') FROM kv WHERE key = 'last_known_balance'" 2>/dev/null)

if [ -z "$CURRENT_CENTS" ] || [ "$CURRENT_CENTS" = "null" ]; then
  echo "[$TIMESTAMP] WARN: Could not read creditsCents from state.db — skipping" >> "$LOG"
  exit 0
fi

CURRENT_DOLLARS=$(echo "scale=2; $CURRENT_CENTS / 100" | bc 2>/dev/null || echo "?")

# First run — no previous balance to compare
if [ ! -f "$RATE_FILE" ]; then
  echo "$CURRENT_CENTS" > "$RATE_FILE"
  echo "[$TIMESTAMP] Conway watchdog initialized — balance: \$${CURRENT_DOLLARS} (${CURRENT_CENTS}c)" >> "$LOG"
  exit 0
fi

PREV_CENTS=$(cat "$RATE_FILE" 2>/dev/null)
if [ -z "$PREV_CENTS" ]; then
  echo "$CURRENT_CENTS" > "$RATE_FILE"
  echo "[$TIMESTAMP] WARN: Previous balance file empty — reinitializing" >> "$LOG"
  exit 0
fi

# Calculate spend (previous - current; positive = credits consumed)
SPEND_CENTS=$((PREV_CENTS - CURRENT_CENTS))

# If balance went UP (topup happened), just record new baseline
if [ "$SPEND_CENTS" -lt 0 ]; then
  echo "$CURRENT_CENTS" > "$RATE_FILE"
  echo "[$TIMESTAMP] Conway OK — balance increased (topup?): \$${CURRENT_DOLLARS} (was ${PREV_CENTS}c)" >> "$LOG"
  exit 0
fi

RATE_PER_HOUR_CENTS=$((SPEND_CENTS * 2))
RATE_PER_HOUR_DOLLARS=$(echo "scale=2; $RATE_PER_HOUR_CENTS / 100" | bc 2>/dev/null || echo "?")

# Save current balance for next comparison
echo "$CURRENT_CENTS" > "$RATE_FILE"

if [ "$SPEND_CENTS" -gt "$MAX_SPEND_PER_30MIN_CENTS" ]; then
  echo "[$TIMESTAMP] ALERT: Spend rate \$${RATE_PER_HOUR_DOLLARS}/hr (${SPEND_CENTS}c in 30min) EXCEEDS threshold — stopping Bastion" >> "$LOG"
  sudo systemctl stop bastion.service
  notify "CONWAY WATCHDOG: Bastion stopped — spend rate exceeded \$0.50/hr (\$${RATE_PER_HOUR_DOLLARS}/hr). Balance: \$${CURRENT_DOLLARS}. Fix before restarting."
  $ALARM CRITICAL "Conway spend rate \$${RATE_PER_HOUR_DOLLARS}/hr — Bastion auto-stopped. Balance: \$${CURRENT_DOLLARS}"
  echo "[$TIMESTAMP] Bastion stopped by conway-watchdog" >> "$LOG"
else
  echo "[$TIMESTAMP] Conway OK — rate: \$${RATE_PER_HOUR_DOLLARS}/hr, balance: \$${CURRENT_DOLLARS}" >> "$LOG"
fi

# Credit level alerts (independent of spend rate)
if [ "$CURRENT_CENTS" -le 100 ] 2>/dev/null; then
  $ALARM CRITICAL "Conway credits critical: \$${CURRENT_DOLLARS} (${CURRENT_CENTS}c) — Bastion will die soon"
  echo "[$TIMESTAMP] ALARM: Credits critical \$${CURRENT_DOLLARS}" >> "$LOG"
elif [ "$CURRENT_CENTS" -le 200 ] 2>/dev/null; then
  $ALARM WARNING "Conway credits low: \$${CURRENT_DOLLARS} (${CURRENT_CENTS}c)"
  echo "[$TIMESTAMP] ALARM: Credits low \$${CURRENT_DOLLARS}" >> "$LOG"
fi
