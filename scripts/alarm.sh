#!/bin/bash
# QSL Swarm Alarm — fires on CRITICAL/WARNING events
# Usage: alarm.sh CRITICAL "Seller rejected job 1234"
# Usage: alarm.sh WARNING "Conway credits below $2"

SEVERITY="${1:-WARNING}"
MESSAGE="${2:-No message provided}"
TIMESTAMP=$(date -u '+%Y-%m-%d %H:%M UTC')

# Credentials sourced from env file (never hardcode)
source ~/.selarix.env 2>/dev/null
EMAIL_TO="michael@quantumshieldlabs.dev"

EMOJI="⚠️"
[ "$SEVERITY" = "CRITICAL" ] && EMOJI="🚨"

FULL_MSG="$EMOJI QSL SWARM $SEVERITY
$MESSAGE
Time: $TIMESTAMP
Dashboard: qsl-dashboard.vercel.app"

# Channel 1: Telegram (with delivery confirmation)
DELIVERED=""
if [ -n "$BOT_TOKEN" ] && [ -n "$CHAT_ID" ]; then
  TG_RESULT=$(curl -s -X POST \
    "https://api.telegram.org/bot$BOT_TOKEN/sendMessage" \
    -d chat_id="$CHAT_ID" \
    -d text="$FULL_MSG" 2>/dev/null)
  TG_OK=$(echo "$TG_RESULT" | python3 -c \
    "import sys,json; d=json.load(sys.stdin); \
     print('ok' if d.get('ok') else 'fail')" 2>/dev/null)
  if [ "$TG_OK" = "ok" ]; then
    DELIVERED="telegram"
  fi
fi

# Channel 2: Email via sendmail (always sends, also fallback if TG failed)
if command -v sendmail &>/dev/null; then
  echo -e "Subject: QSL $SEVERITY ALERT\nTo: $EMAIL_TO\n\n$FULL_MSG" | \
    sendmail "$EMAIL_TO" 2>/dev/null
  DELIVERED="${DELIVERED:+$DELIVERED+}email"
fi

# If Telegram failed, log the fallback
if [ "$TG_OK" != "ok" ] && [ -n "$BOT_TOKEN" ]; then
  echo "[$(date -u '+%Y-%m-%d %H:%M UTC')] WARNING: Telegram delivery failed — fell through to email" \
    >> /home/ubuntu/crawdaddy-security/logs/alarms.log
fi

# Channel 3: Twilio SMS (TODO — no credentials found)
# if [ -n "$TWILIO_SID" ] && [ -n "$TWILIO_AUTH" ] && [ -n "$TWILIO_FROM" ] && [ -n "$TWILIO_TO" ]; then
#   curl -s -X POST "https://api.twilio.com/2010-04-01/Accounts/$TWILIO_SID/Messages.json" \
#     -u "$TWILIO_SID:$TWILIO_AUTH" \
#     -d "From=$TWILIO_FROM" -d "To=$TWILIO_TO" -d "Body=$FULL_MSG" > /dev/null 2>&1 &
#   wait
#   DELIVERED="${DELIVERED:+$DELIVERED+}sms"
# fi

# Log every alarm
mkdir -p /home/ubuntu/crawdaddy-security/logs
echo "[$TIMESTAMP] $SEVERITY: $MESSAGE [delivered: ${DELIVERED:-NONE}]" >> /home/ubuntu/crawdaddy-security/logs/alarms.log

# Channel 4: IncidentResponder — auto-repair on CRITICAL alarms
IR_SCRIPT="$HOME/qsl-swarm/SELARIX-AGENTS/incident-responder/incident-responder.sh"
if [ "$SEVERITY" = "CRITICAL" ] && [ -x "$IR_SCRIPT" ]; then
  nohup "$IR_SCRIPT" "$SEVERITY" "$MESSAGE" >> /home/ubuntu/crawdaddy-security/logs/incidents.log 2>&1 &
  echo "[$TIMESTAMP] IncidentResponder dispatched for: $MESSAGE" >> /home/ubuntu/crawdaddy-security/logs/alarms.log
fi
