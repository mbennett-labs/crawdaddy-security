#!/bin/bash
# Bastion Conway Automaton Watchdog - restarts bastion.service if dead + Telegram alerts

LOG="/home/ubuntu/crawdaddy-security/logs/bastion-watchdog.log"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
BOT_TOKEN="REDACTED_TOKEN_2"
CHAT_ID="REDACTED_CHAT_ID"

notify() {
  curl -s "https://api.telegram.org/bot${BOT_TOKEN}/sendMessage" \
    -d "chat_id=${CHAT_ID}" \
    -d "text=$1" > /dev/null
}

if ! systemctl is-active --quiet bastion.service; then
    echo "[$TIMESTAMP] Bastion DOWN - restarting..." >> $LOG
    notify "🛡️ Bastion Conway automaton DOWN — restarting now..."
    sudo systemctl start bastion.service
    sleep 10
    if systemctl is-active --quiet bastion.service; then
        echo "[$TIMESTAMP] Bastion restarted OK" >> $LOG
        notify "✅ Bastion Conway automaton back online"
    else
        echo "[$TIMESTAMP] Bastion restart FAILED" >> $LOG
        notify "❌ Bastion restart FAILED — manual intervention needed"
    fi
else
    echo "[$TIMESTAMP] Bastion OK" >> $LOG
fi
