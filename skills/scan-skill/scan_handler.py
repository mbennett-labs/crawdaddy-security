#!/usr/bin/env python3
"""
QuantumShield Quick Security Scan - Telegram Handler
Scans GitHub repos for quantum-vulnerable cryptography
"""

import os
import re
import asyncio
import subprocess
import tempfile
import shutil
from datetime import datetime
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes

# Get bot token from environment
BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")

async def scan_help(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show help message"""
    help_text = """
🛡️ *QuantumShield Quick Security Scan*

Scan any public GitHub repo for quantum-vulnerable cryptography.

*Commands:*
/scan <github-url> - Scan a repository
/scanhelp - Show this message

*Example:*
/scan https://github.com/username/repo

*Cost:* 0.001 ETH (~$3)
*Time:* < 5 minutes

Powered by $QSHIELD on Base
    """
    await update.message.reply_text(help_text, parse_mode='Markdown')

async def scan_repo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Scan a GitHub repository"""

    # Check if URL provided
    if not context.args:
        await update.message.reply_text("❌ Please provide a GitHub URL\n\nExample: /scan https://github.com/username/repo")
        return

    url = context.args[0]

    # Validate GitHub URL
    github_pattern = r'^https?://github\.com/[\w\-\.]+/[\w\-\.]+/?$'
    if not re.match(github_pattern, url):
        await update.message.reply_text("❌ Invalid GitHub URL\n\nMust be: https://github.com/username/repo")
        return

    # Notify user scan is starting
    await update.message.reply_text(f"🔍 Starting scan of:\n{url}\n\n⏳ This may take a few minutes...")

    # Create temp directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    scan_dir = f"/tmp/scan-{timestamp}"
    report_path = f"/tmp/report-{timestamp}.html"

    try:
        # Clone repo
        await update.message.reply_text("📥 Cloning repository...")
        result = subprocess.run(
            ["git", "clone", "--depth", "1", url, scan_dir],
            capture_output=True,
            text=True,
            timeout=120
        )

        if result.returncode != 0:
            await update.message.reply_text(f"❌ Failed to clone repository\n\n{result.stderr}")
            return

        # Run crypto-scanner
        await update.message.reply_text("🔬 Scanning for vulnerabilities...")
        result = subprocess.run(
            ["/home/ubuntu/.local/bin/crypto-scanner", "scan", scan_dir, "--html", "--output", report_path],
            capture_output=True,
            text=True,
            timeout=300
        )

        if result.returncode != 0:
            await update.message.reply_text(f"❌ Scan failed\n\n{result.stderr}")
            return

        # Send report
        await update.message.reply_text("📄 Scan complete! Sending report...")

        with open(report_path, 'rb') as report_file:
            doc_msg = await update.message.reply_document(
                document=report_file,
                filename=f"qshield-scan-{timestamp}.html",
                caption="🛡️ QuantumShield Security Scan Report\n\nOpen in browser to view full results."
            )

        warning_msg = await update.message.reply_text(
            "⏳ This report will self-destruct in 1 hour. Download it now.",
            reply_to_message_id=doc_msg.message_id
        )

        # Schedule message deletion after 1 hour
        async def _delete_after_delay(chat_id, msg_ids, delay=3600):
            await asyncio.sleep(delay)
            for mid in msg_ids:
                try:
                    await context.bot.delete_message(chat_id=chat_id, message_id=mid)
                except Exception:
                    pass  # Message may already be deleted

        asyncio.create_task(
            _delete_after_delay(
                update.effective_chat.id,
                [doc_msg.message_id, warning_msg.message_id]
            )
        )

        await update.message.reply_text("✅ Scan complete!\n\n🛡️ Powered by QuantumShield\n💎 $QSHIELD on Base")

    except subprocess.TimeoutExpired:
        await update.message.reply_text("❌ Scan timed out. Repository may be too large.")
    except Exception as e:
        await update.message.reply_text(f"❌ Error: {str(e)}")
    finally:
        # Cleanup
        if os.path.exists(scan_dir):
            shutil.rmtree(scan_dir)
        if os.path.exists(report_path):
            os.remove(report_path)

def main():
    """Start the bot"""
    if not BOT_TOKEN:
        print("ERROR: TELEGRAM_BOT_TOKEN not set")
        return

    app = Application.builder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("scanhelp", scan_help))
    app.add_handler(CommandHandler("scan", scan_repo))

    print("🛡️ QuantumShield Scan Bot starting...")
    app.run_polling()

if __name__ == "__main__":
    main()
