#!/usr/bin/env python3
"""
CrawDaddy Autoresearch Orchestrator
Runs experiments every 6 hours to improve detection patterns.
"""

import argparse
import hashlib
import json
import os
import random
import re
import sqlite3
import subprocess
import sys
import urllib.request
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path

# --- Config ---
DB_PATH = Path.home() / "crawdaddy-security" / "autoresearch.db"
RESOURCES_MD = Path.home() / "crawdaddy-security" / "resources.md"
REPOS_DIR = Path.home() / "crawdaddy-security" / "autoresearch" / "repos"
ENV_FILE = Path(__file__).parent / ".env"

TEST_REPOS = [
    "https://github.com/openclaw/openclaw",
    "https://github.com/mbennett-labs/crawdaddy-security",
    "https://github.com/mbennett-labs/automaton",
]

# Detection patterns that can be tuned
BASELINE_PATTERNS = {
    "honeypot_threshold": 50,
    "sell_tax_warning": 10,
    "holder_concentration": 50,
    "risk_critical": 80,
    "risk_high": 60,
    "risk_medium": 40,
    "risk_low": 20,
}

PATTERN_MUTATIONS = {
    "honeypot_threshold": (30, 70),
    "sell_tax_warning": (5, 20),
    "holder_concentration": (30, 70),
    "risk_critical": (70, 90),
    "risk_high": (50, 75),
    "risk_medium": (30, 55),
    "risk_low": (10, 30),
}


def load_env():
    """Load env vars from .env file."""
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, val = line.split("=", 1)
                os.environ.setdefault(key.strip(), val.strip())


def init_db():
    """Create SQLite database and experiments table."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS experiments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            hypothesis TEXT NOT NULL,
            baseline_score REAL NOT NULL,
            challenger_score REAL NOT NULL,
            winner TEXT NOT NULL,
            learning TEXT NOT NULL
        )
    """)
    conn.commit()
    return conn


def clone_or_pull(repo_url: str) -> Path:
    """Clone repo if not present, otherwise pull latest."""
    repo_name = repo_url.rstrip("/").split("/")[-1]
    repo_dir = REPOS_DIR / repo_name
    REPOS_DIR.mkdir(parents=True, exist_ok=True)

    if repo_dir.exists():
        subprocess.run(
            ["git", "-C", str(repo_dir), "pull", "--ff-only"],
            capture_output=True, timeout=60
        )
    else:
        subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, str(repo_dir)],
            capture_output=True, timeout=120
        )
    return repo_dir


def find_handlers(repo_dir: Path) -> list[Path]:
    """Find handlers.ts files in a repo."""
    return list(repo_dir.rglob("handlers.ts"))


def score_handlers(handlers_files: list[Path], patterns: dict) -> float:
    """
    Score detection quality 0-100 based on pattern coverage.
    Checks how well the handlers cover key security patterns.
    """
    if not handlers_files:
        return 0.0

    total_score = 0.0
    checks = 0

    for f in handlers_files:
        try:
            content = f.read_text()
        except Exception:
            continue

        # Check: honeypot detection present and threshold reasonable
        if "honeypot" in content.lower() or "isHoneypot" in content:
            total_score += 15
        checks += 1

        # Check: sell tax detection
        if "sellTax" in content or "sell_tax" in content:
            threshold = patterns.get("sell_tax_warning", 10)
            if f"> {threshold}" in content or f"> {threshold}" in content:
                total_score += 15
            else:
                total_score += 10
        checks += 1

        # Check: holder concentration analysis
        if "holderPercent" in content or "holder_concentration" in content:
            total_score += 10
        checks += 1

        # Check: mintable token detection
        if "isMintable" in content or "mintable" in content.lower():
            total_score += 10
        checks += 1

        # Check: blacklist detection
        if "blacklist" in content.lower() or "hasBlacklist" in content:
            total_score += 10
        checks += 1

        # Check: source verification
        if "isOpenSource" in content or "open_source" in content:
            total_score += 10
        checks += 1

        # Check: risk level categorization
        risk_levels = sum(1 for lvl in ["critical", "high", "medium", "low", "minimal"]
                         if lvl in content.lower())
        total_score += min(risk_levels * 4, 15)
        checks += 1

        # Check: multi-chain support
        chains = sum(1 for c in ["ethereum", "bsc", "arbitrum", "polygon", "solana", "base"]
                     if c in content.lower())
        total_score += min(chains * 2.5, 15)
        checks += 1

    # Normalize to 0-100
    max_possible = 100.0
    return min(round(total_score, 1), max_possible)


def generate_hypothesis(patterns: dict) -> tuple[str, dict]:
    """Generate one challenger hypothesis by mutating a single pattern."""
    key = random.choice(list(PATTERN_MUTATIONS.keys()))
    lo, hi = PATTERN_MUTATIONS[key]
    old_val = patterns[key]
    new_val = random.randint(lo, hi)
    while new_val == old_val:
        new_val = random.randint(lo, hi)

    challenger = dict(patterns)
    challenger[key] = new_val
    hypothesis = f"Change {key} from {old_val} to {new_val}"
    return hypothesis, challenger


def send_telegram(message: str, dry_run: bool = False):
    """Send a message via Telegram bot."""
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")

    if not token or not chat_id:
        print("[telegram] TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID not set, skipping")
        return

    if dry_run:
        print(f"[telegram][dry-run] Would send: {message[:200]}...")
        return

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    data = json.dumps({"chat_id": chat_id, "text": message, "parse_mode": "Markdown"}).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=10)
        print("[telegram] Summary sent")
    except Exception as e:
        print(f"[telegram] Failed to send: {e}")


def should_send_daily_summary(conn: sqlite3.Connection) -> bool:
    """Check if we've sent a summary in the last 24 hours."""
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    row = conn.execute(
        "SELECT COUNT(*) FROM experiments WHERE timestamp > ? AND learning LIKE '%[daily-summary-sent]%'",
        (cutoff,)
    ).fetchone()
    return row[0] == 0


def build_daily_summary(conn: sqlite3.Connection) -> str:
    """Build daily summary message."""
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    rows = conn.execute(
        "SELECT hypothesis, baseline_score, challenger_score, winner, learning "
        "FROM experiments WHERE timestamp > ? ORDER BY id DESC",
        (cutoff,)
    ).fetchall()

    if not rows:
        return "No experiments run in the last 24 hours."

    best_score = max(max(r[1], r[2]) for r in rows)
    wins = sum(1 for r in rows if r[3] == "challenger")
    top_learning = rows[0][4] if rows else "N/A"

    return (
        f"*CrawDaddy Autoresearch Daily*\n"
        f"Experiments today: {len(rows)}\n"
        f"Challenger wins: {wins}/{len(rows)}\n"
        f"Current best score: {best_score}\n"
        f"Top learning: {top_learning}"
    )


def append_to_resources(learning: str):
    """Append a learning to resources.md."""
    RESOURCES_MD.parent.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
    entry = f"\n- [{timestamp}] {learning}\n"

    if RESOURCES_MD.exists():
        content = RESOURCES_MD.read_text()
    else:
        content = "# CrawDaddy Autoresearch Learnings\n"

    RESOURCES_MD.write_text(content + entry)


def run_experiment(conn: sqlite3.Connection, dry_run: bool = False):
    """Run one experiment cycle across all test repos."""
    print(f"\n{'='*60}")
    print(f"Experiment cycle starting at {datetime.now(timezone.utc).isoformat()}")
    print(f"{'='*60}")

    all_handlers = []
    for repo_url in TEST_REPOS:
        repo_name = repo_url.split("/")[-1]
        if dry_run:
            print(f"[dry-run] Would clone/pull {repo_name}")
        else:
            try:
                repo_dir = clone_or_pull(repo_url)
                handlers = find_handlers(repo_dir)
                all_handlers.extend(handlers)
                print(f"[repo] {repo_name}: found {len(handlers)} handlers.ts")
            except Exception as e:
                print(f"[repo] {repo_name}: error - {e}")

    # For dry-run, also check local handlers
    local_handlers = list(Path.home().joinpath("crawdaddy-security", "autoresearch").rglob("*.ts"))
    all_handlers.extend(local_handlers)

    # Score baseline
    baseline_score = score_handlers(all_handlers, BASELINE_PATTERNS)
    print(f"[baseline] Score: {baseline_score}/100")

    # Generate challenger
    hypothesis, challenger_patterns = generate_hypothesis(BASELINE_PATTERNS)
    print(f"[challenger] Hypothesis: {hypothesis}")

    challenger_score = score_handlers(all_handlers, challenger_patterns)
    print(f"[challenger] Score: {challenger_score}/100")

    # Compare
    diff = challenger_score - baseline_score
    if diff >= 2:
        winner = "challenger"
        learning = f"WIN (+{diff}): {hypothesis}"
    elif diff <= -2:
        winner = "baseline"
        learning = f"LOSE ({diff}): {hypothesis} - baseline better"
    else:
        winner = "tie"
        learning = f"TIE (diff={diff}): {hypothesis} - no significant difference"

    print(f"[result] Winner: {winner} | Learning: {learning}")

    # Log to SQLite
    if not dry_run:
        conn.execute(
            "INSERT INTO experiments (timestamp, hypothesis, baseline_score, challenger_score, winner, learning) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (datetime.now(timezone.utc).isoformat(), hypothesis, baseline_score, challenger_score, winner, learning)
        )
        conn.commit()

        # Append top learning to resources.md
        append_to_resources(learning)

        # Daily Telegram summary
        if should_send_daily_summary(conn):
            summary = build_daily_summary(conn)
            send_telegram(summary)
            conn.execute(
                "INSERT INTO experiments (timestamp, hypothesis, baseline_score, challenger_score, winner, learning) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (datetime.now(timezone.utc).isoformat(), "daily-summary", 0, 0, "n/a", "[daily-summary-sent]")
            )
            conn.commit()
    else:
        print(f"[dry-run] Would log to SQLite: {learning}")
        print(f"[dry-run] Would append to resources.md")
        if should_send_daily_summary(conn):
            summary = build_daily_summary(conn)
            send_telegram(summary, dry_run=True)

    return winner, learning


def main():
    parser = argparse.ArgumentParser(description="CrawDaddy Autoresearch Orchestrator")
    parser.add_argument("--dry-run", action="store_true", help="Run without cloning repos or writing results")
    args = parser.parse_args()

    load_env()
    conn = init_db()

    try:
        winner, learning = run_experiment(conn, dry_run=args.dry_run)
        print(f"\nDone. Winner: {winner}")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
