#!/bin/bash
# ============================================================================
# CrawDaddy Moltlaunch Task Automation Daemon
# ============================================================================
# Polls Moltlaunch inbox for new tasks, auto-quotes, runs scans on accepted
# tasks, and submits results back. Full autonomous agent loop.
#
# Install: Copy to EC2, chmod +x, run setup script below
# Requires: mltl CLI, jq, git
# ============================================================================

set -euo pipefail

# === CONFIGURATION ===
AGENT_ID="0x41c7"
WALLET_ADDRESS="0xb1053C3C80551E958C3BBf49BC567F0d8dA67d27"
WORK_DIR="/home/ubuntu/crawdaddy-tasks"
LOG_FILE="/home/ubuntu/logs/moltlaunch-daemon.log"
SCAN_SCRIPT="/home/ubuntu/scripts/qshield-scan.sh"
REPORTS_DIR="/home/ubuntu/crawdaddy-tasks/reports"

# Polling intervals (seconds)
POLL_INBOX=120        # Check for new tasks every 2 min
POLL_ACCEPTED=60      # Check accepted tasks every 1 min (client waiting)
POLL_SUBMITTED=300    # Check submitted tasks every 5 min
POLL_IDLE=300         # Idle polling every 5 min

# Pricing (ETH) - matches Moltlaunch gig listings
PRICE_QUICK_SCAN="0.001"
PRICE_DEEP_ASSESSMENT="0.05"
PRICE_MIGRATION_PLAN="0.5"

# === SETUP ===
mkdir -p "$WORK_DIR" "$REPORTS_DIR" "$(dirname "$LOG_FILE")"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log "🦞 CrawDaddy Moltlaunch Daemon starting..."
log "Agent: $AGENT_ID | Wallet: $WALLET_ADDRESS"

# === HELPER FUNCTIONS ===

# Determine price based on task description
determine_price() {
    local task_desc="$1"
    task_lower=$(echo "$task_desc" | tr '[:upper:]' '[:lower:]')
    
    if echo "$task_lower" | grep -qE "migration|roadmap|full|comprehensive|plan"; then
        echo "$PRICE_MIGRATION_PLAN"
    elif echo "$task_lower" | grep -qE "assessment|deep|detailed|audit|evaluation"; then
        echo "$PRICE_DEEP_ASSESSMENT"
    else
        echo "$PRICE_QUICK_SCAN"
    fi
}

# Extract GitHub URL from task description
extract_repo_url() {
    local text="$1"
    echo "$text" | grep -oP 'https?://github\.com/[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+' | head -1
}

# Run the actual scan
run_scan() {
    local repo_url="$1"
    local task_id="$2"
    local report_file="$REPORTS_DIR/${task_id}-report.md"
    
    log "🔍 Running scan on: $repo_url"
    
    # Clone the repo
    local repo_dir="$WORK_DIR/repos/$(basename "$repo_url")-$(date +%s)"
    mkdir -p "$WORK_DIR/repos"
    
    if ! git clone --depth 1 "$repo_url" "$repo_dir" 2>/dev/null; then
        log "❌ Failed to clone $repo_url"
        echo "Failed to clone repository. Please verify the URL is correct and the repo is public." > "$report_file"
        echo "$report_file"
        return 1
    fi
    
    # Run scan using existing scan script if available
    if [ -f "$SCAN_SCRIPT" ]; then
        log "Using qshield-scan.sh for scan..."
        bash "$SCAN_SCRIPT" "$repo_dir" "$report_file" 2>/dev/null || true
    fi
    
    # If scan script didn't produce output or doesn't exist, run manual scan
    if [ ! -s "$report_file" ]; then
        log "Running manual cryptographic scan..."
        generate_scan_report "$repo_dir" "$repo_url" "$report_file"
    fi
    
    # Cleanup cloned repo
    rm -rf "$repo_dir"
    
    log "✅ Report generated: $report_file"
    echo "$report_file"
}

# Generate scan report by analyzing the codebase
generate_scan_report() {
    local repo_dir="$1"
    local repo_url="$2"
    local report_file="$3"
    
    local critical=0
    local warnings=0
    local findings=""
    
    # Scan for quantum-vulnerable crypto patterns
    # RSA usage
    local rsa_hits=$(grep -rl --include="*.py" --include="*.js" --include="*.ts" --include="*.java" --include="*.go" --include="*.rs" --include="*.rb" --include="*.php" --include="*.c" --include="*.cpp" --include="*.cs" -iE "RSA|rsa_key|RSAPublicKey|RSA-OAEP|RSA_PKCS1" "$repo_dir" 2>/dev/null | head -20)
    if [ -n "$rsa_hits" ]; then
        critical=$((critical + 1))
        while IFS= read -r file; do
            local rel_path="${file#$repo_dir/}"
            local line_num=$(grep -n -iE "RSA|rsa_key|RSAPublicKey" "$file" 2>/dev/null | head -1 | cut -d: -f1)
            findings="$findings\n### ⛔ CRITICAL: RSA Key Usage\n- **File:** \`$rel_path\` (Line $line_num)\n- **Risk:** RSA is quantum-vulnerable. Shor's algorithm breaks RSA in polynomial time.\n- **Fix:** Migrate to ML-KEM (CRYSTALS-Kyber) for key encapsulation.\n"
        done <<< "$rsa_hits"
    fi
    
    # ECC/ECDSA usage
    local ecc_hits=$(grep -rl --include="*.py" --include="*.js" --include="*.ts" --include="*.java" --include="*.go" --include="*.rs" -iE "ECDSA|secp256k1|P-256|P-384|elliptic_curve|EC_KEY|ecdh" "$repo_dir" 2>/dev/null | head -20)
    if [ -n "$ecc_hits" ]; then
        critical=$((critical + 1))
        while IFS= read -r file; do
            local rel_path="${file#$repo_dir/}"
            findings="$findings\n### ⛔ CRITICAL: Elliptic Curve Cryptography\n- **File:** \`$rel_path\`\n- **Risk:** ECC/ECDSA is quantum-vulnerable via Shor's algorithm.\n- **Fix:** Migrate to ML-DSA (CRYSTALS-Dilithium) for signatures, ML-KEM for key exchange.\n"
        done <<< "$ecc_hits"
    fi
    
    # SHA-1 usage
    local sha1_hits=$(grep -rl --include="*.py" --include="*.js" --include="*.ts" --include="*.java" --include="*.go" -iE "sha1|SHA-1|sha_1|hashlib\.sha1|createHash\('sha1'\)" "$repo_dir" 2>/dev/null | head -10)
    if [ -n "$sha1_hits" ]; then
        warnings=$((warnings + 1))
        findings="$findings\n### ⚠️ WARNING: SHA-1 Hash Usage\n- **Files:** $(echo "$sha1_hits" | sed "s|$repo_dir/||g" | tr '\n' ', ')\n- **Risk:** SHA-1 is deprecated and collision-vulnerable. Quantum Grover's attack further weakens it.\n- **Fix:** Upgrade to SHA-256 minimum, SHA-3 preferred.\n"
    fi
    
    # Hardcoded secrets
    local secret_hits=$(grep -rl --include="*.py" --include="*.js" --include="*.ts" --include="*.env" --include="*.yaml" --include="*.yml" --include="*.json" -iE "(api_key|apikey|secret_key|password|private_key)\s*[:=]\s*['\"][a-zA-Z0-9]" "$repo_dir" 2>/dev/null | grep -v node_modules | grep -v ".lock" | head -10)
    if [ -n "$secret_hits" ]; then
        critical=$((critical + 1))
        findings="$findings\n### ⛔ CRITICAL: Potential Hardcoded Secrets\n- **Files:** $(echo "$secret_hits" | sed "s|$repo_dir/||g" | tr '\n' ', ')\n- **Risk:** Exposed credentials in source code.\n- **Fix:** Use environment variables or secrets management (Vault, AWS Secrets Manager).\n"
    fi
    
    # Weak TLS
    local tls_hits=$(grep -rl --include="*.py" --include="*.js" --include="*.ts" --include="*.conf" --include="*.yaml" -iE "TLSv1\.0|TLSv1\.1|SSLv3|ssl_version|TLS_1_0" "$repo_dir" 2>/dev/null | head -5)
    if [ -n "$tls_hits" ]; then
        warnings=$((warnings + 1))
        findings="$findings\n### ⚠️ WARNING: Outdated TLS Version\n- **Files:** $(echo "$tls_hits" | sed "s|$repo_dir/||g" | tr '\n' ', ')\n- **Risk:** TLS 1.0/1.1 are deprecated and vulnerable.\n- **Fix:** Enforce TLS 1.3 minimum.\n"
    fi
    
    # Count total files scanned
    local total_files=$(find "$repo_dir" -type f \( -name "*.py" -o -name "*.js" -o -name "*.ts" -o -name "*.java" -o -name "*.go" -o -name "*.rs" -o -name "*.rb" -o -name "*.c" -o -name "*.cpp" \) | grep -v node_modules | wc -l)
    
    # Calculate quantum readiness score
    local score=100
    score=$((score - (critical * 25)))
    score=$((score - (warnings * 10)))
    if [ $score -lt 0 ]; then score=0; fi
    
    # Determine risk level
    local risk_level="LOW"
    local risk_emoji="🟢"
    if [ $score -lt 70 ]; then risk_level="MEDIUM"; risk_emoji="🟡"; fi
    if [ $score -lt 40 ]; then risk_level="HIGH"; risk_emoji="🔴"; fi
    
    # Generate the report
    cat > "$report_file" << REPORT
# 🦞 CrawDaddy Security Scan Report
## QuantumShield Labs — Post-Quantum Vulnerability Analysis

---

| Field | Value |
|-------|-------|
| **Repository** | $repo_url |
| **Scanned** | $(date '+%Y-%m-%d %H:%M:%S %Z') |
| **Files Analyzed** | $total_files |
| **Scanner** | QuantumShield v1.0 |
| **Agent** | CrawDaddy (Moltlaunch Agent $AGENT_ID) |

---

## Quantum Readiness Score: $score/100 $risk_emoji

**Risk Level: $risk_level**

| Category | Count |
|----------|-------|
| ⛔ Critical | $critical |
| ⚠️ Warnings | $warnings |
| ✅ Passing | $((total_files - critical - warnings)) |

---

## Findings

$(echo -e "$findings")

---

## Recommendations

1. **Immediate:** Replace all RSA and ECC usage with NIST-approved post-quantum algorithms (ML-KEM, ML-DSA)
2. **Short-term:** Audit all cryptographic dependencies and upgrade to quantum-safe versions
3. **Medium-term:** Implement crypto-agility layer for future algorithm swaps
4. **Ongoing:** Monitor NIST PQC standardization updates

---

## What is Harvest-Now-Decrypt-Later?

Adversaries are collecting encrypted data TODAY, storing it until quantum computers can break the encryption (estimated 2027-2030). If your data has long-term value (healthcare records, financial data, intellectual property), the threat is NOW, not later.

---

## Next Steps

- **Deep Assessment (0.05 ETH):** Full infrastructure evaluation with migration priority matrix
- **Migration Plan (0.5 ETH):** Complete PQC migration roadmap with implementation guide
- **Contact:** @QuarkMichael on X | quantumshieldlabs.dev

---

*Powered by QuantumShield Labs × CrawDaddy 🦞*
*Report ID: $(echo "$task_id" | head -c 12)*
REPORT
}


# === MAIN TASK PROCESSING FUNCTIONS ===

# Process new task requests (quote them)
process_new_requests() {
    log "📥 Checking inbox for new requests..."
    
    local inbox_json
    inbox_json=$(mltl inbox --agent "$AGENT_ID" --json 2>/dev/null) || {
        log "⚠️ Failed to fetch inbox"
        return 0
    }
    
    # Check if there are tasks
    local task_count
    task_count=$(echo "$inbox_json" | jq -r '.total // 0' 2>/dev/null) || task_count=0
    
    if [ "$task_count" -eq 0 ]; then
        log "📭 Inbox empty"
        return 0
    fi
    
    log "📬 Found $task_count task(s) in inbox"
    
    # Process each task
    echo "$inbox_json" | jq -c '.tasks[]? // empty' 2>/dev/null | while IFS= read -r task; do
        local task_id=$(echo "$task" | jq -r '.id')
        local task_status=$(echo "$task" | jq -r '.status')
        local task_desc=$(echo "$task" | jq -r '.task')
        local client=$(echo "$task" | jq -r '.clientAddress')
        
        log "  Task $task_id | Status: $task_status | Client: $client"
        log "  Description: $task_desc"
        
        case "$task_status" in
            "requested")
                handle_requested "$task_id" "$task_desc" "$client"
                ;;
            "accepted")
                handle_accepted "$task_id" "$task_desc"
                ;;
            "submitted")
                handle_submitted "$task_id"
                ;;
            *)
                log "  ℹ️ Status '$task_status' — no action needed"
                ;;
        esac
    done
}

# Handle new request: auto-quote
handle_requested() {
    local task_id="$1"
    local task_desc="$2"
    local client="$3"
    
    # Check if we already quoted (avoid double-quoting)
    local task_detail
    task_detail=$(mltl view --task "$task_id" --json 2>/dev/null) || true
    local already_quoted=$(echo "$task_detail" | jq -r '.quotedPriceWei // empty' 2>/dev/null)
    
    if [ -n "$already_quoted" ]; then
        log "  ✅ Already quoted task $task_id, waiting for client"
        return 0
    fi
    
    # Determine price based on task description
    local price=$(determine_price "$task_desc")
    
    # Extract repo URL for the quote message
    local repo_url=$(extract_repo_url "$task_desc")
    local quote_msg="CrawDaddy here 🦞 I'll scan this for quantum-vulnerable cryptography, hardcoded secrets, and security issues. Results delivered as a full markdown report."
    
    if [ -n "$repo_url" ]; then
        quote_msg="$quote_msg Detected repo: $repo_url — I'll have results ready within minutes of your acceptance."
    else
        quote_msg="$quote_msg Please include a public GitHub repo URL in your task description so I can run the scan."
    fi
    
    log "  💰 Quoting $price ETH for task $task_id"
    
    mltl quote --task "$task_id" --price "$price" --message "$quote_msg" 2>&1 | tee -a "$LOG_FILE"
    
    if [ $? -eq 0 ]; then
        log "  ✅ Quote sent: $price ETH"
    else
        log "  ❌ Failed to send quote"
    fi
}

# Handle accepted task: escrow funded, DO THE WORK
handle_accepted() {
    local task_id="$1"
    local task_desc="$2"
    
    log "  🔒 Escrow funded for task $task_id — STARTING WORK"
    
    # Extract repo URL
    local repo_url=$(extract_repo_url "$task_desc")
    
    if [ -z "$repo_url" ]; then
        log "  ⚠️ No GitHub URL found in task description"
        # Message the client asking for a URL
        mltl message --task "$task_id" --content "🦞 Hey! I need a public GitHub repo URL to scan. Can you share the link? Example: https://github.com/username/repo" 2>&1 | tee -a "$LOG_FILE"
        return 0
    fi
    
    # Run the scan
    local report_file
    report_file=$(run_scan "$repo_url" "$task_id")
    
    if [ -f "$report_file" ]; then
        log "  📤 Submitting results for task $task_id"
        
        # Read report for inline result
        local result_summary
        result_summary=$(head -30 "$report_file")
        
        # Submit with file attachment
        mltl submit --task "$task_id" \
            --result "🦞 CrawDaddy scan complete. Full report attached. See quantum readiness score and all findings in the report file." \
            --files "$report_file" 2>&1 | tee -a "$LOG_FILE"
        
        if [ $? -eq 0 ]; then
            log "  ✅ Work submitted with report attached!"
            log "  ⏰ 24h review window started. Client can approve, revise, or dispute."
        else
            log "  ❌ Failed to submit. Trying without file..."
            # Fallback: submit result as text
            local result_text=$(cat "$report_file")
            mltl submit --task "$task_id" --result "$result_text" 2>&1 | tee -a "$LOG_FILE"
        fi
    else
        log "  ❌ Scan failed for $repo_url"
        mltl message --task "$task_id" --content "🦞 Had trouble scanning that repo. Could you verify the URL is correct and the repo is public? I'll retry once confirmed." 2>&1 | tee -a "$LOG_FILE"
    fi
}

# Handle submitted task: check for timeout to auto-claim
handle_submitted() {
    local task_id="$1"
    
    local task_detail
    task_detail=$(mltl view --task "$task_id" --json 2>/dev/null) || return 0
    
    local submitted_at=$(echo "$task_detail" | jq -r '.submittedAt // 0')
    local now=$(date +%s%3N)  # milliseconds
    local elapsed=$(( (now - submitted_at) / 1000 / 3600 ))  # hours
    
    if [ "$elapsed" -ge 24 ]; then
        log "  ⏰ 24h timeout reached for task $task_id — claiming payment"
        mltl claim --task "$task_id" 2>&1 | tee -a "$LOG_FILE"
    else
        local remaining=$((24 - elapsed))
        log "  ⏳ Task $task_id submitted, ${remaining}h until auto-claim"
    fi
}

# Check for fee claims
check_and_claim_fees() {
    log "💰 Checking for claimable fees..."
    
    local fees_json
    fees_json=$(mltl fees --json 2>/dev/null) || {
        log "⚠️ Failed to check fees"
        return 0
    }
    
    local pending=$(echo "$fees_json" | jq -r '.pendingFees // "0"' 2>/dev/null)
    
    if [ -n "$pending" ] && [ "$pending" != "0" ] && [ "$pending" != "null" ]; then
        log "  💰 Pending fees: $pending ETH — claiming..."
        mltl fees --claim 2>&1 | tee -a "$LOG_FILE"
    else
        log "  📊 No fees to claim right now"
    fi
}


# === MAIN LOOP ===

log "🚀 Daemon running. Press Ctrl+C to stop."
log "Polling inbox every ${POLL_INBOX}s, accepted tasks every ${POLL_ACCEPTED}s"

cycle=0

while true; do
    cycle=$((cycle + 1))
    
    # Every cycle: check inbox for new/accepted tasks
    process_new_requests
    
    # Every 10 cycles (~20 min): check for fee claims
    if [ $((cycle % 10)) -eq 0 ]; then
        check_and_claim_fees
    fi
    
    # Every 30 cycles (~1 hour): log heartbeat
    if [ $((cycle % 30)) -eq 0 ]; then
        log "💓 Heartbeat — Cycle $cycle, daemon healthy"
        log "📊 Wallet: $(mltl wallet 2>/dev/null | grep -i balance || echo 'check failed')"
    fi
    
    # Sleep
    sleep "$POLL_INBOX"
done
