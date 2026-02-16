#!/usr/bin/env bash
# ============================================================================
# qshield-scan.sh v2 — QuantumShield Branded Security Scanner
# ============================================================================
# Scans GitHub repos for quantum-vulnerable cryptography.
# Produces full branded markdown report + GitHub Gist shareable link.
#
# Usage: bash qshield-scan.sh scan <github-url>
#        bash qshield-scan.sh info
#        bash qshield-scan.sh help
# ============================================================================

set -euo pipefail

# Source environment for GITHUB_TOKEN
[ -f /home/ubuntu/.env ] && source /home/ubuntu/.env

SCANNER="/home/ubuntu/.local/bin/crypto-scanner"
REPORTS_DIR="/home/ubuntu/crawdaddy-tasks/reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
GITHUB_API="https://api.github.com/gists"

mkdir -p "$REPORTS_DIR"

# ============================================================================
# HELPERS
# ============================================================================

usage() {
    echo "Usage: qshield-scan.sh <command> [args]"
    echo ""
    echo "Commands:"
    echo "  scan <github-url>    Clone and scan a GitHub repo"
    echo "  info                 Show scanner info"
    echo "  help                 Show this help message"
}

# Search source files for a pattern, returns file list (one per line)
search_source() {
    local dir="$1"
    local pattern="$2"
    grep -rPl --include="*.py" --include="*.js" --include="*.ts" --include="*.tsx" \
              --include="*.java" --include="*.go" --include="*.rs" --include="*.rb" \
              --include="*.php" --include="*.c" --include="*.cpp" --include="*.cs" \
              --include="*.swift" --include="*.kt" --include="*.scala" \
              "$pattern" "$dir" 2>/dev/null \
        | grep -v node_modules | grep -v '.lock' | grep -v vendor \
        | grep -v __pycache__ | grep -v '.min.js' | grep -v dist/ \
        | head -10 || true
}

# Search config/env files for a pattern
search_config() {
    local dir="$1"
    local pattern="$2"
    grep -rPl --include="*.env" --include="*.yaml" --include="*.yml" \
              --include="*.toml" --include="*.conf" --include="*.cfg" \
              --include="*.ini" --include="*.properties" \
              "$pattern" "$dir" 2>/dev/null \
        | grep -v node_modules | grep -v '.lock' | grep -v vendor \
        | head -10 || true
}

# Get first matching line number in a file
first_line() {
    local file="$1"
    local pattern="$2"
    grep -Pn -m1 "$pattern" "$file" 2>/dev/null | cut -d: -f1 || echo "?"
}

# Build a file list for the report (max 5 shown, rest summarized)
format_file_list() {
    local scan_dir="$1"
    local pattern="$2"
    shift 2
    local files=("$@")
    local count=${#files[@]}
    local shown=0
    local result=""

    for file in "${files[@]}"; do
        [ -z "$file" ] && continue
        if [ $shown -ge 5 ]; then
            local remaining=$((count - shown))
            result="${result}\n- ...and ${remaining} more files"
            break
        fi
        local rel="${file#$scan_dir/}"
        local ln
        ln=$(first_line "$file" "$pattern")
        result="${result}\n- \`${rel}\` (Line ${ln})"
        shown=$((shown + 1))
    done
    echo -e "$result"
}

# ============================================================================
# SCAN + REPORT GENERATION
# ============================================================================

scan_repo() {
    local url="$1"

    # Validate URL
    if ! echo "$url" | grep -qP '^https?://github\.com/[\w\-\.]+/[\w\-\.]+/?$'; then
        echo "ERROR: Invalid GitHub URL. Must be https://github.com/owner/repo"
        exit 1
    fi

    local repo_name
    repo_name=$(basename "$url" .git)
    local scan_dir="/tmp/scan-${repo_name}-${TIMESTAMP}"
    local report_path="${REPORTS_DIR}/qshield-report-${repo_name}-${TIMESTAMP}.md"
    local scan_id="${repo_name}-${TIMESTAMP}"

    echo "SCAN_STATUS=cloning"
    echo "Cloning ${url}..."
    if ! git clone --depth 1 "$url" "$scan_dir" 2>&1; then
        echo "ERROR: Failed to clone repository. Check URL and ensure repo is public."
        echo "SCAN_STATUS=failed"
        exit 1
    fi

    echo "SCAN_STATUS=scanning"
    echo "Running QuantumShield analysis..."

    # --- Detection Phase ---
    # Each category counts ONCE for scoring, with affected files listed underneath
    local critical=0
    local warnings=0
    local findings=""
    local total_affected=0

    # --- CRITICAL CHECKS ---

    # 1. RSA usage (quantum-vulnerable via Shor's algorithm)
    local rsa_pattern='\b(RSA|rsa_key|RSAPublicKey|RSA[-_]OAEP|RSA[-_]PKCS1|rsa_generate|RSA\.generate|RSA\.import|from\s+.*rsa\s+import)\b'
    local rsa_files_raw
    rsa_files_raw=$(search_source "$scan_dir" "$rsa_pattern")
    if [ -n "$rsa_files_raw" ]; then
        local -a rsa_arr=()
        while IFS= read -r f; do [ -n "$f" ] && rsa_arr+=("$f"); done <<< "$rsa_files_raw"
        local rsa_count=${#rsa_arr[@]}
        total_affected=$((total_affected + rsa_count))
        critical=$((critical + 1))
        findings="${findings}
### ⛔ CRITICAL: RSA Key Usage (${rsa_count} files)

**Risk:** RSA is quantum-vulnerable. Shor's algorithm breaks RSA in polynomial time on a cryptographically relevant quantum computer.
**Fix:** Migrate to **ML-KEM (CRYSTALS-Kyber)** for key encapsulation, **ML-DSA (CRYSTALS-Dilithium)** for signatures.

**Affected files:**
$(format_file_list "$scan_dir" "$rsa_pattern" "${rsa_arr[@]}")
"
    fi

    # 2. ECC/ECDSA usage (quantum-vulnerable via Shor's algorithm)
    local ecc_pattern='\b(ECDSA|secp256[kr]1|P-256|P-384|P-521|elliptic[_.]curve|EC_KEY|ECDH|Ed25519|Curve25519|NIST.*curve)\b'
    local ecc_files_raw
    ecc_files_raw=$(search_source "$scan_dir" "$ecc_pattern")
    if [ -n "$ecc_files_raw" ]; then
        local -a ecc_arr=()
        while IFS= read -r f; do [ -n "$f" ] && ecc_arr+=("$f"); done <<< "$ecc_files_raw"
        local ecc_count=${#ecc_arr[@]}
        total_affected=$((total_affected + ecc_count))
        critical=$((critical + 1))
        findings="${findings}
### ⛔ CRITICAL: Elliptic Curve Cryptography (${ecc_count} files)

**Risk:** ECC/ECDSA/EdDSA is quantum-vulnerable via Shor's algorithm. All elliptic curve operations are at risk.
**Fix:** Migrate to **ML-DSA (CRYSTALS-Dilithium)** for signatures, **ML-KEM (CRYSTALS-Kyber)** for key exchange.

**Affected files:**
$(format_file_list "$scan_dir" "$ecc_pattern" "${ecc_arr[@]}")
"
    fi

    # 3. DES/3DES/RC4 (broken classically, worse under Grover's)
    # Specific crypto patterns only — avoids matching "description", "descriptor", etc.
    local des_pattern='\b(3DES|TripleDES|Triple[-_]?DES|DESede|DES[-_]EDE|DES[-_]CBC|DES[-_]ECB|DES[-_]KEY|DES\.new|pyDes|Cipher\.DES|RC4|ARC4|ARCFOUR)\b'
    local des_files_raw
    des_files_raw=$(search_source "$scan_dir" "$des_pattern")
    if [ -n "$des_files_raw" ]; then
        local -a des_arr=()
        while IFS= read -r f; do [ -n "$f" ] && des_arr+=("$f"); done <<< "$des_files_raw"
        local des_count=${#des_arr[@]}
        total_affected=$((total_affected + des_count))
        critical=$((critical + 1))
        findings="${findings}
### ⛔ CRITICAL: Deprecated Symmetric Cipher (${des_count} files)

**Risk:** DES/3DES/RC4 are broken classically. Grover's algorithm further halves remaining security.
**Fix:** Migrate to **AES-256-GCM** minimum. AES-256 remains quantum-resistant against Grover's.

**Affected files:**
$(format_file_list "$scan_dir" "$des_pattern" "${des_arr[@]}")
"
    fi

    # 4. Hardcoded secrets (exclude tests, examples, docs, package.json)
    local secret_pattern='(api_key|apikey|api_secret|secret_key|private_key|PRIVATE_KEY|SECRET_KEY|DATABASE_PASSWORD)\s*[:=]\s*["\x27][A-Za-z0-9/+]{8,}'
    local secret_files_raw
    secret_files_raw=$(search_source "$scan_dir" "$secret_pattern")
    # Also check .env files
    local secret_config_raw
    secret_config_raw=$(search_config "$scan_dir" "$secret_pattern")
    local secret_combined
    secret_combined=$(echo -e "${secret_files_raw}\n${secret_config_raw}" | grep -v '/test/' | grep -v '/tests/' | grep -v '/spec/' | grep -v '/__test' | grep -v '/example' | grep -v '/fixtures/' | grep -v 'package.json' | grep -v 'package-lock' | grep -v '.example' | grep -v '.sample' | sort -u)
    # Remove empty lines
    secret_combined=$(echo "$secret_combined" | sed '/^$/d')
    if [ -n "$secret_combined" ]; then
        local -a secret_arr=()
        while IFS= read -r f; do [ -n "$f" ] && secret_arr+=("$f"); done <<< "$secret_combined"
        local secret_count=${#secret_arr[@]}
        total_affected=$((total_affected + secret_count))
        critical=$((critical + 1))
        findings="${findings}
### ⛔ CRITICAL: Potential Hardcoded Secrets (${secret_count} files)

**Risk:** Credentials in source code are exposed to anyone with repo access. Quantum computers will accelerate brute-force attacks on exposed keys.
**Fix:** Use environment variables or secrets management (AWS Secrets Manager, HashiCorp Vault, Doppler).

**Affected files:**
$(format_file_list "$scan_dir" "$secret_pattern" "${secret_arr[@]}")
"
    fi

    # --- WARNING CHECKS ---

    # 5. SHA-1 / MD5 usage
    local hash_pattern='\b(sha[-_]?1|SHA[-_]1|hashlib\.sha1|hashlib\.md5|createHash\s*\(\s*["\x27](?:sha1|md5)["\x27]\s*\)|MessageDigest.*(?:SHA-1|MD5)|Digest::(?:SHA1|MD5))\b'
    local hash_files_raw
    hash_files_raw=$(search_source "$scan_dir" "$hash_pattern")
    if [ -n "$hash_files_raw" ]; then
        local -a hash_arr=()
        while IFS= read -r f; do [ -n "$f" ] && hash_arr+=("$f"); done <<< "$hash_files_raw"
        local hash_count=${#hash_arr[@]}
        total_affected=$((total_affected + hash_count))
        warnings=$((warnings + 1))
        findings="${findings}
### ⚠️ WARNING: Weak Hash Algorithm — SHA-1/MD5 (${hash_count} files)

**Risk:** SHA-1 and MD5 are collision-vulnerable classically. Grover's algorithm further weakens them.
**Fix:** Upgrade to **SHA-256** minimum, **SHA-3** preferred for long-term quantum resistance.

**Affected files:**
$(format_file_list "$scan_dir" "$hash_pattern" "${hash_arr[@]}")
"
    fi

    # 6. Weak TLS versions
    local tls_pattern='\b(TLSv1[._]0|TLSv1[._]1|SSLv[23]|PROTOCOL_TLSv1\b|TLS_1_0|TLS_1_1|ssl\.PROTOCOL_TLS(?!v1_[23]))\b'
    local tls_files_raw
    tls_files_raw=$(search_source "$scan_dir" "$tls_pattern")
    local tls_config_raw
    tls_config_raw=$(search_config "$scan_dir" "$tls_pattern")
    local tls_combined
    tls_combined=$(echo -e "${tls_files_raw}\n${tls_config_raw}" | sort -u | sed '/^$/d')
    if [ -n "$tls_combined" ]; then
        local -a tls_arr=()
        while IFS= read -r f; do [ -n "$f" ] && tls_arr+=("$f"); done <<< "$tls_combined"
        local tls_count=${#tls_arr[@]}
        total_affected=$((total_affected + tls_count))
        warnings=$((warnings + 1))
        findings="${findings}
### ⚠️ WARNING: Outdated TLS Version (${tls_count} files)

**Risk:** TLS 1.0/1.1 are deprecated (RFC 8996). Known vulnerabilities including BEAST, POODLE.
**Fix:** Enforce **TLS 1.3** minimum. TLS 1.3 includes post-quantum key exchange options via ML-KEM.

**Affected files:**
$(format_file_list "$scan_dir" "$tls_pattern" "${tls_arr[@]}")
"
    fi

    # 7. Weak key sizes (512, 768, 1024 bits)
    local weakkey_pattern='key[-_.]?size\s*[:=]\s*(512|768|1024)|bits\s*[:=]\s*(512|768|1024)|generate[-_]?key.*\b(512|768|1024)\b'
    local weakkey_files_raw
    weakkey_files_raw=$(search_source "$scan_dir" "$weakkey_pattern")
    if [ -n "$weakkey_files_raw" ]; then
        local -a weakkey_arr=()
        while IFS= read -r f; do [ -n "$f" ] && weakkey_arr+=("$f"); done <<< "$weakkey_files_raw"
        local weakkey_count=${#weakkey_arr[@]}
        total_affected=$((total_affected + weakkey_count))
        warnings=$((warnings + 1))
        findings="${findings}
### ⚠️ WARNING: Weak Key Size (${weakkey_count} files)

**Risk:** Key sizes below 2048 bits are insecure classically. All asymmetric keys are quantum-vulnerable regardless of size.
**Fix:** Migrate to post-quantum algorithms. If classical-only: minimum 2048-bit RSA, 256-bit ECC.

**Affected files:**
$(format_file_list "$scan_dir" "$weakkey_pattern" "${weakkey_arr[@]}")
"
    fi

    # --- Count total source files ---
    local total_files
    total_files=$(find "$scan_dir" -type f \( \
        -name "*.py" -o -name "*.js" -o -name "*.ts" -o -name "*.tsx" \
        -o -name "*.java" -o -name "*.go" -o -name "*.rs" -o -name "*.rb" \
        -o -name "*.c" -o -name "*.cpp" -o -name "*.cs" -o -name "*.php" \
        -o -name "*.swift" -o -name "*.kt" -o -name "*.scala" \
    \) ! -path "*/node_modules/*" ! -path "*/.git/*" ! -path "*/vendor/*" | wc -l)
    total_files=$(echo "$total_files" | tr -d ' ')

    # --- Also run crypto-scanner if available ---
    local scanner_output=""
    if [ -f "$SCANNER" ]; then
        scanner_output=$("$SCANNER" scan "$scan_dir" 2>/dev/null || true)
    fi

    # --- Calculate score (per-category, not per-file) ---
    local score=100
    score=$((score - (critical * 25)))
    score=$((score - (warnings * 10)))
    [ $score -lt 0 ] && score=0

    local risk_level="LOW"
    local risk_emoji="🟢"
    if [ $score -lt 70 ]; then risk_level="MEDIUM"; risk_emoji="🟡"; fi
    if [ $score -lt 40 ]; then risk_level="HIGH"; risk_emoji="🔴"; fi

    # --- Handle clean repos ---
    if [ $critical -eq 0 ] && [ $warnings -eq 0 ]; then
        findings="
### ✅ No Quantum-Vulnerable Cryptography Detected

No RSA, ECC, DES, SHA-1/MD5, hardcoded secrets, or weak TLS configurations were found in the scanned source files.

**This is a good baseline**, but note:
- Dependencies and transitive libraries were not deeply audited in this quick scan
- Runtime cryptographic behavior may differ from static analysis
- Consider a **Deep Assessment** for full infrastructure evaluation including dependencies, configs, and TLS endpoints
"
    fi

    local passing=$((total_files - critical - warnings))
    [ $passing -lt 0 ] && passing=0

    # --- Generate Branded Report ---
    cat > "$report_path" << REPORT
# 🦞 CrawDaddy Security Scan Report
## QuantumShield Labs — Post-Quantum Vulnerability Analysis

---

| Field | Value |
|-------|-------|
| **Repository** | ${url} |
| **Scanned** | $(date '+%Y-%m-%d %H:%M:%S %Z') |
| **Files Analyzed** | ${total_files} |
| **Scanner** | QuantumShield v2.0 |
| **Agent** | CrawDaddy (QuantumShield Labs) |

---

## Quantum Readiness Score: ${score}/100 ${risk_emoji}

**Risk Level: ${risk_level}**

| Category | Count |
|----------|-------|
| ⛔ Critical | ${critical} |
| ⚠️ Warnings | ${warnings} |
| ✅ Passing | ${passing} |

---

## Findings
${findings}

---

## Recommendations

1. **Immediate:** Replace all RSA and ECC usage with NIST-approved post-quantum algorithms (ML-KEM for key encapsulation, ML-DSA for digital signatures)
2. **Short-term:** Audit all cryptographic dependencies — transitive dependencies often contain legacy crypto
3. **Medium-term:** Implement a crypto-agility layer so future algorithm swaps don't require full rewrites
4. **Ongoing:** Monitor NIST PQC standardization updates and CNSA 2.0 timeline requirements

---

## What is Harvest-Now-Decrypt-Later?

Adversaries are collecting encrypted data **TODAY**, storing it until quantum computers can break the encryption (estimated 2027-2030 for cryptographically relevant quantum computers). If your data has long-term value — healthcare records, financial data, intellectual property, authentication tokens — the threat is **NOW**, not later.

NIST has finalized post-quantum standards (FIPS 203, 204, 205). The migration window is closing.

---

## Next Steps

| Service | Price | What You Get |
|---------|-------|-------------|
| 🟡 **Deep Assessment** | 0.05 ETH | Full infrastructure evaluation with migration priority matrix, dependency audit, TLS endpoint analysis |
| 🔴 **Migration Plan** | 0.5 ETH | Complete PQC migration roadmap with implementation guide, timeline, vendor recommendations, executive summary |

**Contact:** @QuarkMichael on X | quantumshieldlabs.dev
**Hire with escrow:** moltlaunch.com/agent/0x41c7

---

*Powered by QuantumShield Labs × CrawDaddy 🦞*
*Report ID: ${scan_id}*
REPORT

    # --- Create GitHub Gist ---
    local gist_url="(gist creation skipped — no token)"
    if [ -n "${GITHUB_TOKEN:-}" ]; then
        local gist_filename="qshield-report-${repo_name}-${TIMESTAMP}.md"
        local gist_desc="QuantumShield Security Scan — ${repo_name} — Score: ${score}/100 ${risk_level}"

        # Use jq to safely build JSON with the report content
        local gist_json
        gist_json=$(jq -n \
            --arg desc "$gist_desc" \
            --arg fname "$gist_filename" \
            --arg content "$(cat "$report_path")" \
            '{
                description: $desc,
                public: false,
                files: {
                    ($fname): { content: $content }
                }
            }')

        local gist_response
        gist_response=$(curl -s -X POST "$GITHUB_API" \
            -H "Authorization: token ${GITHUB_TOKEN}" \
            -H "Content-Type: application/json" \
            -H "Accept: application/vnd.github+json" \
            -d "$gist_json" 2>/dev/null) || true

        gist_url=$(echo "$gist_response" | jq -r '.html_url // empty' 2>/dev/null) || true

        if [ -z "$gist_url" ] || [ "$gist_url" = "null" ]; then
            local gist_error
            gist_error=$(echo "$gist_response" | jq -r '.message // "unknown error"' 2>/dev/null) || true
            echo "GIST_ERROR=${gist_error}"
            gist_url="(gist creation failed: ${gist_error})"
        fi
    fi

    # --- Send report as Telegram file attachment ---
    local telegram_doc_status="skipped"
    if [ -n "${TELEGRAM_BOT_TOKEN:-}" ] && [ -f "$report_path" ]; then
        # Resolve the chat_id: extract from today's OpenClaw gateway log,
        # fall back to the allowFrom list in openclaw.json
        local chat_id=""
        local today_log="/tmp/openclaw/openclaw-$(date +%Y-%m-%d).log"
        if [ -f "$today_log" ]; then
            chat_id=$(grep -oP '"chatId":"\K[0-9]+' "$today_log" 2>/dev/null | tail -1) || true
        fi
        if [ -z "$chat_id" ]; then
            chat_id=$(jq -r '.channels.telegram.allowFrom[0] // empty' ~/.openclaw/openclaw.json 2>/dev/null) || true
        fi

        if [ -n "$chat_id" ]; then
            local doc_caption
            doc_caption=$(printf '🦞 QuantumShield Scan Report — %s — Score: %s/100 %s' "$repo_name" "$score" "$risk_emoji")
            local doc_response
            doc_response=$(curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendDocument" \
                -F "chat_id=${chat_id}" \
                -F "document=@${report_path}" \
                -F "caption=${doc_caption}" 2>&1) || true
            local doc_ok
            doc_ok=$(echo "$doc_response" | jq -r '.ok // false' 2>/dev/null) || true
            if [ "$doc_ok" = "true" ]; then
                telegram_doc_status="success"

                # --- Self-destruct: delete report message after 1 hour ---
                local doc_msg_id
                doc_msg_id=$(echo "$doc_response" | jq -r '.result.message_id // empty' 2>/dev/null) || true

                if [ -n "$doc_msg_id" ]; then
                    # Send self-destruct warning
                    local warning_response
                    warning_response=$(curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage"                         -d "chat_id=${chat_id}"                         -d "text=⏳ This report will self-destruct in 1 hour. Download it now."                         -d "reply_to_message_id=${doc_msg_id}" 2>&1) || true
                    local warning_msg_id
                    warning_msg_id=$(echo "$warning_response" | jq -r '.result.message_id // empty' 2>/dev/null) || true

                    # Background process: delete both messages after 1 hour
                    (
                        sleep 3600
                        curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/deleteMessage"                             -d "chat_id=${chat_id}" -d "message_id=${doc_msg_id}" > /dev/null 2>&1
                        if [ -n "${warning_msg_id}" ]; then
                            curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/deleteMessage"                                 -d "chat_id=${chat_id}" -d "message_id=${warning_msg_id}" > /dev/null 2>&1
                        fi
                    ) &
                    disown
                fi
            else
                local doc_err
                doc_err=$(echo "$doc_response" | jq -r '.description // "unknown"' 2>/dev/null) || true
                telegram_doc_status="failed: ${doc_err}"
            fi
        else
            telegram_doc_status="no chat_id found"
        fi
    fi

    # --- Cleanup ---
    rm -rf "$scan_dir"

    # --- Output structured markers for CrawDaddy ---
    echo ""
    echo "SCAN_STATUS=complete"
    echo "SCAN_REPO=${url}"
    echo "SCAN_REPO_NAME=${repo_name}"
    echo "SCAN_SCORE=${score}"
    echo "SCAN_RISK_LEVEL=${risk_level}"
    echo "SCAN_RISK_EMOJI=${risk_emoji}"
    echo "SCAN_CRITICAL=${critical}"
    echo "SCAN_WARNINGS=${warnings}"
    echo "SCAN_TOTAL_FILES=${total_files}"
    echo "SCAN_PASSING=${passing}"
    echo "REPORT_PATH=${report_path}"
    echo "GIST_URL=${gist_url}"
    echo "TELEGRAM_DOC=${telegram_doc_status}"
    echo "SCAN_COMPLETE"
}

# ============================================================================
# MAIN
# ============================================================================

case "${1:-help}" in
    scan)
        if [ -z "${2:-}" ]; then
            echo "ERROR: Please provide a GitHub URL"
            echo "Example: qshield-scan.sh scan https://github.com/owner/repo"
            exit 1
        fi
        scan_repo "$2"
        ;;
    info)
        echo "QuantumShield Scanner v2.0"
        echo "Checks: RSA, ECC/ECDSA, DES/3DES/RC4, SHA-1/MD5, hardcoded secrets, weak TLS, weak key sizes"
        echo "Output: Branded markdown report + GitHub Gist link"
        if [ -f "$SCANNER" ]; then
            echo ""
            "$SCANNER" info
        fi
        ;;
    help|--help|-h)
        usage
        ;;
    *)
        echo "Unknown command: $1"
        usage
        exit 1
        ;;
esac
