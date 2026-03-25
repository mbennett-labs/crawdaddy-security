#!/usr/bin/env python3
"""
CrawDaddy Security — Beautiful PDF Report Generator
Powered by QuantumShield Labs

Usage: python3 generate-report.py <markdown_report_path>
Outputs: .html and .pdf alongside the .md file
"""

import sys
import os
import re
from datetime import datetime


def parse_markdown_report(md_path):
    """Parse the markdown report into structured data."""
    with open(md_path, "r") as f:
        content = f.read()

    data = {
        "repo": "",
        "repo_name": "",
        "score": 0,
        "risk_level": "UNKNOWN",
        "risk_color": "#64748b",
        "risk_bg": "#1e293b",
        "findings": [],
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M UTC"),
        "files_scanned": 0,
        "critical_count": 0,
        "warning_count": 0,
        "passing_count": 0,
        "report_id": "",
    }

    # Extract repo
    m = re.search(r"\*\*Repository\*\*\s*\|\s*(.+)", content)
    if m:
        data["repo"] = m.group(1).strip()
        data["repo_name"] = data["repo"].rstrip("/").split("/")[-1]

    # Extract score
    m = re.search(r"Score:\s*(\d+)/100", content)
    if m:
        data["score"] = int(m.group(1))

    # Extract timestamp from report
    m = re.search(r"\*\*Scanned\*\*\s*\|\s*(.+)", content)
    if m:
        data["timestamp"] = m.group(1).strip()

    # Extract files scanned
    m = re.search(r"\*\*Files Analyzed\*\*\s*\|\s*(\d+)", content)
    if m:
        data["files_scanned"] = int(m.group(1))

    # Extract counts
    m = re.search(r"⛔ Critical\s*\|\s*(\d+)", content)
    if m:
        data["critical_count"] = int(m.group(1))
    m = re.search(r"⚠️ Warnings\s*\|\s*(\d+)", content)
    if m:
        data["warning_count"] = int(m.group(1))
    m = re.search(r"✅ Passing\s*\|\s*(\d+)", content)
    if m:
        data["passing_count"] = int(m.group(1))

    # Extract report ID
    m = re.search(r"Report ID:\s*(.+)", content)
    if m:
        data["report_id"] = m.group(1).strip()

    # Determine risk level and color
    score = data["score"]
    if score >= 80:
        data["risk_level"] = "LOW RISK"
        data["risk_color"] = "#10b981"
        data["risk_bg"] = "#064e3b"
    elif score >= 50:
        data["risk_level"] = "MEDIUM RISK"
        data["risk_color"] = "#f59e0b"
        data["risk_bg"] = "#451a03"
    elif score >= 25:
        data["risk_level"] = "HIGH RISK"
        data["risk_color"] = "#ef4444"
        data["risk_bg"] = "#450a0a"
    else:
        data["risk_level"] = "CRITICAL RISK"
        data["risk_color"] = "#dc2626"
        data["risk_bg"] = "#3b0000"

    # Extract findings blocks
    finding_blocks = re.findall(
        r"###\s*(⛔ CRITICAL|⚠️ WARNING|✅):\s*(.+?)(?:\((\d+)\s*files?\))?\s*\n(.*?)(?=\n###|\n---|\Z)",
        content,
        re.DOTALL,
    )

    for icon, title, file_count, body in finding_blocks:
        if "CRITICAL" in icon:
            severity = "CRITICAL"
            color = "#dc2626"
        elif "WARNING" in icon:
            severity = "WARNING"
            color = "#f59e0b"
        else:
            severity = "PASS"
            color = "#10b981"

        # Extract risk and fix lines
        risk_match = re.search(r"\*\*Risk:\*\*\s*(.+)", body)
        fix_match = re.search(r"\*\*Fix:\*\*\s*(.+)", body)

        # Extract affected files
        files = re.findall(r"- `([^`]+)`(?:\s*\(Line (\d+|\?)\))?", body)

        data["findings"].append(
            {
                "severity": severity,
                "title": title.strip(),
                "color": color,
                "file_count": int(file_count) if file_count else 0,
                "risk": risk_match.group(1).strip() if risk_match else "",
                "fix": fix_match.group(1).strip() if fix_match else "",
                "files": files,
            }
        )

    # Handle clean scan (no findings detected message)
    if not data["findings"]:
        clean_match = re.search(r"✅ No Quantum-Vulnerable Cryptography Detected", content)
        if clean_match:
            data["findings"].append(
                {
                    "severity": "PASS",
                    "title": "No Quantum-Vulnerable Cryptography Detected",
                    "color": "#10b981",
                    "file_count": 0,
                    "risk": "",
                    "fix": "",
                    "files": [],
                }
            )

    return data


def generate_html(data):
    """Generate beautiful HTML report."""

    score = data["score"]
    radius = 80
    circumference = 2 * 3.14159 * radius
    progress = (score / 100) * circumference
    gap = circumference - progress

    # Build findings HTML
    findings_html = ""
    for f in data["findings"]:
        files_html = ""
        if f["files"]:
            files_html = '<div class="file-list">'
            for filepath, line in f["files"][:5]:
                line_str = f" : {line}" if line and line != "?" else ""
                files_html += f'<div class="file-path">{filepath}{line_str}</div>'
            if f["file_count"] > 5:
                files_html += f'<div class="file-path more">...and {f["file_count"] - 5} more files</div>'
            files_html += "</div>"

        risk_html = ""
        if f["risk"]:
            risk_html = f'<div class="finding-risk"><strong>Risk:</strong> {f["risk"]}</div>'

        fix_html = ""
        if f["fix"]:
            fix_html = f'<div class="finding-fix"><strong>Fix:</strong> {f["fix"]}</div>'

        badge_text = f["severity"]
        if f["file_count"]:
            badge_text += f' · {f["file_count"]} file{"s" if f["file_count"] != 1 else ""}'

        findings_html += f"""
        <div class="finding-card">
          <div class="finding-header">
            <span class="severity-badge" style="background: {f['color']}18;
                color: {f['color']}; border: 1px solid {f['color']}35;">
                {badge_text}
            </span>
            <span class="finding-title">{f['title']}</span>
          </div>
          {risk_html}
          {fix_html}
          {files_html}
        </div>"""

    if not data["findings"]:
        findings_html = '<div class="no-findings">No vulnerabilities detected</div>'

    # Determine critical+high count for stats
    crit_high = len([f for f in data["findings"] if f["severity"] in ("CRITICAL", "HIGH")])
    warn_count = len([f for f in data["findings"] if f["severity"] == "WARNING"])

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CrawDaddy Security Report — {data['repo_name']}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap');

  * {{ margin: 0; padding: 0; box-sizing: border-box; }}

  :root {{
    --bg-primary: #080d1a;
    --bg-secondary: #0d1424;
    --bg-card: #111827;
    --bg-elevated: #1a2236;
    --border: #1e2d4a;
    --text-primary: #f1f5f9;
    --text-secondary: #94a3b8;
    --text-muted: #475569;
    --accent-blue: #3b82f6;
    --accent-purple: #8b5cf6;
    --risk-color: {data['risk_color']};
    --risk-bg: {data['risk_bg']};
  }}

  body {{
    font-family: 'Inter', -apple-system, sans-serif;
    background: var(--bg-primary);
    color: var(--text-primary);
    min-height: 100vh;
    -webkit-font-smoothing: antialiased;
  }}

  .page {{
    max-width: 880px;
    margin: 0 auto;
    padding: 48px 40px;
  }}

  /* ── HEADER ── */
  .header {{
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    margin-bottom: 48px;
    padding-bottom: 32px;
    border-bottom: 1px solid var(--border);
  }}

  .brand {{ display: flex; align-items: center; gap: 14px; }}

  .brand-icon {{
    width: 44px; height: 44px;
    background: linear-gradient(135deg, #1d4ed8, #7c3aed);
    border-radius: 11px;
    display: flex; align-items: center; justify-content: center;
    font-size: 22px;
    box-shadow: 0 4px 12px rgba(29, 78, 216, 0.3);
  }}

  .brand-text h1 {{
    font-size: 18px; font-weight: 700; color: #fff;
    letter-spacing: -0.3px;
  }}
  .brand-text p {{
    font-size: 11px; color: var(--text-muted);
    font-family: 'JetBrains Mono', monospace;
    margin-top: 2px;
  }}

  .report-meta {{
    text-align: right;
    font-family: 'JetBrains Mono', monospace;
    font-size: 10.5px; color: var(--text-muted);
    line-height: 1.9;
  }}
  .report-meta .label {{ color: var(--text-secondary); font-weight: 500; }}

  /* ── SCORE HERO ── */
  .score-section {{
    display: grid;
    grid-template-columns: 240px 1fr;
    gap: 32px;
    margin-bottom: 40px;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 32px;
  }}

  .score-gauge {{
    display: flex; flex-direction: column;
    align-items: center; justify-content: center;
  }}

  .gauge-wrap {{ position: relative; width: 180px; height: 180px; }}
  .gauge-wrap svg {{ transform: rotate(-90deg); }}

  .gauge-center {{
    position: absolute; top: 50%; left: 50%;
    transform: translate(-50%, -50%);
    text-align: center;
  }}

  .gauge-number {{
    font-size: 52px; font-weight: 800;
    color: var(--risk-color);
    font-family: 'JetBrains Mono', monospace;
    line-height: 1;
    letter-spacing: -2px;
  }}
  .gauge-sub {{
    font-size: 12px; color: var(--text-muted);
    font-family: 'JetBrains Mono', monospace;
    margin-top: 2px;
  }}

  .risk-pill {{
    margin-top: 14px;
    padding: 5px 18px;
    border-radius: 99px;
    font-size: 11px; font-weight: 700;
    font-family: 'JetBrains Mono', monospace;
    background: var(--risk-bg);
    color: var(--risk-color);
    border: 1px solid {data['risk_color']}30;
    letter-spacing: 1px;
    text-transform: uppercase;
  }}

  .score-info {{
    display: flex; flex-direction: column;
    justify-content: center; gap: 16px;
  }}

  .repo-title {{
    font-size: 24px; font-weight: 700;
    color: var(--text-primary);
    letter-spacing: -0.5px;
    word-break: break-all;
  }}
  .repo-url {{
    font-size: 12px; color: var(--accent-blue);
    font-family: 'JetBrains Mono', monospace;
    word-break: break-all;
    margin-top: -8px;
  }}

  .stat-row {{
    display: grid; grid-template-columns: repeat(4, 1fr);
    gap: 10px;
  }}
  .stat-box {{
    background: var(--bg-elevated);
    border-radius: 10px;
    padding: 12px 10px; text-align: center;
    border: 1px solid var(--border);
  }}
  .stat-val {{
    font-size: 22px; font-weight: 700;
    font-family: 'JetBrains Mono', monospace;
    color: var(--text-primary);
  }}
  .stat-lbl {{
    font-size: 9px; color: var(--text-muted);
    text-transform: uppercase; letter-spacing: 0.8px;
    margin-top: 2px;
  }}

  /* ── SECTION TITLES ── */
  .section {{ margin-bottom: 32px; }}
  .section-head {{
    font-size: 12px; font-weight: 600;
    text-transform: uppercase; letter-spacing: 1.5px;
    color: var(--text-muted);
    margin-bottom: 14px;
    display: flex; align-items: center; gap: 10px;
  }}
  .section-head::after {{
    content: ''; flex: 1; height: 1px; background: var(--border);
  }}

  /* ── FINDINGS ── */
  .findings-wrap {{
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 14px;
    overflow: hidden;
  }}

  .finding-card {{
    padding: 18px 22px;
    border-bottom: 1px solid var(--border);
  }}
  .finding-card:last-child {{ border-bottom: none; }}

  .finding-header {{
    display: flex; align-items: center; gap: 12px;
    margin-bottom: 8px;
  }}

  .severity-badge {{
    font-size: 10px; font-weight: 700;
    font-family: 'JetBrains Mono', monospace;
    padding: 3px 10px; border-radius: 99px;
    white-space: nowrap; flex-shrink: 0;
  }}

  .finding-title {{
    font-size: 14px; font-weight: 600;
    color: var(--text-primary);
  }}

  .finding-risk, .finding-fix {{
    font-size: 12px; color: var(--text-secondary);
    line-height: 1.6; margin-bottom: 4px;
    padding-left: 2px;
  }}
  .finding-risk strong, .finding-fix strong {{
    color: var(--text-muted); font-weight: 600;
  }}

  .file-list {{
    margin-top: 8px;
    background: var(--bg-primary);
    border-radius: 8px;
    padding: 10px 14px;
    border: 1px solid var(--border);
  }}
  .file-path {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px; color: var(--accent-blue);
    padding: 3px 0;
    border-bottom: 1px solid #0d1424;
  }}
  .file-path:last-child {{ border-bottom: none; }}
  .file-path.more {{ color: var(--text-muted); font-style: italic; }}

  .no-findings {{
    padding: 32px; text-align: center;
    color: #10b981; font-size: 15px; font-weight: 500;
  }}

  /* ── QUANTUM INFO BOX ── */
  .quantum-box {{
    background: linear-gradient(135deg, #0c1a3a, var(--bg-secondary));
    border: 1px solid #1d4ed830;
    border-radius: 14px;
    padding: 24px 28px;
    margin-bottom: 32px;
  }}
  .quantum-title {{
    font-size: 14px; font-weight: 600;
    color: #60a5fa; margin-bottom: 10px;
  }}
  .quantum-text {{
    font-size: 13px; color: var(--text-secondary);
    line-height: 1.75;
  }}
  .quantum-text strong {{ color: var(--text-primary); }}

  /* ── THREAT TIMELINE ── */
  .timeline {{
    display: grid; grid-template-columns: repeat(3, 1fr);
    gap: 12px; margin-bottom: 32px;
  }}
  .tl-card {{
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 12px; padding: 18px; text-align: center;
  }}
  .tl-year {{
    font-size: 22px; font-weight: 800;
    font-family: 'JetBrains Mono', monospace;
    margin-bottom: 8px;
  }}
  .tl-desc {{
    font-size: 11px; color: var(--text-muted); line-height: 1.6;
  }}

  /* ── UPSELL ── */
  .upsell {{
    background: linear-gradient(135deg, #071a12, var(--bg-secondary));
    border: 1px solid #10b98130;
    border-radius: 14px;
    padding: 24px 28px;
    margin-bottom: 32px;
  }}
  .upsell-title {{
    font-size: 15px; font-weight: 600;
    color: #10b981; margin-bottom: 18px;
  }}
  .upsell-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }}
  .upsell-card {{
    background: #0a1a12;
    border: 1px solid #10b98118;
    border-radius: 10px; padding: 16px;
  }}
  .upsell-price {{
    font-size: 20px; font-weight: 700;
    color: #10b981;
    font-family: 'JetBrains Mono', monospace;
  }}
  .upsell-price .approx {{
    font-size: 12px; color: var(--text-muted); font-weight: 400;
  }}
  .upsell-name {{
    font-size: 14px; font-weight: 600;
    color: var(--text-primary); margin: 6px 0;
  }}
  .upsell-desc {{
    font-size: 11.5px; color: var(--text-muted); line-height: 1.6;
  }}
  .upsell-contact {{
    margin-top: 18px;
    font-size: 12px; color: var(--text-muted);
  }}
  .upsell-contact a {{ color: var(--accent-blue); text-decoration: none; }}

  /* ── FOOTER ── */
  .footer {{
    border-top: 1px solid var(--border);
    padding-top: 28px;
    display: flex; justify-content: space-between; align-items: center;
  }}
  .footer-left {{
    font-size: 13px; color: var(--text-muted);
  }}
  .footer-left strong {{ color: var(--text-secondary); }}
  .footer-left .sub {{
    font-size: 10.5px; margin-top: 4px;
    font-family: 'JetBrains Mono', monospace;
  }}
  .footer-right {{
    text-align: right;
    font-size: 10.5px; color: var(--accent-blue);
    font-family: 'JetBrains Mono', monospace;
    line-height: 1.9;
  }}
  .footer-crab {{ font-size: 24px; margin-right: 4px; }}

  /* ── PDF PRINT TWEAKS ── */
  @media print {{
    body {{ background: #080d1a !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
    .page {{ padding: 24px 20px; }}
  }}
  @page {{
    size: A4;
    margin: 0;
  }}
</style>
</head>
<body>
<div class="page">

  <!-- HEADER -->
  <div class="header">
    <div class="brand">
      <div class="brand-icon">&#x1f6e1;&#xfe0f;</div>
      <div class="brand-text">
        <h1>Quantum Shield Labs</h1>
        <p>Post-Quantum Security &middot; Agent Economy</p>
      </div>
    </div>
    <div class="report-meta">
      <div><span class="label">SECURITY SCAN REPORT</span></div>
      <div>{data['timestamp']}</div>
      <div>Scanner: QuantumShield v2.0</div>
      <div>Agent: CrawDaddy &#x1f99e;</div>
    </div>
  </div>

  <!-- SCORE HERO -->
  <div class="score-section">
    <div class="score-gauge">
      <div class="gauge-wrap">
        <svg width="180" height="180" viewBox="0 0 200 200">
          <circle cx="100" cy="100" r="{radius}"
            fill="none" stroke="#1e293b" stroke-width="14"/>
          <circle cx="100" cy="100" r="{radius}"
            fill="none"
            stroke="{data['risk_color']}"
            stroke-width="14"
            stroke-dasharray="{progress:.1f} {gap:.1f}"
            stroke-linecap="round"/>
        </svg>
        <div class="gauge-center">
          <div class="gauge-number">{score}</div>
          <div class="gauge-sub">/ 100</div>
        </div>
      </div>
      <div class="risk-pill">{data['risk_level']}</div>
    </div>

    <div class="score-info">
      <div>
        <div class="repo-title">{data['repo_name']}</div>
        <div class="repo-url">{data['repo']}</div>
      </div>
      <div class="stat-row">
        <div class="stat-box">
          <div class="stat-val">{data['files_scanned']}</div>
          <div class="stat-lbl">Files</div>
        </div>
        <div class="stat-box">
          <div class="stat-val" style="color: #dc2626;">{data['critical_count']}</div>
          <div class="stat-lbl">Critical</div>
        </div>
        <div class="stat-box">
          <div class="stat-val" style="color: #f59e0b;">{data['warning_count']}</div>
          <div class="stat-lbl">Warnings</div>
        </div>
        <div class="stat-box">
          <div class="stat-val" style="color: #10b981;">{data['passing_count']}</div>
          <div class="stat-lbl">Passing</div>
        </div>
      </div>
    </div>
  </div>

  <!-- FINDINGS -->
  <div class="section">
    <div class="section-head">Security Findings</div>
    <div class="findings-wrap">
      {findings_html}
    </div>
  </div>

  <!-- QUANTUM EDUCATION -->
  <div class="quantum-box">
    <div class="quantum-title">&#x1f510; What is Harvest-Now-Decrypt-Later?</div>
    <div class="quantum-text">
      Adversaries are collecting encrypted data <strong>today</strong>,
      waiting for quantum computers powerful enough to crack it
      (estimated 2027&ndash;2030). If your data has long-term value &mdash;
      healthcare records, financial data, IP, auth tokens &mdash;
      the threat is <strong>active right now</strong>.
      NIST finalized post-quantum standards (ML-KEM, ML-DSA) in 2024.
      Migration takes 12&ndash;24 months. The window is open.
    </div>
  </div>

  <!-- TIMELINE -->
  <div class="section">
    <div class="section-head">Quantum Threat Timeline</div>
    <div class="timeline">
      <div class="tl-card">
        <div class="tl-year" style="color: #ef4444;">NOW</div>
        <div class="tl-desc">Harvest-now-decrypt-later attacks active. Encrypted data being collected today.</div>
      </div>
      <div class="tl-card">
        <div class="tl-year" style="color: #f59e0b;">2027&ndash;30</div>
        <div class="tl-desc">Fault-tolerant quantum computers expected. RSA-2048 and ECDSA breakable.</div>
      </div>
      <div class="tl-card">
        <div class="tl-year" style="color: #10b981;">2030+</div>
        <div class="tl-desc">NIST deprecates all quantum-vulnerable algorithms. Migration deadline.</div>
      </div>
    </div>
  </div>

  <!-- UPSELL -->
  <div class="upsell">
    <div class="upsell-title">Need help fixing these findings?</div>
    <div class="upsell-grid">
      <div class="upsell-card">
        <div class="upsell-price">0.05 ETH <span class="approx">(~$100)</span></div>
        <div class="upsell-name">&#x1f7e1; Deep Assessment</div>
        <div class="upsell-desc">Full cryptographic inventory, dependency audit, TLS endpoint analysis, and 30-day remediation roadmap.</div>
      </div>
      <div class="upsell-card">
        <div class="upsell-price">0.5 ETH <span class="approx">(~$1,000)</span></div>
        <div class="upsell-name">&#x1f534; Full Migration Plan</div>
        <div class="upsell-desc">Complete PQC migration roadmap with NIST FIPS 203/204/205 implementation, timeline, and executive summary.</div>
      </div>
    </div>
    <div class="upsell-contact">
      &#x2192; <a href="#">@QuarkMichael</a> on X &nbsp;&middot;&nbsp;
      <a href="#">quantumshieldlabs.dev</a> &nbsp;&middot;&nbsp;
      <a href="#">moltlaunch.com/agent/0x41c7</a>
    </div>
  </div>

  <!-- FOOTER -->
  <div class="footer">
    <div class="footer-left">
      <span class="footer-crab">&#x1f99e;</span>
      <strong>CrawDaddy Security</strong> &middot; Autonomous AI Security Agent
      <div class="sub">ERC-8004 Identity &middot; Base L2 &middot; Virtuals ACP &middot; {data['report_id']}</div>
    </div>
    <div class="footer-right">
      quantumshieldlabs.dev<br>
      @QuarkMichael
    </div>
  </div>

</div>
</body>
</html>"""

    return html


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 generate-report.py <markdown_report_path>")
        sys.exit(1)

    md_path = sys.argv[1]
    if not os.path.exists(md_path):
        print(f"ERROR: {md_path} not found")
        sys.exit(1)

    data = parse_markdown_report(md_path)
    html_content = generate_html(data)

    # Write HTML
    html_path = md_path.replace(".md", ".html")
    with open(html_path, "w") as f:
        f.write(html_content)
    print(f"HTML_PATH={html_path}")

    # Generate PDF
    pdf_path = md_path.replace(".md", ".pdf")
    try:
        from weasyprint import HTML

        HTML(string=html_content, base_url=".").write_pdf(pdf_path)
        print(f"PDF_PATH={pdf_path}")
    except Exception as e:
        print(f"PDF_ERROR={e}")

    print("REPORT_READY=true")


if __name__ == "__main__":
    main()
