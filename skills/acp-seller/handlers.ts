import type { ExecuteJobResult, ValidationResult } from "../../runtime/offeringTypes.js";
import { execSync } from "child_process";
import { mkdtempSync, rmSync, existsSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";

// Strip temp scan directory paths → clean relative paths
function cleanPath(filePath: string): string {
  return filePath.replace(/\/tmp\/acp-scan-[^/]+\/repo\/?/, "");
}

// Deduplicate findings: group by (description + file), return unique with counts
function deduplicateFindings(findings: any[]): any[] {
  const map = new Map<string, { finding: any; count: number }>();
  for (const f of findings) {
    const key = `${f.description || f.type || ""}::${f.file_path || ""}`;
    const existing = map.get(key);
    if (existing) {
      existing.count++;
    } else {
      map.set(key, { finding: f, count: 1 });
    }
  }
  return Array.from(map.values()).map(({ finding, count }) => ({
    ...finding,
    file_path: finding.file_path ? cleanPath(finding.file_path) : undefined,
    occurrences: count,
  }));
}

export async function executeJob(request: any): Promise<ExecuteJobResult> {
  const repoUrl: string = request.repo_url;
  const scanDepth: string = request.scan_depth || "quick";
  const scanDir = mkdtempSync(join(tmpdir(), "acp-scan-"));

  try {
    execSync(`git clone --depth 1 ${repoUrl} ${scanDir}/repo`, {
      timeout: 60000,
      stdio: "pipe",
    });

    const scanCmd = `${process.env.HOME}/.local/bin/crypto-scanner scan ${scanDir}/repo`;
    let scanOutput: string;
    try {
      scanOutput = execSync(scanCmd, {
        timeout: 120000,
        stdio: "pipe",
        encoding: "utf-8",
        env: { ...process.env, NO_COLOR: "1" },
      });
    } catch (scanErr: any) {
      scanOutput = scanErr.stdout || "{}";
    }

    let results: any;
    try {
      results = JSON.parse(scanOutput);
    } catch {
      results = { raw_output: scanOutput, parse_error: true };
    }

    const rawFindings = results.findings || results.vulnerabilities || [];
    const totalRaw = Array.isArray(rawFindings) ? rawFindings.length : 0;
    const findings = Array.isArray(rawFindings) ? deduplicateFindings(rawFindings) : [];
    const uniqueCount = findings.length;

    const quantumVulns = findings.filter((f: any) =>
      /RSA|ECC|ECDSA|DSA|DH|SHA-1|MD5/i.test(f.algorithm || f.type || f.description || "")
    ).length;
    const generalVulns = uniqueCount - quantumVulns;

    const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of findings) {
      const level = (f.risk_level || "").toLowerCase();
      if (level.includes("critical")) severityCounts.critical++;
      else if (level.includes("high")) severityCounts.high++;
      else if (level.includes("medium")) severityCounts.medium++;
      else if (level.includes("low")) severityCounts.low++;
      else severityCounts.info++;
    }

    const riskScore = Math.min(
      100,
      severityCounts.critical * 25 + severityCounts.high * 10 + severityCounts.medium * 3 + severityCounts.low * 1
    );

    const criticalFindings = findings
      .filter((f: any) => /critical|high/i.test(f.risk_level || ""))
      .sort((a: any, b: any) => {
        const order: Record<string, number> = { critical: 0, high: 1 };
        return (order[(a.risk_level || "").toLowerCase()] ?? 2) - (order[(b.risk_level || "").toLowerCase()] ?? 2);
      })
      .slice(0, 10)
      .map((f: any) => {
        const count = f.occurrences > 1 ? ` (×${f.occurrences})` : "";
        return `[${(f.risk_level || "HIGH").toLowerCase()}] ${f.description || f.type || "Unknown vulnerability"} in ${f.file_path || "unknown file"}${count}`;
      });

    const remediationSteps: string[] = [];
    if (quantumVulns > 0) remediationSteps.push("Inventory all quantum-vulnerable cryptography (RSA, ECC, ECDSA) and plan migration to NIST PQC standards (ML-KEM, ML-DSA)");
    if (findings.some((f: any) => /secret|key|credential|token|password/i.test(f.description || f.type || ""))) remediationSteps.push("Immediately rotate any exposed secrets, API keys, or hardcoded credentials");
    if (findings.some((f: any) => /MD5|SHA-?1|DES|3DES|RC4/i.test(f.description || f.type || f.algorithm || ""))) remediationSteps.push("Replace deprecated hash/cipher algorithms with modern alternatives (SHA-256+, AES-256-GCM)");
    if (findings.some((f: any) => /TLS|SSL/i.test(f.description || f.type || ""))) remediationSteps.push("Enforce TLS 1.3 minimum; disable TLS 1.0/1.1");
    if (findings.some((f: any) => /dependency|package|version/i.test(f.description || f.type || ""))) remediationSteps.push("Update all dependencies and enable automated vulnerability alerts");
    if (remediationSteps.length === 0) remediationSteps.push("No critical issues found. Continue monitoring with regular security scans.");
    remediationSteps.push("Implement automated security scanning in CI/CD pipeline");

    const deliverable = {
      risk_score: riskScore,
      severity_summary: severityCounts,
      vulnerabilities_found: totalRaw,
      unique_findings: uniqueCount,
      quantum_vulnerabilities: quantumVulns,
      general_vulnerabilities: generalVulns,
      critical_findings: criticalFindings,
      remediation_steps: remediationSteps,
      scan_depth: scanDepth,
      scanner: "CrawDaddy Security | Quantum Shield Labs",
      repo_scanned: repoUrl,
      timestamp: new Date().toISOString(),
    };

    return { deliverable: JSON.stringify(deliverable) };
  } catch (err: any) {
    return {
      deliverable: JSON.stringify({
        error: true,
        message: `Scan failed: ${err.message}`,
        repo_url: repoUrl,
      }),
    };
  } finally {
    if (existsSync(scanDir)) {
      rmSync(scanDir, { recursive: true, force: true });
    }
  }
}

export function validateRequirements(request: any): ValidationResult {
  const repoUrl = request.repo_url;
  if (!repoUrl || typeof repoUrl !== "string") {
    return { valid: false, reason: "repo_url is required and must be a string" };
  }
  const githubPattern = /^https:\/\/github\.com\/[\w.-]+\/[\w.-]+\/?$/;
  if (!githubPattern.test(repoUrl)) {
    return { valid: false, reason: "repo_url must be a valid public GitHub repository URL" };
  }
  const validDepths = ["quick", "deep", "full"];
  if (request.scan_depth && !validDepths.includes(request.scan_depth)) {
    return { valid: false, reason: `scan_depth must be one of: ${validDepths.join(", ")}` };
  }
  return { valid: true };
}

export function requestPayment(request: any): string {
  const depth = request.scan_depth || "quick";
  return `Security scan (${depth}) of ${request.repo_url} - CrawDaddy Security by Quantum Shield Labs`;
}
