import type { ExecuteJobResult, ValidationResult } from "../../runtime/offeringTypes.js";
import { execSync } from "child_process";
import { mkdtempSync, rmSync, existsSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";

export async function executeJob(request: any): Promise<ExecuteJobResult> {
  const repoUrl: string = request.repo_url;
  const scanDepth: string = request.scan_depth || "quick";
  const scanDir = mkdtempSync(join(tmpdir(), "acp-scan-"));

  try {
    // Clone the repository
    execSync(`git clone --depth 1 ${repoUrl} ${scanDir}/repo`, {
      timeout: 60000,
      stdio: "pipe",
    });

    // Run crypto-scanner
    const scanCmd = `${process.env.HOME}/.local/bin/crypto-scanner scan ${scanDir}/repo --json`;
    let scanOutput: string;
    try {
      scanOutput = execSync(scanCmd, {
        timeout: 120000,
        stdio: "pipe",
        encoding: "utf-8",
      });
    } catch (scanErr: any) {
      // crypto-scanner may exit non-zero when findings exist
      scanOutput = scanErr.stdout || "{}";
    }

    // Parse scan results
    let results: any;
    try {
      results = JSON.parse(scanOutput);
    } catch {
      results = { raw_output: scanOutput, parse_error: true };
    }

    // Build structured deliverable
    const findings = results.findings || results.vulnerabilities || [];
    const totalVulns = Array.isArray(findings) ? findings.length : 0;

    const quantumVulns = Array.isArray(findings)
      ? findings.filter((f: any) =>
          /RSA|ECC|ECDSA|DSA|DH|SHA-1|MD5/i.test(
            f.algorithm || f.type || f.description || ""
          )
        ).length
      : 0;

    const generalVulns = totalVulns - quantumVulns;

    // Calculate risk score (0-100, higher = more risk)
    const criticalCount = Array.isArray(findings)
      ? findings.filter((f: any) => /critical/i.test(f.risk || f.severity || "")).length
      : 0;
    const highCount = Array.isArray(findings)
      ? findings.filter((f: any) => /high/i.test(f.risk || f.severity || "")).length
      : 0;

    const riskScore = Math.min(100, criticalCount * 25 + highCount * 10 + generalVulns * 3);

    const criticalFindings = Array.isArray(findings)
      ? findings
          .filter((f: any) => /critical|high/i.test(f.risk || f.severity || ""))
          .map((f: any) => `[${f.risk || f.severity || "HIGH"}] ${f.description || f.type || "Unknown vulnerability"} in ${f.file || "unknown file"}`)
          .slice(0, 10)
      : [];

    const remediationSteps = [
      ...(quantumVulns > 0
        ? ["Inventory all quantum-vulnerable cryptography (RSA, ECC, ECDSA) and plan migration to NIST PQC standards (ML-KEM, ML-DSA)"]
        : []),
      ...(criticalCount > 0
        ? ["Immediately rotate any exposed secrets, API keys, or hardcoded credentials"]
        : []),
      "Update all dependencies to latest stable versions",
      "Implement automated security scanning in CI/CD pipeline",
      "Review and enforce TLS 1.3 minimum across all connections",
    ];

    const deliverable = {
      risk_score: riskScore,
      vulnerabilities_found: totalVulns,
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
    // Cleanup
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
    return { valid: false, reason: "repo_url must be a valid public GitHub repository URL (https://github.com/owner/repo)" };
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
