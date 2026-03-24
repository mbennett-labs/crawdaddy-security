```import type { ExecuteJobResult, ValidationResult } from "../../runtime/offeringTypes.js";

const API_BASE = "https://quantumshield-api.vercel.app";

async function fetchWithTimeout(url: string, timeoutMs: number = 30000): Promise<any> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, { signal: controller.signal });
    if (!response.ok) {
      throw new Error(`API returned ${response.status}: ${response.statusText}`);
    }
    return await response.json();
  } finally {
    clearTimeout(timeout);
  }
}

export async function executeJob(request: any): Promise<ExecuteJobResult> {
  const address: string = request.address;
  const scanType: string = request.scan_type || "token";
  const chain: string = request.chain || "base";

  try {
    let deliverable: any;

    if (scanType === "token") {
      // Token security scan via QuantumShield API
      const tokenData = await fetchWithTimeout(
        `${API_BASE}/api/token/security?address=${address}&chain=${chain}`
      );

      // Also run honeypot check for comprehensive results
      let honeypotData: any = null;
      try {
        honeypotData = await fetchWithTimeout(
          `${API_BASE}/api/honeypot/check?address=${address}&chain=${chain}`
        );
      } catch {
        // Honeypot check is supplementary, don't fail the whole scan
      }

      const tokenInfo = tokenData?.data || tokenData || {};
      const honeypotInfo = honeypotData?.data || honeypotData || {};

      const riskScore = tokenInfo.riskScore ?? tokenInfo.risk_score ?? 0;
      const flags = tokenInfo.flags || [];
      const details = tokenInfo.details || {};

      deliverable = {
        scan_type: "token_security",
        address,
        chain,
        risk_score: riskScore,
        risk_level: tokenInfo.riskLevel || getRiskLevel(riskScore),
        token_name: tokenInfo.name || details.name || "Unknown",
        token_symbol: tokenInfo.symbol || details.symbol || "Unknown",
        is_honeypot: honeypotInfo.isHoneypot ?? details.isHoneypot ?? "unknown",
        flags,
        security_details: {
          is_open_source: details.isOpenSource ?? "unknown",
          is_mintable: details.isMintable ?? "unknown",
          is_proxy: details.isProxy ?? "unknown",
          has_blacklist: details.hasBlacklist ?? "unknown",
          buy_tax: details.buyTax ?? "unknown",
          sell_tax: details.sellTax ?? "unknown",
          holder_count: details.holderCount ?? "unknown",
          top_10_holder_percent: details.top10HolderPercent ?? "unknown",
          liquidity_usd: details.liquidityUSD ?? "unknown",
        },
        honeypot_simulation: honeypotInfo.simulation
          ? {
              can_buy: honeypotInfo.simulation.canBuy,
              can_sell: honeypotInfo.simulation.canSell,
              buy_tax: honeypotInfo.simulation.buyTax,
              sell_tax: honeypotInfo.simulation.sellTax,
            }
          : null,
        remediation: generateTokenRemediation(riskScore, flags, details),
        scanner: "CrawDaddy Security | QuantumShield API | Quantum Shield Labs",
        timestamp: new Date().toISOString(),
      };

    } else if (scanType === "wallet") {
      // Wallet risk scan
      const walletData = await fetchWithTimeout(
        `${API_BASE}/api/wallet/risk?address=${address}&chain=${chain}`
      );

      const walletInfo = walletData?.data || walletData || {};
      const riskScore = walletInfo.riskScore ?? walletInfo.risk_score ?? 0;
      const details = walletInfo.details || {};

      deliverable = {
        scan_type: "wallet_risk",
        address,
        chain,
        risk_score: riskScore,
        risk_level: walletInfo.riskLevel || getRiskLevel(riskScore),
        labels: walletInfo.labels || [],
        flags: walletInfo.flags || [],
        security_details: {
          is_malicious: details.isMalicious ?? "unknown",
          is_contract: details.isContract ?? "unknown",
          blacklist_count: details.blacklistCount ?? 0,
          honeypot_related: details.honeypotRelated ?? false,
          phishing_related: details.phishingRelated ?? false,
          mixer_related: details.mixerRelated ?? false,
        },
        remediation: riskScore > 50
          ? ["Exercise extreme caution interacting with this address",
             "Check transaction history for suspicious patterns",
             "Verify address through multiple sources before sending funds"]
          : ["Address appears low risk based on available data",
             "Always verify addresses before large transactions"],
        scanner: "CrawDaddy Security | QuantumShield API | Quantum Shield Labs",
        timestamp: new Date().toISOString(),
      };

    } else if (scanType === "honeypot") {
      // Dedicated honeypot check
      const honeypotData = await fetchWithTimeout(
        `${API_BASE}/api/honeypot/check?address=${address}&chain=${chain}`
      );

      const hpInfo = honeypotData?.data || honeypotData || {};
      const simulation = hpInfo.simulation || {};

      const riskScore = hpInfo.isHoneypot ? 95 : (simulation.sellTax > 10 ? 60 : 10);

      deliverable = {
        scan_type: "honeypot_check",
        address,
        chain,
        risk_score: riskScore,
        risk_level: getRiskLevel(riskScore),
        is_honeypot: hpInfo.isHoneypot ?? "unknown",
        simulation: {
          can_buy: simulation.canBuy ?? "unknown",
          can_sell: simulation.canSell ?? "unknown",
          buy_tax: simulation.buyTax ?? "unknown",
          sell_tax: simulation.sellTax ?? "unknown",
          transfer_tax: simulation.transferTax ?? "unknown",
          buy_gas: simulation.buyGas ?? "unknown",
          sell_gas: simulation.sellGas ?? "unknown",
        },
        pair_info: hpInfo.pair || null,
        remediation: hpInfo.isHoneypot
          ? ["DO NOT INTERACT — this token is a confirmed honeypot",
             "You will not be able to sell tokens after buying",
             "Report this contract address to relevant security databases"]
          : simulation.sellTax > 10
            ? [`High sell tax detected (${simulation.sellTax}%) — proceed with caution`,
               "Verify tokenomics documentation for tax justification",
               "Test with a small amount before committing larger funds"]
            : ["Token passed honeypot simulation",
               "Buy and sell transactions appear functional",
               "Always verify with multiple sources before trading"],
        scanner: "CrawDaddy Security | QuantumShield API | Quantum Shield Labs",
        timestamp: new Date().toISOString(),
      };
    } else {
      return {
        deliverable: JSON.stringify({
          error: true,
          message: `Unknown scan_type: ${scanType}. Use 'token', 'wallet', or 'honeypot'.`,
        }),
      };
    }

    return { deliverable: JSON.stringify(deliverable) };

  } catch (err: any) {
    return {
      deliverable: JSON.stringify({
        error: true,
        message: `Scan failed: ${err.message}`,
        address,
        scan_type: scanType,
        chain,
        scanner: "CrawDaddy Security | Quantum Shield Labs",
      }),
    };
  }
}

function getRiskLevel(score: number): string {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 40) return "medium";
  if (score >= 20) return "low";
  return "minimal";
}

function generateTokenRemediation(riskScore: number, flags: string[], details: any): string[] {
  const steps: string[] = [];

  if (flags.includes("is_honeypot") || details.isHoneypot) {
    steps.push("CRITICAL: Token identified as honeypot — do not buy or interact");
  }
  if (flags.includes("high_sell_tax") || (details.sellTax && parseFloat(details.sellTax) > 10)) {
    steps.push(`High sell tax detected (${details.sellTax}%) — selling will cost significantly more than expected`);
  }
  if (flags.includes("concentrated_holders") || (details.top10HolderPercent && parseFloat(details.top10HolderPercent) > 50)) {
    steps.push("Top holders control majority of supply — high dump risk");
  }
  if (details.isMintable) {
    steps.push("Token is mintable — supply can be increased at any time by the owner");
  }
  if (!details.isOpenSource) {
    steps.push("Contract source code is not verified — unable to audit logic");
  }
  if (details.hasBlacklist) {
    steps.push("Contract has blacklist function — your address could be blocked from selling");
  }
  if (riskScore < 30 && steps.length === 0) {
    steps.push("Token appears relatively safe based on available data");
    steps.push("Always conduct your own research and verify with multiple sources");
  }
  if (steps.length === 0) {
    steps.push("Review token documentation and community before investing");
    steps.push("Start with small test transactions");
  }

  return steps;
}

export function validateRequirements(request: any): ValidationResult {
  const address = request.address;
  if (!address || typeof address !== "string") {
    return { valid: false, reason: "address is required and must be a string" };
  }

  // Accept both EVM (0x...) and Solana addresses
  const evmPattern = /^0x[a-fA-F0-9]{40}$/;
  const solanaPattern = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;

  if (!evmPattern.test(address) && !solanaPattern.test(address)) {
    return { valid: false, reason: "address must be a valid EVM (0x...) or Solana address" };
  }

  const validScanTypes = ["token", "wallet", "honeypot"];
  if (request.scan_type && !validScanTypes.includes(request.scan_type)) {
    return { valid: false, reason: `scan_type must be one of: ${validScanTypes.join(", ")}` };
  }

  const validChains = ["base", "ethereum", "bsc", "arbitrum", "polygon", "solana"];
  if (request.chain && !validChains.includes(request.chain)) {
    return { valid: false, reason: `chain must be one of: ${validChains.join(", ")}` };
  }

  return { valid: true };
}

export function requestPayment(request: any): string {
  const scanType = request.scan_type || "token";
  const chain = request.chain || "base";
  return `${scanType} security scan of ${request.address} on ${chain} - CrawDaddy Security by Quantum Shield Labs`;
}
**
***

2. **Then paste the ENTIRE handlers.ts content** (everything from `import type { ExecuteJobResult...` to the last `}`)

3. **After pasting, press Enter and type:**
```
