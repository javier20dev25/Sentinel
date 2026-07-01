/**
 * Sentinel: Threat Intelligence & IOC Engine
 */

export interface IOCMatch {
  blocked: boolean;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  campaign: string;
  reason: string;
}

export interface ScanContext {
  isLifecycleScript: boolean;
  packageManager?: string;
  repoName?: string;
}

const MALICIOUS_DOMAINS = new Set([
  'api.telegram.org', // Often abused for exfiltration
  'discord.com/api/webhooks',
  'pastebin.com',
  'ngrok.io',
  'webhook.site',
  'burpcollaborator.net',
  'oast.pro',
  'requestrepo.com',
  'dnslog.cn',
  // Known malware C2s
  'npm-stat.com',
  'registry.npmjs.org.security-audit.top',
]);

const SUSPICIOUS_STRINGS = [
  '/etc/passwd',
  '/etc/shadow',
  '.aws/credentials',
  '.ssh/id_rsa',
  'powershell -enc',
  'base64 --decode',
  'curl -fsSL',
  'wget -qO-',
];

/**
 * Checks a URL against known IOCs
 */
export function checkUrl(url: string, ctx: ScanContext): IOCMatch {
  const result: IOCMatch = {
    blocked: false,
    severity: 'INFO',
    campaign: 'NONE',
    reason: 'CLEAN',
  };

  try {
    const urlObj = new URL(url);
    const domain = urlObj.hostname;

    if (MALICIOUS_DOMAINS.has(domain)) {
      result.blocked = true;
      result.severity = 'CRITICAL';
      result.campaign = 'KNOWN_C2_INFRASTRUCTURE';
      result.reason = `Domain ${domain} is identified as a high-risk exfiltration endpoint.`;
      return result;
    }

    // Heuristics for Discord/Telegram abuse
    if (domain.includes('discord.com') && url.includes('webhooks')) {
      result.blocked = true;
      result.severity = 'HIGH';
      result.campaign = 'DISCORD_WEBHOOK_EXFIL';
      result.reason = 'Discord webhooks are frequently used for stealing environment variables.';
      return result;
    }

    if (domain.includes('telegram.org') && ctx.isLifecycleScript) {
      result.blocked = true;
      result.severity = 'CRITICAL';
      result.campaign = 'TELEGRAM_BOT_EXFIL';
      result.reason = 'Telegram API call detected in lifecycle script (preinstall/postinstall).';
      return result;
    }

  } catch {
    // Invalid URL, ignore
  }

  return result;
}

/**
 * Scans raw text for suspicious patterns (heuristic)
 */
export function scanText(text: string): IOCMatch[] {
  const matches: IOCMatch[] = [];

  for (const pattern of SUSPICIOUS_STRINGS) {
    if (text.includes(pattern)) {
      matches.push({
        blocked: true,
        severity: 'HIGH',
        campaign: 'SUSPICIOUS_CLI_PATTERN',
        reason: `Found sensitive string/command pattern: ${pattern}`,
      });
    }
  }

  return matches;
}
