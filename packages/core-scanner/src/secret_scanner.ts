/* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unused-vars, @typescript-eslint/no-require-imports, react-hooks/exhaustive-deps, @next/next/no-img-element */
/**
 * Sentinel: Advanced Secret Scanner
 * Detects hardcoded secrets using pattern matching, entropy analysis, and context filtering.
 */

import { ForensicFinding } from './types';

// ─── Types ──────────────────────────────────────────────────────────────────

interface KnownPattern {
  type: string;
  severity: 'CRITICAL' | 'HIGH';
  riskLevel: number;
  pattern: RegExp;
  message: string;
}

interface LineAnalysis {
  line: string;
  lineNumber: number;
  filePath: string;
  context: 'PRODUCTION' | 'TEST_FIXTURE' | 'SANDBOX';
}

type CharSet = 'hex' | 'base64' | 'alpha' | 'alphanumeric' | 'mixed';

// ─── Known Credential Patterns ──────────────────────────────────────────────

const KNOWN_PATTERNS: KnownPattern[] = [
  {
    type: 'AWS_ACCESS_KEY_ID',
    severity: 'CRITICAL',
    riskLevel: 10,
    pattern: /(?<![0-9a-zA-Z])AKIA[2-7A-Z]{16}(?![0-9a-zA-Z])/,
    message: 'AWS Access Key ID detected in source code',
  },
  {
    type: 'AWS_SECRET_ACCESS_KEY',
    severity: 'CRITICAL',
    riskLevel: 10,
    pattern: /(?<![0-9a-zA-Z+/])[0-9a-zA-Z+/]{40}(?![0-9a-zA-Z+/=])/,
    message: 'AWS Secret Access Key detected in source code',
  },
  {
    type: 'GITHUB_PAT',
    severity: 'CRITICAL',
    riskLevel: 10,
    pattern: /(?<![0-9a-zA-Z])ghp_[0-9a-zA-Z]{36}(?![0-9a-zA-Z])/,
    message: 'GitHub Personal Access Token detected in source code',
  },
  {
    type: 'GITHUB_FINE_GRAINED_TOKEN',
    severity: 'CRITICAL',
    riskLevel: 10,
    pattern: /(?<![0-9a-zA-Z])github_pat_[0-9a-zA-Z]{82}(?![0-9a-zA-Z])/,
    message: 'GitHub Fine-Grained Personal Access Token detected in source code',
  },
  {
    type: 'GITLAB_PAT',
    severity: 'CRITICAL',
    riskLevel: 10,
    pattern: /(?<![0-9a-zA-Z])glpat-[0-9a-zA-Z\-]{20,}(?![0-9a-zA-Z])/,
    message: 'GitLab Personal Access Token detected in source code',
  },
  {
    type: 'SLACK_TOKEN',
    severity: 'CRITICAL',
    riskLevel: 10,
    pattern: /(?<![0-9a-zA-Z])xox[bapr]-[0-9a-zA-Z\-]{10,}(?![0-9a-zA-Z])/,
    message: 'Slack Token detected in source code',
  },
  {
    type: 'DISCORD_BOT_TOKEN',
    severity: 'CRITICAL',
    riskLevel: 10,
    pattern: /(?<![0-9a-zA-Z])[0-9a-zA-Z]{24}\.[0-9a-zA-Z]{6}\.[0-9a-zA-Z\-_]{27}(?![0-9a-zA-Z])/,
    message: 'Discord Bot Token detected in source code',
  },
  {
    type: 'GOOGLE_API_KEY',
    severity: 'CRITICAL',
    riskLevel: 10,
    pattern: /(?<![0-9a-zA-Z])AIza[0-9A-Za-z\-_]{35}(?![0-9a-zA-Z])/,
    message: 'Google API Key detected in source code',
  },
  {
    type: 'GOOGLE_OAUTH_CLIENT',
    severity: 'CRITICAL',
    riskLevel: 10,
    pattern: /(?<![0-9a-zA-Z])[0-9]+-[0-9a-zA-Z_]{32}\.apps\.googleusercontent\.com(?![0-9a-zA-Z])/,
    message: 'Google OAuth Client ID detected in source code',
  },
  {
    type: 'STRIPE_LIVE_KEY',
    severity: 'CRITICAL',
    riskLevel: 10,
    pattern: /(?<![0-9a-zA-Z])sk_live_[0-9a-zA-Z]{24,}(?![0-9a-zA-Z])/,
    message: 'Stripe Live Secret Key detected in source code',
  },
  {
    type: 'STRIPE_TEST_KEY',
    severity: 'CRITICAL',
    riskLevel: 10,
    pattern: /(?<![0-9a-zA-Z])sk_test_[0-9a-zA-Z]{24,}(?![0-9a-zA-Z])/,
    message: 'Stripe Test Secret Key detected in source code',
  },
  {
    type: 'TWILIO_API_KEY',
    severity: 'CRITICAL',
    riskLevel: 10,
    pattern: /(?<![0-9a-zA-Z])SK[a-fA-F0-9]{32}(?![0-9a-zA-Z])/,
    message: 'Twilio API Key detected in source code',
  },
  {
    type: 'JWT_TOKEN',
    severity: 'CRITICAL',
    riskLevel: 10,
    pattern: /(?<![0-9a-zA-Z])eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+(?![0-9a-zA-Z])/,
    message: 'JWT Token detected in source code',
  },
  {
    type: 'PEM_PRIVATE_KEY',
    severity: 'CRITICAL',
    riskLevel: 10,
    pattern: /-----BEGIN\s*(RSA|EC|DSA|OPENSSH)?\s*PRIVATE\s*KEY-----/,
    message: 'PEM-encoded private key detected in source code',
  },
  {
    type: 'NPM_TOKEN',
    severity: 'CRITICAL',
    riskLevel: 10,
    pattern: /(?<![0-9a-zA-Z])npm_[0-9a-zA-Z]{36}(?![0-9a-zA-Z])/,
    message: 'npm Token detected in source code',
  },
  {
    type: 'DOCKER_HUB_TOKEN',
    severity: 'CRITICAL',
    riskLevel: 10,
    pattern: /(?<![0-9a-zA-Z])dckr_pat_[0-9a-zA-Z\-_]+(?![0-9a-zA-Z])/,
    message: 'Docker Hub Personal Access Token detected in source code',
  },
];

// ─── Suspicious Variable Patterns (for entropy-based detection) ────────────

const SUSPICIOUS_VAR_NAMES = [
  'password', 'passwd', 'pwd', 'secret', 'api[_-]?key', 'apikey',
  'auth[_-]?token', 'auth_token', 'access[_-]?key', 'access_key',
  'private[_-]?key', 'private_key', 'token', 'credential',
  'secret_key', 'secretkey', 'db[_-]?url', 'database_url',
  'connection_string', 'conn[_-]?string', 'jwt[_-]?secret',
  'jwt_secret', 'session[_-]?secret', 'session_secret',
  'encryption[_-]?key', 'encryption_key', 'auth[_-]?secret',
  'auth_secret', 'client[_-]?secret', 'client_secret',
  'consumer[_-]?key', 'consumer_key', 'consumer[_-]?secret',
  'consumer_secret', 'slack[_-]?token', 'discord[_-]?token',
  'github[_-]?token', 'gitlab[_-]?token', 'stripe[_-]?key',
  'stripe_key', 'twilio[_-]?[a-z]+', 'sendgrid[_-]?[a-z]+',
  'mailgun[_-]?[a-z]+', 'aws[_-]?[a-z_]*key', 'aws[_-]?[a-z_]*secret',
];

const SUSPICIOUS_VAR_REGEX = new RegExp(
  `(?:${SUSPICIOUS_VAR_NAMES.join('|')})\\s*[:=]\\s*['"\`]([^'"\`]{8,})['"\`]`,
  'i',
);

// ─── Context / FP Reduction Patterns ───────────────────────────────────────

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SHA256_REGEX = /^[0-9a-f]{64}$/i;
const SHA1_REGEX = /^[0-9a-f]{40}$/i;
const MD5_REGEX = /^[0-9a-f]{32}$/i;
const VERSION_REGEX = /^[\^~]?\d+\.\d+\.\d+/;
const URL_REGEX = /^https?:\/\//i;
const FILE_PATH_REGEX = /^(\/[^\0]*|[a-zA-Z]:\\(?:[^\\\0]+\\)*[^\\\0]*)$/;
const HEX_STRING_REGEX = /^[0-9a-fA-F]+$/;
const BASE64_STRING_REGEX = /^[0-9a-zA-Z+/]+=*$/;

const SAFE_VALUE_PATTERNS = [
  'example', 'sample', 'test', 'mock', 'fixture', 'placeholder',
  'your-', 'xxxx', 'changeme', 'replaceme', 'todo', 'demo',
  'dummy', 'fake', 'tbd', 'xxx', '***',
];

const TEST_PATH_PATTERNS = [
  'test/', 'tests/', '__tests__/', 'spec/', 'fixtures/',
  'mocks/', 'examples/', '.test.', '.spec.',
];

const SANDBOX_PATH_PATTERNS = ['sandbox', 'sentinel-sandbox', 'baseline.js', 'simulation'];

// ─── Entropy Calculation ────────────────────────────────────────────────────

function detectCharset(str: string): CharSet {
  if (/^[a-zA-Z]+$/.test(str)) return 'alpha';
  if (/^[0-9a-fA-F]+$/.test(str)) return 'hex';
  if (/^[0-9a-zA-Z]+$/.test(str)) return 'alphanumeric';
  if (/^[0-9a-zA-Z+/]*[+/=][0-9a-zA-Z+/=]*$/.test(str)) return 'base64';
  return 'mixed';
}

function calculateEntropy(str: string): number {
  const len = str.length;
  if (len === 0) return 0;

  const freq: Record<string, number> = {};
  for (const char of str) {
    freq[char] = (freq[char] || 0) + 1;
  }

  let entropy = 0;
  for (const char of Object.keys(freq)) {
    const p = freq[char] / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

function getEntropyThreshold(charset: CharSet): number {
  switch (charset) {
    case 'hex': return 3.5;
    case 'base64': return 4.5;
    case 'alpha': return 4.2;
    case 'alphanumeric': return 4.0;
    case 'mixed': return 4.5;
  }
}

// ─── AWS Access Key Validation ──────────────────────────────────────────────

function isValidAWSKey(key: string): boolean {
  return /^AKIA[2-7A-Z]{16}$/.test(key);
}

// ─── Context Classification ────────────────────────────────────────────────

function classifyFileContext(filePath: string): 'PRODUCTION' | 'TEST_FIXTURE' | 'SANDBOX' {
  const lower = filePath.toLowerCase();
  if (SANDBOX_PATH_PATTERNS.some((p) => lower.includes(p))) return 'SANDBOX';
  if (TEST_PATH_PATTERNS.some((p) => lower.includes(p))) return 'TEST_FIXTURE';
  return 'PRODUCTION';
}

// ─── Safe Value Checking ────────────────────────────────────────────────────

const SAFE_VALUE_REGEX = new RegExp(
  SAFE_VALUE_PATTERNS.map((p) => {
    const escaped = p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    if (p.endsWith('-')) {
      return `(?:^|[^a-zA-Z0-9])${escaped}`;
    }
    return `(?:^|[^a-zA-Z0-9])${escaped}(?:$|[^a-zA-Z0-9])`;
  }).join('|'),
  'i',
);

function isSafeValue(value: string): boolean {
  return SAFE_VALUE_REGEX.test(value);
}

function isStructuralString(value: string): boolean {
  if (UUID_REGEX.test(value)) return true;
  if (SHA256_REGEX.test(value)) return true;
  if (SHA1_REGEX.test(value)) return true;
  if (MD5_REGEX.test(value)) return true;
  if (VERSION_REGEX.test(value)) return true;
  return false;
}

function isLikelySafeLine(line: string, value: string): boolean {
  const trimmed = line.trim();

  if (/^\s*import\s/.test(line)) return true;
  if (/\brequire\s*\(/.test(trimmed)) return true;
  if (isSafeValue(value)) return true;
  if (isStructuralString(value)) return true;

  if (URL_REGEX.test(value)) return true;
  if (FILE_PATH_REGEX.test(value.trim())) return true;

  return false;
}

// ─── Line Analysis Helpers ──────────────────────────────────────────────────

function extractStringLiterals(line: string): string[] {
  const literals: string[] = [];

  const singleQuote = /'([^'\\]*(?:\\.[^'\\]*)*)'/g;
  const doubleQuote = /"([^"\\]*(?:\\.[^"\\]*)*)"/g;
  const templateLiteral = /`([^`\\]*(?:\\.[^`\\]*)*)`/g;

  let m: RegExpExecArray | null;
  while ((m = singleQuote.exec(line)) !== null) literals.push(m[1]);
  while ((m = doubleQuote.exec(line)) !== null) literals.push(m[1]);
  while ((m = templateLiteral.exec(line)) !== null) literals.push(m[1]);

  return literals;
}

function containsSecretIndicator(value: string): boolean {
  const mixedCase = /[a-z]/.test(value) && /[A-Z]/.test(value);
  const hasDigits = /[0-9]/.test(value);
  const hasSpecial = /[+\/-]/.test(value);
  const length = value.length;

  if (length >= 32 && mixedCase && hasDigits) return true;
  if (length >= 20 && mixedCase && hasDigits && hasSpecial) return true;
  if (length >= 40 && /^[0-9a-zA-Z+/]+=*$/.test(value)) return true;

  return false;
}

// ─── Entropy-Based Detection ────────────────────────────────────────────────

function entropyScan(line: string, lineNumber: number, analysis: LineAnalysis): ForensicFinding[] {
  const findings: ForensicFinding[] = [];
  const { context } = analysis;

  const varMatch = line.match(SUSPICIOUS_VAR_REGEX);
  if (!varMatch) return findings;

  const value = varMatch[1];
  if (isLikelySafeLine(line, value)) return findings;
  if (!containsSecretIndicator(value)) return findings;

  const charset = detectCharset(value);
  const entropy = calculateEntropy(value);
  const threshold = getEntropyThreshold(charset);

  if (entropy < threshold) return findings;

  let severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' = 'HIGH';
  let riskLevel = 8;

  if (entropy > threshold + 1.0) {
    severity = 'CRITICAL';
    riskLevel = 9;
  }

  if (context === 'TEST_FIXTURE') {
    severity = 'HIGH';
    riskLevel = 7;
  }

  if (isSafeValue(value)) {
    severity = 'INFO';
    riskLevel = 1;
  }

  findings.push({
    type: 'GENERIC_HIGH_ENTROPY_SECRET',
    severity,
    riskLevel,
    message: `Potential hardcoded secret detected (entropy: ${entropy.toFixed(2)}, charset: ${charset})`,
    evidence: value.length > 200 ? value.substring(0, 200) : value,
    source_engine: 'SECRET_SCANNER',
    context,
    line_number: lineNumber,
    metadata: {
      entropy: entropy,
      charset: charset,
      variable: varMatch[0].split(/[:=]/)[0].trim(),
    },
  });

  return findings;
}

// ─── Base64 / Hex String Scanning ───────────────────────────────────────────

function scanRawStrings(line: string, lineNumber: number, analysis: LineAnalysis): ForensicFinding[] {
  const findings: ForensicFinding[] = [];
  const { context } = analysis;

  const literals = extractStringLiterals(line);
  for (const literal of literals) {
    if (literal.length < 32) continue;
    if (isLikelySafeLine(line, literal)) continue;

    const charset = detectCharset(literal);
    if (charset !== 'base64' && charset !== 'hex') continue;

    if (charset === 'hex' && literal.length < 40) continue;

    const entropy = calculateEntropy(literal);
    const threshold = getEntropyThreshold(charset);
    if (entropy < threshold) continue;

    if (!containsSecretIndicator(literal)) continue;

    let severity: 'HIGH' | 'MEDIUM' | 'INFO' = 'HIGH';
    let riskLevel = 8;

    if (context === 'TEST_FIXTURE') {
      severity = 'MEDIUM';
      riskLevel = 6;
    }

    if (isSafeValue(literal)) {
      severity = 'INFO';
      riskLevel = 1;
    }

    findings.push({
      type: charset === 'hex' ? 'HIGH_ENTROPY_HEX_STRING' : 'HIGH_ENTROPY_BASE64_STRING',
      severity,
      riskLevel,
      message: `${charset === 'hex' ? 'Hex' : 'Base64'} string with high entropy found${literal.length > 64 ? ' (potential key material)' : ''}`,
      evidence: literal.length > 200 ? literal.substring(0, 200) : literal,
      source_engine: 'SECRET_SCANNER',
      context,
      line_number: lineNumber,
      metadata: {
        entropy,
        charset,
        length: literal.length,
      },
    });
  }

  return findings;
}

// ─── Known Pattern Matching ─────────────────────────────────────────────────

function shouldSkipKnownPattern(line: string, value: string): boolean {
  const trimmed = line.trim();
  if (/^\s*import\s/.test(line)) return true;
  if (/\brequire\s*\(/.test(trimmed)) return true;
  if (isStructuralString(value)) return true;
  if (URL_REGEX.test(value)) return true;
  if (FILE_PATH_REGEX.test(value.trim())) return true;
  return false;
}

function scanKnownPatterns(code: string, analysis: LineAnalysis): ForensicFinding[] {
  const findings: ForensicFinding[] = [];
  const lines = code.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNumber = i + 1;

    for (const rule of KNOWN_PATTERNS) {
      const match = line.match(rule.pattern);
      if (!match) continue;

      if (rule.type === 'AWS_ACCESS_KEY_ID' && !isValidAWSKey(match[0])) continue;

      if (shouldSkipKnownPattern(line, match[0])) continue;

      const masked = maskSecret(match[0]);

      findings.push({
        type: rule.type,
        severity: rule.severity,
        riskLevel: rule.riskLevel,
        message: rule.message,
        evidence: masked,
        source_engine: 'SECRET_SCANNER',
        context: analysis.context,
        line_number: lineNumber,
        metadata: {
          pattern_type: rule.type,
          match_length: match[0].length,
        },
        remediation: getRemediation(rule.type),
        impact: getImpact(rule.type),
      });
    }
  }

  return findings;
}

// ─── PEM Private Key Scanner (multi-line) ──────────────────────────────────

function scanPEMKeys(code: string, analysis: LineAnalysis): ForensicFinding[] {
  const findings: ForensicFinding[] = [];

  const pemMatch = code.match(/-----BEGIN\s*(RSA|EC|DSA|OPENSSH)?\s*PRIVATE\s*KEY-----[\s\S]*?-----END\s*(?:RSA|EC|DSA|OPENSSH)?\s*PRIVATE\s*KEY-----/);
  if (!pemMatch) return findings;

  const keyType = pemMatch[1] ? `${pemMatch[1]} ` : '';

  const lineBefore = code.substring(0, pemMatch.index).split('\n');
  const lineNumber = lineBefore.length;

  findings.push({
    type: 'PEM_PRIVATE_KEY',
    severity: 'CRITICAL',
    riskLevel: 10,
    message: `${keyType}PEM private key detected in source code`,
    evidence: pemMatch[0].substring(0, 80) + '...[TRUNCATED]',
    source_engine: 'SECRET_SCANNER',
    context: analysis.context,
    line_number: lineNumber,
    metadata: {
      key_type: pemMatch[1] || 'RSA/DSA/EC',
      key_length: pemMatch[0].length,
    },
    remediation: 'Remove the private key from source code and store in a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault). Use environment variables or secret injection at runtime.',
    impact: 'Exposed private keys allow unauthorized access to encrypted communications, SSH servers, and signed software artifacts.',
  });

  return findings;
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function maskSecret(secret: string): string {
  if (secret.length <= 8) return '***[MASKED]***';
  return `${secret.substring(0, 4)}***[MASKED]***${secret.substring(secret.length - 4)}`;
}

function getRemediation(type: string): string {
  const remediations: Record<string, string> = {
    AWS_ACCESS_KEY_ID: 'Rotate the AWS access key immediately. Remove from source and use IAM roles or environment variables.',
    AWS_SECRET_ACCESS_KEY: 'Rotate the AWS secret key immediately. Remove from source and use IAM roles or environment variables.',
    GITHUB_PAT: 'Revoke the token on GitHub and remove from source. Use GitHub Actions secrets or environment variables.',
    GITHUB_FINE_GRAINED_TOKEN: 'Revoke the token on GitHub and remove from source. Use GitHub Actions secrets or environment variables.',
    GITLAB_PAT: 'Revoke the token on GitLab and remove from source. Use CI/CD variables instead.',
    SLACK_TOKEN: 'Rotate the Slack token immediately. Remove from source and use environment variables or Slack app authentication.',
    DISCORD_BOT_TOKEN: 'Regenerate the bot token in Discord Developer Portal. Store in environment variables.',
    GOOGLE_API_KEY: 'Regenerate the API key in Google Cloud Console. Restrict the key to specific APIs and IP addresses.',
    GOOGLE_OAUTH_CLIENT: 'Regenerate the OAuth client secret in Google Cloud Console.',
    STRIPE_LIVE_KEY: 'Rotate the key in Stripe Dashboard immediately. Use Stripe CLI or environment variables for local development.',
    STRIPE_TEST_KEY: 'Rotate the key in Stripe Dashboard. While test keys are lower risk, they should still follow secrets management best practices.',
    TWILIO_API_KEY: 'Rotate the Twilio API key in Twilio Console. Store in environment variables.',
    JWT_TOKEN: 'Revoke the JWT immediately. Ensure JWTs are stored securely and never committed to source control.',
    PEM_PRIVATE_KEY: 'Remove the private key from source code and store in a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault). Use environment variables or secret injection at runtime.',
    NPM_TOKEN: 'Revoke the npm token immediately. Use .npmrc with environment variable interpolation (e.g., \${NPM_TOKEN}).',
    DOCKER_HUB_TOKEN: 'Rotate the Docker Hub token. Use Docker credential helpers or environment variables.',
  };
  return remediations[type] || 'Remove the secret from source code and use environment variables or a secrets manager.';
}

function getImpact(type: string): string {
  const impacts: Record<string, string> = {
    AWS_ACCESS_KEY_ID: 'Compromises AWS account resources including EC2, S3, and IAM. Could lead to data exfiltration and financial loss.',
    AWS_SECRET_ACCESS_KEY: 'Full AWS API access. Can be used with the access key ID to perform any AWS operation as the associated IAM user or role.',
    GITHUB_PAT: 'Full access to GitHub repositories, potentially including read/write access to private repos.',
    GITHUB_FINE_GRAINED_TOKEN: 'Scoped access to GitHub resources as defined in the token permissions.',
    GITLAB_PAT: 'Full access to GitLab projects and registries.',
    SLACK_TOKEN: 'Unrestricted access to Slack workspace messages and channels.',
    DISCORD_BOT_TOKEN: 'Full control of the Discord bot and access to all guilds the bot is in.',
    GOOGLE_API_KEY: 'Access to Google Cloud services and APIs. Could result in unexpected charges.',
    GOOGLE_OAUTH_CLIENT: 'Could be used for OAuth impersonation or authorization bypass.',
    STRIPE_LIVE_KEY: 'Full access to Stripe payment processing, customer data, and refund capabilities.',
    STRIPE_TEST_KEY: 'Access to Stripe test mode data only, but real keys should not be in source code.',
    TWILIO_API_KEY: 'Access to Twilio telephony services, SMS, and voice capabilities.',
    JWT_TOKEN: 'Unauthorized access to the application or API the JWT was issued for.',
    PEM_PRIVATE_KEY: 'Man-in-the-middle attacks, SSH server compromise, and software signing forgery.',
    NPM_TOKEN: 'Ability to publish packages under the associated npm organization or user account.',
    DOCKER_HUB_TOKEN: 'Access to Docker Hub repositories and organization settings.',
  };
  return impacts[type] || 'Exposed credentials can lead to unauthorized access, data breaches, and financial fraud.';
}

// ─── Main Scanner ───────────────────────────────────────────────────────────

export function scanSecrets(code: string, filePath: string = 'unknown'): ForensicFinding[] {
  if (!code || code.length === 0) return [];

  const analysis: LineAnalysis = {
    line: '',
    lineNumber: 0,
    filePath,
    context: classifyFileContext(filePath),
  };

  const findings: ForensicFinding[] = [];

  const seenKeys = new Set<string>();

  function addFinding(finding: ForensicFinding): void {
    const key = `${finding.type}:${finding.line_number}:${finding.evidence?.substring(0, 40)}`;
    if (!seenKeys.has(key)) {
      seenKeys.add(key);
      findings.push(finding);
    }
  }

  const knownFindings = scanKnownPatterns(code, analysis);
  for (const f of knownFindings) addFinding(f);

  const pemFindings = scanPEMKeys(code, analysis);
  for (const f of pemFindings) addFinding(f);

  const lines = code.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineAnalysis: LineAnalysis = { ...analysis, line, lineNumber: i + 1 };

    const entropyFindings = entropyScan(line, i + 1, lineAnalysis);
    for (const f of entropyFindings) addFinding(f);

    const rawFindings = scanRawStrings(line, i + 1, lineAnalysis);
    for (const f of rawFindings) addFinding(f);
  }

  return findings;
}

export {
  calculateEntropy,
  detectCharset,
  getEntropyThreshold,
  isValidAWSKey,
  isSafeValue,
  isStructuralString,
  isLikelySafeLine,
  SUSPICIOUS_VAR_NAMES,
  KNOWN_PATTERNS,
};
