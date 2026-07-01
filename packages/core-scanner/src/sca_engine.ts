import { ForensicFinding } from './types';
import { matchAdvisories, Advisory } from './vulnerability_db';

interface ScanManifestResult {
  findings: ForensicFinding[];
  components: number;
  vulnerable: number;
}

function severityToRiskLevel(severity: Advisory['severity']): number {
  switch (severity) {
    case 'CRITICAL': return 10;
    case 'HIGH': return 8;
    case 'MEDIUM': return 5;
    case 'LOW': return 2;
  }
}

function buildFindings(
  name: string,
  version: string,
  advisories: Advisory[],
  filePath: string,
  repoName?: string,
): ForensicFinding[] {
  return advisories.map(adv => ({
    type: 'VULNERABLE_DEPENDENCY',
    severity: adv.severity,
    riskLevel: severityToRiskLevel(adv.severity),
    message: `${name}@${version} has known vulnerability: ${adv.title}`,
    evidence: `${adv.id} | CVSS: ${adv.cvss ?? 'N/A'}`,
    remediation: `Upgrade ${name} to ${adv.patchedVersions}`,
    source_engine: 'SCA',
    context: 'PRODUCTION',
    line_number: 0,
    impact: adv.description,
    metadata: {
      advisory_id: adv.id,
      cwe: adv.cwe,
      published_at: adv.publishedAt,
      vulnerable_range: adv.vulnerableVersions,
      patched_version: adv.patchedVersions,
    },
  }));
}

function parsePackageJson(
  content: string,
  filePath: string,
  repoName?: string,
): ScanManifestResult {
  const findings: ForensicFinding[] = [];
  let components = 0;
  const vulnerableSet = new Set<string>();

  try {
    const pkg = JSON.parse(content);
    const deps: Record<string, string> = {};

    if (pkg.dependencies) Object.assign(deps, pkg.dependencies);
    if (pkg.devDependencies) Object.assign(deps, pkg.devDependencies);
    if (pkg.peerDependencies) Object.assign(deps, pkg.peerDependencies);

    components = Object.keys(deps).length;

    for (const [name, verStr] of Object.entries(deps)) {
      const cleanVer = (verStr as string).replace(/^[\^~]=?/, '').replace(/^\s*[\^~]\s*/, '').trim();
      const advisories = matchAdvisories(name, cleanVer, 'npm');
      if (advisories.length > 0) {
        vulnerableSet.add(name);
        findings.push(...buildFindings(name, cleanVer, advisories, filePath, repoName));
      }
    }
  } catch {
  }

  return { findings, components, vulnerable: vulnerableSet.size };
}

function normalizeVersion(ver: string): string {
  const parts = ver.split('.');
  while (parts.length < 3) parts.push('0');
  return parts.slice(0, 3).join('.');
}

function parseRequirementsTxt(
  content: string,
  filePath: string,
  repoName?: string,
): ScanManifestResult {
  const findings: ForensicFinding[] = [];
  let components = 0;
  const vulnerableSet = new Set<string>();

  const lines = content.split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('-')) continue;
    const match = trimmed.match(/^([a-zA-Z0-9_.-]+)\s*(?:[~=<>!]+)?\s*([\d.]+)?/);
    if (!match) {
      components++;
      continue;
    }
    const name = match[1].toLowerCase();
    const rawVer = match[2] || '0.0.0';
    const version = normalizeVersion(rawVer);
    components++;
    const advisories = matchAdvisories(name, version, 'pypi');
    if (advisories.length > 0) {
      vulnerableSet.add(name);
      findings.push(...buildFindings(name, version, advisories, filePath, repoName));
    }
  }

  return { findings, components, vulnerable: vulnerableSet.size };
}

function parseGoMod(
  content: string,
  filePath: string,
  repoName?: string,
): ScanManifestResult {
  const findings: ForensicFinding[] = [];
  let components = 0;
  const vulnerableSet = new Set<string>();

  const lines = content.split(/\r?\n/);
  let inRequire = false;
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith('require (') || trimmed === 'require (') {
      inRequire = true;
      continue;
    }
    if (inRequire && trimmed === ')') {
      inRequire = false;
      continue;
    }
    if (inRequire || trimmed.startsWith('require ')) {
      const reqMatch = inRequire
        ? trimmed.match(/^([a-zA-Z0-9_./-]+)\s+v?([\d.]+)/)
        : trimmed.match(/^require\s+([a-zA-Z0-9_./-]+)\s+v?([\d.]+)/);
      if (reqMatch) {
        const name = reqMatch[1];
        const version = reqMatch[2];
        components++;
        const advisories = matchAdvisories(name, version, 'go');
        if (advisories.length > 0) {
          vulnerableSet.add(name);
          findings.push(...buildFindings(name, version, advisories, filePath, repoName));
        }
      }
    }
  }

  return { findings, components, vulnerable: vulnerableSet.size };
}

function basename(p: string): string {
  const sep = p.includes('\\') ? '\\' : '/';
  return p.split(sep).pop() || p;
}

export function scanManifest(
  content: string,
  filename: string,
  repoName?: string,
): ScanManifestResult {
  const base = basename(filename).toLowerCase();

  if (base === 'package.json') {
    return parsePackageJson(content, filename, repoName);
  }

  if (base === 'requirements.txt') {
    return parseRequirementsTxt(content, filename, repoName);
  }

  if (base === 'go.mod') {
    return parseGoMod(content, filename, repoName);
  }

  return { findings: [], components: 0, vulnerable: 0 };
}

export function detectManifestType(filename: string): 'npm' | 'pypi' | 'go' | null {
  const base = basename(filename).toLowerCase();
  if (base === 'package.json') return 'npm';
  if (base === 'requirements.txt') return 'pypi';
  if (base === 'go.mod') return 'go';
  return null;
}
