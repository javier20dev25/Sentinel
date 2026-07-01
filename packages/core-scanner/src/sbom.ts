/* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unused-vars, @typescript-eslint/no-require-imports, react-hooks/exhaustive-deps, @next/next/no-img-element */
import * as yaml from 'js-yaml';

export interface SBOMComponent {
  type: 'library' | 'application' | 'framework';
  name: string;
  version: string;
  purl: string;
  hashes?: Array<{ alg: string; content: string }>;
  licenses?: Array<{ license: { id: string } }>;
  evidence?: { identity: { field: string } };
}

export interface SBOMDependency {
  ref: string;
  dependsOn: string[];
}

export interface VulnerabilityRef {
  id: string;
  source: { name: string; url: string };
  ratings: Array<{ score: number; severity: string; method: string }>;
  description: string;
}

export interface SBOMResult {
  format: 'cyclonedx' | 'spdx';
  content: string;
  components: number;
  dependencies: number;
}

export interface ManifestFiles {
  [filename: string]: string;
}

const SPDX_LICENSE_MAP: Record<string, string> = {
  'MIT': 'MIT',
  'Apache-2.0': 'Apache-2.0',
  'Apache 2.0': 'Apache-2.0',
  'Apache2': 'Apache-2.0',
  'ISC': 'ISC',
  'BSD-2-Clause': 'BSD-2-Clause',
  'BSD-3-Clause': 'BSD-3-Clause',
  'BSD': 'BSD-3-Clause',
  'GPL-2.0': 'GPL-2.0-only',
  'GPL-2.0+': 'GPL-2.0-or-later',
  'GPL-3.0': 'GPL-3.0-only',
  'GPL-3.0+': 'GPL-3.0-or-later',
  'LGPL-2.1': 'LGPL-2.1-only',
  'LGPL-3.0': 'LGPL-3.0-only',
  'MPL-2.0': 'MPL-2.0',
  'Unlicense': 'Unlicense',
  'CC0-1.0': 'CC0-1.0',
  'WTFPL': 'WTFPL',
  'Artistic-2.0': 'Artistic-2.0',
  'Zlib': 'Zlib',
  'Python-2.0': 'Python-2.0',
  'BSL-1.0': 'BSL-1.0',
  '0BSD': '0BSD',
};

const COMMON_LICENSES: Record<string, string> = {
  'express': 'MIT',
  'react': 'MIT',
  'lodash': 'MIT',
  'axios': 'MIT',
  'next': 'MIT',
  'typescript': 'Apache-2.0',
  'webpack': 'MIT',
  'babel': 'MIT',
  'eslint': 'MIT',
  'prettier': 'MIT',
  'jest': 'MIT',
  'mocha': 'MIT',
  'chai': 'MIT',
  'sinon': 'BSD-3-Clause',
  'moment': 'MIT',
  'chalk': 'MIT',
  'commander': 'MIT',
  'ws': 'MIT',
  'pg': 'MIT',
  'bcrypt': 'MIT',
  'jsonwebtoken': 'MIT',
  'passport': 'MIT',
  'socket.io': 'MIT',
  'uuid': 'MIT',
  'debug': 'MIT',
  'tslib': '0BSD',
  'minimist': 'MIT',
  'semver': 'ISC',
  'glob': 'ISC',
  'js-yaml': 'MIT',
  'inquirer': 'MIT',
  'ora': 'MIT',
};

interface KnownVuln {
  id: string;
  versions: string[];
  severity: string;
  score: number;
  description: string;
}

const KNOWN_VULNERABILITIES: Record<string, KnownVuln[]> = {
  'npm:axios': [
    { id: 'CVE-2023-45857', versions: ['<1.6.0'], severity: 'HIGH', score: 7.5, description: 'Server-Side Request Forgery in axios' },
    { id: 'CVE-2024-39338', versions: ['<1.7.3'], severity: 'HIGH', score: 7.5, description: 'axios request smuggling via absolute URL' },
  ],
  'npm:lodash': [
    { id: 'CVE-2020-28500', versions: ['<4.17.21'], severity: 'CRITICAL', score: 9.1, description: 'Prototype pollution in lodash' },
    { id: 'CVE-2021-23337', versions: ['<4.17.21'], severity: 'HIGH', score: 7.2, description: 'Command injection in lodash' },
  ],
  'npm:express': [
    { id: 'CVE-2024-29041', versions: ['<4.19.2'], severity: 'MEDIUM', score: 5.5, description: 'Express path traversal vulnerability' },
  ],
  'npm:next': [
    { id: 'CVE-2024-34351', versions: ['<14.1.1'], severity: 'HIGH', score: 7.5, description: 'Next.js Server-Side Request Forgery' },
  ],
  'npm:minimist': [
    { id: 'CVE-2021-44906', versions: ['<1.2.6'], severity: 'CRITICAL', score: 9.8, description: 'Prototype pollution in minimist' },
  ],
  'pypi:requests': [
    { id: 'CVE-2024-35195', versions: ['<2.32.0'], severity: 'MEDIUM', score: 5.5, description: 'Requests certificate verification bypass' },
  ],
  'pypi:flask': [
    { id: 'CVE-2023-30861', versions: ['<2.3.2'], severity: 'HIGH', score: 7.5, description: 'Flask possible XSS via debugger' },
  ],
  'golang:golang.org/x/net': [
    { id: 'CVE-2023-44487', versions: ['<0.17.0'], severity: 'HIGH', score: 7.5, description: 'HTTP/2 rapid reset attack' },
  ],
  'cargo:serde': [
    { id: 'RUSTSEC-2024-0001', versions: ['<1.0.190'], severity: 'MEDIUM', score: 5.0, description: 'Serde deserialization vulnerability' },
  ],
};

function normalizeLicense(license: string | undefined | null): string {
  if (!license) return 'NOASSERTION';
  const normalized = license.trim();
  if (SPDX_LICENSE_MAP[normalized]) return SPDX_LICENSE_MAP[normalized];
  if (SPDX_LICENSE_MAP[normalized.toUpperCase()]) return SPDX_LICENSE_MAP[normalized.toUpperCase()];
  const upper = normalized.toUpperCase();
  if (upper.startsWith('MIT') || upper === 'X11' || upper === 'NPM-UNIQUE-MIT') return 'MIT';
  if (upper.includes('APACHE') && (upper.includes('2') || upper.includes('TWO'))) return 'Apache-2.0';
  if (upper.includes('GPL') && upper.includes('2')) return 'GPL-2.0-only';
  if (upper.includes('GPL') && upper.includes('3')) return 'GPL-3.0-only';
  if (upper.includes('BSD')) return 'BSD-3-Clause';
  if (upper.includes('MPL')) return 'MPL-2.0';
  return normalized;
}

function detectLicense(fields: Record<string, unknown>): string {
  const raw = fields.license;
  if (typeof raw === 'string') return normalizeLicense(raw);
  if (raw && typeof raw === 'object' && 'type' in (raw as object)) {
    return normalizeLicense((raw as { type: string }).type);
  }
  if (Array.isArray(raw) && raw.length > 0) {
    const first = raw[0];
    if (typeof first === 'string') return normalizeLicense(first);
    if (first && typeof first === 'object' && 'type' in (first as object)) {
      return normalizeLicense((first as { type: string }).type);
    }
  }
  return 'NOASSERTION';
}

function toPurl(type: string, name: string, version: string): string {
  const encodedName = encodeURIComponent(name).replace(/%2F/g, '/').replace(/%40/g, '@');
  return `pkg:${type}/${encodedName}@${version}`;
}

function makeComponent(
  name: string,
  version: string,
  hasIntegrity?: string,
  license?: string
): SBOMComponent {
  const comp: SBOMComponent = {
    type: 'library',
    name,
    version,
    purl: toPurl('npm', name, version),
    licenses: [{ license: { id: license || 'NOASSERTION' } }],
    evidence: { identity: { field: 'purl' } },
  };
  if (hasIntegrity) {
    const algMap: Record<string, string> = { sha512: 'SHA-512', sha384: 'SHA-384', sha256: 'SHA-256', sha1: 'SHA-1' };
    const prefix = Object.keys(algMap).find(k => hasIntegrity.startsWith(k));
    if (prefix) {
      comp.hashes = [{ alg: algMap[prefix], content: hasIntegrity.slice(prefix.length + 1) }];
    }
  }
  return comp;
}

function semverCmp(a: string, b: string): number {
  const pa = a.replace(/^[^0-9]*/, '').split('.').map(Number);
  const pb = b.replace(/^[^0-9]*/, '').split('.').map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const na = pa[i] || 0;
    const nb = pb[i] || 0;
    if (na > nb) return 1;
    if (na < nb) return -1;
  }
  return 0;
}

function versionInRange(version: string, range: string): boolean {
  if (range.startsWith('<=')) return semverCmp(version, range.slice(2)) <= 0;
  if (range.startsWith('>=')) return semverCmp(version, range.slice(2)) >= 0;
  if (range.startsWith('<')) return semverCmp(version, range.slice(1)) < 0;
  if (range.startsWith('>')) return semverCmp(version, range.slice(1)) > 0;
  if (range.includes('||')) return range.split('||').some(r => versionInRange(version, r.trim()));
  return version === range;
}

function checkVulnerabilities(ecosystem: string, name: string, version: string): VulnerabilityRef[] {
  const key = `${ecosystem}:${name}`;
  const vulns = KNOWN_VULNERABILITIES[key];
  if (!vulns) return [];

  const matched: VulnerabilityRef[] = [];
  for (const vuln of vulns) {
    if (vuln.versions.some(r => versionInRange(version, r))) {
      matched.push({
        id: vuln.id,
        source: { name: 'Sentinel Vulnerability DB', url: `https://sentinel.security/advisories/${vuln.id.toLowerCase()}` },
        ratings: [{ score: vuln.score, severity: vuln.severity, method: 'CVSSv3' }],
        description: vuln.description,
      });
    }
  }
  return matched;
}

function depLicenseFromMap(name: string): string {
  return COMMON_LICENSES[name] || 'MIT';
}

function parsePackageJson(
  content: string,
  repoName: string,
  repoVersion?: string
): { components: SBOMComponent[]; deps: SBOMDependency[]; appComp: SBOMComponent } {
  const pkg = JSON.parse(content);
  const appName = pkg.name || repoName;
  const appVersion = pkg.version || repoVersion || '0.0.0';

  const appComp: SBOMComponent = {
    type: 'application',
    name: appName,
    version: appVersion,
    purl: toPurl('npm', appName, appVersion),
    licenses: [{ license: { id: detectLicense(pkg) } }],
    evidence: { identity: { field: 'purl' } },
  };

  const allDeps: Record<string, string> = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
  const components: SBOMComponent[] = [];
  const depRefs: string[] = [];

  for (const [depName, depVersion] of Object.entries(allDeps)) {
    const ver = String(depVersion).replace(/^[\^~]/, '');
    const comp = makeComponent(depName, ver, undefined, depLicenseFromMap(depName));
    components.push(comp);
    depRefs.push(comp.purl);
  }

  return { components, deps: [{ ref: appComp.purl, dependsOn: depRefs }], appComp };
}

function parsePackageLock(
  content: string,
  repoName: string,
  repoVersion?: string
): { components: SBOMComponent[]; deps: SBOMDependency[]; appComp: SBOMComponent } {
  const lock = JSON.parse(content);
  const appName = lock.name || repoName;
  const appVersion = lock.version || repoVersion || '0.0.0';

  const appComp: SBOMComponent = {
    type: 'application',
    name: appName,
    version: appVersion,
    purl: toPurl('npm', appName, appVersion),
    licenses: [{ license: { id: 'NOASSERTION' } }],
    evidence: { identity: { field: 'purl' } },
  };

  const components: SBOMComponent[] = [];
  const depRefs: string[] = [];
  const seen = new Set<string>();

  const packages = lock.packages || {};
  for (const [key, info] of Object.entries(packages)) {
    if (key === '') continue;
    const pkgInfo = info as Record<string, unknown>;
    const pkgName = key.replace(/^node_modules\//, '');
    const pkgVersion = String(pkgInfo.version || '0.0.0');
    const integrity = String(pkgInfo.integrity || '');
    const license = typeof pkgInfo.license === 'string' ? String(pkgInfo.license) : '';
    const comp = makeComponent(pkgName, pkgVersion, integrity || undefined, license ? normalizeLicense(license) : depLicenseFromMap(pkgName));
    components.push(comp);
    depRefs.push(comp.purl);
    seen.add(`${pkgName}@${pkgVersion}`);
  }

  const deps = lock.dependencies || {};
  for (const [depName, depInfo] of Object.entries(deps)) {
    const info = depInfo as Record<string, unknown>;
    const ver = String(info.version || '0.0.0');
    const key = `${depName}@${ver}`;
    if (seen.has(key)) continue;
    const integrity = String(info.integrity || '');
    const comp = makeComponent(depName, ver, integrity || undefined);
    components.push(comp);
    depRefs.push(comp.purl);
    seen.add(key);
  }

  return { components, deps: [{ ref: appComp.purl, dependsOn: depRefs }], appComp };
}

function parseYarnLock(
  content: string,
  repoName: string,
  repoVersion?: string
): { components: SBOMComponent[]; deps: SBOMDependency[]; appComp: SBOMComponent } {
  const appComp: SBOMComponent = {
    type: 'application',
    name: repoName,
    version: repoVersion || '0.0.0',
    purl: toPurl('npm', repoName, repoVersion || '0.0.0'),
    licenses: [{ license: { id: 'NOASSERTION' } }],
    evidence: { identity: { field: 'purl' } },
  };

  const components: SBOMComponent[] = [];
  const depRefs: string[] = [];
  const seen = new Set<string>();
  const lines = content.split('\n');
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];
    if (!(/^["']?@?[a-zA-Z0-9_\-./]+@[^:]+:\s*$/.test(line.trim()) || /^["']@[^"']+["']:\s*$/.test(line.trim()))) {
      i++;
      continue;
    }

    i++;
    let pkgName = '';
    let pkgVersion = '';
    let integrity = '';

    while (i < lines.length) {
      const depLine = lines[i].trim();
      if (depLine === '' || depLine.startsWith('#')) { i++; continue; }
      if (!depLine.startsWith(' ') && !depLine.startsWith('\t') && depLine.includes(':')) break;

      if (depLine.startsWith('version ')) {
        pkgVersion = depLine.replace('version ', '').replace(/^["']|["']$/g, '').trim();
      } else if (depLine.startsWith('integrity ')) {
        integrity = depLine.replace('integrity ', '').replace(/^["']|["']$/g, '').trim();
      }
      i++;
    }

    const decl = line.trim().replace(/:$/, '');
    const match = decl.match(/^["']?([^"']+?)["']?@/);
    if (match) pkgName = match[1].trim();

    if (pkgName && pkgVersion) {
      const cleanVer = pkgVersion.replace(/^[\^~]/, '');
      const key = `${pkgName}@${cleanVer}`;
      if (!seen.has(key)) {
        const comp = makeComponent(pkgName, cleanVer, integrity || undefined);
        components.push(comp);
        depRefs.push(comp.purl);
        seen.add(key);
      }
    }
  }

  return { components, deps: [{ ref: appComp.purl, dependsOn: depRefs }], appComp };
}

function parsePnpmLock(
  content: string,
  repoName: string,
  repoVersion?: string
): { components: SBOMComponent[]; deps: SBOMDependency[]; appComp: SBOMComponent } {
  const appComp: SBOMComponent = {
    type: 'application',
    name: repoName,
    version: repoVersion || '0.0.0',
    purl: toPurl('npm', repoName, repoVersion || '0.0.0'),
    licenses: [{ license: { id: 'NOASSERTION' } }],
    evidence: { identity: { field: 'purl' } },
  };

  const components: SBOMComponent[] = [];
  const depRefs: string[] = [];

  const doc = yaml.load(content) as Record<string, unknown> | null;
  if (!doc || typeof doc !== 'object') {
    return { components, deps: [{ ref: appComp.purl, dependsOn: depRefs }], appComp };
  }

  const packages = doc.packages as Record<string, unknown> | undefined;
  if (packages && typeof packages === 'object') {
    for (const key of Object.keys(packages)) {
      const pkgMatch = key.match(/^\/(@?[^@]+)@(.+)$/);
      if (!pkgMatch) continue;
      const rawName = pkgMatch[1].replace(/^node_modules\//, '');
      const pkgVersion = pkgMatch[2];
      const integ = packages[key] as Record<string, unknown>;
      const resolution = integ?.resolution as Record<string, unknown> | undefined;
      const integrity = typeof resolution?.integrity === 'string' ? resolution.integrity : '';
      const comp = makeComponent(rawName, pkgVersion, integrity || undefined);
      components.push(comp);
      depRefs.push(comp.purl);
    }
  }

  const importers = doc.importers as Record<string, unknown> | undefined;
  if (importers && typeof importers === 'object' && '.' in importers) {
    const deps = (importers['.'] as Record<string, unknown>)?.dependencies as Record<string, unknown> | undefined;
    if (deps && typeof deps === 'object') {
      for (const [depName, depInfo] of Object.entries(deps)) {
        const info = depInfo as Record<string, unknown>;
        const ver = String(info.version || '').replace(/^[\^~]/, '');
        if (!components.some(c => c.name === depName && c.version === ver)) {
          const comp = makeComponent(depName, ver);
          components.push(comp);
          depRefs.push(comp.purl);
        }
      }
    }
  }

  return { components, deps: [{ ref: appComp.purl, dependsOn: depRefs }], appComp };
}

function parseRequirementsTxt(
  content: string,
  repoName: string,
  repoVersion?: string
): { components: SBOMComponent[]; deps: SBOMDependency[]; appComp: SBOMComponent } {
  const appComp: SBOMComponent = {
    type: 'application',
    name: repoName,
    version: repoVersion || '0.0.0',
    purl: toPurl('pypi', repoName, repoVersion || '0.0.0'),
    licenses: [{ license: { id: 'NOASSERTION' } }],
    evidence: { identity: { field: 'purl' } },
  };

  const components: SBOMComponent[] = [];
  const depRefs: string[] = [];

  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('-') || trimmed.startsWith('--')) continue;

    const match = trimmed.match(/^([a-zA-Z0-9_\-\.]+)\s*([><=!~]+)\s*(.+)$/);
    if (match) {
      const pkgName = match[1];
      const cleanVer = match[3].trim();
      const comp = makeComponent(pkgName, cleanVer);
      comp.purl = toPurl('pypi', pkgName, cleanVer);
      components.push(comp);
      depRefs.push(comp.purl);
    } else if (/^[a-zA-Z0-9_\-\.]+$/.test(trimmed) && !trimmed.includes('==')) {
      const comp = makeComponent(trimmed, '0.0.0');
      comp.purl = toPurl('pypi', trimmed, '0.0.0');
      components.push(comp);
      depRefs.push(comp.purl);
    }
  }

  return { components, deps: [{ ref: appComp.purl, dependsOn: depRefs }], appComp };
}

function parseGoMod(
  content: string,
  repoName: string,
  repoVersion?: string
): { components: SBOMComponent[]; deps: SBOMDependency[]; appComp: SBOMComponent } {
  const appComp: SBOMComponent = {
    type: 'application',
    name: repoName,
    version: repoVersion || '0.0.0',
    purl: toPurl('golang', repoName, repoVersion || '0.0.0'),
    licenses: [{ license: { id: 'NOASSERTION' } }],
    evidence: { identity: { field: 'purl' } },
  };

  const components: SBOMComponent[] = [];
  const depRefs: string[] = [];
  let inRequire = false;

  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('//')) continue;

    if (trimmed.startsWith('require (')) { inRequire = true; continue; }
    if (inRequire && trimmed === ')') { inRequire = false; continue; }

    if (inRequire) {
      const m = trimmed.match(/^([a-zA-Z0-9_\-\.\/]+)\s+v?([a-zA-Z0-9_\-\.]+)/);
      if (m) {
        const comp = makeComponent(m[1], m[2]);
        comp.purl = toPurl('golang', m[1], m[2]);
        components.push(comp);
        depRefs.push(comp.purl);
      }
    }

    const sm = trimmed.match(/^require\s+([a-zA-Z0-9_\-\.\/]+)\s+v?([a-zA-Z0-9_\-\.]+)/);
    if (sm) {
      const comp = makeComponent(sm[1], sm[2]);
      comp.purl = toPurl('golang', sm[1], sm[2]);
      components.push(comp);
      depRefs.push(comp.purl);
    }
  }

  return { components, deps: [{ ref: appComp.purl, dependsOn: depRefs }], appComp };
}

function parseCargoToml(
  content: string,
  repoName: string,
  repoVersion?: string
): { components: SBOMComponent[]; deps: SBOMDependency[]; appComp: SBOMComponent } {
  const appComp: SBOMComponent = {
    type: 'application',
    name: repoName,
    version: repoVersion || '0.0.0',
    purl: toPurl('cargo', repoName, repoVersion || '0.0.0'),
    licenses: [{ license: { id: 'NOASSERTION' } }],
    evidence: { identity: { field: 'purl' } },
  };

  const components: SBOMComponent[] = [];
  const depRefs: string[] = [];
  let inDeps = false;

  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    if (trimmed.startsWith('[')) {
      inDeps = /^\[dependencies\]$|^\[dev-dependencies\]$|^\[build-dependencies\]$/i.test(trimmed);
      continue;
    }
    if (!inDeps) continue;

    const simple = trimmed.match(/^([a-zA-Z0-9_\-]+)\s*=\s*"([^"]+)"/);
    if (simple) {
      const ver = simple[2].replace(/^[\^~>=<]/, '');
      const comp = makeComponent(simple[1], ver);
      comp.purl = toPurl('cargo', simple[1], ver);
      components.push(comp);
      depRefs.push(comp.purl);
    } else {
      const tbl = trimmed.match(/^([a-zA-Z0-9_\-]+)\s*=\s*\{/);
      if (tbl) {
        const vm = trimmed.match(/version\s*=\s*"([^"]+)"/);
        if (vm) {
          const ver = vm[1].replace(/^[\^~>=<]/, '');
          const comp = makeComponent(tbl[1], ver);
          comp.purl = toPurl('cargo', tbl[1], ver);
          components.push(comp);
          depRefs.push(comp.purl);
        }
      }
    }
  }

  return { components, deps: [{ ref: appComp.purl, dependsOn: depRefs }], appComp };
}

function generateCycloneDX(
  appComp: SBOMComponent,
  components: SBOMComponent[],
  deps: SBOMDependency[],
  vulnerabilities: VulnerabilityRef[]
): string {
  const bom: Record<string, unknown> = {
    $schema: 'http://cyclonedx.org/schema/bom-1.5.schema.json',
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [{ vendor: 'Sentinel', name: 'sentinel-cloud', version: '2.0' }],
      component: appComp,
    },
    components,
    dependencies: deps,
  };

  if (vulnerabilities.length > 0) {
    bom.vulnerabilities = vulnerabilities;
  }

  return JSON.stringify(bom, null, 2);
}

function generateSpdx(
  appComp: SBOMComponent,
  components: SBOMComponent[],
  deps: SBOMDependency[]
): string {
  const now = new Date().toISOString().replace(/[:\-]/g, '').split('.')[0] + 'Z';
  const namespace = `https://sentinel.security/spdx/${encodeURIComponent(appComp.name)}-${appComp.version}`;

  const lines: string[] = [
    'SPDXVersion: SPDX-2.3',
    'DataLicense: CC0-1.0',
    'SPDXID: SPDXRef-DOCUMENT',
    `DocumentName: ${appComp.name}-${appComp.version}`,
    `DocumentNamespace: ${namespace}`,
    '',
    '## Creator Information',
    'Creator: Tool: Sentinel-sentinel-cloud-2.0',
    'Creator: Person: Sentinel Security Scanner',
    `Created: ${now}`,
    '',
    '## Package Information',
  ];

  const toSpdxId = (s: string) => s.replace(/[^a-zA-Z0-9\-]/g, '-').replace(/^-+|-+$/g, '') || 'unknown';

  lines.push(
    '',
    `PackageName: ${appComp.name}`,
    `SPDXID: SPDXRef-${toSpdxId(appComp.name)}-${appComp.version}`,
    `PackageVersion: ${appComp.version}`,
    'PackageDownloadLocation: NOASSERTION',
    'FilesAnalyzed: false',
    `PackageLicenseConcluded: ${appComp.licenses?.[0]?.license?.id || 'NOASSERTION'}`,
    `PackageLicenseDeclared: ${appComp.licenses?.[0]?.license?.id || 'NOASSERTION'}`,
    'PackageCopyrightText: NOASSERTION',
    'PackageType: APPLICATION',
    `ExternalRef: SECURITY purl ${appComp.purl}`,
  );

  const allRefs: string[] = [];

  for (const comp of components) {
    const spdxId = `SPDXRef-${toSpdxId(comp.name)}-${comp.version}`;
    allRefs.push(spdxId);

    lines.push(
      '',
      `PackageName: ${comp.name}`,
      `SPDXID: ${spdxId}`,
      `PackageVersion: ${comp.version}`,
      'PackageDownloadLocation: NOASSERTION',
      'FilesAnalyzed: false',
      `PackageLicenseConcluded: ${comp.licenses?.[0]?.license?.id || 'NOASSERTION'}`,
      `PackageLicenseDeclared: ${comp.licenses?.[0]?.license?.id || 'NOASSERTION'}`,
      'PackageCopyrightText: NOASSERTION',
      'PackageType: LIBRARY',
      `ExternalRef: SECURITY purl ${comp.purl}`,
    );

    if (comp.hashes) {
      for (const h of comp.hashes) {
        lines.push(`PackageChecksum: ${h.alg}:${h.content}`);
      }
    }
  }

  lines.push('', '## Relationships');
  const rootId = `SPDXRef-${toSpdxId(appComp.name)}-${appComp.version}`;
  lines.push(`Relationship: ${rootId} DESCRIBES ${rootId}`);
  for (const ref of allRefs) {
    lines.push(`Relationship: ${rootId} DEPENDS_ON ${ref}`);
  }

  return lines.join('\n');
}

export function generateSBOM(
  manifestFiles: ManifestFiles,
  repoName: string,
  version?: string,
  outputFormat: 'cyclonedx' | 'spdx' = 'cyclonedx'
): SBOMResult {
  const allComponents: SBOMComponent[] = [];
  const deps: SBOMDependency[] = [];
  let appComp: SBOMComponent | null = null;

  const orderedFilenames = Object.keys(manifestFiles).sort((a, b) => {
    const score = (name: string): number => {
      if (name === 'package.json') return 0;
      if (name === 'package-lock.json') return 1;
      if (name === 'yarn.lock') return 2;
      if (name === 'pnpm-lock.yaml') return 3;
      return 10;
    };
    const basenameA = a.toLowerCase().split(/[/\\]/).pop() || '';
    const basenameB = b.toLowerCase().split(/[/\\]/).pop() || '';
    return score(basenameA) - score(basenameB);
  });

  for (const filename of orderedFilenames) {
    const content = manifestFiles[filename];
    const basename = filename.toLowerCase().split(/[/\\]/).pop() || '';

    let result: ReturnType<typeof parsePackageJson> | null = null;

    try {
      switch (basename) {
        case 'package.json':
          result = parsePackageJson(content, repoName, version);
          break;
        case 'package-lock.json':
          result = parsePackageLock(content, repoName, version);
          break;
        case 'yarn.lock':
          result = parseYarnLock(content, repoName, version);
          break;
        case 'pnpm-lock.yaml':
          result = parsePnpmLock(content, repoName, version);
          break;
        case 'requirements.txt':
          result = parseRequirementsTxt(content, repoName, version);
          break;
        case 'go.mod':
          result = parseGoMod(content, repoName, version);
          break;
        case 'cargo.toml':
          result = parseCargoToml(content, repoName, version);
          break;
        default:
          if (content.trim().startsWith('{') && content.includes('"name"')) {
            result = parsePackageJson(content, repoName, version);
          } else if (content.trim().startsWith('{') && content.includes('"lockfileVersion"')) {
            result = parsePackageLock(content, repoName, version);
          } else if (content.trim().startsWith('#') && content.includes('yarn lockfile')) {
            result = parseYarnLock(content, repoName, version);
          } else if (content.trim().startsWith('module ')) {
            result = parseGoMod(content, repoName, version);
          } else {
            continue;
          }
      }
    } catch {
      continue;
    }

    if (!result) continue;
    if (!appComp) appComp = result.appComp;

    const existing = new Set(allComponents.map(c => c.purl));
    for (const comp of result.components) {
      if (!existing.has(comp.purl)) {
        allComponents.push(comp);
        existing.add(comp.purl);
      }
    }
    deps.push(...result.deps);
  }

  if (!appComp) {
    appComp = {
      type: 'application',
      name: repoName,
      version: version || '0.0.0',
      purl: toPurl('npm', repoName, version || '0.0.0'),
      licenses: [{ license: { id: 'NOASSERTION' } }],
      evidence: { identity: { field: 'purl' } },
    };
  }

  const vulnerabilities: VulnerabilityRef[] = [];
  for (const comp of allComponents) {
    const eco = comp.purl.startsWith('pkg:pypi') ? 'pypi' :
                comp.purl.startsWith('pkg:golang') ? 'golang' :
                comp.purl.startsWith('pkg:cargo') ? 'cargo' : 'npm';
    vulnerabilities.push(...checkVulnerabilities(eco, comp.name, comp.version));
  }

  const content = outputFormat === 'spdx'
    ? generateSpdx(appComp, allComponents, deps)
    : generateCycloneDX(appComp, allComponents, deps, vulnerabilities);

  const dependencyCount = deps.reduce((sum, d) => sum + d.dependsOn.length, 0);

  return { format: outputFormat, content, components: allComponents.length, dependencies: dependencyCount };
}
