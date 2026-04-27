/**
 * Sentinel: Docker Ecosystem Adapter (v2.0 — Zero Trust)
 * 
 * Threat model:
 *  - Images are opaque (black box) → trust is about PROVENANCE, not code
 *  - Key signals: Publisher tier, Digest pinning, Tag hygiene, Image mimicry
 *  - Foundation for: Cosign verification, SLSA provenance, Notary v2
 */
'use strict';

// Docker Official Library images (maintained by Docker, Inc.)
const DOCKER_OFFICIAL = [
    'ubuntu', 'debian', 'alpine', 'centos', 'fedora', 'amazonlinux',
    'nginx', 'httpd', 'caddy', 'traefik',
    'node', 'python', 'ruby', 'golang', 'rust', 'openjdk', 'eclipse-temurin',
    'mysql', 'postgres', 'mariadb', 'mongo', 'redis', 'memcached',
    'elasticsearch', 'kibana', 'logstash',
    'wordpress', 'drupal', 'ghost',
    'jenkins', 'sonarqube', 'grafana',
    'busybox', 'scratch', 'hello-world'
];

// Docker Verified Publishers
const DOCKER_VERIFIED_ORGS = [
    'bitnami', 'grafana', 'hashicorp', 'datadog', 'newrelic',
    'circleci', 'gitlab', 'atlassian', 'vmware', 'redhat',
    'microsoft', 'google', 'amazon', 'ibm', 'oracle',
    'portainer', 'rancher', 'aquasec', 'snyk'
];

// Known malicious or deprecated base image patterns
const SUSPICIOUS_BASE_PATTERNS = [
    /^.*miner.*$/i,
    /^.*cryptojack.*$/i,
    /^.*backdoor.*$/i,
    /^.*rootkit.*$/i
];

const DockerAdapter = {
    id: 'docker',
    aliases: ['docker'],
    installCmd: (image, args = []) => ['docker', ['pull', image, ...args]],
    protected: DOCKER_OFFICIAL,

    /**
     * Parse a Docker image reference into its components.
     * 
     * Examples:
     *   "nginx"                              → { registry: docker.io, org: library, image: nginx, tag: latest, digest: null }
     *   "nginx:1.25-alpine"                  → { ..., tag: 1.25-alpine }
     *   "nginx@sha256:abc123..."             → { ..., tag: null, digest: sha256:abc123... }
     *   "ghcr.io/owner/image:v1"             → { registry: ghcr.io, org: owner, image: image, tag: v1 }
     *   "evil-org/nginx:latest"              → { registry: docker.io, org: evil-org, image: nginx, tag: latest }
     */
    parseImageRef(imageRef) {
        let registry = 'docker.io';
        let digest = null;
        let tag = null;
        let remaining = imageRef;

        // Extract digest
        if (remaining.includes('@sha256:')) {
            const parts = remaining.split('@');
            remaining = parts[0];
            digest = parts[1];
        }

        // Extract tag
        if (remaining.includes(':') && !remaining.includes('/')) {
            // Simple case: image:tag
            const parts = remaining.split(':');
            remaining = parts[0];
            tag = parts[1];
        } else if (remaining.includes(':')) {
            // Could be registry:port/image or org/image:tag
            const lastColon = remaining.lastIndexOf(':');
            const afterColon = remaining.substring(lastColon + 1);
            if (!afterColon.includes('/')) {
                tag = afterColon;
                remaining = remaining.substring(0, lastColon);
            }
        }

        if (!digest && !tag) tag = 'latest'; // Docker default

        // Extract registry (if contains a dot or localhost)
        const slashParts = remaining.split('/');
        if (slashParts.length >= 2 && (slashParts[0].includes('.') || slashParts[0] === 'localhost')) {
            registry = slashParts.shift();
        }

        // Remaining: org/image or just image
        const org = slashParts.length > 1 ? slashParts.slice(0, -1).join('/') : 'library';
        const image = slashParts[slashParts.length - 1];

        return { registry, org, image, tag, digest, fullRef: imageRef };
    },

    /**
     * Classify trust tier based on parsed image reference.
     */
    classifyImage(imageRef) {
        const parsed = DockerAdapter.parseImageRef(imageRef);
        const { registry, org, image, tag, digest } = parsed;
        const isDockerHub = registry === 'docker.io';
        const isPinned = !!digest;

        // Official: docker.io/library/<official-name>
        if (isDockerHub && org === 'library' && DOCKER_OFFICIAL.includes(image)) {
            return { ...parsed, tier: 'OFFICIAL', pinned: isPinned };
        }

        // Verified publisher
        if (isDockerHub && DOCKER_VERIFIED_ORGS.includes(org.toLowerCase())) {
            return { ...parsed, tier: 'VERIFIED', pinned: isPinned };
        }

        // Known suspicious names
        for (const pattern of SUSPICIOUS_BASE_PATTERNS) {
            if (pattern.test(image) || pattern.test(org)) {
                return { ...parsed, tier: 'MALICIOUS_INTENT', pinned: isPinned };
            }
        }

        // Mimicry: someone using official image name under a custom org
        if (isDockerHub && org !== 'library' && DOCKER_OFFICIAL.includes(image)) {
            return { ...parsed, tier: 'MIMICRY', pinned: isPinned };
        }

        // Third-party registry (ghcr.io, ecr, gcr, etc.) — trust varies
        if (!isDockerHub) {
            return { ...parsed, tier: 'THIRD_PARTY_REGISTRY', pinned: isPinned };
        }

        // Generic community image
        return { ...parsed, tier: 'COMMUNITY', pinned: isPinned };
    },

    /** No lifecycle scripts to parse for docker images */
    parseManifest() { return { scripts: {} }; },
    auditScripts()  { return []; },

    checkScopeAbuse(imageRef) {
        const c = DockerAdapter.classifyImage(imageRef);
        if (c.tier === 'MIMICRY') return { type: 'IMAGE_MIMICRY', target: c.image, publisher: c.org };
        if (c.tier === 'MALICIOUS_INTENT') return { type: 'MALICIOUS_NAME', target: c.image };
        return null;
    },

    /**
     * Generate Docker-specific risk signals.
     * This is the heart of the Docker adapter — provenance-based trust.
     */
    getDockerSignals(imageRef) {
        const c = DockerAdapter.classifyImage(imageRef);
        const signals = [];

        // ── Digest Enforcement ──────────────────────────────────────────
        if (!c.pinned) {
            const severity = c.tag === 'latest' ? 0.45 : 0.25;
            signals.push({
                type: 'BEHAVIOR_SUSPICIOUS',
                category: c.tag === 'latest' ? 'unpinned_latest' : 'unpinned_tag',
                description: c.tag === 'latest'
                    ? `Using ':latest' provides no reproducibility or integrity guarantee. Pin to a SHA256 digest.`
                    : `Tag '${c.tag}' is mutable and can be overwritten. Pin to @sha256: for immutable references.`,
                riskLevel: severity
            });
        }

        // ── Publisher Trust Tier ─────────────────────────────────────────
        const tierRisk = {
            'OFFICIAL':              null,
            'VERIFIED':              null,
            'THIRD_PARTY_REGISTRY':  { level: 0.30, desc: `Image from non-Docker-Hub registry '${c.registry}'. Ensure organizational policy permits this source.` },
            'COMMUNITY':             { level: 0.45, desc: `Publisher '${c.org}' is not an Official or Verified Docker publisher.` },
            'MIMICRY':               { level: 0.90, desc: `Image '${c.org}/${c.image}' appears to impersonate the official '${c.image}' image.` },
            'MALICIOUS_INTENT':      { level: 0.95, desc: `Image name matches known malicious naming patterns.` }
        };

        const risk = tierRisk[c.tier];
        if (risk) {
            signals.push({
                type: risk.level >= 0.85 ? 'INTENT_MALICIOUS' : 'BEHAVIOR_SUSPICIOUS',
                category: c.tier === 'MIMICRY' ? 'image_mimicry' : (c.tier === 'MALICIOUS_INTENT' ? 'malicious_name' : 'unverified_publisher'),
                description: risk.desc,
                riskLevel: risk.level
            });
        }

        return { signals, classification: c };
    }
};

module.exports = DockerAdapter;
