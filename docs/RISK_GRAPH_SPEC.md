# Technical Specification: Sentinel Risk Graph (v1.0)

## 1. Executive Summary
The Sentinel Risk Graph is a stateful intelligence system designed to correlate security signals across multiple execution contexts. By transforming isolated scanning events into a directed graph of relationships, Sentinel achieves "Collective Intelligence," where each evaluation improves the accuracy of future decisions through reputational analysis and pattern detection.

## 2. Data Architecture

### 2.1 Node Taxonomy
The graph consists of four primary entity types:
- **Package**: Software dependencies (e.g., `npm:axios`).
- **Repository**: Evaluation targets (e.g., `github:owner/repo`).
- **Signal**: Atomic security findings (e.g., `typosquatting`, `malicious-script`).
- **Decision**: Final verdicts emitted by playbooks (`allow`, `block`, `sandbox`).

### 2.2 Relationship Schema (Edges)
- `USED_BY`: (Package) → (Repository)
- `TRIGGERED_IN`: (Signal) → (Repository)
- `AFFECTED`: (Signal) → (Package)
- `BLOCKED_IN` / `ALLOWED_IN`: (Package) → (Decision)

## 3. Reputational Intelligence

### 3.1 Package Reputation Score
The global risk score for a package is dynamically calculated using a weighted aggregation:
- **Block Frequency**: Higher ratio of `BLOCKED_IN` relationships increases risk.
- **Signal Density**: Volume of signals with high weight (e.g., `weight > 0.8`).
- **Novelty**: Packages with low `seen_count` but high signal volume are flagged.

### 3.2 Temporal Spike Detection (Bursts)
Sentinel monitors the "Velocity of Risk." A spike is defined as a statistically significant increase in negative signals for a specific entity within a 24-hour window.
- **Formula**: `Count(Edges where type == 'blocked_in' and timestamp > T-24h)`.

## 4. Playbook Integration (SPL)

The Risk Graph exposes its intelligence to the **Sentinel Playbook Language** via the `risk_graph_enrichment` engine.

### 4.1 Usage Example
```sentinel
workflow "reputational-guard" {
  target package
  profile strict

  when install package {
    run risk_graph_enrichment
    run supply_chain_shield

    // Block if the package has a high global risk or a recent burst of blocks
    if package.global.risk_score > 0.8 or package.global.temporal_spike_24h > 5 {
      block
      notify admin
    }
  }
}
```

## 5. Persistence and Scalability
- **Storage**: Local JSON (`~/.sentinel/risk_graph.json`) for the MVP.
- **Consistency**: ACID-compliant atomic writes via `fs.writeFileSync`.
- **Roadmap**: Transition to a graph database (e.g., Neo4j) for multi-tenant SaaS deployments to support millions of nodes and edges with sub-millisecond traversal.
