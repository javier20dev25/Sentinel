# Sentinel: Global Intelligence Sync Protocol (v1.0)

## 1. Introduction
The Sentinel Sync Protocol (SSP) defines the mechanism for sharing reputational metadata between localized Sentinel instances and the Global Intelligence Network. The objective is to achieve networked defense where a threat detected in one environment is mitigated across all connected nodes.

## 2. Synchronization Primitives

### 2.1 PUSH Operation
- **Objective**: Export local findings to the global pool.
- **Privacy Filtering**: Before transmission, all local file paths, PII, and repository-specific identifiers are stripped. Only `package_name`, `signal_type`, and `aggregate_score` are exported.
- **Trigger**: Automatic post-execution (if configured) or manual via `sentinel sync push`.

### 2.2 PULL Operation
- **Objective**: Import verified global threat signals.
- **Conflict Resolution**: Global data is merged into the `global` namespace of the local Risk Graph. It does not overwrite local data but acts as a secondary weighting factor in the risk formula.

## 3. Federated Trust Model
The protocol relies on a multi-tiered trust system to prevent network poisoning (Sybil attacks).
- **Trusted Sources**: Sentinel Official Feeds, Verified Enterprise Partners.
- **Untrusted Sources**: Anonymous community telemetry (subjected to statistical anomaly detection before promotion to "Verified").

## 4. Federated Risk Formula
The total risk score for an entity is calculated as a weighted sum of three independent vectors:
1. **Local Context (50%)**: Direct signals observed in the current environment.
2. **Global Intelligence (30%)**: Reputation pulled from the network, weighted by source trust.
3. **Temporal Dynamics (20%)**: Recent spikes in signal velocity within a 24-hour window.

## 5. Network Moat Implementation
By implementing the SSP, Sentinel creates a network effect where the marginal cost of attack detection decreases as the network grows. Every new repository connected to the network increases the collective intelligence of all other nodes.
