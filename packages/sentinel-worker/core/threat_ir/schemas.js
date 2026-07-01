/**
 * Sentinel: Threat IR Schemas (v6.0)
 * 
 * Defines the Universal Representation for security findings.
 */

'use strict';

const NODE_TYPES = {
    PROCESS_EXEC:      "EXECUTION",
    NETWORK_REQUEST:   "EXFILTRATION",
    FILE_READ:         "ACCESS",
    FILE_WRITE:        "PERSISTENCE",
    SECRET_ACCESS:     "EXFILTRATION",
    ENV_ACCESS:        "EXFILTRATION",
    SHELL_EXEC:        "EXECUTION",
    DYNAMIC_EXEC:      "EVASION",
    ENCODING:          "EVASION",
    OBFUSCATION:       "EVASION",
    PACKAGE_INSTALL:   "SUPPLY_CHAIN",
    LIFECYCLE_SCRIPT:  "SUPPLY_CHAIN",
    REGISTRY_OVERRIDE: "SUPPLY_CHAIN",
    PRIV_ESCALATION:   "PRIVILEGE"
};

const EDGE_TYPES = {
    DATA_FLOW:         "DATA_FLOW",
    CONTROL_FLOW:      "CONTROL_FLOW",
    TEMPORAL:          "TEMPORAL",
    TRUST_BOUNDARY:   "TRUST_BOUNDARY",
    EXECUTION_CHAIN:   "EXECUTION_CHAIN"
};

module.exports = {
    NODE_TYPES,
    EDGE_TYPES
};
