/**
 * Sentinel: Node Mapper (v6.0)
 * 
 * Maps raw rule IDs and categories to Universal Threat IR nodes.
 */

'use strict';

const { NODE_TYPES } = require('./schemas');

function mapToNode(finding) {
    const type = (finding.type || 'UNKNOWN').toUpperCase();
    
    // Semantic Heuristics
    if (type.includes('EXEC') || type.includes('SPAWN') || type.includes('SHELL')) return NODE_TYPES.PROCESS_EXEC;
    if (type.includes('URL') || type.includes('NETWORK') || type.includes('FETCH') || type.includes('HTTP')) return NODE_TYPES.NETWORK_REQUEST;
    if (type.includes('SECRET') || type.includes('KEY') || type.includes('TOKEN') || type.includes('ENV')) return NODE_TYPES.SECRET_ACCESS;
    if (type.includes('EVAL') || type.includes('DYNAMIC') || type.includes('VM')) return NODE_TYPES.DYNAMIC_EXEC;
    if (type.includes('BASE64') || type.includes('HEX') || type.includes('OBFUSCATION') || type.includes('ENTROPY')) return NODE_TYPES.OBFUSCATION;
    if (type.includes('INSTALL') || type.includes('LIFECYCLE') || type.includes('DEPENDENCY')) return NODE_TYPES.LIFECYCLE_SCRIPT;
    if (type.includes('WRITE') || type.includes('MUTATE')) return NODE_TYPES.FILE_WRITE;
    if (type.includes('SUDO') || type.includes('ROOT') || type.includes('PERMISSION')) return NODE_TYPES.PRIV_ESCALATION;

    return "GENERIC_SIGNAL";
}

module.exports = {
    mapToNode
};
