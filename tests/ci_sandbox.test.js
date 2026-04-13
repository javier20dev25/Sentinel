const ci = require('../src/ui/backend/lib/ci_sandbox');
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

// Mock child_process
jest.mock('child_process', () => ({
    execFileSync: jest.fn()
}));

describe('Sentinel 3.0: CI Sandbox Orchestrator', () => {
    
    beforeEach(() => {
        jest.clearAllMocks();
    });

    test('generateWorkflowTemplate returns valid YAML and instructions', () => {
        const result = ci.generateWorkflowTemplate();
        expect(result.success).toBe(true);
        expect(result.workflowContent).toContain('Sentinel Sandbox');
        expect(result.instructions.length).toBeGreaterThan(0);
    });

    test('triggerSandboxRun calls gh CLI with correct arguments', async () => {
        // First call is the dispatch (no return value used/expected in code)
        execFileSync.mockReturnValueOnce(""); 
        // Second call is the lookup for the run ID
        execFileSync.mockReturnValueOnce(JSON.stringify({ 
            id: 12345, 
            html_url: 'https://github.com/test/run/12345',
            status: 'queued'
        }));

        const result = await ci.triggerSandboxRun('owner/repo', 'main');
        
        expect(result.success).toBe(true);
        expect(result.runId).toBe(12345);
        // Verify the FIRST call (dispatch)
        expect(execFileSync).toHaveBeenNthCalledWith(
            1,
            'gh', 
            expect.arrayContaining(['workflow', 'run', 'sentinel-sandbox.yml', '--ref', 'main']),
            expect.any(Object)
        );
    });

    test('analyzeTelemetry detects WASM threats', () => {
        const mockTempDir = path.join(__dirname, 'mock_telemetry_wasm');
        if (!fs.existsSync(mockTempDir)) fs.mkdirSync(mockTempDir, { recursive: true });
        
        const nodeModulesPath = path.join(mockTempDir, 'node_modules', 'evil-pkg');
        fs.mkdirSync(nodeModulesPath, { recursive: true });
        fs.writeFileSync(path.join(nodeModulesPath, 'payload.wasm'), 'dummy binary data');
        
        // Write a dummy wasm-files.txt since analyzeTelemetry reads it
        fs.writeFileSync(path.join(mockTempDir, 'wasm-files.txt'), 'node_modules/evil-pkg/payload.wasm');

        const result = ci.analyzeTelemetry(mockTempDir, 'owner/repo');
        
        expect(result.threats).toContainEqual(expect.objectContaining({
            type: 'WASM_MODULE_DETECTED',
            severity: 'MEDIUM'
        }));

        fs.rmSync(mockTempDir, { recursive: true });
    });

    test('analyzeTelemetry detects LOCKFILE modifications', () => {
        const mockTempDir = path.join(__dirname, 'mock_telemetry_lock');
        if (!fs.existsSync(mockTempDir)) fs.mkdirSync(mockTempDir, { recursive: true });
        
        fs.writeFileSync(path.join(mockTempDir, 'lockfile-diff.txt'), '> @scoped/malicious: "latest"');

        const result = ci.analyzeTelemetry(mockTempDir, 'owner/repo');
        
        expect(result.threats).toContainEqual(expect.objectContaining({
            type: 'LOCKFILE_MODIFIED_AT_INSTALL',
            severity: 'HIGH'
        }));

        fs.rmSync(mockTempDir, { recursive: true });
    });

    test('analyzeTelemetry detects suspicious NETWORK activity', () => {
        const mockTempDir = path.join(__dirname, 'mock_telemetry_net');
        if (!fs.existsSync(mockTempDir)) fs.mkdirSync(mockTempDir, { recursive: true });
        
        // Match the filename expected by the orchestrator: netstat-diff.txt
        fs.writeFileSync(path.join(mockTempDir, 'netstat-diff.txt'), '> tcp 192.168.1.5:44321 45.33.22.11:80 ESTABLISHED');

        const result = ci.analyzeTelemetry(mockTempDir, 'owner/repo');
        
        expect(result.threats).toContainEqual(expect.objectContaining({
            type: 'UNEXPECTED_NETWORK_CONNECTIONS',
            severity: 'HIGH'
        }));

        fs.rmSync(mockTempDir, { recursive: true });
    });
});
