# Sentinel Testing Guide (v3.0)

Este documento detalla la arquitectura de pruebas de Sentinel, los procedimientos para ejecutar suites unitarias y la estrategia para pruebas End-to-End (E2E).

> [!NOTE]
> **Resumen Ejecutivo (Español)**:
> Sentinel utiliza **Jest** como motor principal de pruebas. Actualmente contamos con una suite robusta de pruebas unitarias que validan el orquestador del Sandbox y el motor de análisis de telemetría, utilizando mocks para simular la CLI de GitHub (`gh`). Las pruebas E2E validan el flujo completo desde el disparo del workflow hasta la generación de alertas en la UI/CLI.

---

## 🧪 Testing Framework

Sentinel uses **Jest** for its speed, built-in mocking capabilities, and widespread industry adoption.

### Prerequisites

Ensure development dependencies are installed:
```bash
npm install --save-dev jest
```

---

## 🛠️ Unit Testing

Unit tests are located in the `tests/` directory. They focus on isolated logic validation without requiring external network access.

### 1. Sandbox Orchestrator (`tests/ci_sandbox.test.js`)
This suite validates `src/ui/backend/lib/ci_sandbox.js`.

- **Mocking Strategy**: We mock `child_process.execFileSync` to simulate GitHub CLI (`gh`) responses. This allows testing successful runs, timeouts, and API errors without hitting GitHub's rate limits.
- **Telemetry Simulation**: The tests create temporary directory structures with mock telemetry files (e.g., `netstat-diff.txt`, `wasm-files.txt`) to verify that the `analyzeTelemetry` engine correctly identifies threats.

### 2. How to Run
```bash
# Run all tests
npm test

# Run a specific suite
npx jest tests/ci_sandbox.test.js

# Watch mode (useful for TDD)
npx jest --watch
```

---

## 🌐 End-to-End (E2E) Testing

E2E tests validate the integration between the CLI, the Backend, and external services (GitHub).

### 1. Strategy
The E2E strategy involves:
- **Sandbox Flow**: Triggering a real workflow run on a test repository (`sentinel-test-repo`) and verifying that logic flows from `trigger` → `wait` → `download` → `analyze`.
- **CLI Integration**: Verifying that `sentinel link` and `sentinel scan` correctly interact with the local SQLite database.

### 2. Manual E2E Validation
Before a release, perform these steps:
1. Run `npm link` to set up the global command.
2. Link a test repo: `sentinel link ./tests/mock_repo owner/repo`.
3. Trigger a sandbox run: `sentinel sandbox trigger owner/repo --wait`.
4. Verify the ASCII output reflects real telemetry data.

---

## 📈 Coverage and Best Practices

- **Mock external calls**: Never let unit tests perform real network requests. Use `jest.mock`.
- **Cleanup**: Always clean up temporary directories created during tests using `fs.rmSync` in `afterEach` or at the end of the test.
- **Tone**: Keep test names descriptive and neutral (e.g., `test('analyzeTelemetry detects WASM threats', ...)`).

---

## 🆘 Troubleshooting Tests

- **Module not found**: Ensure your pathing in `require()` statements is relative to the test file location.
- **Mock mismatch**: If `triggerSandboxRun` fails, verify how many times `execFileSync` is being called in the implementation vs. the mock setup.
