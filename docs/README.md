# 🛡️ Sentinel Documentation

Welcome to the official documentation for **Sentinel**, your local security guardian for GitHub repositories.

## 🌐 Sentinel Local Web Edition v1.0

This edition is designed for developers who need enterprise-grade security within their local workflow.

### Core Security Modules

#### 📜 Global Audit Trail (SGA)
Sentinel maintains a high-fidelity record of every security event. 
- **Traceability**: Connects local security blocks directly to GitHub commits.
- **Persistence**: Uses a hardened local SQLite database.

#### 🔒 Asset Guard (DLP)
Prevents data leaks by intercepting unauthorized files before they are pushed to the cloud.
- **Detección temprana**: Interceptación en el hook `pre-push`.
- **Control parental**: Requiere contraseña maestra para cualquier anulación (override).

#### 🛡️ Sentinel Project Shield (SPS)
An active hardening layer for your project's environment.
- **Sandboxing**: Desactiva scripts de dependencias no confiables.
- **Análisis AST**: Detecta patrones de exfiltración de datos en tiempo real.

## 🚀 Getting Started

1. **Setup**: Run `npm start` and follow the on-screen instructions to set your Master Password.
2. **Dashboard**: Access the glassmorphic UI to link your first repository.
3. **Protection**: Sentinel will immediately begin monitoring your staged changes and background processes.

---

*Sentinel: Security that scales with your ambition.*
