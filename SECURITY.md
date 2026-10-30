# Security Policy & Vulnerability Disclosure

## Supported Versions
Only the latest release running on the `main` branch of this repository receives security hardening and patches.

| Version / Branch | Supported | Security Policy |
| :--- | :---: | :--- |
| `main` (Production) | :white_check_mark: | Active hardening, SAST/DAST gated |
| `lab-vulnerable` | :x: | Deliberately vulnerable for academic research & PoC |

---

## Reporting a Vulnerability
We welcome responsible security research. If you discover a vulnerability in this project, please follow these guidelines:

1. **Do NOT open public GitHub issues** for zero-day security vulnerabilities or unpatched flaws.
2. Submit a confidential report directly to the security engineering team:
   - **Talal Nadeem Awan** (FA23-BCT-051)
   - **Shahroze Afaq** (FA23-BCT-039)
   - **Instructor:** Engr. Muhammad Ahmad Nawaz (`m.ahmadnawazz@gmail.com`)
3. Provide full reproduction steps, payload details, affected endpoints, and impact assessment.
4. The team will acknowledge receipt within 24 hours and provide an estimated remediation timeline.

---

## Security Architecture & Best Practices
The production application enforces:
- **Defense in Depth:** Validation at web, application worker, and native C layers.
- **Least Privilege:** Non-root execution, parameterized subprocesses without shell invocation.
- **Fail-Safe Defaults:** Object-level authorization by default (`WHERE id = ? AND owner_id = ?`).
- **Complete Mediation:** All state changes require cryptographic anti-CSRF synchronizer tokens.
- **Memory Safety:** Bounded string copies (`memcpy` with explicit capacity checks) and compiler stack canaries.
