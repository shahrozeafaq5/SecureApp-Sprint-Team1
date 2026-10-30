# Contributing Guidelines & Git Workflow Policy

**Project:** SecureDrop DevSecOps Security Sprint (`SecureApp-Sprint-Team1`)  
**Course:** CYC386 – Secure Software Design and Development (Fall 2026)  

---

## 1. Branching Strategy & Workflow
To maintain repository integrity and adhere to Section 6.1 of the sprint guidelines, direct pushes to `main` are strictly prohibited.

### Branch Structure:
- `main`: Production-ready, attack-resistant, fully hardened codebase. Protected branch requiring PR approvals and passing CI/CD checks.
- `develop`: Staging and integration branch for sprint features.
- `feature/<name>`: New features (e.g., `feature/csrf-protection`, `feature/native-parser-integration`).
- `fix/<name>`: Vulnerability remediation branches (e.g., `fix/command-injection-neutralization`, `fix/buffer-overflow-bounds`).

---

## 2. Pull Request & Mandatory Peer Review Protocol
Every pull request MUST fulfill the following criteria before merging into `main`:
1. **Mandatory Peer Review:** At least one fellow team member (**Talal Nadeem Awan** or **Shahroze Afaq**) must review, comment on, and explicitly approve the PR.
2. **Automated CI/CD Green Gate:** The GitHub Actions workflow must pass all build steps, unit tests, vulnerability verification proofs, and Bandit SAST checks without failure.
3. **Traceability:** Every commit and PR description must reference its corresponding Jira issue key (e.g., `SASS-8: Remediate OS Command Injection in /process`).
4. **Clean Commit History:** Commits must have descriptive messages explaining the rationale behind security-critical changes.

---

## 3. Secure Coding Standards
All code submitted must conform to:
- **Python:** PEP 8 styling, zero use of `shell=True` in subprocess calls, parameterized database queries using `sqlite3`, strict input validation.
- **C/C++:** CERT C Coding Standard (ARR38-C, STR31-C), bounded memory copy routines, compiler warnings treated as errors (`-Wall -Wextra`).
- **Templates:** All forms must include the `csrf_token` hidden field.
