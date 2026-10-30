# SecureDrop: Attack-Resistant Document Vault
### 1-Week DevSecOps Security Engineering Sprint | Fall 2026
**Course:** CYC386 – Secure Software Design and Development  
**Department of Computer Science, COMSATS University Islamabad**  
**Instructor:** Engr. Muhammad Ahmad Nawaz  

---

## 👥 Engineering Team
- **Talal Nadeem Awan** (FA23-BCT-051)
- **Shahroze Afaq** (FA23-BCT-039)

---

## 🛡️ Project Overview & Architecture
**SecureDrop** is a production-hardened web application and document processing service engineered to resist multi-vector cyber attacks. The application integrates:
- **Web Frontend & API Layer:** Python Flask with Jinja2 templates, enforcing Synchronizer Anti-CSRF tokens and strict HTTP security response headers (`X-Frame-Options: DENY`, CSP `frame-ancestors 'none'`).
- **Data Persistence:** Relational SQLite database (`secureapp.db`) enforcing strict **Object-Level Authorization** (IDOR defense) on all read, update, process, and delete queries.
- **Worker Process:** Parameterized Python worker (`processor.py`) eliminating OS command injection via `shell=False` execve-style argument arrays and strict regex whitelisting.
- **Native Security Engine:** Compiled C helper binary (`native/metadata_parser.exe`) compiled with GCC stack canaries (`-fstack-protector-strong`), strict bounds verification, and bounded `memcpy` routines.

---

## 📂 Repository Structure

```text
SecureApp-Sprint-Team1/
├── .github/
│   └── workflows/
│       └── ci-cd.yml             # Automated CI/CD DevSecOps pipeline
├── docs/
│   └── THREAT_MODEL.md           # DFDs, STRIDE table, Attack Trees, CVSS v3.1 scoring
├── native/
│   ├── metadata.c                # Remediated secure C metadata parser
│   ├── metadata_vulnerable.c     # Pre-remediation vulnerable C parser (Lab PoC)
│   ├── metadata_cli.c            # Standalone CLI wrapper for C parser
│   └── harness.c                 # Buffer overflow test harness
├── reports/
│   ├── sast_vuln_report.txt      # Bandit SAST report on vulnerable code (2 Highs)
│   └── sast_secure_report.txt    # Bandit SAST report on secure code (0 Highs)
├── templates/
│   └── index.html                # Jinja2 template with CSRF tokens & UI defenses
├── tests/
│   ├── clickjacking_poc.html     # Interactive Clickjacking iframe test harness
│   ├── csrf_poc.html             # Cross-Site Request Forgery exploit test harness
│   ├── test_app_flow.py          # Baseline functional unit tests
│   └── verify_all_vulnerabilities.py # Unified PoC verification suite for all 5 vulns
├── app.py                        # Hardened production Flask web application
├── app_vulnerable.py             # Pre-remediation lab demonstration application
├── processor.py                  # Hardened document processing worker
├── processor_vulnerable.py       # Vulnerable document processing worker (CWE-78 PoC)
├── CONTRIBUTING.md               # Git branching strategy & PR review policy
├── jira_backlog_import.csv       # 1-Click Jira Cloud backlog import file
├── PNE_Report.md                 # Protection Needs Elicitation & CIA mapping
├── README.md                     # System documentation & quickstart
├── requirements.txt              # Python project dependencies
├── SECURITY.md                   # Vulnerability disclosure & security policy
├── SECURITY_IMPLEMENTATION.md    # In-depth technical remediation & PoC evidence
└── SECURITY_TEST_REPORT.md       # SAST & DAST security testing evaluation
```

---

## 🚀 Quickstart & Setup Guide

### 1. Prerequisites
- **Python 3.10+** (Python 3.12 recommended)
- **GCC / MinGW** (for native C component compilation)

### 2. Installation
```powershell
# Clone the repository
git clone https://github.com/shahrozeafaq5/SecureApp-Sprint-Team1.git
cd SecureApp-Sprint-Team1

# Install Python dependencies
python -m pip install -r requirements.txt
```

### 3. Build Native C Components
```powershell
# Compile the hardened C metadata parser
gcc -g -O2 -static -Wall -Wextra -fstack-protector-strong native\metadata.c native\metadata_cli.c -o native\metadata_parser.exe

# Compile the secure and vulnerable test harnesses
gcc -g -O2 -static -Wall -Wextra -fstack-protector-strong native\metadata.c native\harness.c -o parser_secure.exe
gcc -g -O0 -fstack-protector-all native\metadata_vulnerable.c native\harness.c -o parser_vulnerable.exe
```

### 4. Run the Hardened Web Application
```powershell
python app.py
```
Access the application at `http://127.0.0.1:5000/`.

---

## 🧪 Automated Testing & Verification Suite

### Run All 5 Vulnerability Demonstrations & Proofs
```powershell
python -m unittest tests/verify_all_vulnerabilities.py
```
This single command executes and validates before/after proofs for:
1. **Buffer Overflow:** Confirms stack smashing on vulnerable binary; confirms clean rejection on secure binary.
2. **Command Injection:** Confirms arbitrary `LAB_MARKER` execution on vulnerable processor; confirms regex rejection on secure processor.
3. **IDOR:** Confirms unauthorized cross-user download on vulnerable app; confirms HTTP 404 Access Denied on secure app.
4. **CSRF:** Confirms silent file deletion without token on vulnerable app; confirms HTTP 403 Forbidden on secure app.
5. **Clickjacking:** Confirms missing headers on vulnerable app; confirms `X-Frame-Options: DENY` and CSP `frame-ancestors 'none'` on secure app.

---

## 🔒 Automated DevSecOps CI/CD Pipeline
The repository includes `.github/workflows/ci-cd.yml` configured to trigger on all pushes and pull requests:
- **Stage 1 (Build & Unit Tests):** Compiles native C binary, executes unit and integration tests.
- **Stage 2 (Vulnerability Verification):** Executes `tests/verify_all_vulnerabilities.py`.
- **Stage 3 (SAST Gate):** Executes Bandit with `-lll` flag; automatically **fails the build** if any High/Critical severity issues are present.
- **Stage 4 (DAST Gate):** Verifies live HTTP security headers.

---
*COMSATS University Islamabad | CYC386 Secure Software Design and Development (Fall 2026)*
