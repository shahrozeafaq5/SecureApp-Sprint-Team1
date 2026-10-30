# Security Test Report: Automated SAST & DAST Verification
**Course:** CYC386 – Secure Software Design and Development  
**Exam:** Midterm Lab Exam — 1-Week DevSecOps Security Sprint (Fall 2026)  
**Institution:** COMSATS University Islamabad, Department of Computer Science  
**Instructor:** Engr. Muhammad Ahmad Nawaz  
**Project:** SecureDrop – Enterprise Document Vault Platform (`SecureApp-Sprint-Team1`)  

### Team Members
- **Talal Nadeem Awan** (FA23-BCT-051)
- **Shahroze Afaq** (FA23-BCT-039)

---

## 1. Executive Summary
This report presents the empirical findings from our automated DevSecOps security testing suite, incorporating both Static Application Security Testing (SAST) and Dynamic Application Security Testing (DAST). In compliance with Section 6.6 of the CYC386 Sprint guidelines, security scanning was incorporated into the CI/CD pipeline with a strict **fail-on-critical** policy.

---

## 2. Static Application Security Testing (SAST)

### 2.1 Scanner Tooling & Configuration
- **Tool:** Bandit 1.9.4 (PyCQA AST-based Security Analyzer)
- **Standards Mapped:** OWASP Top 10, CWE-78 (OS Command Injection), CWE-259 (Hardcoded Secrets)
- **Execution Profile:** Full recursive audit with severe-failure threshold (`-lll` flag enforces non-zero exit code on High severity findings).

---

### 2.2 Baseline Scan Results (Pre-Remediation Codebase)
**Command:**
```powershell
bandit -r app_vulnerable.py processor_vulnerable.py -f txt -o reports\sast_vuln_report.txt
```

**Quantitative Scan Metrics (Vulnerable):**
- **Total Lines of Code Scanned:** 205
- **High Severity Issues:** **2**
- **Medium Severity Issues:** 0
- **Low Severity Issues:** 3
- **Pipeline Exit Code:** **1 (Build Failed)**

**Critical Findings Breakdown:**
1. **Issue B602 (High Severity / High Confidence):**  
   *Location:* `app_vulnerable.py:212`  
   *CWE:* CWE-78 (OS Command Injection)  
   *Snippet:* `subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)`  
   *Risk:* Passing user-supplied string directly to an active shell interpreter.
2. **Issue B602 (High Severity / High Confidence):**  
   *Location:* `processor_vulnerable.py:21`  
   *CWE:* CWE-78 (OS Command Injection)  
   *Snippet:* `subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)`  
   *Risk:* Direct command interpolation allows arbitrary subshell command execution.
3. **Issue B105 (Low Severity / Medium Confidence):**  
   *Location:* `app_vulnerable.py:24`  
   *CWE:* CWE-259 (Hardcoded Password / Secret)  
   *Snippet:* `app.secret_key = "insecure-hardcoded-secret-key-for-lab-demo"`

> **[SCREENSHOT CHECKPOINT #27]:** Capture Bandit SAST scan output showing the 2 High Severity findings and pipeline failure on vulnerable code.

---

### 2.3 Hardened Scan Results (Post-Remediation Production Codebase)
**Command:**
```powershell
bandit -r app.py processor.py -lll
```

**Quantitative Scan Metrics (Secure):**
- **Total Lines of Code Scanned:** 278
- **High Severity Issues:** **0**
- **Medium Severity Issues:** **0**
- **Low Severity Issues:** 4 (Informational B404/B603 noting standard parameterized subprocess usage with `shell=False`)
- **Pipeline Exit Code:** **0 (Build Passed Cleanly)**

```text
Run started: 2026-10-30 14:52:53
Test results:
    No issues identified.
Code scanned:
    Total lines of code: 278
Run metrics:
    Total issues (by severity):
        High: 0
        Medium: 0
        Low: 4
Files skipped: 0
ExitCode: 0
```

> **[SCREENSHOT CHECKPOINT #28]:** Capture terminal showing Bandit SAST output on `app.py` returning `No issues identified` with ExitCode: 0.

---

## 3. Dynamic Application Security Testing (DAST)

### 3.1 DAST Methodology & Setup
- **Target Application:** `http://127.0.0.1:5000/` (Live Flask daemon)
- **Scanning Engine:** Automated HTTP Header & Security Control Audit (OWASP ZAP Core Rule Equivalents)
- **Audit Points:** Header enforcement (CWE-1021, CWE-693), CSRF token enforcement (CWE-352), Session state isolation.

---

### 3.2 Dynamic Audit Comparison Matrix

| Security Control / Header | Vulnerable Target (Port 5001) | Hardened Target (Port 5000) | Remediation Status | OWASP / CWE Mapping |
| :--- | :--- | :--- | :---: | :--- |
| **X-Frame-Options** | *Missing* (Framing Allowed) | `DENY` | **Remediated** | CWE-1021 (Clickjacking) |
| **Content-Security-Policy** | *Missing* | `default-src 'self'; frame-ancestors 'none';` | **Remediated** | CWE-1021 (Clickjacking) |
| **X-Content-Type-Options** | *Missing* (MIME Sniffing) | `nosniff` | **Remediated** | CWE-79 / MIME Sniffing |
| **Referrer-Policy** | *Missing* | `strict-origin-when-cross-origin` | **Remediated** | CWE-200 (Info Disclosure) |
| **X-XSS-Protection** | *Missing* | `1; mode=block` | **Remediated** | CWE-79 (Cross-Site Scripting)|
| **Cookie SameSite Policy** | None / Lax | `Strict` | **Remediated** | CWE-352 (CSRF) |
| **Cookie HttpOnly Flag** | False / Not configured | `True` | **Remediated** | CWE-1004 (Cookie Theft) |
| **Anti-CSRF Token** | *Absent* (Forged POST succeeds) | Synchronizer Token enforced | **Remediated** | CWE-352 (CSRF) |
| **Object-Level Auth (IDOR)**| *Absent* (Any user file exposed) | Enforced `owner_id` check | **Remediated** | CWE-639 (IDOR) |

---

## 4. Automated CI/CD Security Gate Demonstration

### 4.1 Fail-on-Critical Enforcement
The DevSecOps pipeline enforces automated regression prevention in `.github/workflows/ci-cd.yml`:
```yaml
- name: Run Bandit SAST on Production Code (Fail on High/Critical)
  run: |
    bandit -r app.py processor.py -lll -f txt -o reports_sast.txt
```

### 4.2 Pipeline Execution Proof
1. **Vulnerable Branch / PR:**  
   When a pull request introduces code with `shell=True` or an unauthenticated SQL access, the Bandit SAST gate detects a High-severity finding, returns status `1`, and automatically blocks merging into `main`.
2. **Remediated Main Branch:**  
   The build, native C compilation, unit tests, vulnerability verification suite, Bandit scan, and security header audit all return status `0`, producing a passing build.

> **[SCREENSHOT CHECKPOINT #29]:** Capture GitHub Actions workflow runs showing the failing build on the vulnerable test branch and the green passing build on `main`.

---
*Report Compiled & Verified by: Talal Nadeem Awan (FA23-BCT-051) & Shahroze Afaq (FA23-BCT-039)*
