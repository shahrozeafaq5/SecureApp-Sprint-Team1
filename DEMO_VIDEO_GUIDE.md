# Technical Demo Video Script & Narration Guide (6–10 Minutes)
**Course:** CYC386 – Secure Software Design and Development  
**Exam:** Midterm Lab Exam — 1-Week DevSecOps Security Sprint (Fall 2026)  
**Institution:** COMSATS University Islamabad, Department of Computer Science  
**Instructor:** Engr. Muhammad Ahmad Nawaz  
**Project:** SecureDrop – Enterprise Document Vault Platform (`SecureApp-Sprint-Team1`)  

### Presenters
- **Talal Nadeem Awan** (FA23-BCT-051)
- **Shahroze Afaq** (FA23-BCT-039)

---

## 🎬 Video Recording Plan & Segment Timeline

| Segment | Duration | Topic | Speaker / Lead | Action on Screen |
| :---: | :---: | :--- | :---: | :--- |
| **1** | 0:00 - 1:15 | Introduction & Architecture Overview | Talal Nadeem Awan | Show GitHub repo, system architecture diagram, and Jira board. |
| **2** | 1:15 - 2:45 | Vulnerability 1: Buffer Overflow (Before vs After) | Shahroze Afaq | Run `parser_vulnerable.exe` (crash) vs `parser_secure.exe` (safe rejection). |
| **3** | 2:45 - 4:15 | Vulnerability 2: Command Injection (Before vs After) | Shahroze Afaq | Show `LAB_MARKER` executed via `shell=True` vs regex rejection in `processor.py`. |
| **4** | 4:15 - 5:45 | Vulnerability 3: IDOR (Before vs After) | Talal Nadeem Awan | Demonstrate cross-user download on Port 5001 vs HTTP 404 Access Denied on Port 5000. |
| **5** | 5:45 - 6:45 | Vulnerabilities 4 & 5: CSRF & Clickjacking Proofs | Talal Nadeem Awan | Open `csrf_poc.html` (403 blocked) and `clickjacking_poc.html` (framing blocked). |
| **6** | 6:45 - 8:15 | DevSecOps CI/CD Pipeline & SAST Gate | Shahroze Afaq | Show GitHub Actions workflow, Bandit fail-on-critical gate, and zero-finding scan. |
| **7** | 8:15 - 9:30 | Conclusion, CIA Residual Risk & Contributions | Talal Nadeem Awan | Recap CIA impact, individual contributions, and close. |

---

## 📝 Word-for-Word Narration Script

### [0:00 - 1:15] Segment 1: Welcome & Architectural Overview
**Speaker (Talal Nadeem Awan):**
> "Good day everyone and Respected Instructor Engr. Muhammad Ahmad Nawaz. Welcome to our DevSecOps Security Engineering Sprint demonstration for CYC386. I am Talal Nadeem Awan (FA23-BCT-051), and presenting alongside me is my teammate Shahroze Afaq (FA23-BCT-039).
> 
> Over this 7-day sprint, our mission was to take a vulnerable file-sharing and document management service and harden it to production-grade security. 
> 
> As you can see on screen, our architecture is divided into three defense tiers: a Python Flask web frontend enforcing strict HTTP security headers and anti-CSRF synchronizer tokens, an SQLite database enforcing relational object-level authorization, a parameterized Python worker process eliminating OS shell command injection, and a hardened native C metadata parser compiled with GCC stack canaries.
> 
> Our sprint backlog was completely tracked in Jira under project key SASS, linking our Protection Needs Elicitation directly to STRIDE threats, code commits, and verification tests. I now hand over to Shahroze to demonstrate our memory and injection defenses."

---

### [1:15 - 2:45] Segment 2: Buffer Overflow Demonstration (Before vs After)
**Speaker (Shahroze Afaq):**
> "Thank you, Talal. Let's examine our first mandatory vulnerability class: Buffer Overflow (CWE-120 and CWE-121).
> 
> In our pre-remediation C parser, `native/metadata_vulnerable.c`, an unbounded copy loop transfers external strings into a 32-byte fixed stack buffer without bounds checking. 
> 
> *(Screen: Execute `.\parser_vulnerable.exe` in PowerShell)*
> 
> Watch what happens when we supply an oversized 63-byte input payload: the process immediately aborts with `*** stack smashing detected ***: terminated`, exiting with Windows status code 0xC0000409. The compiler stack canary detected that stack memory was corrupted.
> 
> *(Screen: Open `native/metadata.c` and execute `.\parser_secure.exe`)*
> 
> Now observe our remediated version. We implemented CERT C coding standards ARR38-C and STR31-C. We explicitly enforce `if (len >= sizeof(filename))` before any memory operation and use bounded `memcpy`. When we re-run the exact same oversized input, the secure parser gracefully rejects the payload with: `Rejected: metadata too long (length 63 exceeds buffer size 31)` and exits cleanly with code 1. Buffer overflow is 100% neutralized."

---

### [2:45 - 4:15] Segment 3: OS Command Injection (Before vs After)
**Speaker (Shahroze Afaq):**
> "Next, let's look at OS Command Injection (CWE-78). 
> 
> In our vulnerable baseline, the `/process` endpoint used Python's `subprocess.run(cmd, shell=True)` with direct string formatting. 
> 
> *(Screen: Run command injection exploit payload in terminal)*
> 
> We craft an attack payload injecting a Windows command separator: `report.txt & echo LAB_MARKER`. Look at the output: the operating system subshell interprets the ampersand and executes `echo LAB_MARKER`. In an enterprise setting, an attacker could chain this into a full reverse shell or ransomware deployment.
> 
> *(Screen: Open `processor.py` and run secure test)*
> 
> To remediate this, we eliminated shell interpretation entirely. We migrated to `subprocess.run([...], shell=False)` with an execve-style argument list, combined with a strict regex whitelist pattern `^[A-Za-z0-9_-]{1,64}\.txt$`. When we submit the identical injection payload against the hardened processor, it is immediately rejected with: `Error: Invalid saved filename pattern`, exiting with code 1. Shell commands can never be interpreted."

---

### [4:15 - 5:45] Segment 4: Insecure Direct Object Reference - IDOR (Before vs After)
**Speaker (Talal Nadeem Awan):**
> "Thank you, Shahroze. I will now demonstrate our access control and web vulnerabilities. Let's start with IDOR (CWE-639).
> 
> *(Screen: Open browser on Port 5001 showing vulnerable app)*
> 
> On Port 5001, we have our pre-remediation app. User 'Alice' has uploaded a private file with ID 1. Now, I log in as User 'Bob'. In the URL, Bob simply navigates to `/download/1`. Because the backend queries `SELECT ... WHERE id = ?` without verifying the owner, Bob immediately downloads Alice's confidential data. This violates the Confidentiality pillar of the CIA triad.
> 
> *(Screen: Switch to Port 5000 showing secure app)*
> 
> Now, let's switch to our hardened application on Port 5000. We implemented strict Object-Level Authorization: every query enforces `WHERE id = ? AND owner_id = session['user_id']`. When Bob attempts to download File ID 101 owned by Alice, the server returns `HTTP 404 Not Found: File not found or access denied`. Bob cannot view, download, or delete any object that does not belong to him."

---

### [5:45 - 6:45] Segment 5: CSRF & Clickjacking Proofs
**Speaker (Talal Nadeem Awan):**
> "We also hardened against CSRF (CWE-352) and Clickjacking (CWE-1021).
> 
> *(Screen: Open `tests/csrf_poc.html`)*
> 
> Here is an external attacker page simulating a Cross-Site Request Forgery attack attempting to delete files. On the vulnerable server, the request succeeds with an HTTP 302 redirect. On our secure server, our Synchronizer Token Pattern checks the session token via constant-time comparison. The forged request is immediately blocked with `HTTP 403 Forbidden: CSRF token missing or invalid`.
> 
> *(Screen: Open `tests/clickjacking_poc.html`)*
> 
> Next is Clickjacking. In this test harness, the left panel attempts to frame the vulnerable application, which succeeds because it lacks framing restrictions. The right panel attempts to frame our secure application. Because we enforce `X-Frame-Options: DENY` and CSP `frame-ancestors 'none'`, the browser completely blocks framing, safeguarding our users from transparent overlay attacks."

---

### [6:45 - 8:15] Segment 6: DevSecOps CI/CD Pipeline & SAST Gate
**Speaker (Shahroze Afaq):**
> "To guarantee that these security controls are continuously enforced, we established an automated CI/CD pipeline using GitHub Actions in `.github/workflows/ci-cd.yml`.
> 
> *(Screen: Show Bandit scan results and GitHub Actions workflow UI)*
> 
> Our pipeline incorporates a mandatory SAST security gate using Bandit with the `-lll` flag. On our pre-remediation codebase, Bandit detects two High-severity Command Injection flaws and immediately exits with status 1, failing the build and blocking the pull request.
> 
> On our production branch, Bandit scans 278 lines of code and reports zero High and zero Medium findings, exiting with status 0. The pipeline then validates our C binary compilation, executes our 5-vulnerability automated verification suite, and audits live HTTP security headers before greenlighting deployment."

---

### [8:15 - 9:30] Segment 7: Conclusion & Contribution Statement
**Speaker (Talal Nadeem Awan):**
> "In summary, our DevSecOps sprint achieved full coverage across the CIA triad. Confidentiality is preserved via IDOR object-level authorization and password hashing. Integrity is protected via Anti-CSRF synchronizer tokens and command injection elimination. Availability is guaranteed through stack canary bounds checking in native C and upload limits.
> 
> In terms of individual contributions:
> - Shahroze Afaq led the C parser development, buffer overflow remediation, command injection elimination, and GitHub Actions CI/CD setup.
> - I, Talal Nadeem Awan, led the Protection Needs Elicitation, IDOR access controls, CSRF synchronizer token implementation, Clickjacking header defenses, and Jira sprint management.
> - Together, we collaborated equally on threat modeling, the IEEE final report, and this demonstration.
> 
> Thank you for watching, and we welcome any questions in our upcoming viva!"
