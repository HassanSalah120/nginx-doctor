# 🩺 nginx-doctor

> SSH-based Server Intelligence System for Nginx + PHP Applications

**Not just configs. Not just auditing. It understands intent.**

## Installation

````bash
> SSH-based Server Intelligence & Diagnostic System for Nginx + PHP Stack

**Nginx-Doctor** is not just a configuration linter. It is an intelligent diagnostic tool that understands the *intent* behind your server setup. It scans remote servers via SSH, builds a comprehensive model of your Nginx configuration, PHP-FPM environment, and local web applications, then cross-references them to find breaking misconfigurations.

## 🚀 Key Features

- **🔍 Automatic App Detection**: Identifies Laravel, PHP MVC, SPA (Vue/React), and Static sites based on filesystem fingerprints.
- **🩺 Intelligent Diagnostics**: 20+ specialized checks including:
  - PHP-FPM socket mismatches.
  - Laravel root misconfigurations (/public vs root).
  - Missing `try_files` for framework routing.
  - Duplicate `server_name` declarations (including those hidden in backups).
- **🔗 Root Cause Chaining**: Detects when one issue (like an enabled `.bak` file) causes many others (like duplicate server names) and groups them as side-effects.
- **🛠️ Actionable Recommendations**: Every finding includes exact, copy-pasteable shell commands (`sudo mv`, `sudo rm`, `sudo reload`) to fix the issue immediately.
- **📊 Professional Reporting**: Uses the `rich` library to provide beautiful terminal summaries and evidence-based findings (File, Line, Excerpt).
- **🛡️ Security Auditor**: Checks for exposed `.env` files, SSL configuration errors, and world-writable directories.

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/HassanSalah120/nginx-doctor.git
cd nginx-doctor

# Install in development mode
pip install -e .
````

## 📋 Quick Start

1. **Configure a server profile:**

   ```bash
   python -m nginx_doctor config add prod-server --host 1.2.3.4 --user root
   ```

2. **Run a health check:**

   ```bash
   # Pre-flight connectivity check
   python -m nginx_doctor check prod-server

   # Full diagnostic scan
   python -m nginx_doctor diagnose prod-server
   ```

3. **Explore discovery results:**
   ```bash
   # See detected projects and PHP/Nginx versions
   python -m nginx_doctor scan prod-server
   ```

## 🛠️ Diagnostic Rule IDs

| ID         | Description                                  | Severity |
| ---------- | -------------------------------------------- | -------- |
| **NGX001** | Backup configuration files are enabled       | WARNING  |
| **NGX002** | Duplicate server_name declaration            | WARNING  |
| **NGX003** | PHP-FPM socket not found                     | CRITICAL |
| **NGX004** | Laravel root misconfigured (/public missing) | CRITICAL |
| **NGX005** | Missing try_files for routing                | WARNING  |
| **NGX200** | .env file exposure risk                      | WARNING  |

## 🛡️ Safety & Reliability

- **Non-Destructive**: Normal scans are read-only. We only read config via `nginx -T` and directory listings.
- **Evidence-Based**: We don't just say "it's broken". We show you the exact file and line number.
- **Compliance Aware**: Exit codes (`0`, `1`, `2`) are provided based on the highest finding severity for easy CI/CD integration.

## 📜 License

MIT
