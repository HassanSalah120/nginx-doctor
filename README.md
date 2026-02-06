# 🩺 nginx-doctor

> **SSH-based Server Intelligence System for Nginx + PHP Applications**

**Not just configs. Not just auditing. It understands intent.**

**Nginx-Doctor** is not simply a configuration linter. It is an intelligent diagnostic tool that scans remote servers via SSH, builds a comprehensive model of your Nginx configuration, PHP-FPM environment, and local web applications, then cross-references them to find breaking misconfigurations.

## 🚀 Key Features

- **🔍 Automatic App Detection**: Identifies Laravel, PHP MVC, SPA (Vue/React), and Static sites based on filesystem fingerprints.
- **🩺 Intelligent Diagnostics**: 20+ specialized checks including:
  - PHP-FPM socket mismatches.
  - Laravel root misconfigurations (missing `/public`).
  - Missing `try_files` for framework routing.
  - Duplicate `server_name` declarations (including hidden backup files).
- **📂 Filesystem Discovery**: Audits your server to find "orphaned" projects that exist on disk but are not served by Nginx.
- **🔗 Root Cause Chaining**: Detects when one issue (like an enabled `.bak` file) causes many others and groups them logically.
- **🛠️ Actionable Recommendations**: Every finding includes copy-pasteable shell commands (`sudo mv`, `sudo rm`) to fix the issue.
- **📊 Professional Reporting**: Beautiful terminal output leveraging the `rich` library, with support for `plain` text and `json` output for CI/CD.
- **🛡️ Security Auditor**: Checks for exposed `.env` files, valid root directives, and safe permission settings.

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/HassanSalah120/nginx-doctor.git
cd nginx-doctor

# Install in development mode
pip install -e .
```

## 📋 Quick Start

### 1. Configure a Server Profile

Store your connection details (SSH key based auth recommended):

```bash
python -m nginx_doctor config add prod-server --host 1.2.3.4 --user root
```

### 2. Run a Health Check (Diagnose)

Run a full scan to find misconfigurations and security risks:

```bash
python -m nginx_doctor diagnose prod-server
```

### 3. Audit Filesystem (Discover)

Find "orphaned" projects that take up space but aren't active in Nginx:

```bash
python -m nginx_doctor discover prod-server
```

### 4. CI/CD Integration

Use plain text or JSON output formats for scripts:

```bash
# JSON output
python -m nginx_doctor diagnose prod-server --format json > report.json

# Clean text for logs
python -m nginx_doctor diagnose prod-server --format plain
```

## 🛠️ Diagnostic Rule IDs

| ID         | Description                                                 | Severity |
| ---------- | ----------------------------------------------------------- | -------- |
| **NGX001** | Backup configuration files are enabled (causing duplicates) | WARNING  |
| **NGX002** | Duplicate `server_name` declaration                         | INFO     |
| **NGX003** | PHP-FPM socket not found                                    | CRITICAL |
| **NGX004** | Laravel root misconfigured (`/public` missing)              | CRITICAL |
| **NGX005** | Missing `try_files` for framework routing                   | WARNING  |
| **NGX200** | `.env` file exposure risk                                   | WARNING  |

## 🛡️ Safety & Reliability

- **Non-Destructive**: Scans are strictly read-only. We use `nginx -T`, `ls`, and `cat` (for config/json files only).
- **Evidence-Based**: We don't just say "it's broken". We show you the exact file, line number, and config excerpt.
- **Compliance Aware**: Exit codes (`0`=Clean, `1`=Warning, `2`=Critical) allow easy integration into pipelines.

## 📜 License

MIT
