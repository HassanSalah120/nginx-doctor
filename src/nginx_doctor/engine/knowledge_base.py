"""Knowledge Base for Nginx Doctor.

Provides context (Why, Risk, Ignore conditions) for findings.
Used by --explain mode.
"""

from dataclasses import dataclass

@dataclass
class Explanation:
    why: str
    risk: str
    ignore: str

# Mapping of ID prefix or full ID to explanation
# specific IDs take precedence over prefixes
KNOWLEDGE_BASE = {
    # LARAVEL
    "LARAVEL-1": Explanation(
        why="APP_DEBUG=true exposes detailed stack traces and configuration values.",
        risk="Attackers can steal API keys, database credentials, and path info.",
        ignore="NEVER safe in production.",
    ),
    "LARAVEL-2": Explanation(
        why="Laravel requires write access to storage/ for logs, sessions, and cache.",
        risk="Application crashes (500 errors) or inability to log errors.",
        ignore="If using ephemeral filesystem (e.g. Lambda) and exclusively external drivers (Redis/S3).",
    ),
    "LARAVEL-3": Explanation(
        why="Laravel needs to write compiled views/services to bootstrap/cache.",
        risk="Performance degradation and application crashes.",
        ignore="If using read-only container with pre-warmed cache (rare).",
    ),
    "LARAVEL-4": Explanation(
        why="Laravel Scheduler relies on a single system cron entry.",
        risk="Scheduled tasks (emails, cleanups) will rarely or never run.",
        ignore="If using an external scheduler or worker-only instance.",
    ),
    "LARAVEL-5": Explanation(
        why="Queued jobs need active worker processes to execute.",
        risk="Async tasks (emails, processing) will pile up and never complete.",
        ignore="If this server is a web-only tier and workers run elsewhere.",
    ),

    # PORTS
    "PORT-1": Explanation(
        why="Nginx is proxying traffic to a backend service that isn't listening.",
        risk="Users receive 502 Bad Gateway errors.",
        ignore="If the backend service is currently restarting or transiently down.",
    ),
    "PORT-2": Explanation(
        why="A process is listening on a port not managed by Nginx.",
        risk="Unnecessary attack surface; services might be exposed directly.",
        ignore="If the service is internal (localhost only) or managed by another proxy.",
    ),

    # SECURITY HEADERS
    "SEC-HEAD-1": Explanation(
        why="Security headers tell browsers to block specific attacks (XSS, Clickjacking).",
        risk="Users are vulnerable to clickjacking, mime-sniffing, and XSS.",
        ignore="If the application is an API with no HTML interface (partial ignore).",
    ),
    "NGX-SEC-2": Explanation(
        why="Autoindex lists all files in a directory if no index file exists.",
        risk="Information disclosure (source code, backups, temp files).",
        ignore="If the directory is specifically meant for public file downloads.",
    ),
    "NGX-SEC-3": Explanation(
        why="Dotfiles (.git, .env) often contain secrets and source history.",
        risk="Full compromise of credentials and source code.",
        ignore="NEVER safe for .env. .git is only safe if not present on server.",
    ),
    "NGX-SEC-4": Explanation(
        why="Upload directories should not execute scripts (PHP/PL).",
        risk="Attackers upload a web shell and gain code execution.",
        ignore="If uploads are stored off-server (S3) or strictly validated by app (risky).",
    ),

    # PHP-FPM
    "PHPFPM-1": Explanation(
        why="Slowlog helps identify performance bottlenecks in code.",
        risk="Unable to diagnose cause of high latency or timeouts.",
        ignore="If using an APM (New Relic, Datadog) that provides trace profiling.",
    ),
    "PHPFPM-2": Explanation(
        why="pm.max_children determines concurrent request capacity.",
        risk="Traffic spikes cause 502 errors as requests queue up.",
        ignore="If the server has extremely low traffic.",
    ),
    
    # PERFORMANCE
    "NGX-PERF-1": Explanation(
        why="Gzip reduces transmission size of text assets (HTML/CSS/JS).",
        risk="Slower page loads and higher bandwidth usage.",
        ignore="If a CDN handles compression upstream.",
    ),
    "NGX-PERF-2": Explanation(
        why="HTTP/2 multiplexes requests over a single connection.",
        risk="Slower load times for asset-heavy pages.",
        ignore="If legacy clients strictly require HTTP/1.1 (very rare).",
    ),
    "NGX-PERF-3": Explanation(
        why="Static assets should be cached by browsers to reduce server load.",
        risk="Repeat visitors re-download distinct files; higher server load.",
        ignore="If a CDN handles caching policies.",
    ),
    "NGX-PERF-5": Explanation(
        why="worker_processes should typically match CPU core count.",
        risk="Underutilization of hardware resources.",
        ignore="If unrelated CPU-heavy workloads run on the same server.",
    ),
    
    # WebSocket
    "NGX-WSS-001": Explanation(
        why="WebSockets require HTTP/1.1 to upgrade connections.",
        risk="Connection upgrade fails; fallback to polling or error.",
        ignore="Never.",
    ),
    "NGX-WSS-002": Explanation(
        why="The Upgrade header is hop-by-hop and not passed by default.",
        risk="WebSockets fail to establish through the proxy.",
        ignore="Never.",
    ),
    "NGX-WSS-003": Explanation(
        why="Connection header must be set to 'Upgrade' explicitly.",
        risk="WebSockets fail to establish.",
        ignore="Never.",
    ),
    "NGX-WSS-004": Explanation(
        why="Nginx buffering breaks real-time long-lived connections.",
        risk="Messages are delayed or connection drops unexpectedly.",
        ignore="If your app handles polling/buffering robustly (unlikely for WS).",
    ),
    "NGX-WSS-005": Explanation(
        why="Short read timeouts kill idle WebSocket connections.",
        risk="Frequent disconnections requiring client reconnection logic.",
        ignore="If you implement application-layer heartbeats more frequent than the timeout.",
    ),
}

def get_explanation(finding_id: str) -> Explanation | None:
    """Get explanation for a finding ID."""
    if finding_id in KNOWLEDGE_BASE:
        return KNOWLEDGE_BASE[finding_id]
    
    # Fallback to generic category explanations if strict ID missing?
    # For now, strict mapping or return None
    return None
