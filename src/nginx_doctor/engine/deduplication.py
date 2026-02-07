"""Deduplication and Ranking Engine for Findings."""

from nginx_doctor.model.evidence import Severity
from nginx_doctor.model.finding import Finding


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Combine, deduplicate, and rank findings from multiple sources.
    
    This function:
    1. Maps missing IDs using condition patterns.
    2. Groups findings by (rule_id, condition).
    3. Merges evidence for duplicate findings.
    4. Applies instance numbering (e.g., NGX002-1, NGX002-2).
    5. Performs cross-linking (Root Cause Analysis).
    """
    if not findings:
        return []

    # Rule ID map (Centralized)
    rule_map = {
        "Backup configuration": "NGX001",
        "Duplicate server_name": "NGX002",
        "PHP-FPM socket not found": "NGX003",
        "Laravel root misconfigured": "NGX004",
        "Missing try_files": "NGX005",
        "Nginx config variables": "NGX006",
        "sites-enabled only contains symlinks": "NGX007",
        "Default nginx site still enabled": "NGX008",
        # Modular checks (to be expanded)
        "PHP version consistency": "NGX100",
        "Multiple PHP versions": "NGX100",
        "Mixed PHP versions": "NGX101",
        ".env file may be exposed": "NGX200",
        "Port 443 without SSL directive": "NGX201",
        "SSL enabled without certificate": "NGX202",
        "Insecure security headers": "SEC001",
        "HSTS missing": "SEC002",
        "X-Frame-Options missing": "SEC003",
    }

    # 1. Assign Rule IDs and Deduplicate
    deduped: list[Finding] = []
    seen_keys: dict[tuple[str, str], Finding] = {} # (rule_id, condition) -> Finding
    
    for f in findings:
        # Resolve ID if it's default
        current_id = f.id
        if current_id == "NGX000":
            for pattern, rid in rule_map.items():
                if pattern.lower() in f.condition.lower():
                    current_id = rid
                    break
        
        # Use (id, condition) as deduplication key
        key = (current_id, f.condition)
        
        if key in seen_keys:
            # Merge evidence into existing finding
            base = seen_keys[key]
            for ev in f.evidence:
                # Check for exact evidence duplicate (file + line)
                is_dup = any(
                    e.source_file == ev.source_file and 
                    e.line_number == ev.line_number and
                    e.excerpt == ev.excerpt
                    for e in base.evidence
                )
                if not is_dup:
                    base.evidence.append(ev)
            
            # Keep higher severity if different
            severity_order = {Severity.CRITICAL: 0, Severity.WARNING: 1, Severity.INFO: 2}
            if severity_order[f.severity] < severity_order[base.severity]:
                base.severity = f.severity
        else:
            f.id = current_id # Provisional ID
            seen_keys[key] = f
            deduped.append(f)
    
    # 2. Instance counters for unique IDs (e.g., NGX002-1, NGX002-2)
    instance_counters: dict[str, int] = {}
    for f in deduped:
        rule_prefix = f.id.split("-")[0] # Strip existing -N if any
        instance_counters[rule_prefix] = instance_counters.get(rule_prefix, 0) + 1
        f.id = f"{rule_prefix}-{instance_counters[rule_prefix]}"
    
    # 3. ROOT CAUSE CHAINING: 
    # Link side-effects to primary causes (e.g., Backup files -> Duplicate server_name)
    _apply_root_cause_linking(deduped)
    
    # 4. Final Sorting (Critical -> Warning -> Info)
    return sorted(
        deduped, 
        key=lambda x: (
            0 if x.severity == Severity.CRITICAL else 
            1 if x.severity == Severity.WARNING else 2,
            x.id
        )
    )


def _apply_root_cause_linking(findings: list[Finding]) -> None:
    """Analyze findings to find parent-child relationships."""
    
    # Relationship: NGX001 (Backup Config) causes many others
    backup_findings = [f for f in findings if "NGX001" in f.id]
    if backup_findings:
        backup_files = set()
        for bf in backup_findings:
            backup_files.update({ev.source_file for ev in bf.evidence if ev.source_file != "nginx.conf"})
        
        for f in findings:
            # Duplicate server_name or PHP socket mismatch might be caused by backups
            if any(prefix in f.id for prefix in ["NGX002", "NGX003"]):
                from_backup = any(ev.source_file in backup_files for ev in f.evidence)
                
                if from_backup:
                    f.derived_from = "NGX001"
                    f.severity = Severity.INFO
                    f.cause = f"{f.cause}. This is likely a side-effect of backup files being enabled (NGX001)."
                    f.treatment = "Resolve parent finding NGX001 first."
