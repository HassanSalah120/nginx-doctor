"""Scoring Engine.

Calculates deterministic health scores based on findings.
Strict rules:
- Max Score: 100
- Categories: Security (40), Performance (20), Architecture (20), Laravel/App (20)
- Penalties: Critical (-10), Warning (-4), Info (-1)
- Min score per category: 0
"""

from dataclasses import dataclass, field
from typing import Dict, List

from nginx_doctor.model.finding import Finding, Severity

@dataclass
class CategoryScore:
    max_points: int
    current_points: int
    penalties: int = 0
    findings: List[str] = field(default_factory=list)

@dataclass
class ServerScore:
    total: int
    security: CategoryScore
    performance: CategoryScore
    architecture: CategoryScore
    app: CategoryScore

class ScoringEngine:
    """Calculates scores from findings."""

    # Penalty values
    PENALTIES = {
        Severity.CRITICAL: 10,
        Severity.WARNING: 4,
        Severity.INFO: 1,
    }

    def calculate(self, findings: List[Finding]) -> ServerScore:
        """Calculate score based on findings."""
        # Initialize categories
        cats = {
            "security": CategoryScore(40, 40),
            "performance": CategoryScore(20, 20),
            "architecture": CategoryScore(20, 20),
            "app": CategoryScore(20, 20),
        }

        for f in findings:
            penalty = self.PENALTIES.get(f.severity, 0)
            target = self._map_to_category(f)
            
            # Apply penalty
            cat = cats[target]
            cat.penalties += penalty
            cat.current_points = max(0, cat.max_points - cat.penalties)
            cat.findings.append(f.id)

        # Calculate Total
        total_current = sum(c.current_points for c in cats.values())
        # Max total is 100
        
        return ServerScore(
            total=total_current,
            security=cats["security"],
            performance=cats["performance"],
            architecture=cats["architecture"],
            app=cats["app"],
        )

    def _map_to_category(self, finding: Finding) -> str:
        """Map finding ID to score category."""
        fid = finding.id.upper()
        
        # Security
        if fid.startswith("SEC-HEAD") or fid.startswith("NGX-SEC") or "SSL" in fid:
            return "security"
        if fid in ["PHPFPM-3"]: # Missing socket is security/availability critical? Or architecture?
             # Let's count missing socket (critical) as App or Arch?
             # Implementation plan said "App/Laravel" is 20.
             pass

        # App (Laravel, PHPFPM)
        if fid.startswith("LARAVEL") or fid.startswith("PHPFPM"):
            return "app"
        
        # Performance
        if fid.startswith("NGX-PERF"):
            return "performance"
            
        # Architecture (Ports, Unknowns, WSS)
        if fid.startswith("PORT") or fid.startswith("NGX-WSS"): 
             # WSS checks are mixed security/arch. 
             # WSS-001/002 are broken arch. WSS-010 is dotfile (security).
             if fid == "NGX-WSS-010": 
                 return "security"
             return "architecture"
             
        # Catch-all defaults based on keywords in ID/Condition could go here, 
        # but relying on ID prefixes is deterministic as requested.
        
        # Default bucket
        return "architecture" 
