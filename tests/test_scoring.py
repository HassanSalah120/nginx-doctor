"""Tests for Scoring Engine.

Verifies deterministic scoring rules:
- Max Score: 100
- Categories: Security (40), Performance (20), Architecture (20), App (20)
- Penalties: Critical (-10), Warning (-4), Info (-1)
- Min score per category: 0
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from nginx_doctor.engine.scoring import ScoringEngine, ServerScore
from unittest.mock import MagicMock
from nginx_doctor.model.finding import Finding, Severity

def test_perfect_score():
    """No findings should yield 100 points."""
    engine = ScoringEngine()
    score = engine.calculate([])
    
    assert score.total == 100
    assert score.security.current_points == 40
    assert score.performance.current_points == 20
    assert score.architecture.current_points == 20
    assert score.app.current_points == 20

def test_critical_security_penalty():
    """One critical security finding should deduct 10 points from Security."""
    f = Finding(
        id="NGX-SEC-3", # Security category
        condition="Dotfiles exposed",
        cause="Missing location block",
        treatment="Add block",
        severity=Severity.CRITICAL,
        confidence=1.0,
        evidence=[MagicMock()]
    )
    
    engine = ScoringEngine()
    score = engine.calculate([f])
    
    assert score.security.current_points == 30 # 40 - 10
    assert score.total == 90
    
def test_category_floor():
    """Score should not go below 0 per category."""
    # 5 Critical Security Findings = -50 points
    findings = []
    for i in range(5):
        findings.append(Finding(
            id="NGX-SEC-X",
            condition="Bad stuff",
            cause="...",
            treatment="...",
            severity=Severity.CRITICAL,
            confidence=1.0,
            evidence=[MagicMock()]
        ))
        
    engine = ScoringEngine()
    score = engine.calculate(findings)
    
    assert score.security.current_points == 0 # Floor at 0, not -10
    assert score.total == 60 # 0 + 20 + 20 + 20

def test_mixed_categories():
    """Verify mixed findings affect correct buckets."""
    findings = [
        Finding(id="NGX-PERF-1", severity=Severity.WARNING, condition="Gzip off", cause="", treatment="", confidence=1.0, evidence=[MagicMock()]),
        Finding(id="LARAVEL-1", severity=Severity.CRITICAL, condition="Debug on", cause="", treatment="", confidence=1.0, evidence=[MagicMock()]),
        Finding(id="PORT-1", severity=Severity.INFO, condition="Orphan port", cause="", treatment="", confidence=1.0, evidence=[MagicMock()]),
    ]
    
    engine = ScoringEngine()
    score = engine.calculate(findings)
    
    assert score.performance.current_points == 16 # 20 - 4
    assert score.app.current_points == 10 # 20 - 10
    assert score.architecture.current_points == 19 # 20 - 1
    assert score.total == 100 - 4 - 10 - 1 # 85
