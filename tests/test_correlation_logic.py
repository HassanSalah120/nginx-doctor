import pytest
from dataclasses import dataclass
from nginx_doctor.analyzer.finding_correlation import CorrelationEngine
from nginx_doctor.model.finding import Finding, Evidence, Severity
from nginx_doctor.model.server import (
    ServerModel, NginxInfo, ServiceStatus, CapabilityLevel, 
    ServerBlock, LocationBlock, ServicesModel, DockerContainer, DockerPort, 
    NetworkSurfaceModel, NetworkEndpoint
)

@pytest.fixture
def mock_topology():
    return ServerModel(
        hostname="test-server",
        nginx=NginxInfo(version="1.24.0", config_path="/etc/nginx/nginx.conf"),
        nginx_status=ServiceStatus(capability=CapabilityLevel.FULL)
    )

def test_header_inheritance_correlation(mock_topology):
    evidence = [Evidence(source_file="/etc/nginx/nginx.conf", line_number=10, excerpt="location / {", command="")]
    findings = [
        Finding(id="SEC-HEAD-1", severity=Severity.WARNING, confidence=0.9, condition="Missing HSTS", cause="Not set", evidence=evidence),
        Finding(id="SEC-HEAD-1", severity=Severity.WARNING, confidence=0.9, condition="Missing HSTS", cause="Not set", evidence=evidence),
        Finding(id="SEC-HEAD-1", severity=Severity.WARNING, confidence=0.9, condition="Missing HSTS", cause="Not set", evidence=evidence),
        Finding(id="SEC-HEAD-1", severity=Severity.WARNING, confidence=0.9, condition="Missing HSTS", cause="Not set", evidence=evidence),
        Finding(id="SEC-HEAD-1", severity=Severity.WARNING, confidence=0.9, condition="Missing HSTS", cause="Not set", evidence=evidence),
    ]
    engine = CorrelationEngine(findings, mock_topology)
    correlations = engine.correlate()
    
    c = next((x for x in correlations if x.correlation_id == "header-inheritance-broken"), None)
    assert c is not None

def test_unintended_exposure_correlation(mock_topology):
    # Fix the test to match network_surface
    mock_topology.network_surface = NetworkSurfaceModel(endpoints=[
        NetworkEndpoint(protocol="tcp", address="0.0.0.0", port=3306, public_exposed=True),
    ])
    mock_topology.nginx.servers = [
        ServerBlock(listen=["80", "443 ssl"])
    ]
    
    findings = [] 
    engine = CorrelationEngine(findings, mock_topology)
    correlations = engine.correlate()
    
    c = next((x for x in correlations if x.correlation_id == "unintended-exposure-risk"), None)
    assert c is not None

def test_tls_posture_correlation(mock_topology):
    mock_topology.hostname = "docker-app-01"
    evidence = [Evidence(source_file="/etc/nginx/nginx.conf", line_number=10, excerpt="ssl_protocols TLSv1;", command="")]
    findings = [
        Finding(id="SEC-TLS-1", severity=Severity.WARNING, confidence=0.9, condition="TLS 1.0 enabled", cause="Old", evidence=evidence),
    ]
    engine = CorrelationEngine(findings, mock_topology)
    correlations = engine.correlate()
    
    c = next((x for x in correlations if x.correlation_id == "ingress-tls-posture-risk"), None)
    assert c is not None
