from nginx_doctor.analyzer.wss_auditor import WSSAuditor
from nginx_doctor.model.server import LocationBlock, NginxInfo, ServerBlock, ServerModel


def _ws_location(
    path: str,
    target: str,
    *,
    upgrade: bool = True,
    connection: bool = True,
    http11: bool = True,
    buffering: str = "off",
    read_timeout: int | None = 300,
    send_timeout: int | None = 300,
    line_number: int = 10,
) -> LocationBlock:
    headers = {}
    if upgrade:
        headers["Upgrade"] = "$http_upgrade"
    if connection:
        headers["Connection"] = "$connection_upgrade"
    return LocationBlock(
        path=path,
        proxy_pass=target,
        proxy_http_version="1.1" if http11 else None,
        proxy_set_headers=headers,
        proxy_buffering=buffering,
        proxy_read_timeout=read_timeout,
        proxy_send_timeout=send_timeout,
        source_file="/etc/nginx/conf.d/default.conf",
        line_number=line_number,
    )


def _model_with_locations(locations: list[LocationBlock]) -> ServerModel:
    return ServerModel(
        hostname="example.com",
        nginx=NginxInfo(
            version="1.24.0",
            config_path="/etc/nginx/nginx.conf",
            servers=[
                ServerBlock(
                    server_names=["example.com"],
                    listen=["443 ssl"],
                    locations=locations,
                    source_file="/etc/nginx/conf.d/default.conf",
                    line_number=1,
                )
            ],
        ),
    )


def test_wss_handshake_quality_good():
    model = _model_with_locations(
        [_ws_location("/wss", "http://backend_ws", buffering="off", read_timeout=600, send_timeout=600)]
    )
    auditor = WSSAuditor(model)
    findings = auditor.audit()
    inventory = auditor.get_inventory()

    assert inventory
    assert inventory[0].handshake_quality == "GOOD"
    assert inventory[0].risk_level == "OK"
    assert not any(f.id in {"NGX-WSS-001", "NGX-WSS-002", "NGX-WSS-003"} for f in findings)


def test_wss_handshake_quality_broken_when_upgrade_missing():
    model = _model_with_locations(
        [_ws_location("/wss", "http://backend_ws", upgrade=False)]
    )
    auditor = WSSAuditor(model)
    findings = auditor.audit()
    inventory = auditor.get_inventory()

    assert inventory[0].handshake_quality == "BROKEN"
    assert inventory[0].risk_level == "CRITICAL"
    ids = {f.id for f in findings}
    assert "NGX-WSS-002" in ids


def test_wss_handshake_quality_degraded_for_buffering():
    model = _model_with_locations(
        [_ws_location("/wss", "http://backend_ws", buffering="on")]
    )
    auditor = WSSAuditor(model)
    findings = auditor.audit()
    inventory = auditor.get_inventory()

    assert inventory[0].handshake_quality == "DEGRADED"
    assert inventory[0].risk_level == "WARNING"
    ids = {f.id for f in findings}
    assert "NGX-WSS-004" in ids


def test_wss_conflict_detection_same_path_multiple_backends():
    model = _model_with_locations(
        [
            _ws_location("/wss", "http://backend_a", line_number=10),
            _ws_location("/wss", "http://backend_b", line_number=20),
        ]
    )
    findings = WSSAuditor(model).audit()
    ids = {f.id for f in findings}
    assert "NGX-WSS-009" in ids
