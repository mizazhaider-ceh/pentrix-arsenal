"""Pipeline _derive_* title-parsing tests.

These functions are the fallback discovery path when modules return plain
finding lists: if a module renames a title, recursive discovery silently
breaks. The tests pin the exact title shapes the pipeline depends on.
"""

from arsenal import pipeline


def _result(*titles, target="example.com"):
    return {"findings": [{"title": t, "target": target} for t in titles]}


def test_derive_alive_hosts():
    res = _result("Alive host: sub.example.com", "Something else",
                  target="")
    hosts = pipeline._derive_alive_hosts(res)
    assert hosts == ["sub.example.com"]


def test_derive_alive_hosts_uses_target_field():
    res = {"findings": [{"title": "Alive host: ", "target": "h.example.com"}]}
    assert pipeline._derive_alive_hosts(res) == ["h.example.com"]


def test_derive_open_ports():
    res = _result("Open port: 443/tcp (https)", "Risky open port: 22/tcp (ssh)",
                  "Open port: not-a-port", target="h.example.com")
    ports = pipeline._derive_open_ports(res)
    assert {"host": "h.example.com", "port": 443, "service": "https"} in ports
    assert {"host": "h.example.com", "port": 22, "service": "ssh"} in ports
    assert len(ports) == 2


def test_derive_open_ports_strips_port_from_target():
    res = _result("Open port: 80/tcp (http)", target="h.example.com:8080")
    ports = pipeline._derive_open_ports(res)
    assert ports[0]["host"] == "h.example.com"


def test_derive_tech_hints():
    res = _result("Technology: jQuery 3.7.1", "Technology: nginx (server)",
                  "Unrelated finding")
    hints = pipeline._derive_tech_hints(res)
    assert "jquery 3.7.1" in hints
    assert "nginx" in hints
    assert len(hints) == 2


def test_derive_empty_inputs():
    empty = {"findings": []}
    assert pipeline._derive_alive_hosts(empty) == []
    assert pipeline._derive_open_ports(empty) == []
    assert pipeline._derive_tech_hints(empty) == []
