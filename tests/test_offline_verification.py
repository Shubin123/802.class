import pytest
from scripts import verify_install


@pytest.mark.parametrize(('same_namespace', 'interfaces', 'expected'), [
    (False, [(1, 'lo')], True),
    (True, [(1, 'lo')], False),
    (False, [(1, 'lo'), (2, 'wlan0')], False),
])
def test_offline_claim_requires_namespace_and_loopback_only(monkeypatch, same_namespace, interfaces, expected):
    monkeypatch.setattr(verify_install.socket, 'if_nameindex', lambda: interfaces)
    def namespace(path):
        return 'net:[1]' if same_namespace or path == '/proc/1/ns/net' else 'net:[2]'
    monkeypatch.setattr(verify_install.os, 'readlink', namespace)
    isolated, _ = verify_install.network_context()
    assert isolated is expected
