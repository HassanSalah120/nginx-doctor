import pytest
from pathlib import Path

from nginx_doctor.connector.ssh import SSHConfig, SSHConnector
# ``SSHConnector`` currently raises the builtin ``ConnectionError`` when
# authentication problems occur; we don't export a module-specific exception.
SSHConnectionError = ConnectionError  # alias for clarity in tests


def test_connect_with_nonexistent_key(tmp_path):
    """Specifying a key_path that doesn't exist should raise a clear error.

    The SSHConnector.connect() logic must validate the presence of an explicit
    key file and fail early rather than letting Paramiko attempt to load it
    (which produced vague errors seen in job logs).
    """
    fake_key = tmp_path / "no_such_key.pem"
    assert not fake_key.exists()

    cfg = SSHConfig(host="example.com", key_path=str(fake_key))
    ssh = SSHConnector(cfg)

    with pytest.raises(SSHConnectionError) as excinfo:
        ssh.connect()
    assert "SSH key file not found" in str(excinfo.value)
    assert str(fake_key) in str(excinfo.value)


def test_connect_with_existing_key(tmp_path, monkeypatch):
    """If the key exists we should pass it through to Paramiko's connect call.

    This test doesn't actually establish a connection; it simply verifies that
    ``connect_kwargs`` are constructed correctly and that ``SSHClient.connect``
    is invoked. We patch out the underlying client so no network activity
    occurs.
    """
    key_file = tmp_path / "mykey"
    key_file.write_text("KEY")

    cfg = SSHConfig(host="foo", key_path=str(key_file), passphrase="secret")
    ssh = SSHConnector(cfg)

    called = {}
    class DummyClient:
        def set_missing_host_key_policy(self, *args, **kwargs):
            pass
        def connect(self, **kwargs):
            called.update(kwargs)
    monkeypatch.setattr(ssh, "_client", None)
    monkeypatch.setattr("paramiko.SSHClient", lambda: DummyClient())

    ssh.connect()
    assert called.get("hostname") == "foo"
    assert called.get("key_filename") == str(key_file)
    assert called.get("passphrase") == "secret"
    assert called.get("look_for_keys") is False
    assert called.get("allow_agent") is False


def test_connect_io_error(monkeypatch):
    """If the underlying SSH client raises an I/O error we want to wrap it.

    This simulates Paramiko failing to load a key even though the path was
    provided (e.g. permission denied). The public API should surface a
    :class:`ConnectionError` with the original message included.
    """
    cfg = SSHConfig(host="foo")
    ssh = SSHConnector(cfg)

    class DummyClient2:
        def set_missing_host_key_policy(self, *args, **kwargs):
            pass
        def connect(self, **kwargs):
            raise OSError("bad key file: permission denied")
    monkeypatch.setattr("paramiko.SSHClient", lambda: DummyClient2())

    with pytest.raises(ConnectionError) as excinfo2:
        ssh.connect()
    assert "SSH key file error" in str(excinfo2.value)
    assert "permission denied" in str(excinfo2.value)


def test_authentication_exception_message(monkeypatch):
    """AuthenticationException should not lead to a duplicated message."""
    cfg = SSHConfig(host="foo")
    ssh = SSHConnector(cfg)

    class DummyClient3:
        def set_missing_host_key_policy(self, *args, **kwargs):
            pass
        def connect(self, **kwargs):
            from paramiko.ssh_exception import AuthenticationException
            raise AuthenticationException("Authentication failed")
    monkeypatch.setattr("paramiko.SSHClient", lambda: DummyClient3())

    with pytest.raises(ConnectionError) as excinfo3:
        ssh.connect()
    msg = str(excinfo3.value)
    assert msg == "Authentication failed"
