"""The temporary callback transport never logs an authorization code."""

import socket
import threading
from urllib.parse import urlsplit

import pytest
import requests

from credential_vault import OAuthAuthenticationError
from credential_vault.loopback import LoopbackRedirect


def test_loopback_callback_and_socket_cleanup(monkeypatch, capsys):
    threads = []

    def browser(url):
        def redirect():
            requests.get(callback + "?code=synthetic-code&state=synthetic-state", timeout=2)
        worker = threading.Thread(target=redirect)
        worker.start()
        threads.append(worker)
        return True

    monkeypatch.setattr("credential_vault.loopback.webbrowser.open", browser)
    with LoopbackRedirect("http://127.0.0.1:0/callback", timeout=2) as listener:
        callback = listener.uri
        assert listener.authorize("https://issuer.example/authorize") == (
            callback + "?code=synthetic-code&state=synthetic-state")
    for thread in threads:
        thread.join(2)
        assert not thread.is_alive()
    assert "synthetic-code" not in capsys.readouterr().err
    with socket.socket() as probe:
        assert probe.connect_ex(("127.0.0.1", urlsplit(callback).port)) != 0


@pytest.mark.parametrize("uri", ["http://0.0.0.0:0/callback", "https://localhost/callback",
                                 "http://remote.example/callback"])
def test_never_binds_external_interface(uri):
    with pytest.raises(OAuthAuthenticationError):
        with LoopbackRedirect(uri, timeout=1):
            pass


def test_timeout_closes_listener(monkeypatch):
    monkeypatch.setattr("credential_vault.loopback.webbrowser.open", lambda url: True)
    with pytest.raises(OAuthAuthenticationError, match="timed out"):
        with LoopbackRedirect("http://127.0.0.1:0/callback", timeout=0.05) as listener:
            listener.authorize("https://issuer.example/authorize")
