#!/usr/bin/env python3
"""Exercise a clean install with every HTTP(S) request blocked and recorded."""

import argparse
from functools import partial
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import subprocess
import tempfile
import threading

from check_cryptfile_source import check_mirror, check_report


def check_install(python: Path, artifact: Path, mirror: Path, dependencies: Path) -> None:
    subprocess.run([str(python), "-I", "-c",
                    "import sys; assert sys.prefix != sys.base_prefix, 'a clean virtual environment is required'"],
                   check=True)
    check_mirror(mirror)
    if list(dependencies.glob("keyrings_cryptfile-*.whl")):
        raise ValueError("dependency staging must not supply an alternate cryptfile wheel")
    requests: list[str] = []

    class DenyNetwork(BaseHTTPRequestHandler):
        def do_CONNECT(self) -> None:
            requests.append(self.path)
            self.send_error(502, "network disabled during install validation")

        do_GET = do_CONNECT
        do_POST = do_CONNECT

        def log_message(self, *args) -> None:
            pass

    with ThreadingHTTPServer(("127.0.0.1", 0), DenyNetwork) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            env = {key: value for key, value in os.environ.items()
                   if not key.startswith("PIP_") and "proxy" not in key.lower()}
            proxy = f"http://127.0.0.1:{server.server_port}"
            env.update(HTTP_PROXY=proxy, HTTPS_PROXY=proxy, ALL_PROXY=proxy,
                       http_proxy=proxy, https_proxy=proxy, all_proxy=proxy,
                       NO_PROXY="", no_proxy="", PIP_CONFIG_FILE=os.devnull,
                       PIP_DISABLE_PIP_VERSION_CHECK="1")
            with tempfile.TemporaryDirectory() as work:
                report = Path(work) / "install.json"
                run = partial(subprocess.run, check=True, env=env, cwd=work)
                # Pre-install selection is checked before any wheel is installed.
                command = [str(python), "-m", "pip", "install", "--no-cache-dir",
                           "--retries", "0", "--timeout", "2", "--only-binary", "keyrings.cryptfile",
                           "--index-url", (mirror / "simple").as_uri() + "/",
                           "--find-links", dependencies.as_uri(), "--report", str(report), str(artifact)]
                run([*command, "--dry-run", "--ignore-installed"])
                check_report(report, mirror)
                run(command)
                check_report(report, mirror)
                run([str(python), "-m", "pip", "check"])
                run([str(python), "-I", "-c", "import credential_vault"])
                run([str(python), "-I", "-B", str(Path(__file__).with_name("check_installed_post.py").resolve())])
        finally:
            server.shutdown()
            thread.join()
    if requests:
        raise ValueError(f"installation attempted network requests: {requests}")
    print("Clean index install: reviewed fork/hash, pip check, import, post; zero HTTP(S) requests")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    # Resolving the Python symlink would bypass the virtual environment.
    parser.add_argument("--python", required=True, type=lambda value: Path(value).absolute())
    for name in ("artifact", "mirror", "dependencies"):
        parser.add_argument("--" + name, required=True, type=lambda value: Path(value).resolve())
    check_install(**vars(parser.parse_args()))
