#!/usr/bin/env python3
"""Validate the reviewed fork in a ghr-pypi mirror and pip install report.

Validation only: no network, package resolution, download or installation.
"""

import argparse
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import re
from urllib.parse import urldefrag, urljoin


SOURCE = json.loads(Path(__file__).with_name("cryptfile-source.json").read_text())


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


class Links(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.hrefs: list[str] = []

    def handle_starttag(self, tag, attrs) -> None:
        if tag == "a":
            self.hrefs.extend(value for key, value in attrs if key == "href" and value)


def check_mirror(mirror: Path) -> Path:
    mirror = mirror.resolve()
    wheel = mirror / "files" / normalize(SOURCE["name"]) / SOURCE["filename"]
    payload = wheel.read_bytes()
    if len(payload) != SOURCE["size"] or hashlib.sha256(payload).hexdigest() != SOURCE["sha256"]:
        raise ValueError("mirrored cryptfile wheel differs from the reviewed release")
    page = mirror / "simple" / normalize(SOURCE["name"]) / "index.html"
    links = Links()
    links.feed(page.read_text())
    resolved = [urljoin(page.as_uri(), link) for link in links.hrefs]
    if any(not link.startswith((mirror / "files").as_uri() + "/") for link in resolved):
        raise ValueError("Simple Index lacks exclusively local artifact links")
    expected = wheel.as_uri() + "#sha256=" + SOURCE["sha256"]
    if expected not in resolved:
        raise ValueError("Simple Index lacks the local reviewed wheel/hash link")
    return wheel


def check_report(report: Path, mirror: Path) -> None:
    wheel = check_mirror(mirror)
    installs = json.loads(report.read_text())["install"]
    selected = [item for item in installs if normalize(item["metadata"]["name"]) == normalize(SOURCE["name"])]
    if len(selected) != 1:
        raise ValueError("pip report must contain exactly one cryptfile install")
    item = selected[0]
    info = item["download_info"]
    if (item["metadata"]["version"] != SOURCE["version"]
            or urldefrag(info["url"])[0] != wheel.as_uri()
            or info.get("archive_info", {}).get("hashes", {}).get("sha256") != SOURCE["sha256"]):
        raise ValueError("pip selected cryptfile outside the reviewed mirror artifact")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mirror", required=True, type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    if args.report:
        check_report(args.report, args.mirror)
    else:
        print(check_mirror(args.mirror))


if __name__ == "__main__":
    main()
