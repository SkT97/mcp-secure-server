"""Run the pinned upstream MCP suite against the real, protected loopback app."""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import socket
import subprocess
import tempfile
from dataclasses import replace
from pathlib import Path

from mcp_secure_server.demo import _start_server, build_demo_config, issue_demo_token
from mcp_secure_server.server import build_server, make_app

REVISION = "74edef34d674f563537be8c6587cebaa58e830ca"
SPEC = "2026-07-28"
SOURCE_HASHES = {
    "package-lock.json": "74e86cd36216d4e84d834de4467fdf6afd9cadf07ff55aa6058018f9baebf895",
    "src/index.ts": "12038525abb9b0a3da73e8c8cc884c5522080e8a54bdaa12c685c38cd3ba7626",
    "requirements/2026-07-28.yaml": "ae2f4f6210fd729e2e318edd5bbfa31a43cee0bc608e48052fa26dbf1d939b57",
}
SAFE_ID = re.compile(r"[a-zA-Z0-9_-][a-zA-Z0-9_./:-]{0,149}")
STATUSES = {"SUCCESS", "FAILURE", "WARNING", "SKIPPED", "INFO"}
# Use the same YAML dependency already locked by the official suite.
LOAD_REQUIREMENTS = """
const fs = require('node:fs');
const { parse } = require('yaml');
const requirements = parse(fs.readFileSync(process.argv[1], 'utf8'));
console.log(JSON.stringify([
  ...requirements.server.map(name => [name, true]),
  ...requirements.not_scored.filter(row => row.leg === 'server').map(row => [row.scenario, false])
]));
"""


def verify_runner_source(root: Path) -> str:
    for relative, expected in SOURCE_HASHES.items():
        data = (root / relative).read_bytes().replace(b"\r\n", b"\n")
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError(f"upstream source fingerprint mismatch: {relative}")
    if not (root / ".git").exists():
        return "source-fingerprints"
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    ).stdout.strip()
    if head != REVISION:
        raise ValueError("the upstream checkout is not at the pinned revision")
    return "git-head-and-source-fingerprints"


def read_results(directory: Path, scenarios: dict[str, bool]) -> list[dict]:
    results = []
    for scenario, required in scenarios.items():
        timestamp = r"\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{3}Z"
        pattern = re.compile(rf"server-{re.escape(scenario)}-{timestamp}")
        matches = [
            path / "checks.json" for path in directory.iterdir() if pattern.fullmatch(path.name)
        ]
        checks = []
        status = "no_result"
        if len(matches) == 1 and matches[0].is_file():
            raw_checks = json.loads(matches[0].read_text(encoding="utf-8"))
            for row in raw_checks:
                check_id = row["id"]
                check_status = row["status"]
                if not SAFE_ID.fullmatch(check_id) or check_status not in STATUSES:
                    raise ValueError("invalid check ID or status from upstream")
                checks.append({"id": check_id, "status": check_status})
            outcomes = {check["status"] for check in checks}
            if "FAILURE" in outcomes:
                status = "failed"
            elif "SUCCESS" in outcomes:
                status = "passed"
            elif "SKIPPED" in outcomes:
                status = "skipped"
            else:
                status = "unscored"
        elif len(matches) > 1:
            raise ValueError("multiple result directories for an upstream scenario")
        results.append(
            {"scenario": scenario, "required": required, "status": status, "checks": checks}
        )
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runner-root", type=Path, required=True)
    parser.add_argument("--json-out", type=Path, required=True)
    parser.add_argument("--anonymous", action="store_true", help="send no bearer token")
    parser.add_argument(
        "--smoke", action="store_true", help="run only the supported tools/list check"
    )
    args = parser.parse_args()
    root = args.runner_root.resolve()
    runner = root / "dist" / "index.js"
    if not runner.is_file():
        parser.error("build the pinned upstream runner with npm ci first")
    source_verification = verify_runner_source(root)
    requirements = subprocess.run(
        ["node", "-e", LOAD_REQUIREMENTS, f"requirements/{SPEC}.yaml"],
        cwd=root,
        check=True,
        capture_output=True,
        encoding="utf-8",
        timeout=30,
    )
    scenarios = dict(json.loads(requirements.stdout))
    if args.smoke:
        scenarios = {"tools-list": scenarios["tools-list"]}
    if not scenarios or any(not SAFE_ID.fullmatch(name) for name in scenarios):
        raise ValueError("invalid scenario names from upstream")
    selection = (
        ["--scenario", "tools-list", "--spec-version", SPEC]
        if args.smoke
        else ["--requirements", SPEC]
    )
    logging.getLogger("mcp").setLevel(logging.CRITICAL)
    with socket.socket() as sock, tempfile.TemporaryDirectory() as temporary:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        config, private_key = build_demo_config(port)
        # Keep any discovery requests within this specific listener.
        config = replace(config, issuer_url=f"http://127.0.0.1:{port}")
        server, _ = _start_server(make_app(build_server(config), config), sock)
        directory = Path(temporary)
        endpoint = f"http://127.0.0.1:{port}/mcp"
        command = ["node"]
        environment = os.environ.copy()
        if not args.anonymous:
            command.extend(("--require", str(Path(__file__).with_name("conformance_client.cjs"))))
            environment["CONFORMANCE_TEST_ENDPOINT"] = endpoint
            environment["CONFORMANCE_TEST_TOKEN"] = issue_demo_token(config, private_key, "north")
        try:
            result = subprocess.run(
                [
                    *command,
                    str(runner),
                    "server",
                    "--url",
                    endpoint,
                    *selection,
                    "--output-dir",
                    str(directory),
                ],
                cwd=root,
                env=environment,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=180,
                check=False,
            )
            exit_code = result.returncode
            timed_out = False
        except subprocess.TimeoutExpired:
            exit_code = 124
            timed_out = True
        finally:
            server.should_exit = True
        payload = {
            "protocol_revision": SPEC,
            "runner_revision": REVISION,
            "source_verification": source_verification,
            "runner_exit_code": exit_code,
            "runner_timed_out": timed_out,
            "selection": "tools-list" if args.smoke else "server-requirements",
            "fixture": (
                "anonymous against protected loopback server"
                if args.anonymous
                else "ephemeral bearer token from loopback test client"
            ),
            "scenarios": read_results(directory, scenarios),
        }
    args.json_out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
