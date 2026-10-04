"""Report the current release's absence of package-owned state transitions.

Invoked as an installed file, separately from pip and package import. Deliberately
do not import credential_vault or inspect caller-selected vault/key state.
"""

import json
import sys


def main() -> int:
    try:
        payload = sys.stdin.buffer.read(65537)
        if len(payload) > 65536:
            raise ValueError
        context = json.loads(payload)
        if (type(context.get("contract_version")) is not int
                or context["contract_version"] != 1
                or context.get("distribution") != "credential-vault"
                or context.get("environment") not in ("beauty", "inference-core")
                or context.get("operation") not in ("deploy", "recover")
                or not isinstance(context.get("reconcile"), bool)
                or context.get("intent", {}) != {}):
            raise ValueError
    except (ValueError, AttributeError, RecursionError):
        print(json.dumps({"status": "failed", "message": "invalid or unsupported Vault deployment context"}))
        return 1
    print(json.dumps({"status": "unchanged", "message": "no package-owned state reconciliation required"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
