---
name: dependency-evaluation
description: Discover existing solutions before designing a mechanism or selecting a dependency for Credential Vault; apply the canonical procedure with local security and ownership checks.
---

# Dependency Evaluation

Read [local policy applicability](../../AGENTS.md#beauty-system-policy-applicability)
and use the current canonical
[discovery/decision procedure](https://github.com/rpwagner/beauty-runtime/blob/main/skills/dependency-evaluation/SKILL.md).
Actively discover solutions before a new mechanism is designed, including when
no dependency has been named. Look beyond installed packages without waiting
for the operator to suggest one. Keep investigation proportionate and reuse its
existing decision evidence; do not maintain a second general checklist here.
Report unavailable sources or unresolved local/upstream conflicts.

## Local ownership and review

Use [ARCHITECTURE.md](../../ARCHITECTURE.md) for package boundaries. Preserve
keyring/keyrings.cryptfile ownership of encryption and file formats, and
Globus SDK ownership of authentication and token lifecycle behavior. Inspect
those maintained interfaces before proposing local substitutes.

Keep application paths, credential identities, scopes and authorization in the
consumer. Evaluate compatibility with the supported Python/POSIX platforms and
the vault persistence, finite locking and redacted-error contracts. Apply the
local implementation review boundaries in
[AGENTS.md](../../AGENTS.md#implementation-stop-conditions); discovery or design
discussion grants no credential, stored-state, locking or publication authority.
