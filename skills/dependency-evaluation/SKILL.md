---
name: dependency-evaluation
description: Evaluate configuration, integration, extension, dependencies, and local code for Credential Vault during design and before adding a dependency or rebuilding existing functionality.
---

# Dependency Evaluation

Read `AGENTS.md` for policy applicability, stage distinctions, and local review
boundaries. Keep this as the repository's focused decision procedure.

1. State the capability needed in one sentence.
2. During design, inspect current package/consumer capabilities and configuration, Python standard facilities, existing dependencies, maintained clients/packages, supported SDK integrations, and upstream extension points. Investigate in proportion to uncertainty and consequence, not through an exhaustive checklist for known mechanisms.
3. Compare practical configuration, integration, extension, dependency, and local-code options using concrete evidence where useful. Preserve keyrings.cryptfile ownership of encryption/file formats and globus-sdk ownership of supported OAuth/token behavior.
4. Consider maintenance activity, security and supply-chain exposure, transitive dependency weight, license, API stability, replaceability, platform support, and how specialized or error-prone the local implementation would be.
5. Prefer a maintained dependency when local code would reproduce specialized, security-sensitive, protocol-sensitive, or compatibility-heavy behavior.
6. Prefer local code when the needed behavior is small, stable, easy to test, and the dependency creates comparable or greater long-term burden.
7. Do not add a dependency merely for convenience when existing project code or the standard library already solves the problem adequately.

Record the decision briefly:

- Capability needed
- Existing solution checked
- Candidate dependency, if any
- Local implementation alternative
- Dependency/integration risks and costs, including affected contracts, effort, platform compatibility, migration/deployment, and ownership
- Local-code risks and costs
- Decision
- Evidence and what would reopen the decision

Reuse an existing decision record where it still applies. During design, expose
material architectural alternatives and their costs rather than treating current
architecture as fixed. During implementation, stop for an unresolved contract
conflict or material change not authorized by the adopted issue. If evidence is
insufficient, identify the smallest useful experiment or decision. Neither stage
authorizes changing credentials, scopes, persistence, locking, or publication.
