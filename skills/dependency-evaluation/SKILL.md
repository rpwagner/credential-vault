---
name: dependency-evaluation
description: Evaluate whether Python functionality should use the standard library, an existing dependency, a new external dependency, or local code. Use before adding a dependency or reimplementing functionality already available elsewhere.
---

# Dependency Evaluation

Prefer the smallest maintainable solution, not automatically the fewest dependencies or the fewest local lines.

1. State the capability needed in one sentence.
2. Check, in order: Python standard library, dependencies already installed by this project, then external packages.
3. If considering a new dependency, compare it with a local implementation using concrete evidence where practical.
4. Consider maintenance activity, security and supply-chain exposure, transitive dependency weight, license, API stability, replaceability, platform support, and how specialized or error-prone the local implementation would be.
5. Prefer a maintained dependency when local code would reproduce specialized, security-sensitive, protocol-sensitive, or compatibility-heavy behavior.
6. Prefer local code when the needed behavior is small, stable, easy to test, and the dependency creates comparable or greater long-term burden.
7. Do not add a dependency merely for convenience when existing project code or the standard library already solves the problem adequately.

Record the decision briefly:

- Capability needed
- Existing solution checked
- Candidate dependency, if any
- Local implementation alternative
- Dependency risks and costs
- Local-code risks and costs
- Decision
- Evidence

If the evidence is insufficient or the choice would materially change the repository architecture, stop and request architectural review.
