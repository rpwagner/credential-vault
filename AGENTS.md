# Repository purpose

credential-vault is a small standalone Python package for portable encrypted credential storage and reusable Globus token lifecycle behavior. It is intentionally designed to be easy for both people and coding models to understand and extend methodically.

## Architecture boundary

This package owns:
- encrypted credential persistence through an explicit `keyring` backend;
- vault master-key provider contracts and platform bootstrap helpers;
- cooperative multi-process locking around vault operations;
- opaque static-secret get/set/delete behavior;
- a Globus SDK `TokenStorage` adapter;
- reusable Globus token validation, refresh, and explicit login composition;
- redacted package-defined credential errors.

This package does not own:
- inference, provider, or model configuration;
- application authorization or policy;
- credential-to-provider selection;
- agent/persona behavior;
- network credential services or brokers;
- background scheduling;
- application-specific paths, credential identities, OAuth clients, scopes, or resources;
- generalized OAuth behavior beyond explicitly supported SDK integrations.

Consumers may depend on credential-vault. credential-vault must not depend on application packages.

## Development rules

- Prefer less code when it produces a simpler maintainable system.
- Do not rebuild functionality that Python, an existing dependency, keyring, keyrings.cryptfile, or globus-sdk already provides adequately.
- Before adding a dependency, follow `skills/dependency-evaluation/SKILL.md` and record the reasoning in the issue or pull request.
- Prefer the latest stable supported Python release and latest stable direct dependency releases. Keep them reasonably current unless a documented compatibility, stability, or security reason justifies holding a version back.
- Keep runtime dependencies minimal. Test/build tools belong in the test extra.
- Keep secrets out of source code, configuration files, logs, exceptions, object representations, command arguments, and test fixtures committed to Git.
- Use keyring interfaces and keyrings.cryptfile for encrypted vault persistence; do not copy or reimplement its cryptographic/file-format internals.
- Use globus-sdk for Globus authentication, token validation, refresh, and token data types rather than reimplementing OAuth.
- Keep application-specific defaults and policy in consuming applications.
- Implement only the issue being worked on. Do not implement anticipated future features.
- Add or update tests with behavior changes.
- Keep modules focused on one responsibility and avoid unnecessary nesting.

## Development workflow

- Before editing, read ARCHITECTURE.md and the current issue, then inspect the affected code and tests.
- Refresh current `origin/main`, open issues, open pull requests, package metadata, and relevant dependency releases before editing.
- Do development work on short-lived branches scoped to the current issue or unit of work. Approved prefixes are `feature/`, `fix/`, `chore/`, `docs/`, and `release/`.
- Start branches from current `origin/main`.
- Use HTTPS GitHub remotes. Do not use SSH remotes, Git worktrees, or GitHub Desktop.
- Keep a canonical checkout on `main` and use a separate development checkout for branch work.
- If useful work is blocked before completion, commit and push that working state to the scoped branch before ending the work session. Record the blocker, validation actually run, unvalidated areas, and exact next step in the issue or a draft pull request. Do not leave the only copy of useful work in uncommitted local state, a temporary checkout, or chat/tool scratch space.
- Keep each branch focused; avoid unrelated changes.
- Make routine implementation decisions within the documented boundaries. Adding a small helper or focused test is not itself a reason to stop.
- Run the normal validation before considering the work complete.
- Submit completed work through a pull request to `main`.
- In the pull request, summarize the changes, validation actually performed, and remaining limitations. Distinguish mocked/offline tests from live-platform validation.
- Changes to `main` should occur through pull requests after bootstrap.
- Do not merge a pull request unless explicitly instructed.
- After a pull request is merged, follow the cleanup rules below.

## Supported runtime

The initial package target is Python 3.13 and 3.14 on POSIX hosts. macOS and Linux are the required platforms for the first release.

Windows support requires an explicit locking design decision; do not silently weaken the POSIX advisory-lock contract.

## Validation

The normal development loop is:

    python -m pip install -e ".[test]"
    python -m pytest
    python -m pip check
    git diff --check

Before release, also build wheel and source distributions, install each into a clean environment, and smoke-test the public package import.

The repository should not require a model or developer to discover additional routine installation steps.

## Releases

- Package releases use annotated `v<project.version>` tags on exact release commits.
- Never move or reuse a release tag.
- Tagged releases are tested and packaged by GitHub Actions.
- Publication uses the protected `release` environment and requires explicit human approval.
- Do not publish a release unless explicitly instructed.
- Keep version changes and release notes in bounded release work.

## Work completion and cleanup

Cleanup is part of completing development work.

- After a pull request is merged, delete its source branch locally and remotely unless it is still needed for active follow-on work.
- Remove temporary clones, scratch directories, and disposable environments you created.
- Before deleting anything, verify that needed changes are preserved.
- Do not delete shared, long-lived, or otherwise persistent resources unless explicitly instructed.
- If something is intentionally retained, state why in the handoff.

## Documentation maintenance

Update AGENTS.md and/or ARCHITECTURE.md in the same pull request when a change alters a stable repository fact represented there. Keep temporary branch names, issue-level progress, and workstream status in GitHub issues and pull requests rather than stable documentation.

## Handoff

Before ending a development thread, make the GitHub branch/PR state current, record validation and unresolved risks, link the relevant GitHub artifacts, and state the exact next action so another thread can resume from GitHub rather than from chat memory.

## Stop conditions

Stop and request architectural review instead of improvising when a change:
- introduces a new architectural layer;
- requires a new external runtime dependency;
- changes a public interface beyond the active issue;
- introduces application-specific provider, authorization, persona, or runtime policy;
- reimplements cryptographic/file-format behavior owned by keyrings.cryptfile;
- reimplements Globus OAuth/token lifecycle behavior owned by globus-sdk;
- requires substantially different persistence or locking semantics;
- makes an existing module serve substantially different purposes;
- requires several new abstractions merely to complete a small issue.

A clean stop is a successful outcome. Explain what was completed, what caused the stop, and the smallest architectural decision needed next.
