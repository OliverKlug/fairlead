# Contributing

Fairlead is maintained by one person and **is not accepting external pull requests** at the moment. Bug reports, agent-integration requests and false-positive or bypass reports are welcome as issues. Report security vulnerabilities through [SECURITY.md](SECURITY.md), not as issues.

## Useful issues

- A hook input from a supported agent (Cursor, Claude Code, Windsurf, OpenHands) that Fairlead decides wrongly. Paste the JSON, the decision and the policy id from the receipt.
- A host version where fail-closed behaviour differs from what [docs/residual-risk.md](docs/residual-risk.md) says.
- A request for another agent adapter. Say where the agent exposes a pre-tool hook and what it does when the hook fails.

## Working on a local copy

```bash
cargo test --workspace
./tests/attack_suite/run.sh
cargo run -p fairlead-cli -- doctor
```

The test suite is the specification. Every rule in `pack/policies/baseline.cedar` has a test in `crates/fairlead-core`, and `pack/tests/doctor/cases.json` holds the fixtures that `fairlead doctor` and `fairlead arm` must reproduce before they will arm.
