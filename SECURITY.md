# Security policy

Fairlead is a security tool, so a bug here can be a bypass of someone else's guardrail. Please report it privately first.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting: open the **Security** tab of this repository and choose **Report a vulnerability**. Do not open a public issue or pull request for a suspected vulnerability.

Include the commit hash you built, the agent and host version (for example Cursor or Claude Code), the exact hook input or command, and what you expected versus what happened. A failing test in `crates/fairlead-core` is the best possible report.

You can expect an acknowledgement within a few days. This is a one-person project, so there is no response-time SLA and no bug bounty.

## What counts as a vulnerability

- A command, file operation or tool call that the baseline policy in `pack/policies/baseline.cedar` is meant to stop, but that gets an Allow.
- A way to make the hook process allow when it should fail closed (crash, invalid JSON, Cedar error, missing pin, drifted pack or binary).
- A forged, replayed or silently dropped receipt, or a way to read or overwrite the local signing seed.
- Memory-unsafe behaviour. The crates set `unsafe_code = "forbid"`, so this should not exist.

## What does not count

The limits in [docs/residual-risk.md](docs/residual-risk.md) are documented, not secret: prompt injection is not solved, a local admin can uninstall Fairlead, and tool calls that never reach a hook are not seen. Reports that restate those limits are welcome as ordinary issues, not as vulnerabilities.

## Supported versions

Only the latest commit on `main`.
