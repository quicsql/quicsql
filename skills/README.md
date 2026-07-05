# Skills — for AI agents using quicSQL

These are [Agent Skills](https://docs.claude.com/en/docs/agents-and-tools/agent-skills/overview): task-scoped instructions that teach an AI agent how to **use** quicSQL (`quicsql.net`) correctly when building on it — connecting a client, deploying a server, or securing one. Each skill is a folder with a `SKILL.md` whose frontmatter `description` says when to load it; the agent reads the description, then pulls in the body when the task matches.

| Skill | Load it when the task is… |
|---|---|
| [`using-quicsql`](using-quicsql/SKILL.md) | connecting to a quicSQL server from Go — the client or the `database/sql` driver (start here) |
| [`deploying-a-server`](deploying-a-server/SKILL.md) | standing up or configuring a quicSQL server — config, the daemon, listeners, transports |
| [`databases-and-backends`](databases-and-backends/SKILL.md) | choosing/configuring a database — file, in-memory, or **vault (encryption + compression)** |
| [`auth-and-tls`](auth-and-tls/SKILL.md) | securing a server or presenting credentials — principals, grants, bearer/password/**mTLS**/keyring, **session tokens**, **device enrollment**, and **CORS** for browser apps |
| [`javascript-and-browser-clients`](javascript-and-browser-clients/SKILL.md) | building a **JavaScript/TypeScript or browser** app on quicSQL — the `@quicsql/client` SDK, session tokens, keyring auth, enrollment, and the live change feed |
| [`transactions-and-hrana`](transactions-and-hrana/SKILL.md) | interactive transactions or batching many statements over Hrana |
| [`liteorm-over-quicsql`](liteorm-over-quicsql/SKILL.md) | using an ORM (LiteORM) against a remote quicSQL database |
| [`operating-a-server`](operating-a-server/SKILL.md) | administering a running server — control plane, metrics, limits, sessions, **online backup / in-place restore**, WAL checkpoint, and the **change feed** |
| [`pitfalls`](pitfalls/SKILL.md) | debugging surprising behaviour, or before shipping |

## For maintainers

Skills ship to consumers and **go stale silently**. When a feature changes, update the matching skill in the same change — this is part of [`AGENTS.md`](../AGENTS.md)'s doc-update checklist. The human-facing equivalents are [`docs/`](../docs/) (narrative guides: getting-started, auth-and-authz, mtls-production, hrana, databases, change-feed, administration, and the [clients guides](../docs/clients/)) and the package docs on pkg.go.dev; skills reference those for depth rather than duplicating them.

To make these discoverable to a local Claude Code session, symlink them: `ln -s ../skills .claude/skills` (or copy the ones you want).
