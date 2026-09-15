# Security

Only is intentionally an **inspection** tool, not a code runner.

- URL capture performs HTTP(S) GET requests and records the response plus basic network metadata.
- Repository capture uses a shallow clone with submodules disabled and inventories files. It never runs repository code, package managers, build tools, hooks, tests, or installers.
- The issue-triggered GitHub Action only runs for issues opened by the repository owner and only accepts public `http://` or `https://` targets; loopback, private, link-local and other non-global destinations are rejected, including redirects.
- Captured material is untrusted input. Do not open unknown binaries outside an appropriate sandbox.

If a target can attack parsers merely by being read, Only is not a security boundary. Run it inside an isolated environment when examining hostile material.
