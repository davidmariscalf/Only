# Connected repositories

Only keeps a small curated registry of external repositories in [`connected-repos.json`](../connected-repos.json).

They are connected as **untrusted reference sources**, not dependencies. The integration never installs their packages, executes their code, runs their tests, initializes their submodules, or grants them credentials. When captured, Only applies the same bounded repository acquisition policy described in the main README and records the exact observed commit and hashes.

## Why this exists

These repositories are useful discovery and reference sources for APIs, MCP servers, LLM applications, developer infrastructure, web extraction, agent workflows and coding-agent patterns. They can inform future work without weakening Only's central rule: untrusted content is data, never code.

## Current set

- `public-apis/public-apis` — public API catalog
- `punkpeye/awesome-mcp-servers` — MCP server catalog
- `Shubhamsaboo/awesome-llm-apps` — LLM, RAG and agent reference applications
- `sindresorhus/awesome` — broad curated technical indexes
- `D4Vinci/Scrapling` — web extraction reference implementation
- `ripienaar/free-for-dev` — developer free-tier catalog
- `langflow-ai/langflow` — agent, RAG and MCP workflow patterns
- `All-Hands-AI/OpenHands` — autonomous coding-agent architecture
- `msitarzewski/agency-agents` — specialized agent role and skill definitions

## Capture them

Use **Actions → Connected Repos Capture → Run workflow**. Each repository is captured independently in a matrix job and uploaded as its own evidence artifact with a manifest digest.

The workflow is manual by design. Merely adding a repository to the registry does not cause network access or code execution.

## Adoption rule

A useful idea found in a connected repository should be reviewed and selectively reimplemented or imported under its actual license and security constraints. Being present in this list is not an endorsement of correctness, safety, maintenance quality or license compatibility.
