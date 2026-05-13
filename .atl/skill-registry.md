# Skill Registry — ia-seguridad

> Generated: 2026-05-12

## Project Context

| Property | Value |
|----------|-------|
| **Project** | ia-seguridad |
| **Description** | Browser extension that detects phishing in Gmail using Gemini AI + MCP |
| **Delivery Deadline** | 19 de Mayo 2026 (7 días) |

## Detected Stack

| Category | Technology |
|----------|------------|
| **Backend** | Python (FastAPI) |
| **Frontend (Extension)** | JavaScript/TypeScript (Chrome Extension MV3) |
| **AI** | Google Gemini 1.5 Flash (free tier) |
| **APIs** | Gmail API, Google Safe Browsing API |
| **Protocol** | MCP (Model Context Protocol) |
| **Auth** | OAuth 2.0 (Gmail API) |
| **Persistence** | engram (Engram MCP only) |

## Testing Capabilities

| Capability | Status |
|------------|--------|
| Test Runner | Not detected |
| Coverage | N/A |
| Linter | N/A |
| Type Checker | N/A |
| Formatter | N/A |

## SDD Configuration

| Setting | Value |
|---------|-------|
| **Strict TDD** | false (no test framework) |
| **Persistence Mode** | engram |
| **openspec** | Not used |

## Available Skills

- `sdd-explore` — Explore SDD ideas before committing to a change
- `sdd-propose` — Create an SDD change proposal with intent, scope, and approach
- `sdd-spec` — Write SDD delta specs with requirements and scenarios
- `sdd-design` — Create the SDD technical design and architecture approach
- `sdd-tasks` — Break an SDD change into implementation tasks
- `sdd-apply` — Implement SDD tasks from specs and design
- `sdd-verify` — Execute tests and prove implementation matches specs
- `sdd-archive` — Archive a completed SDD change by syncing delta specs

## Next Steps

1. Run `/sdd-explore` to start exploring the first change
2. Define initial features to prototype (phishing detection logic, Gmail integration, etc.)
3. Set up the FastAPI backend and Chrome Extension skeleton