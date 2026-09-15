# Agent Skills Repository

Curated collection of production-grade skills, security baselines, and execution protocols for autonomous AI coding agents (Claude Code, PI-Desktop, Cursor, Windsurf, Roo Code).

## Overview

AI coding agents need explicit, enforceable boundaries to avoid generating security debt or compromising production architectures. This repository provides modular, standardized agent skills structured for progressive disclosure:
- **Metadata**: Rapid intent matching and trigger evaluation via frontmatter.
- **SKILL.md**: Operational workflows, enforceable rules, and pull-request gates.
- **Bundled Resources**: Zero-dependency automation scripts (`scripts/`) and full technical references (`references/`).

---

## Available Skills

### [Universal Security Baseline](universal-security-baseline/SKILL.md)
Deterministic security controls and pull-request gatekeeper mapping across:
- **ISO/IEC 27001:2022**: Environment separation, least-privilege datastore access, immutable migrations.
- **NIST CSF 2.0**: Sanitized error boundaries, outbound timeouts/circuit breaking, fail-closed defaults.
- **OWASP**: Query parameterization, boundary DTO validation, constant-time equality, secure session lifecycle.
- **MITRE ATT&CK**: Structured audit logs (T1070/T1562), credential masking (T1552), abuse telemetry (T1110).
- **Security Engineering**: Modern crypto primitives (AEAD, Argon2id, Ed25519), secrets lifecycle, non-root container isolation.

Includes automated scanner: `universal-security-baseline/scripts/check_baseline.py`.

---

## Quick Start

### 1. Register Skill with Agent
Point your agent environment or skill registry to the skill directory:
```bash
# Example invocation via Claude Code / PI-Desktop
Skill(id="universal-security-baseline")
```

Or inject `SKILL.md` directly into the system prompt or agent rules file (`CLAUDE.md`, `.cursorrules`, etc.).

### 2. Run Automated Verification Tool
Run the zero-dependency Python 3 scanner against any target codebase:
```bash
# Human-readable report
python universal-security-baseline/scripts/check_baseline.py path/to/project

# Structured JSON for CI/CD or Agent ingestion
python universal-security-baseline/scripts/check_baseline.py path/to/project --json
```

---

## Repository Structure

```
.
├── README.md
└── <skill-name>/
    ├── SKILL.md          # Primary entry point & agent instructions (<500 lines)
    ├── references/       # In-depth standards and architecture references
    ├── scripts/          # Deterministic execution & verification tools
    └── evals/            # Test prompts and validation benchmarks
```

---

## Contributing

Skills added to this repository must:
1. Include valid YAML frontmatter (`name`, `description`).
2. Keep `SKILL.md` under 500 lines; move dense specs to `references/`.
3. Provide actionable, testable checks (`DO`, `DO NOT`, and verification heuristics).
4. Supply zero-dependency automation scripts for repetitive tasks in `scripts/`.

---

## License

MIT
