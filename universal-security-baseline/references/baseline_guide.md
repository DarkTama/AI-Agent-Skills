# Universal Security Baseline Guide
**Standards: ISO/IEC 27001, NIST CSF 2.0, OWASP, MITRE ATT&CK, Security Engineering**  
*Audience: Software Engineers and Autonomous AI Code Agents*

---

## Agent Usage Instructions
When auditing or generating code:
1. Every rule is actionable and testable.
2. Flag any code containing anti-patterns listed in **DO NOT**.
3. Run the **Agent Verification Check** heuristic before approving pull requests or committing code.

---

## 1. ISO/IEC 27001:2022 — Governance & Environment Controls

### SEC-ISO-01: Environment Configuration Segregation
* **Statement:** Runtime configuration, credentials, and network topologies must be loaded from execution environment, never embedded in application binaries or repository source code.
* **DO:**
  * Inject environment-specific configs via standard environment variables or externalized configuration servers.
  * Maintain clean separation between `development`, `staging`, and `production` runtime states.
* **DO NOT:**
  * Hardcode environment-specific flags, IP addresses, or secrets inside code files or committed config profiles.
  * Fall back to production credentials in development mode.
* **Rationale:** Prevents credential leakage across security perimeters and inadvertent actions against production datastores during development.
* **Agent Verification Check:**
  * Search for hardcoded credentials, connection strings, or production hostnames in source tree (`grep -rnE "(password|secret|apikey|token)\s*=\s*['\"][^'\"]{4,}['\"]" .`).

---

### SEC-ISO-02: Least-Privilege Datastore Access
* **Statement:** Application runtime database connections must operate strictly with Data Manipulation Language (DML) rights only.
* **DO:**
  * Restrict application service user permissions to `SELECT`, `INSERT`, `UPDATE`, `DELETE`.
  * Use separate, restricted migration credentials for schema modifications.
* **DO NOT:**
  * Run application services using `root`, `sa`, `postgres` superuser, or `DBA` roles.
  * Grant `DROP`, `ALTER`, `CREATE`, or `TRUNCATE` privileges to the standard runtime user.
* **Rationale:** Mitigates impact of SQL injection vulnerabilities by preventing attackers from dropping tables, modifying database schemas, or reading administrative metadata.
* **Agent Verification Check:**
  * Verify database permission manifests / migration scripts show separate roles for application runtime vs schema migration.

---

### SEC-ISO-03: Immutable & Version-Controlled Schema Migrations
* **Statement:** Database schema modifications must occur exclusively via deterministic, versioned, code-reviewed migration scripts executed in controlled pipelines.
* **DO:**
  * Use explicit migration tools (e.g., Flyway, Liquibase, Prisma Migrate, Alembic, Goose) with incremental versioning.
  * Validate that every schema migration runs inside transactions where supported.
* **DO NOT:**
  * Allow ORMs to auto-generate or mutate production schemas at application startup (e.g., `ddl-auto: update`, Hibernate schema export, raw unversioned sync).
* **Rationale:** Eliminates race conditions, partial schema state corruption, and unreviewed structural database changes across deployments.
* **Agent Verification Check:**
  * Check configuration files for disabled auto-DDL flags (`ddl-auto: none` or `ddl-auto: validate` in ORMs).

---

## 2. NIST CSF 2.0 — Cyber Operations & Resilience

### SEC-NIST-01: Centralized Error Masking & Safe Exception Boundaries
* **Statement:** Unhandled exceptions must be intercepted at the application boundary; internal system details must never be exposed to consumers.
* **DO:**
  * Implement global exception filters/middleware returning standardized, sanitized client error formats (e.g., RFC 7807 Problem Details).
  * Generate opaque unique Incident/Trace IDs returned to the client and linked to internal logs.
* **DO NOT:**
  * Expose stack traces, internal paths, SQL query snippets, database table names, or third-party dependency names in HTTP responses or user-facing errors.
* **Rationale:** Deprives adversaries of reconnaissance data regarding framework versions, file paths, and database structures.
* **Agent Verification Check:**
  * Trigger mock exceptions in integration tests; verify response body contains only sanitized error message and correlation ID, without stack trace elements.

---

### SEC-NIST-02: Outbound Fault Isolation & Circuit Breaking
* **Statement:** All external network calls must enforce strict timeouts, retry caps, and circuit-breaker isolation.
* **DO:**
  * Set explicit connect and read timeouts (maximum 3–5 seconds for standard synchronous requests).
  * Wrap remote calls in circuit breakers with defined fallback responses.
  * Use exponential backoff with jitter on retries.
* **DO NOT:**
  * Make unbounded HTTP or socket calls without timeout configurations.
  * Use infinite retry loops or blocking threads on degraded third-party systems.
* **Rationale:** Prevents cascade failures and resource exhaustion (thread/socket pool starvation) when external services fail or undergo DDoS attacks.
* **Agent Verification Check:**
  * Inspect outbound HTTP/RPC client initialization; flag any client instance missing connect/read timeout configurations.

---

### SEC-NIST-03: Fail-Closed Default Access State
* **Statement:** System components must reject operations by default whenever an error, unknown state, or authorization failure occurs.
* **DO:**
  * Default access-control checks to deny (`return false` / throw unauthorized).
  * Require explicit affirmative authorization checks to grant execution rights.
* **DO NOT:**
  * Allow operations to continue if authentication provider is unreachable or returns ambiguous status.
  * Write access gates where uncaught exceptions bypass security checks (`catch { return true; }`).
* **Rationale:** Guarantees that system failures downgrade to reduced availability rather than unauthorized privilege escalation.
* **Agent Verification Check:**
  * Verify security boundary code: ensure catch blocks on auth checks explicitly return unauthorized/deny.

---

## 3. OWASP — Application Security & Interface Defenses

### SEC-OWASP-01: Universal Query & Command Parameterization
* **Statement:** All dynamic database queries, shell executions, and directory lookups must use parameterized APIs or safe typed wrappers.
* **DO:**
  * Use parameterized queries (prepared statements, ORM parameter binders) for all SQL, NoSQL, and LDAP operations.
  * Pass arguments to child processes as typed array elements, never raw string interpolation in a shell context.
* **DO NOT:**
  * Concatenate strings or format strings using user input to construct queries (`"SELECT * FROM users WHERE id = '" + id + "'"`).
  * Pass user-controlled strings into raw shell evaluators (`exec`, `system`, `sh -c`, `cmd.exe /c`).
* **Rationale:** Completely eliminates SQL injection (SQLi), Command Injection, and NoSQL injection attack vectors.
* **Agent Verification Check:**
  * Scan codebase for string concatenation inside query or command execution contexts (`grep -rnE "(executeQuery|raw|nativeQuery|exec|spawn)\s*\(.*(\+|format|\$\{)" .`).

---

### SEC-OWASP-02: Strict Boundary Schema Validation
* **Statement:** Every untrusted external input must be validated against a strict, explicit schema before ingestion into business logic.
* **DO:**
  * Define strict Data Transfer Object (DTO) validation rules (type, format, length limits, allowed character set).
  * Strip or reject unexpected fields (reject mass-assignment).
* **DO NOT:**
  * Pass raw HTTP request bodies or query params directly to domain services or database entities.
  * Rely solely on client-side frontend validation.
* **Rationale:** Stops mass-assignment, payload tampering, buffer/resource exhaustion, and invalid state transitions.
* **Agent Verification Check:**
  * Check controller / handler methods: ensure every incoming payload is bound to an explicit schema/validator before consumption.

---

### SEC-OWASP-03: Constant-Time Sensitive Data Comparison
* **Statement:** Verification of sensitive data (hashes, passwords, HMACs, security tokens, API keys) must execute in constant time.
* **DO:**
  * Use standard library constant-time equality functions (e.g., `MessageDigest.isEqual`, `crypto.timingSafeEqual`, `subtle.timingSafeEqual`).
* **DO NOT:**
  * Use standard short-circuit string equality operators (`==`, `===`, `.equals()`) to check HMACs, signatures, or secret tokens.
* **Rationale:** Prevents side-channel timing attacks that allow attackers to deduce cryptographic tokens byte-by-byte by measuring response times.
* **Agent Verification Check:**
  * Search for token or hash equality checks: flag any usage of standard `.equals()` or `===` comparing API keys, signatures, or auth tokens.

---

### SEC-OWASP-04: Secure Session & Token Lifecycle
* **Statement:** Authentication tokens and session identifiers must be cryptographically random, transmitted securely, and strictly bounded by time.
* **DO:**
  * Use minimum 128-bit cryptographically secure pseudorandom numbers (CSPRNG) for session tokens.
  * Set `HttpOnly`, `Secure`, and `SameSite=Strict|Lax` flags on session cookies.
  * Enforce short lifespan for access tokens (e.g., 15 minutes) with revocable refresh tokens.
* **DO NOT:**
  * Store sensitive authentication tokens in browser `localStorage` or `sessionStorage` (vulnerable to XSS).
  * Allow infinite session validity or reuse tokens after logout/password change.
* **Rationale:** Defends against session hijacking, Cross-Site Scripting (XSS) token theft, and Cross-Site Request Forgery (CSRF).
* **Agent Verification Check:**
  * Check cookie creation configs: verify `httpOnly: true`, `secure: true`, and valid `sameSite` settings are present.

---

## 4. MITRE ATT&CK — Adversary Telemetry & Detection

### SEC-MITRE-01: Immutable Structured Security Audit Logging
* **Statement:** Security-relevant actions must generate structured, non-repudiable audit logs written to append-only destinations.
* **DO:**
  * Log security lifecycle events: login successes/failures, password resets, role changes, privilege escalations, critical data export/delete.
  * Include standardized fields: `timestamp` (ISO 8601 UTC), `event_type`, `actor_id`, `target_resource`, `action`, `status`, `source_ip`, `user_agent`, `correlation_id`.
* **DO NOT:**
  * Allow user input to dictate log file names or log message formatting without encoding (prevent Log Injection / CRLF injection).
  * Allow application users or standard service accounts to modify or truncate historical audit logs.
* **Rationale:** Maps to MITRE T1070 (Indicator Removal on Host) and T1562 (Impair Defenses); ensures forensic traceability during and after an incident.
* **Agent Verification Check:**
  * Check auth and access-control endpoints: ensure every denial or authorization change invokes an audit logging call.

---

### SEC-MITRE-02: Sensitive Data Masking & Log Sanitization
* **Statement:** Logs and traces must never contain raw credentials, tokens, payment data, or sensitive PII.
* **DO:**
  * Implement centralized log interceptors/masks replacing values of sensitive fields (`password`, `authorization`, `token`, `cardNumber`, `ssn`) with `***MASKED***` or one-way cryptographic hashes.
* **DO NOT:**
  * Log full HTTP request/response headers or bodies blindly at `DEBUG` or `INFO` levels in production.
  * Print credentials or tokens in console output, standard out, or unencrypted text files.
* **Rationale:** Prevents credential harvesting (MITRE T1552) and inadvertent data breaches via third-party log aggregators or monitoring dashboards.
* **Agent Verification Check:**
  * Run pattern matches against log configuration and log statements: ensure sensitive key names are masked or explicitly excluded.

---

### SEC-MITRE-03: Abuse & Anomaly Telemetry
* **Statement:** Authentication, authorization, and rate-limited boundaries must emit real-time metrics for brute-force and probing detection.
* **DO:**
  * Export structured metric counters for HTTP `401 Unauthorized`, `403 Forbidden`, `429 Too Many Requests`.
  * Trigger alerting thresholds on sudden spikes in failed authentications or rapid resource enumeration.
* **DO NOT:**
  * Silently drop or handle failed authentication attempts without incrementing security metrics.
* **Rationale:** Detects adversary reconnaissance and credential stuffing attacks (MITRE T1110 - Brute Force).
* **Agent Verification Check:**
  * Ensure security interceptors emit metrics counters for all 401, 403, and 429 status transitions.

---

## 5. Security Engineering & Cryptography

### SEC-ENG-01: Cryptographic Primitive Selection
* **Statement:** Use exclusively industry-standard, modern cryptographic algorithms; zero proprietary or deprecated cryptography.
* **DO:**
  * Symmetric Encryption: **AES-256-GCM** or **ChaCha20-Poly1305** (Authenticated Encryption with Associated Data - AEAD). Generate fresh random nonce/IV for every encryption.
  * Password Hashing: **Argon2id** (preferred), **bcrypt** (cost factor >= 12), or **PBKDF2-HMAC-SHA256** (iterations >= 600,000).
  * Digital Signatures & Asymmetric: **Ed25519**, **ECDSA (P-256/P-384)**, or **RSA (>= 3072-bit)**.
  * Hash Functions: **SHA-256**, **SHA-384**, **SHA-512**, **BLAKE3**.
* **DO NOT:**
  * Use broken/deprecated algorithms: `MD5`, `SHA-1`, `DES`, `3DES`, `RC4`, `AES-ECB`.
  * Reuse an IV/nonce with the same key in AES-GCM.
* **Rationale:** Protects confidentiality and integrity against cryptanalysis, offline dictionary cracking, and replay attacks.
* **Agent Verification Check:**
  * Grep codebase for forbidden algorithm strings (`grep -rniE "(MD5|SHA1|DES|RC4|ECB)" .`). Flag all non-compliant hits.

---

### SEC-ENG-02: Secrets Ingestion & Storage Lifecycle
* **Statement:** Cryptographic keys, tokens, and database passwords must exist only in volatile memory or dedicated external key stores.
* **DO:**
  * Ingest secrets at startup via container secrets (e.g., mounted `tmpfs` RAM files), environment variables, or dedicated vaults (e.g., HashiCorp Vault, AWS Secrets Manager).
  * Clear plaintext sensitive byte arrays from memory immediately after use when language runtime permits.
* **DO NOT:**
  * Commit secret files (`.env`, `.pem`, `id_rsa`, `keystore.jks`) to git or image layers.
  * Store credentials unencrypted on local disks.
* **Rationale:** Eliminates static credential theft from code repositories, container image caches, and compromised disk snapshots.
* **Agent Verification Check:**
  * Check `.gitignore` contains `.env`, `*.pem`, `*.key`, `*.jks`, `credentials*`.
  * Ensure CI pipeline runs secret detection tools (e.g., Gitleaks, TruffleHog).

---

### SEC-ENG-03: Least-Privilege Process Execution Context
* **Statement:** Applications must execute as an unprivileged, isolated user on the host system or container runtime.
* **DO:**
  * Run containers with a non-root UID/GID (e.g., `USER 10001:10001`).
  * Mount root filesystem as read-only (`readOnlyRootFilesystem: true` in K8s / `--read-only` in Docker) with designated temporary write directories (`/tmp` on `tmpfs`).
* **DO NOT:**
  * Run application processes as `root` / `Administrator`.
  * Grant container `privileged: true` or broad host-level capabilities (`CAP_SYS_ADMIN`).
* **Rationale:** Prevents container breakout and limits damage if the application suffers remote code execution (RCE).
* **Agent Verification Check:**
  * Inspect `Dockerfile` or container manifests: verify `USER <non-root>` is set and root write permissions are disabled.

---

## Quick Reference Audit Checklist for AI Code Agents

| Check ID | Area | Condition to Block PR / Reject Code |
|---|---|---|
| `SEC-ISO-01` | Config | Hardcoded password, API key, token, or private IP string found in repo |
| `SEC-ISO-02` | Database | Application runs with DB admin / DDL rights in production config |
| `SEC-ISO-03` | Schema | Auto-DDL (`update`, `create`, `drop`) enabled in production config |
| `SEC-NIST-01` | Resilience | Raw exception stack trace returned directly in API response body |
| `SEC-NIST-02` | Outbound | HTTP or RPC client instantiated without explicit connect/read timeout |
| `SEC-NIST-03` | Defaults | Authorization failure catch block returns `true` or permits access |
| `SEC-OWASP-01` | Injection | SQL/Command query constructed via string concatenation |
| `SEC-OWASP-02` | Validation | Request body accepted directly into domain model without schema validation |
| `SEC-OWASP-03` | Crypto | Token, secret, or HMAC compared using `==` or `.equals()` instead of constant-time equal |
| `SEC-OWASP-04` | Session | Session cookie missing `HttpOnly`, `Secure`, or valid `SameSite` flags |
| `SEC-MITRE-01` | Audit | Auth login, role change, or security setting change lacks audit logging call |
| `SEC-MITRE-02` | Telemetry | Unmasked password, secret, or PAN written to logger |
| `SEC-MITRE-03` | Detection | 401/403/429 errors silently discarded without metric increment |
| `SEC-ENG-01` | Primitives | Deprecated crypto used (`MD5`, `SHA1`, `DES`, `AES-ECB`) or plain password hashing |
| `SEC-ENG-02` | Secrets | Secret files committed to VCS or embedded in Dockerfile layers |
| `SEC-ENG-03` | Runtime | Container runs as UID 0 / root without non-root directive |
