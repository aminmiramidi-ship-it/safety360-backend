# Safety360 Market Readiness Control Matrix

This document is the living release-control matrix for Safety360. It is intentionally conservative: a feature is not considered production-ready merely because code exists. Production readiness requires implementation, automated validation, operational controls and documented ownership.

## Release principles

- Multi-tenant isolation is mandatory for every tenant-owned object.
- Security, HSE, legal, standards and payment decisions keep a human approval point where consequences are material.
- Production data is never reset to solve schema problems; Alembic migrations are required.
- Secrets, tokens, payment credentials and customer data are never committed to source control.
- Safety360 does not store raw payment-card or bank-authentication data.
- ISO/EN references are metadata and implementation mappings; licensed/current standards remain authoritative.
- Machine-generated or machine-translated critical content remains reviewable and auditable.
- No component is described as certified, bank-compliant or authority-compliant solely because a control exists in code.

## Current platform foundation

| Area | Current state | Release gate |
| --- | --- | --- |
| Authentication | JWT/bcrypt foundation | Add production session lifecycle, recovery, verification, MFA/SSO options and revocation |
| Tenant isolation | Tenant-scoped core models/APIs | Add systematic cross-tenant tests and production DB isolation hardening |
| RBAC | Role/permission matrix | Move toward configurable least-privilege roles and separation-of-duties controls |
| Document control | Draft/review/approve/revision workflow | Add distribution, acknowledgement, retention, supersession and controlled templates |
| File repository | Tenant paths, SHA-256, archive | Add quarantine/malware scanning, object-storage adapter, retention and backup verification |
| IMS orchestration | Activity -> generated draft artifacts | Add structured risk scoring, measure ownership, training assignments, audit/review linkage |
| AI assistant | Provider-neutral rules/local/external adapter | Add governed RAG, citations/provenance, prompt security, redaction and tenant-safe retrieval |
| Translation | Provider-neutral BCP-47 API | Add glossary/terminology governance, translation records, approval/version linkage and broader UI key coverage |
| Billing | Trial/professional/enterprise model | Add PCI-compliant PSP adapter, signed webhooks, entitlement enforcement and invoicing/tax workflow |
| Web app | React/Vite | Complete accessibility, localization, end-to-end tests, CSP and production telemetry |
| Installable app | PWA branch | Validate offline policy, install/update behavior, device storage and later native wrapper/signing |
| CI/security | Compile, lint, tests, migrations, Bandit, pip-audit | Add SBOM, secret scan, container scan, SAST expansion and release provenance |

## Enterprise/security track

### Identity and access

- [ ] E-mail verification and secure password-reset workflow
- [ ] Refresh/session rotation and explicit logout/revocation
- [ ] MFA support
- [ ] OIDC/SAML SSO adapter for enterprise customers
- [ ] Service accounts/API keys with scoped permissions and rotation
- [ ] Configurable tenant roles and separation of duties
- [ ] Privileged-operation re-authentication where appropriate

### Data protection

- [ ] PostgreSQL production baseline and hardened connection/TLS settings
- [ ] Tenant isolation tests for every tenant-owned resource
- [ ] Evaluate PostgreSQL Row Level Security as defense in depth
- [ ] Encryption-key rotation strategy and KMS/HSM adapter
- [ ] Object storage with server-side encryption and tenant-aware keys/prefixes
- [ ] Backup/restore automation and regular restore tests
- [ ] Retention, legal hold, deletion and export workflows
- [ ] EU/data-residency deployment profiles

### Application and supply-chain security

- [ ] Request rate limiting and abuse controls
- [ ] Content Security Policy for the web application
- [ ] File quarantine and malware scan before release/download
- [ ] MIME/magic-byte validation in addition to filename checks
- [ ] SBOM generation and release artifacts
- [ ] Secret scanning and dependency update automation
- [ ] Container/image scanning for containerized deployments
- [ ] Security event logging and alerting
- [ ] Penetration test before commercial production release
- [ ] Incident-response runbook and security-contact process

## IMS/HSE automation track

- [x] Tenant-scoped activity descriptions
- [x] Draft risk-assessment generation
- [x] Draft operating-instruction generation
- [x] Draft training-plan generation
- [x] High-level IMS requirements mapping
- [x] Human-review gate for generated artifacts
- [ ] Structured hazard library by activity/industry/equipment/substance
- [ ] Configurable risk matrix and residual-risk workflow
- [ ] STOP hierarchy and measure effectiveness tracking
- [ ] Generated controlled documents linked into document control
- [ ] Training assignments, competence checks, expiry and refresh cycles
- [ ] Audit findings linked to actions, risks and documents
- [ ] Management-review inputs generated from verified KPIs/findings/actions
- [ ] Environmental aspects/impacts register
- [ ] Energy review, SEUs, EnPIs and objectives/actions
- [ ] Quality process/risk/nonconformity/CAPA linkage
- [ ] Information-security risk/control/evidence linkage
- [ ] Data-center asset, availability, maintenance and operational evidence linkage

## Standards architecture

Initial registry coverage:

- ISO 45001
- ISO 14001
- ISO 50001
- ISO 9001
- ISO/IEC 27001
- EN 50600

The registry must remain extensible. Safety360 stores references, customer mappings, implementation evidence and verification metadata rather than copying protected standards text.

Required next controls:

- [ ] Standards registry stored as versioned data, not hard-coded only
- [ ] Source/version/effective-date metadata
- [ ] Requirement-to-control-to-evidence graph
- [ ] Customer scope/applicability decisions with reason and approver
- [ ] Change-impact workflow when a referenced source changes
- [ ] Evidence completeness dashboard

## Multilingual track

- [x] i18n framework in the frontend
- [x] German/English/Turkish/Persian/Arabic starter UI resources
- [x] RTL document direction support
- [x] BCP-47 language handling in backend translation API
- [x] Local LibreTranslate-compatible and OpenAI-compatible adapter design
- [x] External processing opt-in only
- [x] Human-review flag for critical translations
- [ ] Move all legacy UI strings to translation keys
- [ ] Per-tenant terminology/glossary
- [ ] Store source language, target language, provider/model and review status for translated controlled content
- [ ] Translation version invalidation when source document changes
- [ ] Locale-aware dates, numbers, units and pluralization
- [ ] Accessibility validation for LTR/RTL layouts

## Commercial track

- [x] Trial/professional/enterprise entitlement model foundation
- [ ] Final product packaging and feature entitlements
- [ ] Payment service provider adapter using hosted checkout/tokenization
- [ ] Webhook signature/idempotency/replay protection
- [ ] Subscription lifecycle and grace-period rules
- [ ] Invoice/tax/VAT process appropriate to operating entity and markets
- [ ] Customer onboarding, DPA/AVV and contractual security documentation
- [ ] Support/SLA model
- [ ] Data export and offboarding to prevent lock-in and support customer trust

## Web/PWA/native application track

- [x] Responsive React/Vite web foundation
- [x] Installable PWA configuration
- [x] PWA static application-shell caching only
- [ ] Full UI localization coverage
- [ ] Automated browser/end-to-end tests
- [ ] Offline classification: define which HSE actions may be safely performed offline
- [ ] Encrypted local/offline data policy
- [ ] Conflict resolution for offline edits
- [ ] Push notification architecture
- [ ] Native wrapper evaluation after web/PWA security baseline is stable
- [ ] Android/iOS signing, store privacy declarations and release process before store launch

## Production go-live gates

Commercial production must not be declared ready until at least:

1. Backend CI and security checks are green for the release commit.
2. Frontend build/audit and end-to-end critical-path tests are green.
3. Production PostgreSQL migrations have been tested from a production-like prior version.
4. Backup and restore have been demonstrated.
5. Tenant-isolation tests cover all tenant data paths.
6. File malware/quarantine controls are active for user uploads.
7. Production secrets are managed outside source control and rotation is documented.
8. Authentication recovery, session revocation and MFA/SSO strategy are implemented for the intended customer tier.
9. Logging/monitoring/alerting and incident response are operational.
10. Privacy, retention/deletion, export/offboarding and contractual documentation are available.
11. Critical AI/translation workflows preserve provenance, human approval and audit records.
12. A security review and penetration test have been completed before serving high-assurance customers.

The Safety360 Autopilot should use this matrix as a living backlog: close high-risk gaps first, update implementation/tests/documentation together and avoid marking a gate complete without verifiable evidence.
