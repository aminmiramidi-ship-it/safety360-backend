# Safety360 Adaptive Autopilot – Learning Architecture

Self-learning and adaptability are permanent Safety360 architecture requirements. They are not optional add-ons and must remain intact as the product evolves.

## Core principle

Safety360 should improve from verified usage outcomes, review feedback, workflow results, incidents, audit findings, user corrections, CI/security results and operational telemetry. Learning must be controlled, explainable, reversible and tenant-safe.

Safety360 must **not** equate self-learning with uncontrolled model retraining. The preferred architecture is governed adaptive intelligence:

1. observe,
2. measure,
3. learn from verified outcomes,
4. propose or stage an adaptation,
5. validate against safety/security/compliance constraints,
6. deploy only within the permitted autonomy level,
7. monitor the result,
8. retain, refine or roll back.

## Invariant guardrails

These rules outrank optimization and must not be weakened by adaptive behavior:

- tenant isolation,
- least privilege,
- human approval for material HSE/legal/security/compliance decisions,
- controlled-document approval rules,
- traceability and auditability,
- data minimization and privacy,
- secure handling of secrets and credentials,
- no autonomous payment or commercial commitment,
- no autonomous production permission escalation,
- no copying of protected standards text,
- no external processing of sensitive tenant content without approved policy,
- no silent change to legal or standards interpretation.

## What the Autopilot should learn

The Autopilot may progressively adapt:

- task prioritization,
- recommended next steps,
- workflow defaults,
- field suggestions,
- activity and hazard prompts,
- document templates,
- training recommendations,
- search/retrieval ranking,
- terminology preferences,
- translation glossary choices,
- module navigation and UI assistance,
- CI/remediation heuristics,
- recurring customer workflow patterns,
- sector-specific and site-specific context,
- frequency of reminders and review prompts,
- which proposals tend to be accepted, rejected or corrected,
- which checks catch real defects versus low-value noise.

## Tenant-aware adaptation

Adaptive behavior should support separate layers:

### Global product learning

Uses non-sensitive, validated engineering outcomes such as test results, security findings, performance regressions, generic workflow success metrics and reviewed product improvements.

### Tenant learning

Uses tenant-specific approved context such as terminology, workflow preferences, role structure, site structure, accepted templates and recurring activities. Tenant learning must never leak into another tenant.

### User preference learning

May remember non-sensitive usability preferences such as language, presentation preferences, frequently used modules and safe workflow defaults. Sensitive profiling is excluded.

## Learning records

Every meaningful adaptation should be traceable with at least:

- observation/event,
- scope: global / tenant / user,
- source,
- hypothesis,
- proposed adaptation,
- expected benefit,
- risk level,
- validation method,
- baseline metric,
- post-change metric,
- reviewer/approval status where required,
- resulting decision: retain / refine / rollback,
- timestamp and version.

## Evaluation loop

The Autopilot should continuously evaluate itself against measurable criteria such as:

- fewer repeated user inputs,
- fewer workflow errors,
- lower rework rate,
- shorter cycle time,
- higher completion rate,
- higher document/evidence completeness,
- fewer security regressions,
- fewer failed CI runs,
- fewer rejected AI suggestions,
- better translation consistency,
- lower number of overdue actions,
- higher effectiveness-check completion,
- reduced false-positive recommendations.

Safety-critical quality must never be traded for speed or convenience.

## Safe adaptation levels

### Level 1 – automatic and low risk

Examples:

- ranking suggestions,
- reordering UI shortcuts,
- proposing defaults,
- improving search ranking,
- suppressing duplicate low-value alerts,
- fixing deterministic CI formatting/lint failures on feature branches.

### Level 2 – automatic staging, human review before release

Examples:

- changing templates,
- changing workflow logic,
- changing risk prompts,
- changing translated terminology,
- modifying tenant role defaults,
- altering AI system instructions,
- changing compliance mapping logic.

### Level 3 – human decision always required

Examples:

- approving a risk assessment,
- approving a controlled operating instruction,
- legal interpretation,
- standards conformity claims,
- production access/privilege elevation,
- deletion/retention exceptions,
- payment activation,
- external disclosure of sensitive data,
- emergency/safety decisions with material consequences.

## Rollback requirement

Every adaptive rule, prompt, model configuration or workflow change must be versioned. If post-change metrics deteriorate, new errors appear, tenant isolation is threatened, security controls weaken or review feedback is materially negative, Safety360 must revert to the last verified safe version or flag the change for human review.

## Knowledge freshness

Learning must distinguish between:

- stable internal knowledge,
- tenant-specific knowledge,
- externally changing information,
- legal/regulatory sources,
- standards metadata,
- security advisories,
- dependency and platform updates.

Time-sensitive knowledge must be refreshed from authoritative sources and must not be treated as permanently true merely because it appeared in an earlier run.

## Required future implementation components

- persistent Autopilot observation store,
- adaptation/experiment registry,
- feedback events,
- outcome metrics,
- versioned policy/heuristic store,
- tenant-specific preference and terminology store,
- evaluation jobs,
- regression detection,
- rollback mechanism,
- governance dashboard showing what changed, why and with what result,
- human review queue for medium/high-risk adaptations.

## Product requirement

Any future Safety360 architecture, refactor, deployment model, mobile app, AI provider, standards module or commercial feature must preserve this adaptive-learning architecture. Removing or bypassing the governed learning loop is considered an architectural regression and should be caught by product review and the Safety360 Autopilot itself.
