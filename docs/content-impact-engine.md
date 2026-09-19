# Safety360 Content Impact Engine

This staged foundation links governed learning/content packs to regulatory and industry change signals without silently changing approved operational content.

## Purpose

The engine answers a simple control question: when a source, requirement, activity or industry template changes, which governed Safety360 content needs review?

It deliberately separates **impact detection** from **operational approval**. Detection may be automated; approval and release of HSE/legal/quality/security-critical content remains a qualified human decision.

## Generic dependency graph

Supported dependency kinds:

- `regulatory_requirement`
- `regulatory_source`
- `industry_activity_template`
- `industry_classification`
- `compliance_subject`
- `manual_reference`

A dependency links a tenant-owned `LearningContentPack` to a referenced source object or stable external key. The record stores the referenced version/hash observed at link time when available.

## Impact workflow

1. A regulated source, requirement, activity template or manual dependency changes.
2. An impact scan compares the current dependency state with the last observed state.
3. A `ContentImpactAssessment` is created or updated for the affected content pack.
4. The content pack is marked `review_required`; approved artifacts are not overwritten.
5. A qualified reviewer can resolve the impact after creating/reviewing a new pack revision.

## Safety and governance

- Tenant isolation applies to all impact records.
- Cross-tenant learning or dependency leakage is not permitted.
- The engine records rationale, source identifiers, observed hashes and audit events.
- No legal conclusion is made solely from string matching.
- No approved artifact is auto-released after a regulatory change.
- Generated replacement material remains a draft until reviewed.
- This public-repository implementation is intentionally generic; proprietary Safety360 prioritization/scoring logic is excluded.
