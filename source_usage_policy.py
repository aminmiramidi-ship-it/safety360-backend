from dataclasses import dataclass
from typing import Final


class SourceUsageDenied(RuntimeError):
    """Raised when an automated source operation is not permitted by policy."""


@dataclass(frozen=True)
class SourceUsagePolicy:
    source_key: str
    display_name: str
    terms_url: str
    allowed_operations: frozenset[str]
    blocked_operations: frozenset[str]
    rights_confirmation_required: frozenset[str]
    notes: str


DGUV_PUBLICATIONS_POLICY: Final[SourceUsagePolicy] = SourceUsagePolicy(
    source_key="dguv-publications",
    display_name="DGUV Publikationsdatenbank / Vorschriften- und Regelwerk",
    terms_url="https://publikationen.dguv.de/nutzungsbestimmungen",
    allowed_operations=frozenset(
        {
            "manual_reference_entry",
            "user_authorized_upload",
            "licensed_feed_ingest",
            "store_minimal_reference_metadata",
            "link_to_official_source",
        }
    ),
    blocked_operations=frozenset(
        {
            "automated_content_scrape",
            "automated_pdf_fetch_for_ai",
            "text_data_mining",
            "model_training",
            "commercial_republication",
        }
    ),
    rights_confirmation_required=frozenset(
        {
            "automated_metadata_sync",
            "automated_change_monitoring",
            "bulk_catalog_ingest",
            "content_ingest",
            "semantic_indexing",
        }
    ),
    notes=(
        "DGUV-Nutzungsbedingungen schützen Inhalte urheberrechtlich und untersagen unter anderem "
        "KI-/TDM-Auslesung sowie kommerzielle Nutzung ohne entsprechende Erlaubnis. Safety360 darf "
        "deshalb keine DGUV-Inhalte automatisiert scrapen, PDFs für KI-Auswertung herunterladen oder "
        "Volltexte kommerziell replizieren. Zulässig sind nur rechtmäßig bereitgestellte bzw. vom Kunden "
        "autorisiert hochgeladene Inhalte, lizenzierte Datenfeeds und minimale Referenzmetadaten aus einer "
        "rechtlich zulässigen Quelle."
    ),
)


SOURCE_POLICIES: Final[dict[str, SourceUsagePolicy]] = {
    DGUV_PUBLICATIONS_POLICY.source_key: DGUV_PUBLICATIONS_POLICY,
}


def get_source_policy(source_key: str) -> SourceUsagePolicy | None:
    return SOURCE_POLICIES.get(source_key.strip().lower())


def assert_source_operation_allowed(
    source_key: str,
    operation: str,
    *,
    rights_confirmed: bool = False,
) -> None:
    policy = get_source_policy(source_key)
    if policy is None:
        return

    normalized_operation = operation.strip().lower()

    if normalized_operation in policy.blocked_operations:
        raise SourceUsageDenied(
            f"Operation '{normalized_operation}' ist für Quelle '{policy.display_name}' durch "
            "Safety360-Quellenrichtlinie gesperrt."
        )

    if normalized_operation in policy.rights_confirmation_required and not rights_confirmed:
        raise SourceUsageDenied(
            f"Operation '{normalized_operation}' erfordert vor Ausführung eine dokumentierte "
            f"Nutzungs-/Lizenzfreigabe für '{policy.display_name}'."
        )

    if (
        normalized_operation not in policy.allowed_operations
        and normalized_operation not in policy.rights_confirmation_required
    ):
        raise SourceUsageDenied(
            f"Operation '{normalized_operation}' ist für Quelle '{policy.display_name}' nicht freigegeben."
        )
