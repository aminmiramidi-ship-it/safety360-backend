import pytest

from source_usage_policy import (
    DGUV_PUBLICATIONS_POLICY,
    SourceUsageDenied,
    assert_source_operation_allowed,
    get_source_policy,
)


def test_dguv_policy_is_registered():
    policy = get_source_policy("dguv-publications")
    assert policy == DGUV_PUBLICATIONS_POLICY
    assert "publikationen.dguv.de/nutzungsbestimmungen" in policy.terms_url


def test_dguv_automated_content_mining_is_blocked():
    for operation in (
        "automated_content_scrape",
        "automated_pdf_fetch_for_ai",
        "text_data_mining",
        "model_training",
        "commercial_republication",
    ):
        with pytest.raises(SourceUsageDenied):
            assert_source_operation_allowed("dguv-publications", operation)


def test_dguv_rights_gated_operations_require_confirmation():
    with pytest.raises(SourceUsageDenied):
        assert_source_operation_allowed(
            "dguv-publications",
            "automated_change_monitoring",
            rights_confirmed=False,
        )

    assert_source_operation_allowed(
        "dguv-publications",
        "automated_change_monitoring",
        rights_confirmed=True,
    )


def test_dguv_authorized_customer_upload_is_allowed():
    assert_source_operation_allowed("dguv-publications", "user_authorized_upload")


def test_unknown_operation_fails_closed_for_governed_source():
    with pytest.raises(SourceUsageDenied):
        assert_source_operation_allowed("dguv-publications", "some_future_operation")


def test_sources_without_specific_policy_are_not_blocked_here():
    assert_source_operation_allowed("some-other-source", "manual_reference_entry")
