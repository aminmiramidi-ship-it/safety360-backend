from legal_baseline_api import LEGAL_INSTRUMENTS, SOURCE_DEFINITIONS


def test_legal_baseline_has_unique_keys_and_core_domains():
    keys = [str(item["key"]) for item in LEGAL_INSTRUMENTS]
    assert len(keys) == len(set(keys))

    domains = {str(item["domain"]) for item in LEGAL_INSTRUMENTS}
    assert {
        "occupational_safety",
        "occupational_health",
        "environment",
        "energy",
        "climate",
        "sustainability",
        "management_system",
    }.issubset(domains)


def test_german_hse_core_is_present():
    keys = {str(item["key"]) for item in LEGAL_INSTRUMENTS}
    assert {
        "de-arbschg",
        "de-asig",
        "de-arbst-ttv",
        "de-betrsichv",
        "de-gefstoffv",
        "de-biostoffv",
        "de-arbmedvv",
        "de-baustellv",
        "de-muschg",
        "de-jarbschg",
        "de-arbzg",
        "de-sgb-vii",
    }.issubset(keys)


def test_baua_rule_families_are_present():
    keys = {str(item["key"]) for item in LEGAL_INSTRUMENTS}
    assert {
        "de-asr-family",
        "de-trbs-family",
        "de-trgs-family",
        "de-trba-family",
        "de-rab-family",
        "de-trlv-family",
        "de-tros-family",
        "de-tremf-family",
    }.issubset(keys)


def test_environment_energy_and_sustainability_core_is_present():
    keys = {str(item["key"]) for item in LEGAL_INSTRUMENTS}
    assert {
        "de-bimschg",
        "de-krwg",
        "de-whg",
        "de-awsv",
        "de-bbodschg",
        "de-ksg",
        "de-tehg",
        "de-enefg",
        "de-edl-g",
        "de-geg",
        "de-lksg",
        "eu-csrd-2022-2464",
        "eu-esrs-2023-2772",
        "eu-taxonomy-2020-852",
        "eu-csddd-2024-1760",
    }.issubset(keys)


def test_management_system_metadata_is_present_without_full_norm_text():
    systems = {
        str(item.get("management_system"))
        for item in LEGAL_INSTRUMENTS
        if item.get("management_system")
    }
    assert {
        "ISO 45001",
        "ISO 14001",
        "ISO 50001",
        "ISO 9001",
        "ISO/IEC 27001",
        "EN 50600",
    }.issubset(systems)

    for item in LEGAL_INSTRUMENTS:
        if item.get("management_system"):
            assert item["source_key"] == "iso-catalogue"
            assert "lizenz" in str(item["applicability_hint"]).lower()


def test_every_instrument_has_source_and_applicability_metadata():
    for item in LEGAL_INSTRUMENTS:
        assert item["source_key"] in SOURCE_DEFINITIONS
        assert str(item["url"]).startswith("https://")
        assert str(item["title"]).strip()
        assert str(item["domain"]).strip()
        assert str(item["jurisdiction"]).strip()
        assert str(item["legal_level"]).strip()
        assert str(item["applicability_hint"]).strip()
