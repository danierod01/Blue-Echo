import logging

from ioc_correlator.audit import audit, mask_token


def test_mask_token_hides_full_value():
    assert mask_token("supersecretotoken12345") == "supersec…"
    assert "supersecretotoken12345" not in mask_token("supersecretotoken12345")


def test_mask_token_empty_is_dash():
    assert mask_token("") == "-"
    assert mask_token(None) == "-"


def test_audit_emits_structured_record(caplog):
    caplog.set_level(logging.INFO, logger="blueecho.audit")
    audit("scan", ioc="1.2.3.4", verdict="clean", token="-")
    msgs = [r.getMessage() for r in caplog.records if r.name == "blueecho.audit"]
    assert any("event=scan" in m and "ioc=1.2.3.4" in m for m in msgs)


def test_audit_omits_none_fields(caplog):
    caplog.set_level(logging.INFO, logger="blueecho.audit")
    audit("auth_failed", token=None)
    msg = [r.getMessage() for r in caplog.records if r.name == "blueecho.audit"][-1]
    assert "event=auth_failed" in msg
    assert "token=" not in msg  # None se omite
