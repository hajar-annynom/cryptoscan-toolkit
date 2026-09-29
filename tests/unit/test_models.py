import pytest
from cryptoscan.core.models import ScanTarget, Severity


def test_scan_target_rejects_bad_port():
    with pytest.raises(ValueError):
        ScanTarget(host="example.com", port=70000)


def test_severity_orders_numerically():
    assert Severity.CRITICAL > Severity.LOW
