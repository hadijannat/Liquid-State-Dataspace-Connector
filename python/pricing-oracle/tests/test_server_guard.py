import logging

import pytest


def test_non_loopback_host_emits_warning(caplog):
    """serve_grpc() must log a warning when the gRPC host is not loopback."""
    from lsdc_pricing_oracle.server import _check_insecure_host_warning

    with caplog.at_level(logging.WARNING, logger="lsdc_pricing_oracle.server"):
        _check_insecure_host_warning("0.0.0.0")

    assert any("not a loopback address" in r.message for r in caplog.records), (
        "Expected a warning when host is not loopback"
    )


def test_loopback_host_no_warning(caplog):
    """serve_grpc() must NOT log a warning for loopback hosts."""
    from lsdc_pricing_oracle.server import _check_insecure_host_warning

    with caplog.at_level(logging.WARNING, logger="lsdc_pricing_oracle.server"):
        _check_insecure_host_warning("127.0.0.1")
        _check_insecure_host_warning("::1")
        _check_insecure_host_warning("localhost")

    assert not any("not a loopback address" in r.message for r in caplog.records), (
        "No warning expected for loopback hosts"
    )
