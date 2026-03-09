import logging
from unittest.mock import AsyncMock

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
        _check_insecure_host_warning("[::1]")
        _check_insecure_host_warning("localhost")

    assert not any("not a loopback address" in r.message for r in caplog.records), (
        "No warning expected for loopback hosts"
    )


def test_format_bind_target_brackets_ipv6():
    from lsdc_pricing_oracle.server import _format_bind_target

    assert _format_bind_target("::1", 50051) == "[::1]:50051"
    assert _format_bind_target("[::1]", 50051) == "[::1]:50051"
    assert _format_bind_target("127.0.0.1", 50051) == "127.0.0.1:50051"


@pytest.mark.asyncio
async def test_bind_failure_raises_and_logs(caplog, monkeypatch):
    from lsdc_pricing_oracle import server as pricing_server

    fake_server = type(
        "FakeServer",
        (),
        {
            "add_insecure_port": lambda self, target: 0,
            "start": AsyncMock(),
            "wait_for_termination": AsyncMock(),
        },
    )()

    monkeypatch.setattr(pricing_server.grpc.aio, "server", lambda: fake_server)
    monkeypatch.setattr(
        pricing_server.pricing_pb2_grpc,
        "add_PricingOracleServicer_to_server",
        lambda servicer, server: None,
    )

    with caplog.at_level(logging.ERROR, logger="lsdc_pricing_oracle.server"):
        with pytest.raises(RuntimeError, match=r"failed to bind insecure gRPC server on \[::1\]:50051"):
            await pricing_server.serve_grpc("::1", 50051)

    assert any("failed to bind insecure gRPC server" in r.message for r in caplog.records)
    fake_server.start.assert_not_called()
    fake_server.wait_for_termination.assert_not_called()
