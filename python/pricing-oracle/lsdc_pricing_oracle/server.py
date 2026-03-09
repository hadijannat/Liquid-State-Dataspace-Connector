"""
FastAPI health endpoint plus a gRPC pricing oracle service.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os

import grpc
from fastapi import FastAPI
import uvicorn

from .proto_loader import load_pricing_proto
from .shapley import (
    ALLOW_DEV_DEFAULTS_ENV,
    MetricsWindow,
    PricingAuditContext,
    ShapleyResult,
    calculate_price_decision,
    allow_dev_defaults,
    estimate_shapley_value,
    resolve_pricing_secret,
)

pricing_pb2, pricing_pb2_grpc = load_pricing_proto()

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})

logger = logging.getLogger(__name__)


def _normalize_host(host: str) -> str:
    host = host.strip()
    if host.startswith("[") and "]" in host:
        return host[1 : host.index("]")]
    if host.count(":") == 1:
        candidate, port = host.rsplit(":", 1)
        if port.isdigit():
            return candidate
    return host


def _is_loopback_host(host: str) -> bool:
    normalized = _normalize_host(host)
    if normalized in _LOOPBACK_HOSTS:
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def _format_bind_target(host: str, port: int) -> str:
    normalized = _normalize_host(host)
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        return f"{normalized}:{port}"
    if address.version == 6:
        return f"[{normalized}]:{port}"
    return f"{normalized}:{port}"


def _check_insecure_host_warning(host: str) -> None:
    """Log a warning if the gRPC host is not a loopback address.

    The gRPC server uses add_insecure_port() (no TLS, no auth).
    Binding to a non-loopback address in this mode is a misconfiguration
    that risks exposing pricing decisions without any transport security.
    """
    if not _is_loopback_host(host):
        logger.warning(
            "LSDC_PRICING_GRPC_HOST=%s is not a loopback address. "
            "The gRPC server has no TLS or authentication. "
            "For production, restrict to loopback or configure mTLS.",
            host,
        )


def _ensure_insecure_bind_allowed(host: str) -> None:
    if not allow_dev_defaults():
        raise RuntimeError(
            f"insecure pricing gRPC requires {ALLOW_DEV_DEFAULTS_ENV}=1"
        )
    if not _is_loopback_host(host):
        raise RuntimeError(
            "insecure pricing gRPC must bind to a loopback address"
        )


app = FastAPI(title="LSDC Pricing Oracle", version="0.2.0")


@app.get("/health")
async def health():
    return {"status": "ok"}


class PricingOracleService(pricing_pb2_grpc.PricingOracleServicer):
    async def EvaluateUtility(self, request, context):
        audit_context = PricingAuditContext(
            dataset_id=request.audit_context.dataset_id,
            transformed_asset_hash=request.audit_context.transformed_asset_hash,
            proof_receipt_hash=request.audit_context.proof_receipt_hash,
            model_run_id=request.audit_context.model_run_id,
            metrics_window=MetricsWindow(
                started_at=request.audit_context.metrics_window_started_at,
                ended_at=request.audit_context.metrics_window_ended_at,
            ),
        )
        result = estimate_shapley_value(
            audit_context=audit_context,
            loss_with=request.loss_with_dataset,
            loss_without=request.loss_without_dataset,
            accuracy_with=request.accuracy_with_dataset,
            accuracy_without=request.accuracy_without_dataset,
        )
        return pricing_pb2.ShapleyResponse(
            dataset_id=result.dataset_id,
            transformed_asset_hash=result.transformed_asset_hash,
            marginal_contribution=result.marginal_contribution,
            confidence=result.confidence,
            algorithm_version=result.algorithm_version,
            audit_context=pricing_pb2.PricingAuditContext(
                dataset_id=result.audit_context.dataset_id,
                transformed_asset_hash=result.audit_context.transformed_asset_hash,
                proof_receipt_hash=result.audit_context.proof_receipt_hash,
                model_run_id=result.audit_context.model_run_id,
                metrics_window_started_at=result.audit_context.metrics_window.started_at,
                metrics_window_ended_at=result.audit_context.metrics_window.ended_at,
            ),
        )

    async def DecidePrice(self, request, context):
        shapley = request.shapley_value
        decision = calculate_price_decision(
            agreement_id=request.agreement_id,
            current_price=request.current_price,
            shapley_value=ShapleyResult(
                dataset_id=shapley.dataset_id,
                transformed_asset_hash=shapley.transformed_asset_hash,
                marginal_contribution=shapley.marginal_contribution,
                confidence=shapley.confidence,
                algorithm_version=shapley.algorithm_version,
                audit_context=PricingAuditContext(
                    dataset_id=shapley.audit_context.dataset_id,
                    transformed_asset_hash=shapley.audit_context.transformed_asset_hash,
                    proof_receipt_hash=shapley.audit_context.proof_receipt_hash,
                    model_run_id=shapley.audit_context.model_run_id,
                    metrics_window=MetricsWindow(
                        started_at=shapley.audit_context.metrics_window_started_at,
                        ended_at=shapley.audit_context.metrics_window_ended_at,
                    ),
                ),
            ),
            signer=os.getenv("LSDC_PRICING_SIGNER", "pricing-oracle"),
        )
        return pricing_pb2.PriceDecisionResponse(
            agreement_id=decision.agreement_id,
            dataset_id=decision.dataset_id,
            original_price=decision.original_price,
            adjusted_price=decision.adjusted_price,
            approval_required=decision.approval_required,
            pricing_mode=decision.pricing_mode,
            shapley_value=pricing_pb2.ShapleyResponse(
                dataset_id=decision.shapley_value.dataset_id,
                transformed_asset_hash=decision.shapley_value.transformed_asset_hash,
                marginal_contribution=decision.shapley_value.marginal_contribution,
                confidence=decision.shapley_value.confidence,
                algorithm_version=decision.shapley_value.algorithm_version,
                audit_context=pricing_pb2.PricingAuditContext(
                    dataset_id=decision.shapley_value.audit_context.dataset_id,
                    transformed_asset_hash=decision.shapley_value.audit_context.transformed_asset_hash,
                    proof_receipt_hash=decision.shapley_value.audit_context.proof_receipt_hash,
                    model_run_id=decision.shapley_value.audit_context.model_run_id,
                    metrics_window_started_at=decision.shapley_value.audit_context.metrics_window.started_at,
                    metrics_window_ended_at=decision.shapley_value.audit_context.metrics_window.ended_at,
                ),
            ),
            signed_by=decision.signed_by,
            signature_hex=decision.signature_hex,
        )


async def serve_grpc(host: str = "127.0.0.1", port: int = 50051):
    resolve_pricing_secret()
    _ensure_insecure_bind_allowed(host)
    server = grpc.aio.server()
    pricing_pb2_grpc.add_PricingOracleServicer_to_server(PricingOracleService(), server)
    _check_insecure_host_warning(host)
    bind_target = _format_bind_target(host, port)
    if server.add_insecure_port(bind_target) == 0:
        logger.error("failed to bind insecure gRPC server on %s", bind_target)
        raise RuntimeError(f"failed to bind insecure gRPC server on {bind_target}")
    await server.start()
    await server.wait_for_termination()


async def serve_health(host: str = "127.0.0.1", port: int = 8000):
    config = uvicorn.Config(app, host=host, port=port, log_level="info")
    server = uvicorn.Server(config)
    await server.serve()


async def main():
    resolve_pricing_secret()
    grpc_host = os.getenv("LSDC_PRICING_GRPC_HOST", "127.0.0.1")
    grpc_port = int(os.getenv("LSDC_PRICING_GRPC_PORT", "50051"))
    health_host = os.getenv("LSDC_PRICING_HTTP_HOST", "127.0.0.1")
    health_port = int(os.getenv("LSDC_PRICING_HTTP_PORT", "8000"))

    await asyncio.gather(
        serve_grpc(grpc_host, grpc_port),
        serve_health(health_host, health_port),
    )


if __name__ == "__main__":
    asyncio.run(main())
