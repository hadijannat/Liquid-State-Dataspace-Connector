"""
Heuristic marginal utility estimation.

Phase 2 keeps pricing advisory-only and reports a truthful algorithm label.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
import os


DEFAULT_PRICING_SECRET = "lsdc-pricing-dev-secret"
PRICING_SECRET_ENV = "LSDC_PRICING_SECRET"
ALLOW_DEV_DEFAULTS_ENV = "LSDC_ALLOW_DEV_DEFAULTS"


@dataclass
class MetricsWindow:
    started_at: str
    ended_at: str


@dataclass
class PricingAuditContext:
    dataset_id: str
    transformed_asset_hash: str
    proof_receipt_hash: str
    model_run_id: str
    metrics_window: MetricsWindow


@dataclass
class ShapleyResult:
    dataset_id: str
    transformed_asset_hash: str
    marginal_contribution: float
    confidence: float
    algorithm_version: str
    audit_context: PricingAuditContext


@dataclass
class PriceDecision:
    agreement_id: str
    dataset_id: str
    original_price: float
    adjusted_price: float
    approval_required: bool
    pricing_mode: str
    shapley_value: ShapleyResult
    signed_by: str
    signature_hex: str


def estimate_shapley_value(
    audit_context: PricingAuditContext,
    loss_with: float,
    loss_without: float,
    accuracy_with: float,
    accuracy_without: float,
) -> ShapleyResult:
    accuracy_delta = accuracy_with - accuracy_without
    loss_delta = loss_without - loss_with
    marginal = 0.7 * accuracy_delta + 0.3 * max(loss_delta, 0.0)

    if accuracy_delta > 0 and loss_delta > 0:
        confidence = 0.9
    elif accuracy_delta > 0 or loss_delta > 0:
        confidence = 0.6
    else:
        confidence = 0.3

    return ShapleyResult(
        dataset_id=audit_context.dataset_id,
        transformed_asset_hash=audit_context.transformed_asset_hash,
        marginal_contribution=round(marginal, 6),
        confidence=confidence,
        algorithm_version="heuristic_marginal_v0",
        audit_context=audit_context,
    )


def calculate_price_decision(
    agreement_id: str,
    current_price: float,
    shapley_value: ShapleyResult,
    signer: str = "pricing-oracle",
) -> PriceDecision:
    adjustment_factor = 1.0 + 1.5 * (shapley_value.marginal_contribution - 0.05)
    adjusted_price = round(current_price * max(adjustment_factor, 0.1), 2)
    decision = PriceDecision(
        agreement_id=agreement_id,
        dataset_id=shapley_value.dataset_id,
        original_price=current_price,
        adjusted_price=adjusted_price,
        approval_required=True,
        pricing_mode="advisory",
        shapley_value=shapley_value,
        signed_by=signer,
        signature_hex="",
    )
    decision.signature_hex = sign_price_decision(decision)
    return decision


def allow_dev_defaults() -> bool:
    return os.getenv(ALLOW_DEV_DEFAULTS_ENV) == "1"


def resolve_pricing_secret(
    explicit_secret: str | None = None,
    allow_dev_defaults_override: bool | None = None,
) -> str:
    if explicit_secret is None:
        explicit_secret = os.getenv(PRICING_SECRET_ENV)
    if explicit_secret is not None:
        explicit_secret = explicit_secret.strip()
    if explicit_secret:
        return explicit_secret

    if allow_dev_defaults_override is None:
        allow_dev_defaults_override = allow_dev_defaults()
    if allow_dev_defaults_override:
        return DEFAULT_PRICING_SECRET

    raise RuntimeError(
        f"{PRICING_SECRET_ENV} must be set unless {ALLOW_DEV_DEFAULTS_ENV}=1"
    )


def sign_price_decision(decision: PriceDecision) -> str:
    payload = json.dumps(
        {
            "agreement_id": decision.agreement_id,
            "dataset_id": decision.dataset_id,
            "original_price": decision.original_price,
            "adjusted_price": decision.adjusted_price,
            "approval_required": decision.approval_required,
            "pricing_mode": decision.pricing_mode,
            "shapley_value": asdict(decision.shapley_value),
            "signed_by": decision.signed_by,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    secret = resolve_pricing_secret().encode("utf-8")
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()
