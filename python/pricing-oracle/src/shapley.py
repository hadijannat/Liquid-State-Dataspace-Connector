"""
Truncated Monte Carlo (TMC) Shapley Value estimation.

Prototype phase: heuristic utility scoring with a signed pricing decision.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
import os


DEFAULT_PRICING_SECRET = "lsdc-pricing-dev-secret"


@dataclass
class ShapleyResult:
    dataset_id: str
    transformed_asset_hash: str
    marginal_contribution: float
    confidence: float
    algorithm_version: str


@dataclass
class PriceDecision:
    agreement_id: str
    dataset_id: str
    original_price: float
    adjusted_price: float
    approval_required: bool
    shapley_value: ShapleyResult
    signed_by: str
    signature_hex: str


def estimate_shapley_value(
    dataset_id: str,
    transformed_asset_hash: str,
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
        dataset_id=dataset_id,
        transformed_asset_hash=transformed_asset_hash,
        marginal_contribution=round(marginal, 6),
        confidence=confidence,
        algorithm_version="tmc_shapley_v0",
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
        shapley_value=shapley_value,
        signed_by=signer,
        signature_hex="",
    )
    decision.signature_hex = sign_price_decision(decision)
    return decision


def sign_price_decision(decision: PriceDecision) -> str:
    payload = json.dumps(
        {
            "agreement_id": decision.agreement_id,
            "dataset_id": decision.dataset_id,
            "original_price": decision.original_price,
            "adjusted_price": decision.adjusted_price,
            "approval_required": decision.approval_required,
            "shapley_value": asdict(decision.shapley_value),
            "signed_by": decision.signed_by,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    secret = os.getenv("LSDC_PRICING_SECRET", DEFAULT_PRICING_SECRET).encode("utf-8")
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()
