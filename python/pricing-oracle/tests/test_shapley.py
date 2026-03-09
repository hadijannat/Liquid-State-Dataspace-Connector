from lsdc_pricing_oracle.shapley import (
    MetricsWindow,
    PricingAuditContext,
    calculate_price_decision,
    estimate_shapley_value,
    resolve_pricing_secret,
)


def audit_context(dataset_id: str, transformed_asset_hash: str) -> PricingAuditContext:
    return PricingAuditContext(
        dataset_id=dataset_id,
        transformed_asset_hash=transformed_asset_hash,
        proof_receipt_hash="receipt-hash",
        model_run_id="run-123",
        metrics_window=MetricsWindow(
            started_at="2026-03-06T10:00:00Z",
            ended_at="2026-03-06T10:05:00Z",
        ),
    )


def test_positive_contribution():
    result = estimate_shapley_value(
        audit_context=audit_context("ds-1", "hash-1"),
        loss_with=0.3,
        loss_without=0.5,
        accuracy_with=0.85,
        accuracy_without=0.75,
    )
    assert result.marginal_contribution > 0
    assert result.confidence == 0.9
    assert result.algorithm_version == "heuristic_marginal_v0"


def test_negative_contribution():
    result = estimate_shapley_value(
        audit_context=audit_context("ds-2", "hash-2"),
        loss_with=0.5,
        loss_without=0.3,
        accuracy_with=0.70,
        accuracy_without=0.80,
    )
    assert result.marginal_contribution < 0
    assert result.confidence == 0.3


def test_mixed_signals():
    result = estimate_shapley_value(
        audit_context=audit_context("ds-3", "hash-3"),
        loss_with=0.4,
        loss_without=0.3,
        accuracy_with=0.82,
        accuracy_without=0.78,
    )
    assert result.confidence == 0.6


def test_price_decision_contains_signature(monkeypatch):
    monkeypatch.setenv("LSDC_PRICING_SECRET", "test-pricing-secret")
    shapley = estimate_shapley_value(
        audit_context=audit_context("ds-1", "hash-1"),
        loss_with=0.3,
        loss_without=0.5,
        accuracy_with=0.85,
        accuracy_without=0.75,
    )
    decision = calculate_price_decision("agreement-1", 100.0, shapley)
    assert decision.adjusted_price > 100.0
    assert decision.approval_required is True
    assert decision.pricing_mode == "advisory"
    assert decision.signature_hex


def test_resolve_pricing_secret_rejects_missing_secret_without_dev_defaults():
    try:
        resolve_pricing_secret(explicit_secret=None, allow_dev_defaults_override=False)
    except RuntimeError as err:
        assert "LSDC_PRICING_SECRET must be set unless LSDC_ALLOW_DEV_DEFAULTS=1" in str(err)
    else:
        raise AssertionError("expected missing pricing secret to fail closed")
