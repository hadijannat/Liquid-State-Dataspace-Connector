from src.shapley import calculate_price_decision, estimate_shapley_value


def test_positive_contribution():
    result = estimate_shapley_value(
        dataset_id="ds-1",
        transformed_asset_hash="hash-1",
        loss_with=0.3,
        loss_without=0.5,
        accuracy_with=0.85,
        accuracy_without=0.75,
    )
    assert result.marginal_contribution > 0
    assert result.confidence == 0.9
    assert result.algorithm_version == "tmc_shapley_v0"


def test_negative_contribution():
    result = estimate_shapley_value(
        dataset_id="ds-2",
        transformed_asset_hash="hash-2",
        loss_with=0.5,
        loss_without=0.3,
        accuracy_with=0.70,
        accuracy_without=0.80,
    )
    assert result.marginal_contribution < 0
    assert result.confidence == 0.3


def test_mixed_signals():
    result = estimate_shapley_value(
        dataset_id="ds-3",
        transformed_asset_hash="hash-3",
        loss_with=0.4,
        loss_without=0.3,
        accuracy_with=0.82,
        accuracy_without=0.78,
    )
    assert result.confidence == 0.6


def test_price_decision_contains_signature():
    shapley = estimate_shapley_value(
        dataset_id="ds-1",
        transformed_asset_hash="hash-1",
        loss_with=0.3,
        loss_without=0.5,
        accuracy_with=0.85,
        accuracy_without=0.75,
    )
    decision = calculate_price_decision("agreement-1", 100.0, shapley)
    assert decision.adjusted_price > 100.0
    assert decision.approval_required is True
    assert decision.signature_hex
