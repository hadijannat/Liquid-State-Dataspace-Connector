from src.shapley import estimate_shapley_value, calculate_price_adjustment


def test_positive_contribution():
    result = estimate_shapley_value(
        dataset_id="ds-1",
        loss_with=0.3,
        loss_without=0.5,
        accuracy_with=0.85,
        accuracy_without=0.75,
    )
    assert result.marginal_contribution > 0
    assert result.confidence == 0.9


def test_negative_contribution():
    result = estimate_shapley_value(
        dataset_id="ds-2",
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
        loss_with=0.4,
        loss_without=0.3,
        accuracy_with=0.82,
        accuracy_without=0.78,
    )
    assert result.confidence == 0.6


def test_price_adjustment_upward():
    adjusted = calculate_price_adjustment(100.0, 0.15)
    assert adjusted > 100.0


def test_price_adjustment_downward():
    adjusted = calculate_price_adjustment(100.0, 0.01)
    assert adjusted < 100.0


def test_price_floor():
    adjusted = calculate_price_adjustment(100.0, -1.0)
    assert adjusted >= 10.0  # 10% floor
