"""
Truncated Monte Carlo (TMC) Shapley Value estimation.

Sprint 0: Simplified marginal contribution calculation.
Sprint 1: Full TMC-Shapley with convergence detection.
"""

from dataclasses import dataclass


@dataclass
class ShapleyResult:
    dataset_id: str
    marginal_contribution: float
    confidence: float
    algorithm_version: str


def estimate_shapley_value(
    dataset_id: str,
    loss_with: float,
    loss_without: float,
    accuracy_with: float,
    accuracy_without: float,
) -> ShapleyResult:
    """
    Estimate the marginal contribution of a dataset to model performance.

    Sprint 0: Simple difference-based estimation.
    Sprint 1: TMC-Shapley with Monte Carlo permutation sampling.
    """
    # Accuracy improvement (primary signal)
    accuracy_delta = accuracy_with - accuracy_without

    # Loss reduction (secondary signal, inverted — lower loss is better)
    loss_delta = loss_without - loss_with

    # Weighted combination
    marginal = 0.7 * accuracy_delta + 0.3 * max(loss_delta, 0.0)

    # Confidence is higher when both signals agree
    if accuracy_delta > 0 and loss_delta > 0:
        confidence = 0.9
    elif accuracy_delta > 0 or loss_delta > 0:
        confidence = 0.6
    else:
        confidence = 0.3

    return ShapleyResult(
        dataset_id=dataset_id,
        marginal_contribution=round(marginal, 6),
        confidence=confidence,
        algorithm_version="heuristic_v0",
    )


def calculate_price_adjustment(
    original_price: float,
    marginal_contribution: float,
    elasticity: float = 1.5,
) -> float:
    """
    Adjust price based on marginal contribution.

    Uses a simple elasticity model: if the data contributes more than
    expected (marginal > 0.5), price increases; if less, price decreases.
    """
    adjustment_factor = 1.0 + elasticity * (marginal_contribution - 0.05)
    adjusted = original_price * max(adjustment_factor, 0.1)  # floor at 10%
    return round(adjusted, 2)
