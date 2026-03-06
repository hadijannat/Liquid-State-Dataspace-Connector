from fastapi.testclient import TestClient

from src.server import app


client = TestClient(app)


def test_evaluate_returns_algorithm_version():
    response = client.post(
        "/evaluate",
        json={
            "dataset_id": "ds-1",
            "loss_with_dataset": 0.3,
            "loss_without_dataset": 0.5,
            "accuracy_with_dataset": 0.85,
            "accuracy_without_dataset": 0.75,
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["dataset_id"] == "ds-1"
    assert payload["algorithm_version"] == "heuristic_v0"


def test_renegotiate_returns_nested_shapley_value():
    response = client.post(
        "/renegotiate",
        json={
            "agreement_id": "agreement-1",
            "current_price": 100.0,
            "shapley_value": {
                "dataset_id": "ds-1",
                "marginal_contribution": 0.15,
                "confidence": 0.9,
                "algorithm_version": "heuristic_v0",
            },
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["agreement_id"] == "agreement-1"
    assert payload["adjusted_price"] > 100.0
    assert payload["shapley_value"]["algorithm_version"] == "heuristic_v0"
