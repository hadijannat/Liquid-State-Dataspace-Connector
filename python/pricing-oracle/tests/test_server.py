import asyncio

from fastapi.testclient import TestClient

from src.server import PricingOracleService, app, pricing_pb2


client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_evaluate_utility_service():
    service = PricingOracleService()
    response = asyncio.run(
        service.EvaluateUtility(
            pricing_pb2.UtilityRequest(
                audit_context=pricing_pb2.PricingAuditContext(
                    dataset_id="ds-1",
                    transformed_asset_hash="hash-1",
                    proof_receipt_hash="receipt-1",
                    model_run_id="run-1",
                    metrics_window_started_at="2026-03-06T10:00:00Z",
                    metrics_window_ended_at="2026-03-06T10:05:00Z",
                ),
                loss_with_dataset=0.3,
                loss_without_dataset=0.5,
                accuracy_with_dataset=0.85,
                accuracy_without_dataset=0.75,
            ),
            None,
        )
    )

    assert response.dataset_id == "ds-1"
    assert response.transformed_asset_hash == "hash-1"
    assert response.algorithm_version == "heuristic_marginal_v0"
    assert response.audit_context.model_run_id == "run-1"
