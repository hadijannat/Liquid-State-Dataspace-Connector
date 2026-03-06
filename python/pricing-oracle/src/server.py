"""
FastAPI server exposing the Shapley pricing oracle.

Sprint 0: REST API. Sprint 1: gRPC service matching pricing.proto.
"""

from fastapi import FastAPI
from pydantic import BaseModel

from .shapley import estimate_shapley_value, calculate_price_adjustment

app = FastAPI(title="LSDC Pricing Oracle", version="0.1.0")


class UtilityRequest(BaseModel):
    dataset_id: str
    loss_with_dataset: float
    loss_without_dataset: float
    accuracy_with_dataset: float
    accuracy_without_dataset: float


class ShapleyResponse(BaseModel):
    dataset_id: str
    marginal_contribution: float
    confidence: float
    algorithm_version: str


class RenegotiateRequest(BaseModel):
    agreement_id: str
    current_price: float
    shapley_value: ShapleyResponse


class PriceAdjustmentResponse(BaseModel):
    agreement_id: str
    original_price: float
    adjusted_price: float
    shapley_value: ShapleyResponse


@app.post("/evaluate", response_model=ShapleyResponse)
async def evaluate_utility(req: UtilityRequest) -> ShapleyResponse:
    result = estimate_shapley_value(
        dataset_id=req.dataset_id,
        loss_with=req.loss_with_dataset,
        loss_without=req.loss_without_dataset,
        accuracy_with=req.accuracy_with_dataset,
        accuracy_without=req.accuracy_without_dataset,
    )
    return ShapleyResponse(
        dataset_id=result.dataset_id,
        marginal_contribution=result.marginal_contribution,
        confidence=result.confidence,
        algorithm_version=result.algorithm_version,
    )


@app.post("/renegotiate", response_model=PriceAdjustmentResponse)
async def renegotiate(req: RenegotiateRequest) -> PriceAdjustmentResponse:
    adjusted = calculate_price_adjustment(
        req.current_price,
        req.shapley_value.marginal_contribution,
    )
    return PriceAdjustmentResponse(
        agreement_id=req.agreement_id,
        original_price=req.current_price,
        adjusted_price=adjusted,
        shapley_value=req.shapley_value,
    )


@app.get("/health")
async def health():
    return {"status": "ok"}
