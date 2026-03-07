use control_plane::pricing::GrpcPricingOracle;
use lsdc_common::crypto::{MetricsWindow, PricingAuditContext};
use lsdc_ports::{PricingOracle, TrainingMetrics};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "http://127.0.0.1:50051".to_string());

    let oracle = GrpcPricingOracle::new(endpoint);
    let shapley = oracle
        .evaluate_utility(
            &PricingAuditContext {
                dataset_id: "dataset-smoke".into(),
                transformed_asset_hash: "transformed-hash-smoke".into(),
                proof_receipt_hash: None,
                model_run_id: "pricing-smoke".into(),
                metrics_window: MetricsWindow {
                    started_at: chrono::Utc::now() - chrono::Duration::minutes(5),
                    ended_at: chrono::Utc::now(),
                },
            },
            &TrainingMetrics {
                loss_with_dataset: 0.21,
                loss_without_dataset: 0.34,
                accuracy_with_dataset: 0.91,
                accuracy_without_dataset: 0.86,
                model_run_id: "pricing-smoke".into(),
                metrics_window_started_at: chrono::Utc::now() - chrono::Duration::minutes(5),
                metrics_window_ended_at: chrono::Utc::now(),
            },
        )
        .await?;

    let decision = oracle
        .decide_price("agreement-smoke", 100.0, &shapley)
        .await?;

    println!("{}", serde_json::to_string_pretty(&decision)?);
    Ok(())
}
