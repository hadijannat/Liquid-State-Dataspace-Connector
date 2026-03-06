use control_plane::pricing::GrpcPricingOracle;
use lsdc_common::traits::{PricingOracle, TrainingMetrics};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "http://127.0.0.1:50051".to_string());

    let oracle = GrpcPricingOracle::new(endpoint);
    let shapley = oracle
        .evaluate_utility(
            "dataset-smoke",
            "transformed-hash-smoke",
            &TrainingMetrics {
                loss_with_dataset: 0.21,
                loss_without_dataset: 0.34,
                accuracy_with_dataset: 0.91,
                accuracy_without_dataset: 0.86,
            },
        )
        .await?;

    let decision = oracle
        .decide_price("agreement-smoke", 100.0, &shapley)
        .await?;

    println!("{}", serde_json::to_string_pretty(&decision)?);
    Ok(())
}
