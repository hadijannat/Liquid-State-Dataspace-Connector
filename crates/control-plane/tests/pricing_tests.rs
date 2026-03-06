use async_trait::async_trait;
use control_plane::orchestrator::Orchestrator;
use control_plane::pricing::RestPricingOracle;
use liquid_data_plane::loader::LiquidDataPlane;
use lsdc_common::crypto::{PriceAdjustment, ShapleyValue};
use lsdc_common::error::Result;
use lsdc_common::traits::{PricingOracle, TrainingMetrics};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

struct MockPricingOracle;

#[async_trait]
impl PricingOracle for MockPricingOracle {
    async fn evaluate_utility(
        &self,
        dataset_id: &str,
        _metrics: &TrainingMetrics,
    ) -> Result<ShapleyValue> {
        Ok(ShapleyValue {
            dataset_id: dataset_id.to_string(),
            marginal_contribution: 0.2,
            confidence: 0.9,
            algorithm_version: "heuristic_v0".into(),
        })
    }

    async fn renegotiate(
        &self,
        agreement_id: &str,
        current_price: f64,
        value: &ShapleyValue,
    ) -> Result<PriceAdjustment> {
        Ok(PriceAdjustment {
            agreement_id: agreement_id.to_string(),
            original_price: current_price,
            adjusted_price: current_price + 25.0,
            shapley_value: value.clone(),
        })
    }
}

#[tokio::test]
async fn test_rest_pricing_oracle_evaluate_utility_contract() {
    let (base_url, request_rx) = spawn_json_server(
        r#"{"dataset_id":"ds-1","marginal_contribution":0.14,"confidence":0.9,"algorithm_version":"heuristic_v0"}"#,
    )
    .await;
    let oracle = RestPricingOracle::new(base_url);

    let value = oracle
        .evaluate_utility(
            "ds-1",
            &TrainingMetrics {
                loss_with_dataset: 0.3,
                loss_without_dataset: 0.5,
                accuracy_with_dataset: 0.85,
                accuracy_without_dataset: 0.75,
            },
        )
        .await
        .unwrap();

    assert_eq!(value.algorithm_version, "heuristic_v0");

    let request = request_rx.await.unwrap();
    assert!(request.starts_with("POST /evaluate HTTP/1.1"));
    assert!(request.contains("\"dataset_id\":\"ds-1\""));
    assert!(request.contains("\"loss_with_dataset\":0.3"));
    assert!(request.contains("\"accuracy_without_dataset\":0.75"));
}

#[tokio::test]
async fn test_rest_pricing_oracle_renegotiate_contract() {
    let (base_url, request_rx) = spawn_json_server(
        r#"{"agreement_id":"agreement-1","original_price":100.0,"adjusted_price":115.0,"shapley_value":{"dataset_id":"ds-1","marginal_contribution":0.1,"confidence":0.9,"algorithm_version":"heuristic_v0"}}"#,
    )
    .await;
    let oracle = RestPricingOracle::new(base_url);

    let adjustment = oracle
        .renegotiate(
            "agreement-1",
            100.0,
            &ShapleyValue {
                dataset_id: "ds-1".into(),
                marginal_contribution: 0.1,
                confidence: 0.9,
                algorithm_version: "heuristic_v0".into(),
            },
        )
        .await
        .unwrap();

    assert_eq!(adjustment.adjusted_price, 115.0);
    assert_eq!(adjustment.shapley_value.algorithm_version, "heuristic_v0");

    let request = request_rx.await.unwrap();
    assert!(request.starts_with("POST /renegotiate HTTP/1.1"));
    assert!(request.contains("\"agreement_id\":\"agreement-1\""));
    assert!(request.contains("\"current_price\":100.0"));
    assert!(request.contains("\"shapley_value\":{\"dataset_id\":\"ds-1\""));
}

#[tokio::test]
async fn test_orchestrator_returns_advisory_price_adjustment() {
    let orchestrator = Orchestrator::with_pricing(
        Arc::new(LiquidDataPlane::new()),
        Arc::new(MockPricingOracle),
    );

    let adjustment = orchestrator
        .advise_price_adjustment(
            "agreement-1",
            "dataset-1",
            100.0,
            &TrainingMetrics {
                loss_with_dataset: 0.2,
                loss_without_dataset: 0.4,
                accuracy_with_dataset: 0.91,
                accuracy_without_dataset: 0.86,
            },
        )
        .await
        .unwrap();

    assert_eq!(adjustment.agreement_id, "agreement-1");
    assert_eq!(adjustment.original_price, 100.0);
    assert_eq!(adjustment.adjusted_price, 125.0);
    assert_eq!(adjustment.shapley_value.algorithm_version, "heuristic_v0");
}

async fn spawn_json_server(response_body: &'static str) -> (String, oneshot::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (request_tx, request_rx) = oneshot::channel();

    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let request = read_http_request(&mut socket).await;
        let _ = request_tx.send(request);

        let body = response_body.as_bytes();
        let headers = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        );

        socket.write_all(headers.as_bytes()).await.unwrap();
        socket.write_all(body).await.unwrap();
    });

    (format!("http://{}", address), request_rx)
}

async fn read_http_request(socket: &mut tokio::net::TcpStream) -> String {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    let mut content_length = 0_usize;
    let mut headers_end = None;

    loop {
        let read = socket.read(&mut chunk).await.unwrap();
        if read == 0 {
            break;
        }

        buffer.extend_from_slice(&chunk[..read]);

        if headers_end.is_none() {
            headers_end = find_headers_end(&buffer);
            if let Some(end) = headers_end {
                content_length = parse_content_length(&buffer[..end]);
            }
        }

        if let Some(end) = headers_end {
            if buffer.len() >= end + content_length {
                break;
            }
        }
    }

    String::from_utf8(buffer).unwrap()
}

fn find_headers_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

fn parse_content_length(headers: &[u8]) -> usize {
    let headers = String::from_utf8_lossy(headers);
    headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("content-length") {
                value.trim().parse().ok()
            } else {
                None
            }
        })
        .unwrap_or(0)
}
