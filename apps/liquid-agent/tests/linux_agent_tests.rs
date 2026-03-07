#![cfg(target_os = "linux")]

use liquid_agent_core::loader::LiquidDataPlane;
use liquid_agent_grpc::client::LiquidAgentGrpcClient;
use liquid_agent_grpc::server::{serve, LiquidAgentService};
use lsdc_common::dsp::{ContractAgreement, EvidenceRequirement, TransportProtocol};
use lsdc_common::execution::TransportBackend;
use lsdc_common::liquid::{LiquidPolicyIr, RuntimeGuard, TransformGuard, TransportGuard};
use lsdc_common::odrl::ast::PolicyId;
use lsdc_ports::{DataPlane, EnforcementStatus};
use std::net::UdpSocket;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
#[ignore = "requires root, loopback XDP support, and a built eBPF object"]
async fn test_loopback_packet_cap_enforcement_and_detach_via_grpc() {
    build_ebpf_object();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let plane = Arc::new(LiquidDataPlane::new());
    tokio::spawn(async move {
        serve(
            listener,
            LiquidAgentService::new(plane, TransportBackend::AyaXdp),
        )
        .await
        .unwrap();
    });

    let client = LiquidAgentGrpcClient::new(format!("http://{address}"));
    let agreement = sample_agreement("linux-agent-grpc", Some(31_337));
    let handle = client.enforce(&agreement, "lo").await.unwrap();

    let receiver = UdpSocket::bind(("127.0.0.1", handle.session_port)).unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let address = receiver.local_addr().unwrap();
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();

    for sequence in 0..150 {
        let payload = format!("pkt-{sequence}");
        sender.send_to(payload.as_bytes(), address).unwrap();
    }

    tokio::time::sleep(Duration::from_millis(100)).await;

    let status = client.status(&handle).await.unwrap();
    match status {
        EnforcementStatus::Active {
            packets_processed, ..
        } => assert_eq!(packets_processed, 100),
        other => panic!("expected active enforcement status, got {other:?}"),
    }

    drain_socket(&receiver);
    client.revoke(&handle).await.unwrap();

    sender.send_to(b"after-revoke", address).unwrap();
    let mut buffer = [0_u8; 64];
    let (size, _) = receiver.recv_from(&mut buffer).unwrap();
    assert_eq!(&buffer[..size], b"after-revoke");
    assert!(matches!(
        client.status(&handle).await.unwrap(),
        EnforcementStatus::Revoked
    ));
}

fn sample_agreement(id: &str, session_port: Option<u16>) -> ContractAgreement {
    ContractAgreement {
        agreement_id: PolicyId(id.into()),
        asset_id: "asset-loopback".into(),
        provider_id: "did:web:provider.example".into(),
        consumer_id: "did:web:consumer.example".into(),
        odrl_policy: serde_json::json!({ "permission": [{ "action": ["read", "transfer"] }] }),
        policy_hash: "policy-hash".into(),
        evidence_requirements: vec![EvidenceRequirement::ProvenanceReceipt],
        liquid_policy: LiquidPolicyIr {
            transport_guard: TransportGuard {
                allow_read: true,
                allow_transfer: true,
                packet_cap: Some(100),
                byte_cap: None,
                allowed_regions: vec!["EU".into()],
                valid_until: Some(chrono::Utc::now() + chrono::Duration::minutes(5)),
                protocol: TransportProtocol::Udp,
                session_port,
            },
            transform_guard: TransformGuard {
                allow_anonymize: true,
                allowed_purposes: vec!["analytics".into()],
                required_ops: vec![],
            },
            runtime_guard: RuntimeGuard {
                delete_after_seconds: Some(300),
                evidence_requirements: vec![EvidenceRequirement::ProvenanceReceipt],
                approval_required: false,
            },
        },
    }
}

fn build_ebpf_object() {
    let status = Command::new("cargo")
        .args(["xtask", "build-ebpf"])
        .status()
        .unwrap();
    assert!(status.success(), "failed to build eBPF object");
}

fn drain_socket(socket: &UdpSocket) {
    let mut buffer = [0_u8; 64];
    loop {
        match socket.recv_from(&mut buffer) {
            Ok(_) => continue,
            Err(err)
                if err.kind() == std::io::ErrorKind::WouldBlock
                    || err.kind() == std::io::ErrorKind::TimedOut =>
            {
                break;
            }
            Err(err) => panic!("failed while draining UDP socket: {err}"),
        }
    }
}
