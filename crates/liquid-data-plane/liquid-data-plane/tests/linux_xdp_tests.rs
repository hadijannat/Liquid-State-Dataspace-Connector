#![cfg(target_os = "linux")]

use chrono::Utc;
use liquid_data_plane::loader::LiquidDataPlane;
use lsdc_common::dsp::ContractAgreement;
use lsdc_common::odrl::ast::{Action, Constraint, Permission, PolicyAgreement, PolicyId};
use lsdc_common::traits::{DataPlane, EnforcementStatus};
use std::net::UdpSocket;
use std::process::Command;
use std::time::Duration;

#[tokio::test]
#[ignore = "requires root, loopback XDP support, and a built eBPF object"]
async fn test_loopback_packet_cap_enforcement_and_detach() {
    build_ebpf_object();

    let plane = LiquidDataPlane::new();
    let agreement = ContractAgreement {
        agreement_id: PolicyId("linux-agreement-1".into()),
        policy: PolicyAgreement {
            id: PolicyId("linux-policy-1".into()),
            provider: "did:web:provider.example".into(),
            consumer: "did:web:consumer.example".into(),
            target: "urn:data:loopback".into(),
            permissions: vec![Permission {
                action: Action::Stream,
                constraints: vec![Constraint::Count { max: 100 }],
                duties: vec![],
            }],
            prohibitions: vec![],
            obligations: vec![],
            valid_from: Utc::now(),
            valid_until: None,
        },
    };

    let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let address = receiver.local_addr().unwrap();
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();

    let handle = plane.enforce(&agreement, "lo").await.unwrap();

    for sequence in 0..150 {
        let payload = format!("pkt-{sequence}");
        sender.send_to(payload.as_bytes(), address).unwrap();
    }

    tokio::time::sleep(Duration::from_millis(100)).await;

    let status = plane.status(&handle).await.unwrap();
    match status {
        EnforcementStatus::Active { packets_processed } => {
            assert_eq!(packets_processed, 100);
        }
        other => panic!("expected active enforcement status, got {other:?}"),
    }

    drain_socket(&receiver);

    plane.revoke(&handle).await.unwrap();

    sender.send_to(b"after-revoke", address).unwrap();
    let mut buffer = [0_u8; 64];
    let (size, _) = receiver.recv_from(&mut buffer).unwrap();
    assert_eq!(&buffer[..size], b"after-revoke");
    assert!(matches!(
        plane.status(&handle).await.unwrap(),
        EnforcementStatus::Revoked
    ));
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
