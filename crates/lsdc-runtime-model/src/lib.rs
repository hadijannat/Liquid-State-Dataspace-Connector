use lsdc_evidence::{canonical_json_bytes, Sha256Hash};
use lsdc_execution_protocol::ExecutionStatementKind;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum NodeStatus {
    Planned,
    Realized,
    Verified,
    Anchored,
    Failed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum DependencyType {
    ImplementedBy,
    VerifiedBy,
    AnchoredBy,
    InvalidatedBy,
    DerivedFrom,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityNode {
    pub node_id: String,
    pub node_type: String,
    pub canonical_hash: Sha256Hash,
    pub status: NodeStatus,
    pub payload_json: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityEdge {
    pub from_node_id: String,
    pub to_node_id: String,
    pub dependency_type: DependencyType,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityGraph {
    pub nodes: Vec<CapabilityNode>,
    pub edges: Vec<CapabilityEdge>,
    pub root_hash: Sha256Hash,
}

impl CapabilityGraph {
    pub fn new(nodes: Vec<CapabilityNode>, edges: Vec<CapabilityEdge>) -> Result<Self, serde_json::Error> {
        let root_hash = graph_root_hash(&nodes, &edges)?;
        Ok(Self { nodes, edges, root_hash })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceNode {
    pub node_id: String,
    pub kind: ExecutionStatementKind,
    pub canonical_hash: Sha256Hash,
    pub status: NodeStatus,
    pub payload_json: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceEdge {
    pub from_node_id: String,
    pub to_node_id: String,
    pub dependency_type: DependencyType,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceDag {
    pub nodes: Vec<EvidenceNode>,
    pub edges: Vec<EvidenceEdge>,
    pub root_hash: Sha256Hash,
}

impl EvidenceDag {
    pub fn new(nodes: Vec<EvidenceNode>, edges: Vec<EvidenceEdge>) -> Result<Self, serde_json::Error> {
        let root_hash = graph_root_hash(&nodes, &edges)?;
        Ok(Self { nodes, edges, root_hash })
    }
}

fn graph_root_hash<N: Serialize, E: Serialize>(
    nodes: &[N],
    edges: &[E],
) -> Result<Sha256Hash, serde_json::Error> {
    let bytes = canonical_json_bytes(&serde_json::json!({
        "nodes": nodes,
        "edges": edges,
    }))?;
    Ok(Sha256Hash::digest_bytes(&bytes))
}
