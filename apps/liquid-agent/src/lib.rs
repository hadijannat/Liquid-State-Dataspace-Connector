pub mod client;
pub mod config;
pub mod server;

pub mod proto {
    tonic::include_proto!("lsdc.agent");
}
