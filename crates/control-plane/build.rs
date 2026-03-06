fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto = "../../python/pricing-oracle/src/proto/pricing.proto";
    println!("cargo:rerun-if-changed={proto}");

    tonic_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(&[proto], &["../../python/pricing-oracle/src/proto"])?;

    Ok(())
}
