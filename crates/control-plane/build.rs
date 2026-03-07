fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto = "../../proto/pricing/v1/pricing.proto";
    println!("cargo:rerun-if-changed={proto}");

    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    unsafe {
        std::env::set_var("PROTOC", protoc);
    }

    tonic_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(&[proto], &["../../proto/pricing/v1"])?;

    Ok(())
}
