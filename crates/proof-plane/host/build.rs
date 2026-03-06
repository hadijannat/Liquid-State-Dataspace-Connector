fn main() {
    println!("cargo:rerun-if-changed=../risc0-guest");

    if std::env::var_os("CARGO_FEATURE_RISC0").is_some() {
        risc0_build::embed_methods();
    }
}
