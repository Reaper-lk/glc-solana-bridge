fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Use the vendored compiler unless the operator has deliberately
    // pointed PROTOC elsewhere, so the build is self-contained and does not
    // depend on what happens to be installed on the host.
    if std::env::var_os("PROTOC").is_none() {
        std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?);
    }
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/federation.proto"], &["proto"])?;
    Ok(())
}
