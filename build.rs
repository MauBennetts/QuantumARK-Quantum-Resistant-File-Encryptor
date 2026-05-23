fn main() {
    tauri_build::try_build(
        tauri_build::Attributes::new().app_manifest(
            tauri_build::AppManifest::new().commands(&[
                "generate_keys",
                "protect_key",
                "unprotect_key",
                "encrypt_file",
                "decrypt_file",
                "compute_hash",
            ]),
        ),
    )
    .expect("failed to run tauri-build");
}
