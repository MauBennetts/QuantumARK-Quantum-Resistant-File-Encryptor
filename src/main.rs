#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::Path;
use blackprism_tauri::crypto::key_manager::{generate_pqc_keypair, protect_private_key, unprotect_private_key};
use blackprism_tauri::crypto::cipher::{encrypt_file_pqc_complete, decrypt_file_pqc, compute_file_hash};
use blackprism_tauri::crypto::shamir::{split_secret, recover_secret};

// ── Gestión de Llaves ──────────────────────────────────────────────────

#[tauri::command]
fn generate_keys() -> Result<(String, String), String> {
    let (pub_bytes, sec_bytes) = generate_pqc_keypair()?;
    let pub_str = String::from_utf8(pub_bytes).map_err(|e| e.to_string())?;
    let sec_str = String::from_utf8(sec_bytes).map_err(|e| e.to_string())?;
    Ok((pub_str, sec_str))
}

#[tauri::command]
fn protect_key(private_key_json: String, password: String) -> Result<String, String> {
    let protected_bytes = protect_private_key(private_key_json.as_bytes(), &password)?;
    Ok(hex::encode(protected_bytes))
}

#[tauri::command]
fn unprotect_key(protected_key_hex: String, password: String) -> Result<String, String> {
    let protected_bytes = hex::decode(&protected_key_hex)
        .map_err(|e| format!("Formato de llave protegida inválida: {}", e))?;
    let decrypted_bytes = unprotect_private_key(&protected_bytes, &password)?;
    String::from_utf8(decrypted_bytes).map_err(|e| format!("Clave no es UTF-8 válido: {}", e))
}

// ── Shamir's Secret Sharing (Feature 5) ───────────────────────────────

#[tauri::command]
fn split_password(password: String, threshold: u8, total: u8) -> Result<Vec<String>, String> {
    split_secret(password.as_bytes(), threshold, total)
}

#[tauri::command]
fn recover_password(shares: Vec<String>, threshold: u8) -> Result<String, String> {
    let recovered_bytes = recover_secret(&shares, threshold)?;
    String::from_utf8(recovered_bytes).map_err(|e| format!("Contraseña recuperada no es UTF-8 válido: {}", e))
}

// ── Cifrado ────────────────────────────────────────────────────────────

/// Cifra un archivo y retorna { output_path, input_hash, output_hash }
#[tauri::command]
fn encrypt_file(
    input_path: String,
    public_key_json: String,
    sender_private_key_json: String,
    password: Option<String>,
    delete_original: bool,
    shred_passes: u8,
    metadata_clean: bool,
    // QuantumARK v4.0 Features
    hardware_pepper: bool,
    ttl_seconds: Option<u64>,
    decoy_file_path: Option<String>,
    decoy_password: Option<String>,
    obfuscate_filename: bool,
    data_shards: Option<usize>,
    parity_shards: Option<usize>,
) -> Result<serde_json::Value, String> {
    let path = Path::new(&input_path);
    let pwd_ref = password.as_deref().filter(|s| !s.is_empty());
    
    let decoy_path_buf = decoy_file_path.as_ref().filter(|s| !s.is_empty()).map(|s| Path::new(s));
    let decoy_pwd_ref = decoy_password.as_deref().filter(|s| !s.is_empty());
    
    let fragmentation = if let (Some(d), Some(p)) = (data_shards, parity_shards) {
        if d > 0 && p > 0 {
            Some((d, p))
        } else {
            None
        }
    } else {
        None
    };

    let (out_path, input_hash, output_hash) = encrypt_file_pqc_complete(
        path,
        public_key_json.as_bytes(),
        sender_private_key_json.as_bytes(),
        pwd_ref,
        delete_original,
        shred_passes,
        metadata_clean,
        hardware_pepper,
        ttl_seconds,
        decoy_path_buf,
        decoy_pwd_ref,
        obfuscate_filename,
        fragmentation,
    )?;

    Ok(serde_json::json!({
        "output_path": out_path,
        "input_hash":  input_hash,
        "output_hash": output_hash
    }))
}

// ── Descifrado ─────────────────────────────────────────────────────────

/// Descifra un archivo y retorna { output_path, output_hash }
#[tauri::command]
fn decrypt_file(
    input_path: String,
    recipient_private_key_json: String,
    sender_public_key_json: String,
    password: Option<String>,
) -> Result<serde_json::Value, String> {
    let path = Path::new(&input_path);
    let pwd_ref = password.as_deref().filter(|s| !s.is_empty());
    let (out_path, output_hash) = decrypt_file_pqc(
        path,
        recipient_private_key_json.as_bytes(),
        sender_public_key_json.as_bytes(),
        pwd_ref,
    )?;
    Ok(serde_json::json!({
        "output_path":  out_path,
        "output_hash":  output_hash
    }))
}

// ── Hash & Verificación ────────────────────────────────────────────────

/// Calcula el hash de un archivo usando el algoritmo especificado.
/// Algoritmos: sha256, sha3-256, sha3-512, sha512, blake3
#[tauri::command]
fn compute_hash(file_path: String, algorithm: String) -> Result<String, String> {
    let path = Path::new(&file_path);
    if !path.exists() {
        return Err(format!("El archivo no existe: {}", file_path));
    }
    compute_file_hash(path, &algorithm)
}

// ── Entry Point ────────────────────────────────────────────────────────

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            generate_keys,
            protect_key,
            unprotect_key,
            split_password,
            recover_password,
            encrypt_file,
            decrypt_file,
            compute_hash
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

