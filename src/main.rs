#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::Path;
use quantumark_tauri::crypto::key_manager::{generate_pqc_keypair, protect_private_key, unprotect_private_key};
use quantumark_tauri::crypto::cipher::{encrypt_file_pqc_complete, decrypt_file_pqc};

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

#[tauri::command]
fn encrypt_file(
    input_path: String,
    public_key_json: String,
    sender_private_key_json: String,
    password: Option<String>,
    delete_original: bool,
    shred_passes: u8,
    metadata_clean: bool,
) -> Result<String, String> {
    let path = Path::new(&input_path);
    let pwd_ref = password.as_deref().filter(|s| !s.is_empty());
    encrypt_file_pqc_complete(
        path,
        public_key_json.as_bytes(),
        sender_private_key_json.as_bytes(),
        pwd_ref,
        delete_original,
        shred_passes,
        metadata_clean,
    )
}

#[tauri::command]
fn decrypt_file(
    input_path: String,
    recipient_private_key_json: String,
    sender_public_key_json: String,
    password: Option<String>,
) -> Result<String, String> {
    let path = Path::new(&input_path);
    let pwd_ref = password.as_deref().filter(|s| !s.is_empty());
    decrypt_file_pqc(
        path,
        recipient_private_key_json.as_bytes(),
        sender_public_key_json.as_bytes(),
        pwd_ref,
    )
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            generate_keys,
            protect_key,
            unprotect_key,
            encrypt_file,
            decrypt_file
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
