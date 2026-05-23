use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use sha3::{Sha3_256, Sha3_512, Digest as Sha3Digest};
use sha2::{Sha256, Sha512};
use flate2::{write::ZlibEncoder, read::ZlibDecoder, Compression};
use rand::{rngs::OsRng, RngCore, Rng};
use serde::{Serialize, Deserialize};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::key_manager::{
    derive_argon2_key, generate_pqc_keypair, encapsulate_secret, decapsulate_secret, sign_data, verify_signature
};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SecureFileMetadata {
    pub filename: String,
    pub original_size: u64,
    pub compressed_size: u64,
    pub sha3_256_checksum: String,
    pub timestamp: f64,
    pub version: String,
    pub algorithm: String,
    pub decrypt_until: Option<u64>, // TTL timestamp in seconds
}

// ────────────────────────────────────────────────────────────────────────
//  HASH — Multi-algoritmo (SHA-256 / SHA3-256 / SHA3-512 / SHA-512 / BLAKE3)
// ────────────────────────────────────────────────────────────────────────

pub fn compute_file_hash(file_path: &Path, algorithm: &str) -> Result<String, String> {
    let mut file = File::open(file_path)
        .map_err(|e| format!("No se pudo abrir el archivo: {}", e))?;

    let mut buffer = [0u8; 65536];

    match algorithm.to_lowercase().as_str() {
        "sha256" => {
            let mut hasher = Sha256::new();
            loop {
                let n = file.read(&mut buffer).map_err(|e| e.to_string())?;
                if n == 0 { break; }
                hasher.update(&buffer[..n]);
            }
            Ok(hex::encode(hasher.finalize()))
        }
        "sha3-256" | "sha3_256" => {
            let mut hasher = Sha3_256::new();
            loop {
                let n = file.read(&mut buffer).map_err(|e| e.to_string())?;
                if n == 0 { break; }
                hasher.update(&buffer[..n]);
            }
            Ok(hex::encode(hasher.finalize()))
        }
        "sha3-512" | "sha3_512" => {
            let mut hasher = Sha3_512::new();
            loop {
                let n = file.read(&mut buffer).map_err(|e| e.to_string())?;
                if n == 0 { break; }
                hasher.update(&buffer[..n]);
            }
            Ok(hex::encode(hasher.finalize()))
        }
        "sha512" => {
            let mut hasher = Sha512::new();
            loop {
                let n = file.read(&mut buffer).map_err(|e| e.to_string())?;
                if n == 0 { break; }
                hasher.update(&buffer[..n]);
            }
            Ok(hex::encode(hasher.finalize()))
        }
        "blake3" => {
            let mut hasher = blake3::Hasher::new();
            loop {
                let n = file.read(&mut buffer).map_err(|e| e.to_string())?;
                if n == 0 { break; }
                hasher.update(&buffer[..n]);
            }
            Ok(hasher.finalize().to_hex().to_string())
        }
        _ => Err(format!("Algoritmo '{}' no soportado. Usa: sha256, sha3-256, sha3-512, sha512, blake3", algorithm))
    }
}

pub fn compute_hash_bytes(data: &[u8], algorithm: &str) -> Result<String, String> {
    match algorithm.to_lowercase().as_str() {
        "sha256" => Ok(hex::encode(Sha256::digest(data))),
        "sha3-256" | "sha3_256" => Ok(hex::encode(Sha3_256::digest(data))),
        "sha3-512" | "sha3_512" => Ok(hex::encode(Sha3_512::digest(data))),
        "sha512" => Ok(hex::encode(Sha512::digest(data))),
        "blake3" => Ok(blake3::hash(data).to_hex().to_string()),
        _ => Err(format!("Algoritmo '{}' no soportado.", algorithm))
    }
}

// ────────────────────────────────────────────────────────────────────────
//  SIGNAL-STYLE SIZE OBFUSCATION
// ────────────────────────────────────────────────────────────────────────

pub fn signal_style_padding_len(payload_len: usize) -> usize {
    const KB: usize = 1024;
    const MB: usize = 1024 * KB;

    let bucket_ceil = if payload_len < KB {
        KB
    } else if payload_len < 16 * KB {
        let rem = payload_len % KB;
        if rem == 0 { payload_len } else { payload_len + (KB - rem) }
    } else if payload_len < 256 * KB {
        let step = 16 * KB;
        let rem = payload_len % step;
        if rem == 0 { payload_len } else { payload_len + (step - rem) }
    } else if payload_len < 4 * MB {
        let step = 256 * KB;
        let rem = payload_len % step;
        if rem == 0 { payload_len } else { payload_len + (step - rem) }
    } else if payload_len < 64 * MB {
        let step = 4 * MB;
        let rem = payload_len % step;
        if rem == 0 { payload_len } else { payload_len + (step - rem) }
    } else {
        let step = 16 * MB;
        let rem = payload_len % step;
        if rem == 0 { payload_len } else { payload_len + (step - rem) }
    };

    let base_padding = if bucket_ceil > payload_len { bucket_ceil - payload_len } else { 0 };
    let jitter: usize = OsRng.gen_range(16..=271);

    base_padding + jitter
}

// ────────────────────────────────────────────────────────────────────────
//  SHREDDER — Destrucción segura
// ────────────────────────────────────────────────────────────────────────

pub fn secure_shred(file_path: &Path, passes: u8) -> Result<(), String> {
    if !file_path.exists() {
        return Ok(());
    }

    let file_size = fs::metadata(file_path)
        .map_err(|e| format!("Error al obtener tamaño del archivo: {}", e))?
        .len();

    let mut file = OpenOptions::new()
        .write(true)
        .open(file_path)
        .map_err(|e| format!("Error al abrir archivo para triturar: {}", e))?;

    let buffer_size = 65536;
    let mut buffer = vec![0u8; buffer_size];

    for pass in 0..passes {
        file.set_len(file_size).map_err(|e| e.to_string())?;
        let mut bytes_written = 0;

        let pattern_type = match pass % 3 {
            0 => 0x00,
            1 => 0xFF,
            _ => 0x55,
        };

        while bytes_written < file_size {
            let chunk = std::cmp::min(buffer_size as u64, file_size - bytes_written) as usize;

            if pass == passes - 1 {
                OsRng.fill_bytes(&mut buffer[0..chunk]);
            } else {
                for i in 0..chunk {
                    buffer[i] = pattern_type;
                }
            }

            file.write_all(&buffer[0..chunk])
                .map_err(|e| format!("Error escribiendo datos de trituración: {}", e))?;
            bytes_written += chunk as u64;
        }

        file.sync_all().map_err(|e| format!("Error al sincronizar disco: {}", e))?;
    }

    buffer.zeroize();
    file.set_len(0).map_err(|e| e.to_string())?;
    drop(file);
    fs::remove_file(file_path).map_err(|e| format!("Error al eliminar archivo final: {}", e))?;

    Ok(())
}

// ────────────────────────────────────────────────────────────────────────
//  COMPRESIÓN
// ────────────────────────────────────────────────────────────────────────

pub fn compress_data(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(data).map_err(|e| format!("Error al comprimir datos: {}", e))?;
    encoder.finish().map_err(|e| format!("Error al finalizar compresión: {}", e))
}

pub fn decompress_data(compressed_data: &[u8]) -> Result<Vec<u8>, String> {
    let mut decoder = ZlibDecoder::new(compressed_data);
    let mut decompressed_data = Vec::new();
    decoder.read_to_end(&mut decompressed_data).map_err(|e| format!("Error de descompresión: {}", e))?;
    Ok(decompressed_data)
}

// ────────────────────────────────────────────────────────────────────────
//  DERIVACIÓN DE CLAVE HÍBRIDA
// ────────────────────────────────────────────────────────────────────────

pub fn derive_hybrid_encryption_key(
    shared_secret: &[u8],
    password: Option<&str>,
    salt: &[u8],
    hardware_pepper: Option<&[u8]>,
) -> Result<Zeroizing<[u8; 32]>, String> {
    let mut ikm = Zeroizing::new(Vec::new());
    ikm.extend_from_slice(shared_secret);

    if let Some(pwd) = password {
        let password_key = Zeroizing::new(derive_argon2_key(pwd, salt)?);
        ikm.extend_from_slice(&*password_key);
    }

    if let Some(pepper) = hardware_pepper {
        ikm.extend_from_slice(pepper);
    }

    let hk = Hkdf::<Sha3_256>::new(Some(salt), &*ikm);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(b"QuantumARKv4-HybridKey", &mut *okm)
        .map_err(|e| format!("Error en derivación HKDF: {:?}", e))?;

    Ok(okm)
}

// ────────────────────────────────────────────────────────────────────────
//  PAQUETES DE CIFRADO Y DESCIFRADO (QARQ 4.0)
// ────────────────────────────────────────────────────────────────────────

/// Crea un paquete cifrado autocontenido con Forward Secrecy.
fn create_package(
    data: &[u8],
    filename: &str,
    recipient_public_key_json: &[u8],
    password: Option<&str>,
    hardware_pepper_active: bool,
    ttl_seconds: Option<u64>,
    metadata_clean: bool,
) -> Result<Vec<u8>, String> {
    // 1. Limpieza opcional de metadatos EXIF
    let mut data_to_encrypt = Zeroizing::new(data.to_vec());
    if metadata_clean {
        crate::utils::metadata::clean_file_metadata_in_memory(&mut data_to_encrypt, filename)?;
    }

    let original_size = data_to_encrypt.len() as u64;

    // 2. Hash SHA3-256 original
    let mut hasher = Sha3_256::new();
    hasher.update(&*data_to_encrypt);
    let sha3_checksum = hex::encode(hasher.finalize());

    // 3. Comprimir
    let compressed_data = compress_data(&*data_to_encrypt)?;
    let compressed_size = compressed_data.len() as u64;
    drop(data_to_encrypt); // Liberación segura en plaintext

    // 4. Clave efímera (Forward Secrecy)
    let (ephem_pub_json, ephem_sec_json) = generate_pqc_keypair()?;

    // 5. Encapsulación KEM (Destinatario + Efímero)
    let (ct_recip, ss_recip) = encapsulate_secret(recipient_public_key_json)?;
    let (ct_ephem, ss_ephem) = encapsulate_secret(&ephem_pub_json)?;

    let mut shared_secret = Zeroizing::new(Vec::new());
    shared_secret.extend_from_slice(&ss_recip);
    shared_secret.extend_from_slice(&ss_ephem);

    // 6. Generar nonces y salt
    let mut salt = [0u8; 32];
    let mut ephem_nonce_bytes = [0u8; 12];
    let mut payload_nonce_bytes = [0u8; 12];
    let mut meta_nonce_bytes = [0u8; 12];
    
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut ephem_nonce_bytes);
    OsRng.fill_bytes(&mut payload_nonce_bytes);
    OsRng.fill_bytes(&mut meta_nonce_bytes);

    // 7. Cifrar la clave privada efímera usando el password derivado con Argon2
    let pwd_str = password.unwrap_or("");
    let protection_key = derive_argon2_key(pwd_str, &salt)?;
    let cipher_ephem = ChaCha20Poly1305::new(&protection_key.into());
    let encrypted_ephem_sk = cipher_ephem
        .encrypt(Nonce::from_slice(&ephem_nonce_bytes), ephem_sec_json.as_slice())
        .map_err(|e| format!("Error al cifrar clave de sesión efímera: {}", e))?;

    // 8. Host Hardware Pepper
    let host_pepper = if hardware_pepper_active {
        Some(crate::crypto::pepper::get_hardware_pepper()?)
    } else {
        None
    };

    // 9. Derivar clave de cifrado simétrico híbrido
    let encryption_key = derive_hybrid_encryption_key(&*shared_secret, password, &salt, host_pepper.as_deref())?;

    // 10. Cifrar metadatos
    let decrypt_until = ttl_seconds.map(|secs| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() + secs
      });

    let metadata = SecureFileMetadata {
        filename: filename.to_string(),
        original_size,
        compressed_size,
        sha3_256_checksum: sha3_checksum,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64(),
        version: "4.0.0".to_string(),
        algorithm: "PQC-Hybrid-ML-KEM1024-Dilithium5-ForwardSecrecy-ChaCha20Poly1305".to_string(),
        decrypt_until,
    };

    let metadata_json = serde_json::to_vec(&metadata).map_err(|e| e.to_string())?;
    let cipher = ChaCha20Poly1305::new((&*encryption_key).into());
    
    let encrypted_metadata = cipher
        .encrypt(Nonce::from_slice(&meta_nonce_bytes), metadata_json.as_slice())
        .map_err(|e| format!("Error al cifrar metadatos: {}", e))?;

    // 11. Cifrar payload comprimido
    let encrypted_payload = cipher
        .encrypt(Nonce::from_slice(&payload_nonce_bytes), compressed_data.as_slice())
        .map_err(|e| format!("Error al cifrar payload: {}", e))?;

    // 12. Signal-style padding
    let padding_len = signal_style_padding_len(encrypted_payload.len());
    let mut padding = vec![0u8; padding_len];
    OsRng.fill_bytes(&mut padding);

    // 13. Empaquetar bloque
    let mut pkg = Vec::new();
    pkg.extend_from_slice(&(ct_recip.len() as u32).to_le_bytes());
    pkg.extend_from_slice(&ct_recip);

    pkg.extend_from_slice(&(ct_ephem.len() as u32).to_le_bytes());
    pkg.extend_from_slice(&ct_ephem);

    pkg.extend_from_slice(&(encrypted_ephem_sk.len() as u32).to_le_bytes());
    pkg.extend_from_slice(&encrypted_ephem_sk);

    pkg.extend_from_slice(&ephem_nonce_bytes);
    pkg.extend_from_slice(&salt);
    pkg.extend_from_slice(&payload_nonce_bytes);
    pkg.extend_from_slice(&meta_nonce_bytes);

    pkg.extend_from_slice(&(encrypted_metadata.len() as u32).to_le_bytes());
    pkg.extend_from_slice(&encrypted_metadata);

    pkg.extend_from_slice(&encrypted_payload);
    pkg.extend_from_slice(&padding);

    padding.zeroize();
    Ok(pkg)
}

/// Descifra un paquete cifrado autocontenido con Forward Secrecy.
fn decrypt_package(
    package_bytes: &[u8],
    recipient_private_key_json: &[u8],
    password: Option<&str>,
    hardware_pepper_active: bool,
) -> Result<(Vec<u8>, SecureFileMetadata), String> {
    if package_bytes.len() < 100 {
        return Err("Datos del paquete cifrado corruptos o demasiado pequeños".to_string());
    }

    let mut cursor = 0;

    // KEM de destinatario
    let ct_recip_len = u32::from_le_bytes(package_bytes[cursor..cursor+4].try_into().unwrap()) as usize;
    cursor += 4;
    if cursor + ct_recip_len > package_bytes.len() { return Err("Paquete corrupto (recip ct)".to_string()); }
    let ct_recip = &package_bytes[cursor..cursor+ct_recip_len];
    cursor += ct_recip_len;

    // KEM efímero
    let ct_ephem_len = u32::from_le_bytes(package_bytes[cursor..cursor+4].try_into().unwrap()) as usize;
    cursor += 4;
    if cursor + ct_ephem_len > package_bytes.len() { return Err("Paquete corrupto (ephem ct)".to_string()); }
    let ct_ephem = &package_bytes[cursor..cursor+ct_ephem_len];
    cursor += ct_ephem_len;

    // Llave privada efímera cifrada
    let enc_ephem_sk_len = u32::from_le_bytes(package_bytes[cursor..cursor+4].try_into().unwrap()) as usize;
    cursor += 4;
    if cursor + enc_ephem_sk_len > package_bytes.len() { return Err("Paquete corrupto (enc ephem sk)".to_string()); }
    let encrypted_ephem_sk = &package_bytes[cursor..cursor+enc_ephem_sk_len];
    cursor += enc_ephem_sk_len;

    // Nonces y salt
    if cursor + 68 > package_bytes.len() { return Err("Paquete corrupto (nonces y salt)".to_string()); }
    let ephem_nonce_bytes = &package_bytes[cursor..cursor+12]; cursor += 12;
    let salt = &package_bytes[cursor..cursor+32]; cursor += 32;
    let payload_nonce_bytes = &package_bytes[cursor..cursor+12]; cursor += 12;
    let meta_nonce_bytes = &package_bytes[cursor..cursor+12]; cursor += 12;

    // Metadatos cifrados
    let meta_len = u32::from_le_bytes(package_bytes[cursor..cursor+4].try_into().unwrap()) as usize;
    cursor += 4;
    if cursor + meta_len > package_bytes.len() { return Err("Paquete corrupto (metadata)".to_string()); }
    let encrypted_metadata = &package_bytes[cursor..cursor+meta_len];
    cursor += meta_len;

    // Payload cifrado + padding
    let encrypted_payload_and_padding = &package_bytes[cursor..];

    // 1. Descifrar la clave privada efímera
    let pwd_str = password.unwrap_or("");
    let protection_key = derive_argon2_key(pwd_str, salt)?;
    let cipher_ephem = ChaCha20Poly1305::new(&protection_key.into());
    let ephemeral_private_key_json = cipher_ephem
        .decrypt(Nonce::from_slice(ephem_nonce_bytes), encrypted_ephem_sk)
        .map_err(|e| format!("Contraseña incorrecta (no se pudo abrir la llave efímera): {}", e))?;

    // 2. Desencapsular secretos compartidos
    let ss_recip = decapsulate_secret(recipient_private_key_json, ct_recip)?;
    let ss_ephem = decapsulate_secret(&ephemeral_private_key_json, ct_ephem)?;

    let mut shared_secret = Zeroizing::new(Vec::new());
    shared_secret.extend_from_slice(&ss_recip);
    shared_secret.extend_from_slice(&ss_ephem);

    // 3. Host Hardware Pepper
    let host_pepper = if hardware_pepper_active {
        Some(crate::crypto::pepper::get_hardware_pepper()?)
    } else {
        None
    };

    // 4. Derivar clave simétrica híbrida
    let encryption_key = derive_hybrid_encryption_key(&*shared_secret, password, salt, host_pepper.as_deref())?;

    // 5. Descifrar metadatos
    let cipher = ChaCha20Poly1305::new((&*encryption_key).into());
    let decrypted_metadata_json = cipher
        .decrypt(Nonce::from_slice(meta_nonce_bytes), encrypted_metadata)
        .map_err(|e| format!("Contraseña incorrecta o firma corrupta en metadatos: {}", e))?;

    let metadata: SecureFileMetadata = serde_json::from_slice(&decrypted_metadata_json)
        .map_err(|e| format!("Error de deserialización en metadatos: {}", e))?;

    // 6. Validar TTL (Time-to-Live)
    if let Some(ttl) = metadata.decrypt_until {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if now > ttl {
            return Err("El tiempo de vida (TTL) de este archivo ha expirado. Operación de descifrado rechazada.".to_string());
        }
    }

    // 7. Descifrar payload
    let expected_payload_len = (metadata.compressed_size + 16) as usize;
    if encrypted_payload_and_padding.len() < expected_payload_len {
        return Err("Payload cifrado corrupto o de tamaño inconsistente".to_string());
    }

    let encrypted_payload = &encrypted_payload_and_padding[0..expected_payload_len];
    let decrypted_compressed = cipher
        .decrypt(Nonce::from_slice(payload_nonce_bytes), encrypted_payload)
        .map_err(|e| format!("Error en payload cifrado (AEAD fallido): {}", e))?;

    // 8. Descomprimir y verificar integridad
    let decompressed = decompress_data(&decrypted_compressed)?;
    
    let mut hasher = Sha3_256::new();
    hasher.update(&decompressed);
    let sha3_checksum = hex::encode(hasher.finalize());

    if sha3_checksum != metadata.sha3_256_checksum {
        return Err("Fallo de integridad: Checksum SHA3-256 no coincide.".to_string());
    }

    Ok((decompressed, metadata))
}

// ────────────────────────────────────────────────────────────────────────
//  CIFRADO COMPLETO PQC (QuantumARK v4.0)
// ────────────────────────────────────────────────────────────────────────

pub fn encrypt_file_pqc_complete(
    input_path: &Path,
    public_key_json: &[u8],
    sender_private_key_json: &[u8],
    password: Option<&str>,
    delete_original: bool,
    shred_passes: u8,
    metadata_clean: bool,
    // v4.0 features
    hardware_pepper: bool,
    ttl_seconds: Option<u64>,
    decoy_file_path: Option<&Path>,
    decoy_password: Option<&str>,
    obfuscate_filename: bool,
    fragmentation: Option<(usize, usize)>, // (data_shards, parity_shards)
) -> Result<(String, String, String), String> {
    if !input_path.exists() {
        return Err("El archivo de entrada no existe".to_string());
    }

    // 1. Cargar archivo original
    let original_bytes = fs::read(input_path)
        .map_err(|e| format!("Error al leer el archivo original: {}", e))?;

    let filename = input_path.file_name()
        .and_then(|n| n.to_str())
        .ok_or("Nombre de archivo original inválido")?;

    // 2. Hash SHA3-256 de entrada para reporte
    let mut hasher = Sha3_256::new();
    hasher.update(&original_bytes);
    let input_hash = hex::encode(hasher.finalize());

    // 3. Crear paquete principal
    let primary_package = create_package(
        &original_bytes,
        filename,
        public_key_json,
        password,
        hardware_pepper,
        ttl_seconds,
        metadata_clean,
    )?;

    // 4. Crear paquete señuelo (Duress Password) si aplica
    let decoy_active = decoy_file_path.is_some();
    let decoy_package = if let Some(decoy_path) = decoy_file_path {
        if !decoy_path.exists() {
            return Err("El archivo señuelo especificado no existe".to_string());
        }
        let decoy_bytes = fs::read(decoy_path)
            .map_err(|e| format!("Error al leer el archivo señuelo: {}", e))?;
        let decoy_name = decoy_path.file_name()
            .and_then(|n| n.to_str())
            .ok_or("Nombre de archivo señuelo inválido")?;

        let pkg = create_package(
            &decoy_bytes,
            decoy_name,
            public_key_json,
            decoy_password,
            hardware_pepper,
            ttl_seconds,
            false, // no limpiar metadatos en señuelo para acelerar
        )?;
        Some(pkg)
    } else {
        None
    };

    // 5. Ensamblar cuerpo del archivo
    let mut file_body = Vec::new();
    file_body.extend_from_slice(b"QARQ4.0\x00"); // Magic Header v4.0

    // Flags (4 bytes)
    file_body.push(hardware_pepper as u8);
    file_body.push(ttl_seconds.is_some() as u8);
    file_body.push(decoy_active as u8);
    file_body.push(obfuscate_filename as u8);

    // Duress active flag (1 byte)
    file_body.push(decoy_active as u8);

    if let Some(decoy_pkg) = decoy_package {
        let prim_len = primary_package.len() as u32;
        let dec_len = decoy_pkg.len() as u32;

        file_body.extend_from_slice(&prim_len.to_le_bytes());
        file_body.extend_from_slice(&primary_package);
        
        file_body.extend_from_slice(&dec_len.to_le_bytes());
        file_body.extend_from_slice(&decoy_pkg);
    } else {
        file_body.extend_from_slice(&primary_package);
    }

    // 6. Firmar cuerpo usando Dilithium-5
    let signature = sign_data(sender_private_key_json, &file_body)?;
    file_body.extend_from_slice(&signature);

    // 7. Determinar ruta de salida y guardar
    let output_dir = input_path.parent().unwrap_or_else(|| Path::new("."));
    
    let final_name = if obfuscate_filename {
        let mut rand_bytes = [0u8; 16];
        OsRng.fill_bytes(&mut rand_bytes);
        format!("{}.qarq", hex::encode(rand_bytes))
    } else {
        format!("{}.qarq", filename)
    };

    let output_path = output_dir.join(final_name);
    let output_path_str = output_path.to_string_lossy().to_string();

    // 8. Manejar fragmentación o escritura directa
    let final_returned_path = if let Some((data, parity)) = fragmentation {
        let fragments = crate::crypto::fragment::fragment_data(&file_body, data, parity)?;
        
        for (i, frag) in fragments.iter().enumerate() {
            let part_path = output_dir.join(format!("{}.part{}", output_path.file_name().unwrap().to_str().unwrap(), i + 1));
            fs::write(part_path, frag).map_err(|e| format!("Error al escribir fragmento {}: {}", i + 1, e))?;
        }
        format!("{}.part1 (fragmentado: {} datos, {} paridad)", output_path_str, data, parity)
    } else {
        fs::write(&output_path, &file_body)
            .map_err(|e| format!("Error al escribir el archivo cifrado final: {}", e))?;
        output_path_str
    };

    // Hash SHA3-256 del archivo cifrado
    let output_hash = compute_hash_bytes(&file_body, "sha3-256")?;

    // 9. Trituración segura del archivo original si se solicita
    if delete_original {
        secure_shred(input_path, shred_passes)?;
    }

    Ok((final_returned_path, input_hash, output_hash))
}

// ────────────────────────────────────────────────────────────────────────
//  DESCIFRADO COMPLETO PQC (QuantumARK v4.0)
// ────────────────────────────────────────────────────────────────────────

pub fn decrypt_file_pqc(
    input_path: &Path,
    recipient_private_key_json: &[u8],
    sender_public_key_json: &[u8],
    password: Option<&str>,
) -> Result<(String, String), String> {
    // 1. Detectar auto-reconstrucción de fragmentos si es necesario
    let file_stem = input_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    
    let file_data = if file_stem.contains(".part") {
        crate::crypto::fragment::auto_reconstruct_from_any_part(input_path)?
    } else {
        if !input_path.exists() {
            return Err("El archivo cifrado no existe".to_string());
        }
        fs::read(input_path).map_err(|e| format!("Error al leer el archivo cifrado: {}", e))?
    };

    let file_len = file_data.len();
    if file_len < 8 {
        return Err("Archivo corrupto o incompleto".to_string());
    }

    // 1. Validar cabecera y versión inmediatamente
    let header = &file_data[0..8];
    if header == b"QARQ3.0\x00" || header == b"QARQ3.1\x00" {
        return Err("Archivo cifrado con versión anterior. Usa BlackPrism v3.1 para descifrar.".to_string());
    }
    if header != b"QARQ4.0\x00" {
        return Err("Formato de cabecera inválido en el archivo .qarq".to_string());
    }

    if file_len < 4627 + 13 {
        return Err("Archivo corrupto o incompleto".to_string());
    }

    // 2. Extraer y verificar firma Dilithium-5
    let signature_start = file_len - 4627;
    let file_body = &file_data[0..signature_start];
    let signature = &file_data[signature_start..];

    let is_valid_signature = verify_signature(sender_public_key_json, file_body, signature);
    if !is_valid_signature {
        return Err("¡Firma Dilithium5 INVÁLIDA! El archivo ha sido manipulado o proviene de una fuente no autorizada.".to_string());
    }

    // Leer flags
    let hardware_pepper_active = file_body[8] == 1;
    let decoy_active = file_body[12] == 1;

    let primary_package;
    let decoy_package;

    if decoy_active {
        let mut cursor = 13;
        if cursor + 8 > file_body.len() { return Err("Archivo QARQ4.0 corrupto".to_string()); }

        let prim_len = u32::from_le_bytes(file_body[cursor..cursor+4].try_into().unwrap()) as usize;
        cursor += 4;
        if cursor + prim_len > file_body.len() { return Err("Archivo QARQ4.0 corrupto (prim pkg)".to_string()); }
        primary_package = &file_body[cursor..cursor+prim_len];
        cursor += prim_len;

        let dec_len = u32::from_le_bytes(file_body[cursor..cursor+4].try_into().unwrap()) as usize;
        cursor += 4;
        if cursor + dec_len > file_body.len() { return Err("Archivo QARQ4.0 corrupto (decoy pkg)".to_string()); }
        decoy_package = Some(&file_body[cursor..cursor+dec_len]);
    } else {
        primary_package = &file_body[13..];
        decoy_package = None;
    }

    // 4. Intentar descifrar el paquete principal
    let primary_decrypt_result = decrypt_package(
        primary_package,
        recipient_private_key_json,
        password,
        hardware_pepper_active,
    );

    let (decrypted_bytes, metadata) = match primary_decrypt_result {
        Ok(res) => res,
        Err(primary_err) => {
            // Si falla el principal y hay señuelo, intentar descifrar el señuelo de forma transparente
            if let Some(decoy_pkg) = decoy_package {
                match decrypt_package(decoy_pkg, recipient_private_key_json, password, hardware_pepper_active) {
                    Ok(decoy_res) => decoy_res,
                    Err(_) => {
                        // Si ambos fallan, retornar el error del principal original
                        return Err(primary_err);
                    }
                }
            } else {
                return Err(primary_err);
            }
        }
    };

    // 5. Escribir archivo descifrado restaurando el nombre real
    let output_dir = input_path.parent().unwrap_or_else(|| Path::new("."));
    let mut output_path = output_dir.join(&metadata.filename);

    let mut counter = 1;
    let stem = output_path.file_stem().unwrap().to_string_lossy().to_string();
    let ext = output_path.extension().unwrap_or_default().to_string_lossy().to_string();

    while output_path.exists() {
        let new_name = if ext.is_empty() {
            format!("{}_({})", stem, counter)
        } else {
            format!("{}_({}).{}", stem, counter, ext)
        };
        output_path = output_dir.join(new_name);
        counter += 1;
    }

    fs::write(&output_path, &decrypted_bytes)
        .map_err(|e| format!("Error al escribir archivo descifrado: {}", e))?;

    let output_hash = compute_file_hash(&output_path, "sha3-256")?;

    Ok((output_path.to_string_lossy().to_string(), output_hash))
}

// ────────────────────────────────────────────────────────────────────────
//  LEGACY
// ────────────────────────────────────────────────────────────────────────

#[allow(dead_code)]
pub fn encrypt_file(
    _input_path: &Path,
    _public_key_json: &[u8],
    _password: Option<&str>,
    _delete_original: bool,
    _shred_passes: u8,
    _metadata_clean: bool,
) -> Result<String, String> {
    Err("encrypt_file está deshabilitada. Usa encrypt_file_pqc_complete.".to_string())
}
