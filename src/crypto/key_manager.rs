use pqcrypto_kyber::kyber1024::{
    self as kyber, PublicKey as KyberPubKey, SecretKey as KyberSecKey,
};
use pqcrypto_dilithium::dilithium5::{
    self as dilithium, PublicKey as DilithiumPubKey, SecretKey as DilithiumSecKey,
};

// Importar los traits necesarios con nombres diferenciados para evitar colisiones
use pqcrypto_traits::kem::{
    PublicKey as KemPublicKey, SecretKey as KemSecretKey, SharedSecret as KemSharedSecret, Ciphertext as KemCiphertext,
};
use pqcrypto_traits::sign::{
    PublicKey as SignPublicKey, SecretKey as SignSecretKey, DetachedSignature as SignSignature,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use argon2::Argon2;
use rand::{rngs::OsRng, RngCore};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct PQCKeyPairHex {
    pub kem_public: String,
    pub sig_public: String,
    pub kem_algorithm: String,
    pub sig_algorithm: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PQCPrivateKeyHex {
    pub kem_private: String,
    pub sig_private: String,
    pub kem_algorithm: String,
    pub sig_algorithm: String,
}

/// Genera un par de llaves post-cuánticas (Kyber1024 y Dilithium5).
/// Retorna (public_key_json_bytes, private_key_json_bytes).
pub fn generate_pqc_keypair() -> Result<(Vec<u8>, Vec<u8>), String> {
    // Generar claves KEM (Kyber1024)
    let (kem_pub, kem_sec) = kyber::keypair();
    
    // Generar claves de Firma (Dilithium5)
    let (sig_pub, sig_sec) = dilithium::keypair();

    let public_key_data = PQCKeyPairHex {
        kem_public: hex::encode(KemPublicKey::as_bytes(&kem_pub)),
        sig_public: hex::encode(SignPublicKey::as_bytes(&sig_pub)),
        kem_algorithm: "Kyber1024".to_string(),
        sig_algorithm: "Dilithium5".to_string(),
    };

    let private_key_data = PQCPrivateKeyHex {
        kem_private: hex::encode(KemSecretKey::as_bytes(&kem_sec)),
        sig_private: hex::encode(SignSecretKey::as_bytes(&sig_sec)),
        kem_algorithm: "Kyber1024".to_string(),
        sig_algorithm: "Dilithium5".to_string(),
    };

    let pub_json = serde_json::to_vec(&public_key_data).map_err(|e| e.to_string())?;
    let sec_json = serde_json::to_vec(&private_key_data).map_err(|e| e.to_string())?;

    Ok((pub_json, sec_json))
}

/// Deriva una clave de 256 bits usando Argon2id a partir de una contraseña.
pub fn derive_argon2_key(password: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    let mut derived_key = [0u8; 32];
    let argon2 = Argon2::default();
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut derived_key)
        .map_err(|e| format!("Error en Argon2id: {}", e))?;
    Ok(derived_key)
}

/// Protege la clave privada cifrándola usando Argon2id y ChaCha20-Poly1305.
/// El formato resultante es: salt (32B) + nonce (12B) + ciphertext
pub fn protect_private_key(private_key_json: &[u8], password: &str) -> Result<Vec<u8>, String> {
    // Generar salt y nonce aleatorios
    let mut salt = [0u8; 32];
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce_bytes);

    // Derivar clave con Argon2id
    let protection_key = derive_argon2_key(password, &salt)?;

    // Cifrar con ChaCha20-Poly1305
    let cipher = ChaCha20Poly1305::new(&protection_key.into());
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, private_key_json)
        .map_err(|e| format!("Error al cifrar clave privada: {}", e))?;

    // Empaquetar: salt + nonce + ciphertext
    let mut protected_data = Vec::new();
    protected_data.extend_from_slice(&salt);
    protected_data.extend_from_slice(&nonce_bytes);
    protected_data.extend_from_slice(&ciphertext);

    Ok(protected_data)
}

/// Desprotege la clave privada usando la contraseña proporcionada.
pub fn unprotect_private_key(protected_data: &[u8], password: &str) -> Result<Vec<u8>, String> {
    if protected_data.len() < 44 {
        return Err("Datos de clave protegida corruptos o incompletos".to_string());
    }

    let salt = &protected_data[0..32];
    let nonce_bytes = &protected_data[32..44];
    let ciphertext = &protected_data[44..];

    // Derivar clave de protección
    let protection_key = derive_argon2_key(password, salt)?;

    // Descifrar con ChaCha20-Poly1305
    let cipher = ChaCha20Poly1305::new(&protection_key.into());
    let nonce = Nonce::from_slice(nonce_bytes);
    let decrypted_key = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("Contraseña incorrecta o clave corrupta: {}", e))?;

    Ok(decrypted_key)
}

/// Encapsula un secreto compartido usando Kyber1024 a partir de los bytes de clave pública JSON.
/// Retorna (ciphertext_bytes, shared_secret_bytes).
pub fn encapsulate_secret(public_key_json: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let key_data: PQCKeyPairHex = serde_json::from_slice(public_key_json)
        .map_err(|e| format!("Formato de clave pública inválido: {}", e))?;

    let kem_pub_bytes = hex::decode(&key_data.kem_public)
        .map_err(|e| format!("Error al decodificar llave KEM: {}", e))?;

    let pubkey: KyberPubKey = KemPublicKey::from_bytes(&kem_pub_bytes)
        .map_err(|e| format!("Llave KEM Kyber1024 inválida: {}", e))?;

    let (ss, ct) = kyber::encapsulate(&pubkey);

    Ok((
        KemCiphertext::as_bytes(&ct).to_vec(),
        KemSharedSecret::as_bytes(&ss).to_vec()
    ))
}

/// Desencapsula un secreto compartido usando Kyber1024 a partir de los bytes de clave privada JSON.
pub fn decapsulate_secret(private_key_json: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let key_data: PQCPrivateKeyHex = serde_json::from_slice(private_key_json)
        .map_err(|e| format!("Formato de clave privada inválido: {}", e))?;

    let kem_priv_bytes = hex::decode(&key_data.kem_private)
        .map_err(|e| format!("Error al decodificar llave KEM privada: {}", e))?;

    let seckey: KyberSecKey = KemSecretKey::from_bytes(&kem_priv_bytes)
        .map_err(|e| format!("Llave KEM Kyber1024 privada inválida: {}", e))?;

    let ct = KemCiphertext::from_bytes(ciphertext)
        .map_err(|e| format!("Ciphertext Kyber1024 corrupto: {}", e))?;

    let ss = kyber::decapsulate(&ct, &seckey);

    Ok(KemSharedSecret::as_bytes(&ss).to_vec())
}

/// Firma datos usando Dilithium5 a partir de los bytes de la clave privada JSON.
pub fn sign_data(private_key_json: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    let key_data: PQCPrivateKeyHex = serde_json::from_slice(private_key_json)
        .map_err(|e| format!("Formato de clave privada inválido: {}", e))?;

    let sig_priv_bytes = hex::decode(&key_data.sig_private)
        .map_err(|e| format!("Error al decodificar llave de firma privada: {}", e))?;

    let seckey: DilithiumSecKey = SignSecretKey::from_bytes(&sig_priv_bytes)
        .map_err(|e| format!("Llave Dilithium5 privada inválida: {}", e))?;

    let sig = dilithium::detached_sign(data, &seckey);

    Ok(SignSignature::as_bytes(&sig).to_vec())
}

/// Verifica una firma digital de Dilithium5 a partir de los bytes de la clave pública JSON.
pub fn verify_signature(public_key_json: &[u8], data: &[u8], signature_bytes: &[u8]) -> bool {
    let key_data: PQCKeyPairHex = match serde_json::from_slice(public_key_json) {
        Ok(k) => k,
        Err(_) => return false,
    };

    let sig_pub_bytes = match hex::decode(&key_data.sig_public) {
        Ok(b) => b,
        Err(_) => return false,
    };

    let pubkey: DilithiumPubKey = match SignPublicKey::from_bytes(&sig_pub_bytes) {
        Ok(pk) => pk,
        Err(_) => return false,
    };

    let signature = match SignSignature::from_bytes(signature_bytes) {
        Ok(sig) => sig,
        Err(_) => return false,
    };

    dilithium::verify_detached_signature(&signature, data, &pubkey).is_ok()
}
