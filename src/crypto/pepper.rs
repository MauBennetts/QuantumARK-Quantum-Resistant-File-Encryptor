use machine_uid;
use sha3::{Sha3_256, Digest};

/// Obtiene un "pepper" único del hardware de la máquina.
/// Este pepper se basa en el UUID único del sistema provisto por el OS
/// y se hashea con SHA3-256 para mayor privacidad.
pub fn get_hardware_pepper() -> Result<Vec<u8>, String> {
    let uid = machine_uid::get()
        .map_err(|e| format!("Error al obtener el identificador único del hardware: {}", e))?;
    
    let mut hasher = Sha3_256::new();
    hasher.update(uid.as_bytes());
    Ok(hasher.finalize().to_vec())
}
