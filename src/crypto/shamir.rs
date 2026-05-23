use sharks::{Sharks, Share};
use std::convert::TryFrom;

/// Divide un secreto en N partes (shares), requiriendo un umbral M (threshold) para la reconstrucción.
/// Retorna una lista de strings hexadecimales que representan cada parte.
pub fn split_secret(secret: &[u8], threshold: u8, total_shares: u8) -> Result<Vec<String>, String> {
    if threshold == 0 || total_shares == 0 {
        return Err("El umbral (threshold) y las partes totales deben ser mayores a 0".to_string());
    }
    if threshold > total_shares {
        return Err("El umbral (threshold) no puede ser mayor que las partes totales".to_string());
    }


    let sharks = Sharks(threshold);
    let dealer = sharks.dealer(secret);
    
    let shares: Vec<String> = dealer
        .take(total_shares as usize)
        .map(|share| {
            let bytes = Vec::from(&share);
            hex::encode(bytes)
        })
        .collect();

    Ok(shares)
}

/// Reconstruye el secreto original a partir de un conjunto de partes hexadecimales.
pub fn recover_secret(shares_hex: &[String], threshold: u8) -> Result<Vec<u8>, String> {
    if shares_hex.len() < threshold as usize {
        return Err(format!(
            "Se proporcionaron {} partes, pero se requiere un umbral de {} partes para la reconstrucción",
            shares_hex.len(),
            threshold
        ));
    }

    let mut shares = Vec::new();
    for share_hex in shares_hex {
        let bytes = hex::decode(share_hex)
            .map_err(|e| format!("Error al decodificar parte hex '{}': {}", share_hex, e))?;
        
        let share = Share::try_from(bytes.as_slice())
            .map_err(|e| format!("Formato de parte inválido para '{}': {}", share_hex, e))?;
        
        shares.push(share);
    }

    let sharks = Sharks(threshold);
    let secret = sharks.recover(&shares)
        .map_err(|e| format!("Error al reconstruir el secreto (las partes pueden estar corruptas o incompletas): {}", e))?;

    Ok(secret)
}
