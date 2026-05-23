use reed_solomon_erasure::galois_8::ReedSolomon;
use std::fs;
use std::path::Path;

const PART_MAGIC: &[u8; 8] = b"QARQPART";

#[derive(Debug, Clone)]
pub struct PartHeader {
    pub index: u8,
    pub total_parts: u8,
    pub data_shards: u8,
    pub parity_shards: u8,
    pub original_size: u64,
}

/// Divide un stream de bytes en fragmentos de datos y paridad con codificación Reed-Solomon.
/// Cada fragmento incluye una cabecera autocontenida que facilita la reconstrucción.
pub fn fragment_data(
    data: &[u8],
    data_shards: usize,
    parity_shards: usize,
) -> Result<Vec<Vec<u8>>, String> {
    if data_shards == 0 || parity_shards == 0 {
        return Err("Los fragmentos de datos y paridad deben ser mayores que 0".to_string());
    }
    let total_shards = data_shards + parity_shards;
    if total_shards > 255 {
        return Err("El total de fragmentos (datos + paridad) no puede exceder 255".to_string());
    }

    // Calcular tamaño de cada fragmento (ceiling division)
    let shard_size = (data.len() + data_shards - 1) / data_shards;
    if shard_size == 0 {
        return Err("Los datos a fragmentar están vacíos o el tamaño de fragmento es 0".to_string());
    }

    // Construir vector de fragmentos
    let mut shards = vec![vec![0u8; shard_size]; total_shards];

    // Llenar fragmentos de datos
    for i in 0..data_shards {
        let start = i * shard_size;
        if start < data.len() {
            let end = std::cmp::min(start + shard_size, data.len());
            shards[i][..end - start].copy_from_slice(&data[start..end]);
        }
    }

    // Ejecutar codificación Reed-Solomon
    let r = ReedSolomon::new(data_shards, parity_shards)
        .map_err(|e| format!("Error al inicializar ReedSolomon: {}", e))?;
    r.encode(&mut shards)
        .map_err(|e| format!("Error en codificación Reed-Solomon: {}", e))?;

    // Empaquetar cada fragmento con su cabecera
    let original_size = data.len() as u64;
    let mut packed_shards = Vec::new();

    for (index, shard) in shards.into_iter().enumerate() {
        let mut packed = Vec::new();
        packed.extend_from_slice(PART_MAGIC);
        packed.push(index as u8);
        packed.push(total_shards as u8);
        packed.push(data_shards as u8);
        packed.push(parity_shards as u8);
        packed.extend_from_slice(&original_size.to_le_bytes());
        packed.extend_from_slice(&shard);
        packed_shards.push(packed);
    }

    Ok(packed_shards)
}

/// Parsea un archivo fragmento recuperando su cabecera y el contenido bruto del shard.
pub fn parse_part_data(part_bytes: &[u8]) -> Result<(PartHeader, Vec<u8>), String> {
    if part_bytes.len() < 20 {
        return Err("Tamaño de fragmento inválido (demasiado pequeño)".to_string());
    }

    if &part_bytes[0..8] != PART_MAGIC {
        return Err("Cabecera de fragmento inválida o no coincide".to_string());
    }

    let index = part_bytes[8];
    let total_parts = part_bytes[9];
    let data_shards = part_bytes[10];
    let parity_shards = part_bytes[11];
    
    let mut size_bytes = [0u8; 8];
    size_bytes.copy_from_slice(&part_bytes[12..20]);
    let original_size = u64::from_le_bytes(size_bytes);

    let shard_data = part_bytes[20..].to_vec();

    Ok((
        PartHeader {
            index,
            total_parts,
            data_shards,
            parity_shards,
            original_size,
        },
        shard_data,
    ))
}

/// Escanea el directorio de un archivo fragmento seleccionado para localizar otros fragmentos de la misma serie,
/// reconstruyendo el stream de bytes original de forma automática si se alcanza el umbral de fragmentos de datos.
pub fn auto_reconstruct_from_any_part(selected_part_path: &Path) -> Result<Vec<u8>, String> {
    if !selected_part_path.exists() {
        return Err("El archivo fragmento seleccionado no existe".to_string());
    }

    // Leer el fragmento inicial para aprender la estructura
    let part_data = fs::read(selected_part_path)
        .map_err(|e| format!("Error al leer el fragmento: {}", e))?;
    let (header, _) = parse_part_data(&part_data)?;

    let directory = selected_part_path.parent().ok_or("Directorio padre inválido")?;
    let file_stem = selected_part_path.file_name()
        .and_then(|n| n.to_str())
        .ok_or("Nombre de archivo fragmento inválido")?;

    // El nombre de archivo base suele terminar en .partX
    let base_name = if let Some(idx) = file_stem.rfind(".part") {
        &file_stem[..idx]
    } else {
        file_stem
    };

    let total_parts = header.total_parts as usize;
    let data_shards = header.data_shards as usize;
    let parity_shards = header.parity_shards as usize;
    let original_size = header.original_size;

    let mut recovery: Vec<Option<Vec<u8>>> = vec![None; total_parts];
    let mut shards_present_count = 0;

    // Escanear el directorio para encontrar todos los fragmentos correspondientes
    for entry in fs::read_dir(directory).map_err(|e| format!("Error leyendo directorio: {}", e))? {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        if path.is_file() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.starts_with(base_name) && name.contains(".part") {
                if let Ok(bytes) = fs::read(&path) {
                    if let Ok((p_header, p_data)) = parse_part_data(&bytes) {
                        let idx = p_header.index as usize;
                        if idx < total_parts && recovery[idx].is_none() {
                            recovery[idx] = Some(p_data);
                            shards_present_count += 1;
                        }
                    }
                }
            }
        }
    }

    if shards_present_count < data_shards {
        return Err(format!(
            "Fragmentos insuficientes para la reconstrucción. Se encontraron {} fragmentos de los {} necesarios.",
            shards_present_count, data_shards
        ));
    }

    // Reconstruir los fragmentos
    let r = ReedSolomon::new(data_shards, parity_shards)
        .map_err(|e| format!("Error al inicializar ReedSolomon: {}", e))?;
    
    r.reconstruct(&mut recovery)
        .map_err(|e| format!("Error durante la reconstrucción Reed-Solomon: {}", e))?;

    // Ensamblar el archivo original
    let mut reconstructed_data = Vec::new();
    for i in 0..data_shards {
        if let Some(shard) = &recovery[i] {
            reconstructed_data.extend_from_slice(shard);
        } else {
            return Err("Reconstrucción fallida: fragmento de datos ausente después de proceso".to_string());
        }
    }

    // Truncar al tamaño original
    if reconstructed_data.len() < original_size as usize {
        return Err("Los datos reconstruidos son más pequeños que el tamaño original especificado en cabecera".to_string());
    }
    reconstructed_data.truncate(original_size as usize);

    Ok(reconstructed_data)
}
