
/// Limpia metadatos en memoria según el tipo de archivo (JPEG, PNG).
/// Si no es una imagen soportada, se deja intacto para el cifrado genérico.
pub fn clean_file_metadata_in_memory(data: &mut Vec<u8>, filename: &str) -> Result<(), String> {
    let lower_name = filename.to_lowercase();
    if lower_name.ends_with(".jpg") || lower_name.ends_with(".jpeg") {
        *data = strip_jpeg_metadata(data)?;
    } else if lower_name.ends_with(".png") {
        *data = strip_png_metadata(data)?;
    }
    Ok(())
}

/// Elimina segmentos APP1 (EXIF), APP13 (Photoshop) y COM (Comentarios) de un archivo JPEG.
fn strip_jpeg_metadata(data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < 4 {
        return Ok(data.to_vec());
    }

    // Un archivo JPEG debe iniciar con SOI (Start of Image) = 0xFF, 0xD8
    if data[0] != 0xFF || data[1] != 0xD8 {
        return Err("Fichero JPEG inválido (sin SOI)".to_string());
    }

    let mut stripped = Vec::new();
    stripped.extend_from_slice(&[0xFF, 0xD8]); // SOI

    let mut cursor = 2;
    let len = data.len();

    while cursor < len {
        // Encontrar siguiente marcador
        if data[cursor] != 0xFF {
            // Si no empieza con 0xFF, copiamos el resto del flujo (puede ser el Entropy Coded Data / SOS)
            stripped.extend_from_slice(&data[cursor..]);
            break;
        }

        // Leer marcador
        let marker = data[cursor + 1];
        if marker == 0xD9 {
            // EOI (End of Image)
            stripped.extend_from_slice(&[0xFF, 0xD9]);
            break;
        }

        if marker == 0xDA {
            // SOS (Start of Scan - Inicia la sección de datos de imagen codificada)
            // Copiamos el resto del archivo ya que SOS contiene los datos de escaneo comprimidos sin marcadores estándar
            stripped.extend_from_slice(&data[cursor..]);
            break;
        }

        // Marcadores sin longitud asociada
        if marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7) {
            stripped.extend_from_slice(&[0xFF, marker]);
            cursor += 2;
            continue;
        }

        // Leer longitud del segmento (2 bytes, big-endian)
        if cursor + 3 >= len {
            return Err("Estructura de metadatos JPEG corrupta".to_string());
        }
        let segment_len = ((data[cursor + 2] as usize) << 8) | (data[cursor + 3] as usize);
        
        // Marcadores de metadatos a OMITIR:
        // - 0xE1: APP1 (EXIF / GPS / XMP)
        // - 0xED: APP13 (Photoshop IPTC)
        // - 0xFE: COM (Comentario de texto)
        let should_skip = marker == 0xE1 || marker == 0xED || marker == 0xFE;

        if !should_skip {
            // Copiar segmento completo si no se debe omitir
            stripped.extend_from_slice(&data[cursor..cursor + 2 + segment_len]);
        }

        cursor += 2 + segment_len;
    }

    Ok(stripped)
}

/// Elimina chunks tEXt, zTXt, iTXt, eXIf y tIME de un archivo PNG en memoria.
fn strip_png_metadata(data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < 8 {
        return Ok(data.to_vec());
    }

    // Firma estándar de PNG (8 bytes)
    let png_signature = [137, 80, 78, 71, 13, 10, 26, 10];
    if data[0..8] != png_signature {
        return Err("Fichero PNG inválido (firma errónea)".to_string());
    }

    let mut stripped = Vec::new();
    stripped.extend_from_slice(&png_signature);

    let mut cursor = 8;
    let len = data.len();

    while cursor + 12 <= len {
        // Leer longitud del chunk (4 bytes, big-endian)
        let chunk_len = ((data[cursor] as u32) << 24
            | (data[cursor + 1] as u32) << 16
            | (data[cursor + 2] as u32) << 8
            | (data[cursor + 3] as u32)) as usize;

        // Leer tipo de chunk (4 bytes ASCII)
        let chunk_type = &data[cursor + 4..cursor + 8];
        let chunk_type_str = match std::str::from_utf8(chunk_type) {
            Ok(s) => s,
            Err(_) => return Err("Chunk PNG inválido".to_string()),
        };

        // Chunks de metadatos a OMITIR:
        // - eXIf: Metadatos de cámara y GPS
        // - tEXt: Texto plano (autor, software, descripción)
        // - zTXt: Texto comprimido
        // - iTXt: Texto UTF-8 internacional
        // - tIME: Fecha de última modificación
        let should_skip = chunk_type_str == "eXIf" 
            || chunk_type_str == "tEXt" 
            || chunk_type_str == "zTXt" 
            || chunk_type_str == "iTXt" 
            || chunk_type_str == "tIME";

        if !should_skip {
            // Copiar el chunk completo: Longitud (4) + Tipo (4) + Datos (chunk_len) + CRC (4)
            stripped.extend_from_slice(&data[cursor..cursor + 12 + chunk_len]);
        }

        cursor += 12 + chunk_len;
    }

    Ok(stripped)
}
