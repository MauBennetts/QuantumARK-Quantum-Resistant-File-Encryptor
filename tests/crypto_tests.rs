use std::fs;
use std::path::Path;
use blackprism_tauri::crypto::key_manager::{generate_pqc_keypair, protect_private_key, unprotect_private_key};
use blackprism_tauri::crypto::cipher::{encrypt_file_pqc_complete, decrypt_file_pqc};
use blackprism_tauri::crypto::shamir::{split_secret, recover_secret};

#[test]
fn test_key_generation_and_protection() {
    let (pub_bytes, priv_bytes) = generate_pqc_keypair().unwrap();
    assert!(!pub_bytes.is_empty());
    assert!(!priv_bytes.is_empty());

    // Debugging print
    use blackprism_tauri::crypto::key_manager::PQCPrivateKeyHex;
    let key_data: PQCPrivateKeyHex = serde_json::from_slice(&priv_bytes).unwrap();
    let kem_priv_bytes = hex::decode(&key_data.kem_private).unwrap();
    println!("--- DEBUG: KEM PRIVATE BYTES LEN = {} ---", kem_priv_bytes.len());

    let password = "my-secure-password";
    let protected = protect_private_key(&priv_bytes, password).unwrap();
    assert!(!protected.is_empty());

    let unprotected = unprotect_private_key(&protected, password).unwrap();
    assert_eq!(priv_bytes, unprotected);
}

#[test]
fn test_shamir_secret_sharing() {
    let secret = b"my-super-secret-password-123";
    let total = 5;
    let threshold = 3;
    let shares = split_secret(secret, threshold, total).unwrap();
    assert_eq!(shares.len(), total as usize);

    // Reconstruct with exactly threshold shares
    let recovered = recover_secret(&shares[0..3].to_vec(), threshold).unwrap();
    assert_eq!(recovered, secret);

    // Reconstruct with 4 shares
    let recovered_4 = recover_secret(&shares[0..4].to_vec(), threshold).unwrap();
    assert_eq!(recovered_4, secret);

    // Attempt reconstruct with fewer shares
    let fail_recovered = recover_secret(&shares[0..2].to_vec(), threshold);
    assert!(fail_recovered.is_err());
}

#[test]
fn test_standard_encrypt_decrypt() {
    let temp_dir = std::env::temp_dir();
    let input_file = temp_dir.join("test_input.txt");
    fs::write(&input_file, b"Hello Quantum World!").unwrap();

    let (recipient_pub, recipient_priv) = generate_pqc_keypair().unwrap();
    let (sender_pub, sender_priv) = generate_pqc_keypair().unwrap();

    // Standard encryption
    let (out_path, in_hash, out_hash) = encrypt_file_pqc_complete(
        &input_file,
        &recipient_pub,
        &sender_priv,
        Some("my-2fa-pwd"),
        false,
        0,
        true,
        false,
        None,
        None,
        None,
        false,
        None,
    ).unwrap();

    assert!(Path::new(&out_path).exists());
    assert!(!in_hash.is_empty());
    assert!(!out_hash.is_empty());

    // Clean input file to test restoration
    fs::remove_file(&input_file).unwrap();

    // Decryption
    let (dec_path, dec_hash) = decrypt_file_pqc(
        Path::new(&out_path),
        &recipient_priv,
        &sender_pub,
        Some("my-2fa-pwd"),
    ).unwrap();

    assert!(Path::new(&dec_path).exists());
    let dec_bytes = fs::read(&dec_path).unwrap();
    assert_eq!(dec_bytes, b"Hello Quantum World!");
    assert_eq!(dec_hash, in_hash);

    // Clean up
    let _ = fs::remove_file(out_path);
    let _ = fs::remove_file(dec_path);
}

#[test]
fn test_hardware_pepper() {
    let temp_dir = std::env::temp_dir();
    let input_file = temp_dir.join("test_input_pepper.txt");
    fs::write(&input_file, b"Hardware Pepper Test").unwrap();

    let (recipient_pub, recipient_priv) = generate_pqc_keypair().unwrap();
    let (sender_pub, sender_priv) = generate_pqc_keypair().unwrap();

    // Encryption with hardware pepper
    let (out_path, _, _) = encrypt_file_pqc_complete(
        &input_file,
        &recipient_pub,
        &sender_priv,
        Some("pwd"),
        false,
        0,
        true,
        true, // hardware pepper
        None,
        None,
        None,
        false,
        None,
    ).unwrap();

    // Decrypting on the same host (should succeed)
    let (dec_path, _) = decrypt_file_pqc(
        Path::new(&out_path),
        &recipient_priv,
        &sender_pub,
        Some("pwd"),
    ).unwrap();

    let dec_bytes = fs::read(&dec_path).unwrap();
    assert_eq!(dec_bytes, b"Hardware Pepper Test");

    // Clean up
    let _ = fs::remove_file(input_file);
    let _ = fs::remove_file(out_path);
    let _ = fs::remove_file(dec_path);
}

#[test]
fn test_ttl_expiration() {
    let temp_dir = std::env::temp_dir();
    let input_file = temp_dir.join("test_input_ttl.txt");
    fs::write(&input_file, b"TTL Expiration Test").unwrap();

    let (recipient_pub, recipient_priv) = generate_pqc_keypair().unwrap();
    let (sender_pub, sender_priv) = generate_pqc_keypair().unwrap();

    // Encryption with expired/expiring TTL (0 seconds from now)
    let (out_path, _, _) = encrypt_file_pqc_complete(
        &input_file,
        &recipient_pub,
        &sender_priv,
        Some("pwd"),
        false,
        0,
        true,
        false,
        Some(0), // TTL = 0 seconds (expires immediately or within 1s)
        None,
        None,
        false,
        None,
    ).unwrap();

    // Wait 1 second to guarantee expiration
    std::thread::sleep(std::time::Duration::from_secs(1));

    // Decrypting should fail due to TTL expiration
    let dec_res = decrypt_file_pqc(
        Path::new(&out_path),
        &recipient_priv,
        &sender_pub,
        Some("pwd"),
    );

    assert!(dec_res.is_err());
    let err_msg = dec_res.unwrap_err();
    assert!(err_msg.contains("El tiempo de vida (TTL) de este archivo ha expirado"));

    // Clean up
    let _ = fs::remove_file(input_file);
    let _ = fs::remove_file(out_path);
}

#[test]
fn test_duress_decoy() {
    let temp_dir = std::env::temp_dir();
    let input_file = temp_dir.join("test_real.txt");
    fs::write(&input_file, b"REAL SECRET DATA").unwrap();

    let decoy_file = temp_dir.join("test_decoy.txt");
    fs::write(&decoy_file, b"DECOY SENUELO DATA").unwrap();

    let (recipient_pub, recipient_priv) = generate_pqc_keypair().unwrap();
    let (sender_pub, sender_priv) = generate_pqc_keypair().unwrap();

    // Encrypt with decoy payload mapping
    let (out_path, _, _) = encrypt_file_pqc_complete(
        &input_file,
        &recipient_pub,
        &sender_priv,
        Some("real_pwd"),
        false,
        0,
        true,
        false,
        None,
        Some(&decoy_file),
        Some("decoy_pwd"),
        false,
        None,
    ).unwrap();

    // Decrypt with real password
    let (real_dec_path, _) = decrypt_file_pqc(
        Path::new(&out_path),
        &recipient_priv,
        &sender_pub,
        Some("real_pwd"),
    ).unwrap();

    let real_dec_bytes = fs::read(&real_dec_path).unwrap();
    assert_eq!(real_dec_bytes, b"REAL SECRET DATA");

    // Decrypt with decoy password (transparently fallbacks to decoy)
    let (decoy_dec_path, _) = decrypt_file_pqc(
        Path::new(&out_path),
        &recipient_priv,
        &sender_pub,
        Some("decoy_pwd"),
    ).unwrap();

    let decoy_dec_bytes = fs::read(&decoy_dec_path).unwrap();
    assert_eq!(decoy_dec_bytes, b"DECOY SENUELO DATA");

    // Clean up
    let _ = fs::remove_file(input_file);
    let _ = fs::remove_file(decoy_file);
    let _ = fs::remove_file(out_path);
    let _ = fs::remove_file(real_dec_path);
    let _ = fs::remove_file(decoy_dec_path);
}

#[test]
fn test_reed_solomon_fragmentation() {
    let temp_dir = std::env::temp_dir();
    let input_file = temp_dir.join("test_frag_input.txt");
    fs::write(&input_file, b"Frag data test. Let's make sure it reconstructs nicely.").unwrap();

    let (recipient_pub, recipient_priv) = generate_pqc_keypair().unwrap();
    let (sender_pub, sender_priv) = generate_pqc_keypair().unwrap();

    // Encrypt with 3 data and 2 parity shards (5 shards total)
    let (out_path_desc, _, _) = encrypt_file_pqc_complete(
        &input_file,
        &recipient_pub,
        &sender_priv,
        Some("pwd"),
        false,
        0,
        true,
        false,
        None,
        None,
        None,
        false,
        Some((3, 2)),
    ).unwrap();

    // The output path contains "part1 (fragmentado...)" description
    // Let's parse out the base part file path.
    let base_part_path_str = out_path_desc.split(" (fragmentado:").next().unwrap().trim();
    let base_part_path = Path::new(base_part_path_str);
    assert!(base_part_path.exists());

    // Ensure all 5 part files exist
    let parent = base_part_path.parent().unwrap();
    let file_name_stem = base_part_path.file_name().unwrap().to_str().unwrap();
    let base_stem = file_name_stem.strip_suffix("1").unwrap(); // "test_frag_input.txt.qarq.part"

    for i in 1..=5 {
        let part_file = parent.join(format!("{}{}", base_stem, i));
        assert!(part_file.exists());
    }

    // Now delete 2 parity shards (part 4 and part 5)
    let part4 = parent.join(format!("{}{}", base_stem, 4));
    let part5 = parent.join(format!("{}{}", base_stem, 5));
    fs::remove_file(&part4).unwrap();
    fs::remove_file(&part5).unwrap();

    // Decrypt using part 1 (should automatically detect fragments and reconstruct)
    let (dec_path, _) = decrypt_file_pqc(
        base_part_path,
        &recipient_priv,
        &sender_pub,
        Some("pwd"),
    ).unwrap();

    let dec_bytes = fs::read(&dec_path).unwrap();
    assert_eq!(dec_bytes, b"Frag data test. Let's make sure it reconstructs nicely.");

    // Clean up
    let _ = fs::remove_file(input_file);
    let _ = fs::remove_file(dec_path);
    for i in 1..=3 {
        let part_file = parent.join(format!("{}{}", base_stem, i));
        let _ = fs::remove_file(part_file);
    }
}

#[test]
fn test_obfuscate_filename() {
    let temp_dir = std::env::temp_dir();
    let input_file = temp_dir.join("test_obfuscate.txt");
    fs::write(&input_file, b"Obfuscate test content").unwrap();

    let (recipient_pub, recipient_priv) = generate_pqc_keypair().unwrap();
    let (sender_pub, sender_priv) = generate_pqc_keypair().unwrap();

    let (out_path, _, _) = encrypt_file_pqc_complete(
        &input_file,
        &recipient_pub,
        &sender_priv,
        Some("pwd"),
        false,
        0,
        true,
        false,
        None,
        None,
        None,
        true, // Obfuscate filename active
        None,
    ).unwrap();

    let out_file = Path::new(&out_path);
    let name_only = out_file.file_name().unwrap().to_str().unwrap();
    assert!(name_only.ends_with(".qarq"));
    assert_eq!(name_only.len(), 37);

    // Clean up input file to prevent duplicate file naming in same directory
    fs::remove_file(&input_file).unwrap();

    // Decryption
    let (dec_path, _) = decrypt_file_pqc(
        out_file,
        &recipient_priv,
        &sender_pub,
        Some("pwd"),
    ).unwrap();

    let dec_file = Path::new(&dec_path);
    assert_eq!(dec_file.file_name().unwrap().to_str().unwrap(), "test_obfuscate.txt");

    let dec_bytes = fs::read(&dec_path).unwrap();
    assert_eq!(dec_bytes, b"Obfuscate test content");

    // Clean up
    let _ = fs::remove_file(input_file);
    let _ = fs::remove_file(out_file);
    let _ = fs::remove_file(dec_file);
}

#[test]
fn test_legacy_rejection() {
    let temp_dir = std::env::temp_dir();
    let legacy_file = temp_dir.join("legacy.qarq");
    
    // Write a mock QARQ3.0 header
    let mut data = Vec::new();
    data.extend_from_slice(b"QARQ3.0\x00");
    data.extend_from_slice(&[0u8; 10000]); // just padding
    fs::write(&legacy_file, &data).unwrap();

    let (_recipient_pub, recipient_priv) = generate_pqc_keypair().unwrap();
    let (sender_pub, _sender_priv) = generate_pqc_keypair().unwrap();

    let dec_res = decrypt_file_pqc(
        &legacy_file,
        &recipient_priv,
        &sender_pub,
        Some("pwd"),
    );

    assert!(dec_res.is_err());
    let err_msg = dec_res.unwrap_err();
    assert_eq!(err_msg, "Archivo cifrado con versión anterior. Usa BlackPrism v3.1 para descifrar.");

    // Clean up
    let _ = fs::remove_file(legacy_file);
}
