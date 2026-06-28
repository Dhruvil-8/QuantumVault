use anyhow::{Context, Result, anyhow};
use quantumvault_core::{PQIdentity, PQPublicKey, PQFile, KeyMeta, write_secure_file};
use std::env;
use std::path::Path;

fn print_usage() {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║                 QuantumVault CLI client                      ║");
    println!("║   Post-Quantum Secure File Encryption (FIPS 203/204)          ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
    println!("USAGE:");
    println!("    quantumvault-cli keygen <out-file.qvk> [--label <label>] [--comment <comment>]");
    println!("    quantumvault-cli export-public -s <secret-key.qvk> -o <out-pub-file.qvk> [--base64]");
    println!("    quantumvault-cli encrypt -i <input> -o <output.qvf> -s <sender-secret.qvk> -r <recipient-public>");
    println!("    quantumvault-cli decrypt -i <input.qvf> -o <output> -r <recipient-secret.qvk> [-s <sender-public>]");
    println!();
    println!("Note: -r / -s for public keys can be either a path to a public key file or a Base64 key string.");
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        return Ok(());
    }

    let command = &args[1];
    match command.as_str() {
        "keygen" => {
            if args.len() < 3 {
                return Err(anyhow!(
                    "Missing output path. Usage: quantumvault-cli keygen <out-file.qvk> [--label <label>] [--comment <comment>]"
                ));
            }
            let out_file = &args[2];
            let mut label = None;
            let mut comment = None;

            let mut i = 3;
            while i < args.len() {
                match args[i].as_str() {
                    "--label" => {
                        if i + 1 < args.len() {
                            label = Some(args[i + 1].clone());
                            i += 2;
                        } else {
                            return Err(anyhow!("Missing value for --label"));
                        }
                    }
                    "--comment" => {
                        if i + 1 < args.len() {
                            comment = Some(args[i + 1].clone());
                            i += 2;
                        } else {
                            return Err(anyhow!("Missing value for --comment"));
                        }
                    }
                    _ => return Err(anyhow!("Unknown argument: {}", args[i])),
                }
            }

            println!("[1/1] Generating new post-quantum identity at {}...", out_file);
            let meta = KeyMeta { label, comment, expires_at: None };
            let identity = PQIdentity::generate_with_meta(meta).context("Failed to generate identity")?;
            let secret_bytes = identity.export_secret().context("Failed to export secret key")?;
            write_secure_file(Path::new(out_file), secret_bytes, true).context("Failed to write secret key file")?;
            
            println!("✓ Identity successfully generated and saved to: {}", out_file);
            if let Ok(pub_b64) = identity.export_public_b64() {
                println!("\nShareable Public Key (Base64):\n{}", pub_b64);
            }
        }
        "export-public" => {
            let mut secret_path = None;
            let mut pub_path = None;
            let mut base64_format = false;

            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "-s" | "--secret" => {
                        if i + 1 < args.len() {
                            secret_path = Some(&args[i + 1]);
                            i += 2;
                        } else {
                            return Err(anyhow!("Missing value for -s/--secret"));
                        }
                    }
                    "-o" | "--output" => {
                        if i + 1 < args.len() {
                            pub_path = Some(&args[i + 1]);
                            i += 2;
                        } else {
                            return Err(anyhow!("Missing value for -o/--output"));
                        }
                    }
                    "--base64" => {
                        base64_format = true;
                        i += 1;
                    }
                    _ => return Err(anyhow!("Unknown argument: {}", args[i])),
                }
            }

            let secret_path = secret_path.ok_or_else(|| anyhow!("Secret key file is required (-s/--secret)"))?;
            let pub_path = pub_path.ok_or_else(|| anyhow!("Output file is required (-o/--output)"))?;

            let secret_bytes = std::fs::read(Path::new(secret_path)).context("Failed to read secret key file")?;
            let identity = PQIdentity::from_secret_bytes(&secret_bytes).context("Failed to load secret key")?;

            if base64_format {
                let pub_b64 = identity.export_public_b64().context("Failed to export public key to B64")?;
                write_secure_file(Path::new(pub_path), pub_b64, false).context("Failed to write public key file")?;
            } else {
                let pub_bytes = identity.export_public().context("Failed to export public key")?;
                write_secure_file(Path::new(pub_path), pub_bytes, false).context("Failed to write public key file")?;
            }

            println!("✓ Public key successfully exported to: {}", pub_path);
        }
        "encrypt" => {
            let mut input = None;
            let mut output = None;
            let mut sender = None;
            let mut recipient = None;

            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "-i" | "--input" => {
                        if i + 1 < args.len() {
                            input = Some(&args[i + 1]);
                            i += 2;
                        } else {
                            return Err(anyhow!("Missing value for -i/--input"));
                        }
                    }
                    "-o" | "--output" => {
                        if i + 1 < args.len() {
                            output = Some(&args[i + 1]);
                            i += 2;
                        } else {
                            return Err(anyhow!("Missing value for -o/--output"));
                        }
                    }
                    "-s" | "--sender" => {
                        if i + 1 < args.len() {
                            sender = Some(&args[i + 1]);
                            i += 2;
                        } else {
                            return Err(anyhow!("Missing value for -s/--sender"));
                        }
                    }
                    "-r" | "--recipient" => {
                        if i + 1 < args.len() {
                            recipient = Some(&args[i + 1]);
                            i += 2;
                        } else {
                            return Err(anyhow!("Missing value for -r/--recipient"));
                        }
                    }
                    _ => {
                        return Err(anyhow!("Unknown parameter: {}", args[i]));
                    }
                }
            }

            let input = input.ok_or_else(|| anyhow!("Input path is required (-i/--input)"))?;
            let output_raw = output.ok_or_else(|| anyhow!("Output path is required (-o/--output)"))?;
            let mut output = output_raw.to_string();
            if !output.ends_with(".qvf") {
                output.push_str(".qvf");
            }
            let sender_path = sender.ok_or_else(|| anyhow!("Sender identity path is required (-s/--sender)"))?;
            let recipient_input = recipient.ok_or_else(|| anyhow!("Recipient public key (path or Base64) is required (-r/--recipient)"))?;

            println!("Encrypting file {} -> {} ...", input, output);
            
            let plaintext = std::fs::read(Path::new(input)).context("Failed to read source file")?;
            let sender_bytes = std::fs::read(Path::new(sender_path)).context("Failed to read sender identity file")?;
            let sender_identity = PQIdentity::from_secret_bytes(&sender_bytes).context("Failed to load sender identity")?;

            // Load recipient public key
            let recipient_pub = if let Ok(pub_bytes) = std::fs::read(Path::new(recipient_input)) {
                PQPublicKey::from_bytes(&pub_bytes).context("Failed to load recipient public key from file")?
            } else {
                PQPublicKey::from_b64(recipient_input.trim()).context("Recipient key was neither a valid file path nor valid Base64")?
            };

            let envelope = PQFile::encrypt_and_sign(&plaintext, &recipient_pub, &sender_identity)
                .context("Failed to encrypt and sign file")?;

            write_secure_file(Path::new(&output), envelope, false).context("Failed to write output envelope file")?;

            println!("✓ Encryption complete!");
        }
        "decrypt" => {
            let mut input = None;
            let mut output = None;
            let mut sender = None;
            let mut recipient = None;

            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "-i" | "--input" => {
                        if i + 1 < args.len() {
                            input = Some(&args[i + 1]);
                            i += 2;
                        } else {
                            return Err(anyhow!("Missing value for -i/--input"));
                        }
                    }
                    "-o" | "--output" => {
                        if i + 1 < args.len() {
                            output = Some(&args[i + 1]);
                            i += 2;
                        } else {
                            return Err(anyhow!("Missing value for -o/--output"));
                        }
                    }
                    "-s" | "--sender" => {
                        if i + 1 < args.len() {
                            sender = Some(&args[i + 1]);
                            i += 2;
                        } else {
                            return Err(anyhow!("Missing value for -s/--sender"));
                        }
                    }
                    "-r" | "--recipient" => {
                        if i + 1 < args.len() {
                            recipient = Some(&args[i + 1]);
                            i += 2;
                        } else {
                            return Err(anyhow!("Missing value for -r/--recipient"));
                        }
                    }
                    _ => {
                        return Err(anyhow!("Unknown parameter: {}", args[i]));
                    }
                }
            }

            let input = input.ok_or_else(|| anyhow!("Input path is required (-i/--input)"))?;
            let output = output.ok_or_else(|| anyhow!("Output path is required (-o/--output)"))?;
            let recipient_path = recipient.ok_or_else(|| anyhow!("Recipient secret key path is required (-r/--recipient)"))?;
            let sender_input = sender; // Optional

            println!("Decrypting file {} -> {} ...", input, output);
            let envelope = std::fs::read(Path::new(input)).context("Failed to read envelope file")?;
            let recipient_bytes = std::fs::read(Path::new(recipient_path)).context("Failed to read recipient secret key file")?;
            let recipient_identity = PQIdentity::from_secret_bytes(&recipient_bytes).context("Failed to load recipient identity")?;

            // Load optional sender public key
            let sender_pub = if let Some(sender_val) = sender_input {
                let pk = if let Ok(pub_bytes) = std::fs::read(Path::new(sender_val)) {
                    PQPublicKey::from_bytes(&pub_bytes).context("Failed to load sender public key from file")?
                } else {
                    PQPublicKey::from_b64(sender_val.trim()).context("Sender public key was neither a valid file path nor valid Base64")?
                };
                Some(pk)
            } else {
                None
            };

            let plaintext = PQFile::decrypt_and_verify(&envelope, &recipient_identity, sender_pub.as_ref())
                .context("Decryption / signature verification failed")?;

            write_secure_file(Path::new(output), plaintext, true).context("Failed to write decrypted output file")?;

            if sender_pub.is_some() {
                println!("✓ Decryption complete and signature verified successfully!");
            } else {
                println!("✓ Decryption complete successfully (signature check skipped)!");
            }
        }
        _ => {
            println!("Error: Unknown command '{}'", command);
            println!();
            print_usage();
            std::process::exit(1);
        }
    }

    Ok(())
}
