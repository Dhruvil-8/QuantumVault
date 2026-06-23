use anyhow::{Context, Result, anyhow};
use quantumvault_core::{Identity, RecipientPublic, SenderPublic, decrypt_file, encrypt_file};
use std::env;
use std::path::Path;

fn print_usage() {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║                 QuantumVault CLI client                      ║");
    println!("║   Post-Quantum Secure File Encryption (FIPS 203/204)          ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
    println!("USAGE:");
    println!("    quantumvault-cli keygen <out-dir>");
    println!(
        "    quantumvault-cli encrypt -i <input> -o <output> -s <sender-dir> -r <recipient-pub-dir>"
    );
    println!(
        "    quantumvault-cli decrypt -i <input> -o <output> -r <recipient-dir> -s <sender-pub-dir>"
    );
    println!();
    println!("OPTIONS:");
    println!("    -i, --input      Input file path");
    println!("    -o, --output     Output file path");
    println!(
        "    -s, --sender     Sender identity directory (for encrypt) or sender public key directory (for decrypt)"
    );
    println!(
        "    -r, --recipient  Recipient public key directory (for encrypt) or recipient identity directory (for decrypt)"
    );
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
                    "Missing output directory path. Usage: quantumvault-cli keygen <out-dir>"
                ));
            }
            let out_dir = &args[2];
            println!(
                "[1/1] Generating new post-quantum identity at {}...",
                out_dir
            );
            let identity = Identity::generate().context("Failed to generate identity")?;
            identity
                .save_to(Path::new(out_dir))
                .context("Failed to save identity")?;
            println!(
                "✓ Identity successfully generated and saved to: {}",
                out_dir
            );
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
            if !output.ends_with(".qvault") {
                output.push_str(".qvault");
            }
            let sender_path =
                sender.ok_or_else(|| anyhow!("Sender identity path is required (-s/--sender)"))?;
            let recipient_pub_path = recipient
                .ok_or_else(|| anyhow!("Recipient public key path is required (-r/--recipient)"))?;

            println!("Encrypting file {} -> {} ...", input, output);
            let sender_identity =
                Identity::load(Path::new(sender_path)).context("Failed to load sender identity")?;
            let recipient_pub = RecipientPublic::load(Path::new(recipient_pub_path))
                .context("Failed to load recipient public keys")?;

            encrypt_file(
                Path::new(input),
                Path::new(&output),
                &sender_identity,
                &recipient_pub,
            )
            .context("Encryption failed")?;

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
            let sender_pub_path = sender
                .ok_or_else(|| anyhow!("Sender public key path is required (-s/--sender)"))?;
            let recipient_path = recipient
                .ok_or_else(|| anyhow!("Recipient identity path is required (-r/--recipient)"))?;

            println!("Decrypting file {} -> {} ...", input, output);
            let recipient_identity = Identity::load(Path::new(recipient_path))
                .context("Failed to load recipient identity")?;
            let sender_pub = SenderPublic::load(Path::new(sender_pub_path))
                .context("Failed to load sender public signing key")?;

            decrypt_file(
                Path::new(input),
                Path::new(output),
                &recipient_identity,
                &sender_pub,
            )
            .context("Decryption failed")?;

            println!("✓ Decryption complete!");
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
