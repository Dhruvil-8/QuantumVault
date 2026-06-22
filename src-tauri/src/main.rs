//! QuantumVault - Post-Quantum Secure File Encryption
//!
//! This is the main entry point for the Tauri application.

fn main() {
    #[cfg(feature = "tauri")]
    quantumvault::run_tauri();

    #[cfg(not(feature = "tauri"))]
    {
        eprintln!("QuantumVault requires the 'tauri' feature to run as a GUI application.");
        eprintln!("Run with: cargo run --features tauri");
        eprintln!(
            "Or use the verification CLI: cargo run --bin verification_cli --no-default-features"
        );
        std::process::exit(1);
    }
}
