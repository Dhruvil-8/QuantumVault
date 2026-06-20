//! QuantumVault Core Tauri GUI Backend

#[cfg(feature = "tauri")]
mod commands;

#[cfg(feature = "tauri")]
pub fn run_tauri() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            commands::generate_identity,
            commands::encrypt_file,
            commands::decrypt_file,
            commands::get_identity_info,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Tauri application");
}
