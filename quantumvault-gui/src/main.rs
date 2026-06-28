//! QuantumVault Native GPU GUI
//!
//! A clean, dark-themed immediate-mode desktop application built using `egui` and `eframe`.
//! Replaces the old Tauri frontend with a 100% Rust implementation.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] // hide console window on Windows in release

use eframe::egui;
use quantumvault_core::{PQIdentity, PQPublicKey, PQFile, KeyMeta};
use std::path::Path;

#[derive(Default, PartialEq)]
enum Tab {
    #[default]
    Encrypt,
    Decrypt,
}

struct QuantumVaultApp {
    // Current Navigation Tab
    active_tab: Tab,

    // Identity Manager State
    identity_path: String,
    identity_info: Option<String>,
    identity_status: Option<Result<String, String>>,
    identity_label: String,
    identity_comment: String,

    // Encryption View State
    enc_source: String,
    enc_output: String,
    enc_sender: String,
    enc_recipient: String,
    enc_status: Option<Result<String, String>>,

    // Decryption View State
    dec_vault: String,
    dec_output: String,
    dec_recipient: String,
    dec_sender_pub: String,
    dec_status: Option<Result<String, String>>,
}

impl Default for QuantumVaultApp {
    fn default() -> Self {
        Self {
            active_tab: Tab::Encrypt,
            identity_path: String::new(),
            identity_info: None,
            identity_status: None,
            identity_label: String::new(),
            identity_comment: String::new(),
            enc_source: String::new(),
            enc_output: String::new(),
            enc_sender: String::new(),
            enc_recipient: String::new(),
            enc_status: None,
            dec_vault: String::new(),
            dec_output: String::new(),
            dec_recipient: String::new(),
            dec_sender_pub: String::new(),
            dec_status: None,
        }
    }
}

impl QuantumVaultApp {
    fn generate_identity(&mut self) {
        if self.identity_path.is_empty() {
            self.identity_status = Some(Err("Please select a target file first.".to_string()));
            return;
        }

        let meta = KeyMeta {
            label: Some(self.identity_label.trim().to_string()),
            comment: Some(self.identity_comment.trim().to_string()),
            expires_at: None,
        };

        match PQIdentity::generate_with_meta(meta) {
            Ok(identity) => match identity.export_secret() {
                Ok(secret_bytes) => match std::fs::write(Path::new(&self.identity_path), &secret_bytes) {
                    Ok(_) => {
                        // Automatically export public key file next to it
                        let parent = Path::new(&self.identity_path).parent().unwrap_or_else(|| Path::new(""));
                        let stem = Path::new(&self.identity_path).file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "identity".to_string());
                        
                        let pub_filename = if stem.ends_with("_secret") {
                            format!("{}_public.qvk", &stem[..stem.len() - 7])
                        } else {
                            format!("{}_public.qvk", stem)
                        };
                        let pub_path = parent.join(pub_filename);
                        
                        let mut auto_save_msg = String::new();
                        if let Ok(pub_bytes) = identity.export_public() {
                            if std::fs::write(&pub_path, &pub_bytes).is_ok() {
                                auto_save_msg = format!(" (public key automatically saved next to it as: {})", pub_path.file_name().unwrap_or_default().to_string_lossy());
                            }
                        }

                        self.identity_info = Some(format!(
                            "Label: {}\nComment: {}",
                            identity.meta.label.as_deref().unwrap_or("None"),
                            identity.meta.comment.as_deref().unwrap_or("None"),
                        ));
                        self.identity_status =
                            Some(Ok(format!("Identity successfully generated and saved!{}", auto_save_msg)));
                    }
                    Err(e) => {
                        self.identity_status = Some(Err(format!("Failed to save secret key file: {}", e)));
                    }
                },
                Err(e) => {
                    self.identity_status = Some(Err(format!("Key export failed: {}", e)));
                }
            },
            Err(e) => {
                self.identity_status = Some(Err(format!("Key generation failed: {}", e)));
            }
        }
    }

    fn export_public_key_file(&mut self) {
        if self.identity_path.is_empty() {
            self.identity_status = Some(Err("No identity file loaded to export.".to_string()));
            return;
        }

        match std::fs::read(Path::new(&self.identity_path)) {
            Ok(bytes) => match PQIdentity::from_secret_bytes(&bytes) {
                Ok(identity) => {
                    let default_name = Path::new(&self.identity_path)
                        .file_stem()
                        .map(|s| format!("{}_public.qvk", s.to_string_lossy()))
                        .unwrap_or_else(|| "public.qvk".to_string());

                    if let Some(path) = rfd::FileDialog::new()
                        .set_file_name(&default_name)
                        .add_filter("QuantumVault Key", &["qvk"])
                        .save_file()
                    {
                        let mut path_str = path.display().to_string();
                        if !path_str.ends_with(".qvk") {
                            path_str.push_str(".qvk");
                        }

                        match identity.export_public() {
                            Ok(pub_bytes) => match std::fs::write(Path::new(&path_str), &pub_bytes) {
                                Ok(_) => {
                                    self.identity_status = Some(Ok(format!("Public key successfully saved to: {}", path_str)));
                                }
                                Err(e) => {
                                    self.identity_status = Some(Err(format!("Failed to write public key file: {}", e)));
                                }
                            },
                            Err(e) => {
                                self.identity_status = Some(Err(format!("Failed to export public key: {}", e)));
                            }
                        }
                    }
                }
                Err(e) => {
                    self.identity_status = Some(Err(format!("Failed to parse secret key: {}", e)));
                }
            },
            Err(e) => {
                self.identity_status = Some(Err(format!("Failed to read secret key file: {}", e)));
            }
        }
    }

    fn load_identity(&mut self) {
        if self.identity_path.is_empty() {
            self.identity_status = Some(Err(
                "Please select an identity file to load.".to_string()
            ));
            return;
        }

        match std::fs::read(Path::new(&self.identity_path)) {
            Ok(bytes) => match PQIdentity::from_secret_bytes(&bytes) {
                Ok(identity) => {
                    self.identity_info = Some(format!(
                        "Label: {}\nComment: {}",
                        identity.meta.label.as_deref().unwrap_or("None"),
                        identity.meta.comment.as_deref().unwrap_or("None"),
                    ));
                    self.identity_status = Some(Ok("Identity successfully loaded!".to_string()));
                }
                Err(e) => {
                    self.identity_status = Some(Err(format!("Failed to parse secret key: {}", e)));
                    self.identity_info = None;
                }
            },
            Err(e) => {
                self.identity_status = Some(Err(format!("Failed to read file: {}", e)));
                self.identity_info = None;
            }
        }
    }

    fn run_encryption(&mut self) {
        if !self.enc_output.is_empty() && !self.enc_output.ends_with(".qvf") {
            self.enc_output.push_str(".qvf");
        }

        if self.enc_source.is_empty()
            || self.enc_output.is_empty()
            || self.enc_sender.is_empty()
            || self.enc_recipient.is_empty()
        {
            self.enc_status = Some(Err("All fields are required to encrypt.".to_string()));
            return;
        }

        let plaintext = match std::fs::read(Path::new(&self.enc_source)) {
            Ok(bytes) => bytes,
            Err(e) => {
                self.enc_status = Some(Err(format!("Failed to read source file: {}", e)));
                return;
            }
        };

        let sender_identity = match std::fs::read(Path::new(&self.enc_sender))
            .and_then(|bytes| PQIdentity::from_secret_bytes(&bytes).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())))
        {
            Ok(id) => id,
            Err(e) => {
                self.enc_status = Some(Err(format!("Failed to load sender identity key file: {}", e)));
                return;
            }
        };

        // Recipient can be a path to a key file or a Base64 string
        let recipient_pub = if let Ok(bytes) = std::fs::read(Path::new(&self.enc_recipient)) {
            match PQPublicKey::from_bytes(&bytes) {
                Ok(pk) => pk,
                Err(e) => {
                    self.enc_status = Some(Err(format!("Failed to parse recipient public key from file: {}", e)));
                    return;
                }
            }
        } else {
            match PQPublicKey::from_b64(&self.enc_recipient.trim()) {
                Ok(pk) => pk,
                Err(e) => {
                    self.enc_status = Some(Err(format!("Recipient is neither a valid public key file nor valid Base64: {}", e)));
                    return;
                }
            }
        };

        self.enc_status = Some(Ok("Encrypting file... Please wait.".to_string()));

        match PQFile::encrypt_and_sign(&plaintext, &recipient_pub, &sender_identity) {
            Ok(envelope) => {
                match std::fs::write(Path::new(&self.enc_output), &envelope) {
                    Ok(_) => {
                        self.enc_status = Some(Ok("✓ Encryption completed successfully!".to_string()));
                    }
                    Err(e) => {
                        self.enc_status = Some(Err(format!("Failed to write encrypted file: {}", e)));
                    }
                }
            }
            Err(e) => {
                self.enc_status = Some(Err(format!("Encryption failed: {}", e)));
            }
        }
    }

    fn run_decryption(&mut self) {
        if self.dec_vault.is_empty()
            || self.dec_output.is_empty()
            || self.dec_recipient.is_empty()
        {
            self.dec_status = Some(Err("Vault file, output file, and recipient identity are required to decrypt.".to_string()));
            return;
        }

        let envelope = match std::fs::read(Path::new(&self.dec_vault)) {
            Ok(bytes) => bytes,
            Err(e) => {
                self.dec_status = Some(Err(format!("Failed to read vault file: {}", e)));
                return;
            }
        };

        let recipient_identity = match std::fs::read(Path::new(&self.dec_recipient))
            .and_then(|bytes| PQIdentity::from_secret_bytes(&bytes).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())))
        {
            Ok(id) => id,
            Err(e) => {
                self.dec_status = Some(Err(format!("Failed to load recipient identity key file: {}", e)));
                return;
            }
        };

        let sender_pub = if self.dec_sender_pub.trim().is_empty() {
            None
        } else {
            let pk = if let Ok(bytes) = std::fs::read(Path::new(&self.dec_sender_pub)) {
                match PQPublicKey::from_bytes(&bytes) {
                    Ok(pk) => Some(pk),
                    Err(e) => {
                        self.dec_status = Some(Err(format!("Failed to parse sender public key from file: {}", e)));
                        return;
                    }
                }
            } else {
                match PQPublicKey::from_b64(&self.dec_sender_pub.trim()) {
                    Ok(pk) => Some(pk),
                    Err(e) => {
                        self.dec_status = Some(Err(format!("Sender public key is neither a valid file nor valid Base64: {}", e)));
                        return;
                    }
                }
            };
            pk
        };

        self.dec_status = Some(Ok("Decrypting file... Please wait.".to_string()));

        match PQFile::decrypt_and_verify(&envelope, &recipient_identity, sender_pub.as_ref()) {
            Ok(plaintext) => {
                match std::fs::write(Path::new(&self.dec_output), &plaintext) {
                    Ok(_) => {
                        let success_msg = if sender_pub.is_some() {
                            "✓ Decryption completed & signature verified successfully!"
                        } else {
                            "✓ Decryption completed successfully (signature check skipped)!"
                        };
                        self.dec_status = Some(Ok(success_msg.to_string()));
                    }
                    Err(e) => {
                        self.dec_status = Some(Err(format!("Failed to write decrypted file: {}", e)));
                    }
                }
            }
            Err(e) => {
                self.dec_status = Some(Err(format!("Decryption failed: {}", e)));
            }
        }
    }
}

impl eframe::App for QuantumVaultApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(8.0);
                ui.heading("QuantumVault");
                ui.label("Post-Quantum Hybrid Secure File Envelope Manager");
                ui.add_space(10.0);
            });

            // Card Style Layout
            let card_fill = egui::Color32::from_rgb(22, 28, 45); // Slate-900

            // ─── IDENTITY MANAGER PANEL ──────────────────────────────────────────────
            egui::Frame::none()
                .fill(card_fill)
                .rounding(12.0)
                .inner_margin(16.0)
                .show(ui, |ui| {
                    ui.strong("Cryptographic Identity Manager");
                    ui.label("Generate or load ML-KEM-1024 / ML-DSA-87 / X25519 identity keys (.qvk).");
                    ui.add_space(8.0);

                    egui::Grid::new("identity_grid")
                        .num_columns(3)
                        .spacing([10.0, 10.0])
                        .show(ui, |ui| {
                            ui.label("Identity File (.qvk):");
                            ui.text_edit_singleline(&mut self.identity_path);
                            if ui.button("Browse").clicked() {
                                if let Some(path) = rfd::FileDialog::new()
                                    .add_filter("QuantumVault Key", &["qvk"])
                                    .pick_file()
                                {
                                    self.identity_path = path.display().to_string();
                                }
                            }
                            ui.end_row();

                            ui.label("Metadata Label:");
                            ui.text_edit_singleline(&mut self.identity_label);
                            ui.label("(Optional label for new keys)");
                            ui.end_row();

                            ui.label("Metadata Comment:");
                            ui.text_edit_singleline(&mut self.identity_comment);
                            ui.label("(Optional comment for new keys)");
                            ui.end_row();
                        });

                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if ui.button("Generate New Key").clicked() {
                            if let Some(path) = rfd::FileDialog::new()
                                .add_filter("QuantumVault Key", &["qvk"])
                                .save_file()
                            {
                                let mut path_str = path.display().to_string();
                                if !path_str.ends_with(".qvk") {
                                    path_str.push_str(".qvk");
                                }
                                self.identity_path = path_str;
                                self.generate_identity();
                            }
                        }
                        if ui.button("Load Key").clicked() {
                            self.load_identity();
                        }
                        if ui.button("Export Public Key File").clicked() {
                            self.export_public_key_file();
                        }
                    });

                    if let Some(status) = &self.identity_status {
                        ui.add_space(6.0);
                        match status {
                            Ok(msg) => {
                                ui.colored_label(egui::Color32::from_rgb(16, 185, 129), format!("Success: {}", msg));
                            }
                            Err(err) => {
                                ui.colored_label(egui::Color32::from_rgb(239, 68, 68), format!("Error: {}", err));
                            }
                        }
                    }

                    if let Some(info) = &self.identity_info {
                        ui.add_space(8.0);
                        egui::Frame::none()
                            .fill(egui::Color32::from_rgb(15, 23, 42)) // Slate-950
                            .inner_margin(10.0)
                            .rounding(6.0)
                            .show(ui, |ui| {
                                ui.monospace(info);
                            });
                    }
                });

            ui.add_space(16.0);

            // ─── TABS & OPERATIONS ───────────────────────────────────────────────────
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.active_tab, Tab::Encrypt, "Encrypt File");
                ui.selectable_value(&mut self.active_tab, Tab::Decrypt, "Decrypt File");
            });

            ui.add_space(8.0);

            egui::Frame::none()
                .fill(card_fill)
                .rounding(12.0)
                .inner_margin(16.0)
                .show(ui, |ui| match self.active_tab {
                    Tab::Encrypt => {
                        ui.strong("Create Encrypted Hybrid Envelope (.qvf)");
                        ui.add_space(8.0);

                        egui::Grid::new("encrypt_grid")
                            .num_columns(3)
                            .spacing([10.0, 12.0])
                            .show(ui, |ui| {
                                // Source File
                                ui.label("Source File:");
                                ui.text_edit_singleline(&mut self.enc_source);
                                if ui.button("Browse").clicked() {
                                    if let Some(path) = rfd::FileDialog::new().pick_file() {
                                        self.enc_source = path.display().to_string();
                                    }
                                }
                                ui.end_row();

                                // Output Vault
                                ui.label("Output Envelope (.qvf):");
                                ui.text_edit_singleline(&mut self.enc_output);
                                if ui.button("Save As").clicked() {
                                    if let Some(path) = rfd::FileDialog::new()
                                        .add_filter("QuantumVault Envelope", &["qvf"])
                                        .save_file()
                                    {
                                        let mut path_str = path.display().to_string();
                                        if !path_str.ends_with(".qvf") {
                                            path_str.push_str(".qvf");
                                        }
                                        self.enc_output = path_str;
                                    }
                                }
                                ui.end_row();

                                // My Identity (Sender)
                                ui.label("My Identity (.qvk):");
                                ui.text_edit_singleline(&mut self.enc_sender);
                                if ui.button("Browse").clicked() {
                                    if let Some(path) = rfd::FileDialog::new()
                                        .add_filter("QuantumVault Key", &["qvk"])
                                        .pick_file()
                                    {
                                        self.enc_sender = path.display().to_string();
                                    }
                                }
                                ui.end_row();

                                // Recipient Public Key
                                ui.label("Recipient Public Key / B64:");
                                ui.text_edit_singleline(&mut self.enc_recipient);
                                if ui.button("Browse").clicked() {
                                    if let Some(path) = rfd::FileDialog::new()
                                        .add_filter("QuantumVault Key", &["qvk"])
                                        .pick_file()
                                    {
                                        self.enc_recipient = path.display().to_string();
                                    }
                                }
                                ui.end_row();
                            });

                        ui.add_space(14.0);
                        let encrypt_btn = ui.add_sized(
                            [140.0, 32.0],
                            egui::Button::new("Encrypt File")
                                .fill(egui::Color32::from_rgb(6, 182, 212))
                        );
                        if encrypt_btn.clicked() {
                            self.run_encryption();
                        }

                        if let Some(status) = &self.enc_status {
                            ui.add_space(6.0);
                            match status {
                                Ok(msg) => {
                                    ui.colored_label(egui::Color32::from_rgb(16, 185, 129), format!("Success: {}", msg));
                                }
                                Err(err) => {
                                    ui.colored_label(egui::Color32::from_rgb(239, 68, 68), format!("Error: {}", err));
                                }
                            }
                        }
                    }
                    Tab::Decrypt => {
                        ui.strong("Open Encrypted Hybrid Envelope (.qvf)");
                        ui.add_space(8.0);

                        egui::Grid::new("decrypt_grid")
                            .num_columns(3)
                            .spacing([10.0, 12.0])
                            .show(ui, |ui| {
                                // Vault File
                                ui.label("Envelope File (.qvf):");
                                ui.text_edit_singleline(&mut self.dec_vault);
                                if ui.button("Browse").clicked() {
                                    if let Some(path) = rfd::FileDialog::new()
                                        .add_filter("QuantumVault Envelope", &["qvf"])
                                        .pick_file()
                                    {
                                        self.dec_vault = path.display().to_string();
                                    }
                                }
                                ui.end_row();

                                // Output File
                                ui.label("Decrypted Output File:");
                                ui.text_edit_singleline(&mut self.dec_output);
                                if ui.button("Save As").clicked() {
                                    if let Some(path) = rfd::FileDialog::new().save_file() {
                                        self.dec_output = path.display().to_string();
                                    }
                                }
                                ui.end_row();

                                // My Identity (Recipient)
                                ui.label("My Identity (.qvk):");
                                ui.text_edit_singleline(&mut self.dec_recipient);
                                if ui.button("Browse").clicked() {
                                    if let Some(path) = rfd::FileDialog::new()
                                        .add_filter("QuantumVault Key", &["qvk"])
                                        .pick_file()
                                    {
                                        self.dec_recipient = path.display().to_string();
                                    }
                                }
                                ui.end_row();

                                // Sender Public Key (Optional)
                                ui.label("Sender Public Key / B64 (Opt):");
                                ui.text_edit_singleline(&mut self.dec_sender_pub);
                                if ui.button("Browse").clicked() {
                                    if let Some(path) = rfd::FileDialog::new()
                                        .add_filter("QuantumVault Key", &["qvk"])
                                        .pick_file()
                                    {
                                        self.dec_sender_pub = path.display().to_string();
                                    }
                                }
                                ui.end_row();
                            });

                        ui.add_space(14.0);
                        let decrypt_btn = ui.add_sized(
                            [140.0, 32.0],
                            egui::Button::new("Decrypt File")
                                .fill(egui::Color32::from_rgb(6, 182, 212))
                        );
                        if decrypt_btn.clicked() {
                            self.run_decryption();
                        }

                        if let Some(status) = &self.dec_status {
                            ui.add_space(6.0);
                            match status {
                                Ok(msg) => {
                                    ui.colored_label(egui::Color32::from_rgb(16, 185, 129), format!("Success: {}", msg));
                                }
                                Err(err) => {
                                    ui.colored_label(egui::Color32::from_rgb(239, 68, 68), format!("Error: {}", err));
                                }
                            }
                        }
                    }
                });
        });
    }
}

fn configure_visuals(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();

    // Typography
    style.text_styles.insert(
        egui::TextStyle::Heading,
        egui::FontId::new(26.0, egui::FontFamily::Proportional),
    );
    style.text_styles.insert(
        egui::TextStyle::Body,
        egui::FontId::new(14.0, egui::FontFamily::Proportional),
    );
    style.text_styles.insert(
        egui::TextStyle::Button,
        egui::FontId::new(14.0, egui::FontFamily::Proportional),
    );

    // Rounded card widgets
    style.visuals.window_rounding = 14.0.into();
    style.visuals.widgets.noninteractive.rounding = 10.0.into();
    style.visuals.widgets.inactive.rounding = 8.0.into();
    style.visuals.widgets.hovered.rounding = 8.0.into();
    style.visuals.widgets.active.rounding = 8.0.into();

    // Slate dark theme with cyan accent
    let bg_color = egui::Color32::from_rgb(11, 15, 26); // Space black
    let card_color = egui::Color32::from_rgb(22, 28, 45); // Slate deep card
    let accent_color = egui::Color32::from_rgb(6, 182, 212); // Neon cyan

    style.visuals.dark_mode = true;
    style.visuals.override_text_color = Some(egui::Color32::from_rgb(241, 245, 249)); // Slate white
    style.visuals.widgets.noninteractive.bg_fill = bg_color;
    style.visuals.widgets.inactive.bg_fill = card_color;
    style.visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(30, 41, 59); // lighter slate
    style.visuals.widgets.active.bg_fill = accent_color;
    style.visuals.selection.bg_fill = accent_color;

    ctx.set_style(style);
}

fn generate_q_icon() -> egui::IconData {
    let width = 64;
    let height = 64;
    let mut rgba = vec![0u8; width * height * 4];

    let cx = 32.0;
    let cy = 30.0; // slightly offset up to balance the tail
    let ring_outer = 18.0;
    let ring_inner = 13.0;

    for y in 0..height {
        for x in 0..width {
            let idx = (y * width + x) * 4;
            let px = x as f32 + 0.5;
            let py = y as f32 + 0.5;

            let dx = px - cx;
            let dy = py - cy;
            let dist = (dx * dx + dy * dy).sqrt();

            // Check if inside the ring
            let in_ring = dist >= ring_inner && dist <= ring_outer;

            // Check if inside the tail
            let in_tail = if dx > 8.0 && dy > 8.0 {
                let dist_to_line = (dx - dy).abs() / 2.0f32.sqrt();
                dist_to_line < 2.5 && dx < 22.0 && dy < 22.0
            } else {
                false
            };

            // Anti-aliased background / foreground
            if in_ring || in_tail {
                // Vibrant Cyan Color (RGB: 6, 182, 212)
                rgba[idx] = 6;
                rgba[idx + 1] = 182;
                rgba[idx + 2] = 212;
                rgba[idx + 3] = 255;
            } else {
                // Transparent background
                rgba[idx] = 0;
                rgba[idx + 1] = 0;
                rgba[idx + 2] = 0;
                rgba[idx + 3] = 0;
                rgba[idx + 3] = 0;
            }
        }
    }

    egui::IconData {
        rgba,
        width: width as u32,
        height: height as u32,
    }
}

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([720.0, 580.0])
            .with_resizable(true)
            .with_icon(generate_q_icon()),
        ..Default::default()
    };

    eframe::run_native(
        "QuantumVault - Post-Quantum File Encryption",
        options,
        Box::new(|cc| {
            configure_visuals(&cc.egui_ctx);
            Ok(Box::new(QuantumVaultApp::default()))
        }),
    )
}
