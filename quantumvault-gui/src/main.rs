//! QuantumVault Native GPU GUI
//!
//! A clean, dark-themed immediate-mode desktop application built using `egui` and `eframe`.
//! Replaces the old Tauri frontend with a 100% Rust implementation.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] // hide console window on Windows in release

use eframe::egui;
use quantumvault_core::{Identity, RecipientPublic, SenderPublic, decrypt_file, encrypt_file};
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
            self.identity_status = Some(Err("Please select a target directory first.".to_string()));
            return;
        }

        let path = Path::new(&self.identity_path);
        match Identity::generate() {
            Ok(identity) => match identity.save_to(path) {
                Ok(_) => {
                    self.identity_info = Some(format!(
                        "X25519 Pub: {}\nML-KEM Key Size: {} bytes\nML-DSA Key Size: {} bytes",
                        hex::encode(identity.x25519_public_bytes()),
                        identity.ml_kem_ek_size(),
                        identity.ml_dsa_pk_size()
                    ));
                    self.identity_status =
                        Some(Ok("Identity successfully generated and saved!".to_string()));
                }
                Err(e) => {
                    self.identity_status = Some(Err(format!("Failed to save keys: {}", e)));
                }
            },
            Err(e) => {
                self.identity_status = Some(Err(format!("Key generation failed: {}", e)));
            }
        }
    }

    fn load_identity(&mut self) {
        if self.identity_path.is_empty() {
            self.identity_status = Some(Err(
                "Please select an identity directory to load.".to_string()
            ));
            return;
        }

        let path = Path::new(&self.identity_path);
        match Identity::load(path) {
            Ok(identity) => {
                self.identity_info = Some(format!(
                    "X25519 Pub: {}\nML-KEM Key Size: {} bytes\nML-DSA Key Size: {} bytes",
                    hex::encode(identity.x25519_public_bytes()),
                    identity.ml_kem_ek_size(),
                    identity.ml_dsa_pk_size()
                ));
                self.identity_status = Some(Ok("Identity successfully loaded!".to_string()));
            }
            Err(e) => {
                self.identity_status = Some(Err(format!("Failed to load identity: {}", e)));
                self.identity_info = None;
            }
        }
    }

    fn run_encryption(&mut self) {
        // Enforce .qvault extension
        if !self.enc_output.is_empty() && !self.enc_output.ends_with(".qvault") {
            self.enc_output.push_str(".qvault");
        }

        if self.enc_source.is_empty()
            || self.enc_output.is_empty()
            || self.enc_sender.is_empty()
            || self.enc_recipient.is_empty()
        {
            self.enc_status = Some(Err("All fields are required to encrypt.".to_string()));
            return;
        }

        let sender_path = Path::new(&self.enc_sender);
        let recipient_path = Path::new(&self.enc_recipient);

        let sender_identity = match Identity::load(sender_path) {
            Ok(id) => id,
            Err(e) => {
                self.enc_status = Some(Err(format!("Failed to load sender identity: {}", e)));
                return;
            }
        };

        let recipient_pub = match RecipientPublic::load(recipient_path) {
            Ok(pub_key) => pub_key,
            Err(e) => {
                self.enc_status = Some(Err(format!("Failed to load recipient public keys: {}", e)));
                return;
            }
        };

        self.enc_status = Some(Ok("Encrypting file... Please wait.".to_string()));

        match encrypt_file(
            Path::new(&self.enc_source),
            Path::new(&self.enc_output),
            &sender_identity,
            &recipient_pub,
        ) {
            Ok(_) => {
                self.enc_status = Some(Ok("✓ Encryption completed successfully!".to_string()));
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
            || self.dec_sender_pub.is_empty()
        {
            self.dec_status = Some(Err("All fields are required to decrypt.".to_string()));
            return;
        }

        let recipient_path = Path::new(&self.dec_recipient);
        let sender_pub_path = Path::new(&self.dec_sender_pub);

        let recipient_identity = match Identity::load(recipient_path) {
            Ok(id) => id,
            Err(e) => {
                self.dec_status = Some(Err(format!("Failed to load recipient identity: {}", e)));
                return;
            }
        };

        let sender_pub = match SenderPublic::load(sender_pub_path) {
            Ok(pub_key) => pub_key,
            Err(e) => {
                self.dec_status = Some(Err(format!("Failed to load sender public key: {}", e)));
                return;
            }
        };

        self.dec_status = Some(Ok("Decrypting file... Please wait.".to_string()));

        match decrypt_file(
            Path::new(&self.dec_vault),
            Path::new(&self.dec_output),
            &recipient_identity,
            &sender_pub,
        ) {
            Ok(_) => {
                self.dec_status = Some(Ok("✓ Decryption completed successfully!".to_string()));
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
                ui.label("Post-Quantum Secure File Encryption");
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
                    ui.strong("My Cryptographic Identity");
                    ui.label("Manage your local ML-KEM-1024 & ML-DSA-87 keypairs.");
                    ui.add_space(8.0);

                    ui.horizontal(|ui| {
                        ui.label("Identity Directory:");
                        ui.text_edit_singleline(&mut self.identity_path);
                        if ui.button("Select").clicked() {
                            if let Some(path) = rfd::FileDialog::new().pick_folder() {
                                self.identity_path = path.display().to_string();
                            }
                        }
                    });

                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("Generate New").clicked() {
                            self.generate_identity();
                        }
                        if ui.button("Load Existing").clicked() {
                            self.load_identity();
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
                        ui.strong("Create Encrypted Container (v6)");
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
                                ui.label("Output Vault (.qvault):");
                                ui.text_edit_singleline(&mut self.enc_output);
                                if ui.button("Save As").clicked() {
                                    if let Some(path) = rfd::FileDialog::new()
                                        .add_filter("QuantumVault Archive", &["qvault"])
                                        .save_file()
                                    {
                                        let mut path_str = path.display().to_string();
                                        if !path_str.ends_with(".qvault") {
                                            path_str.push_str(".qvault");
                                        }
                                        self.enc_output = path_str;
                                    }
                                }
                                ui.end_row();

                                // My Identity (Sender)
                                ui.label("My Identity (Sender):");
                                ui.text_edit_singleline(&mut self.enc_sender);
                                if ui.button("Select").clicked() {
                                    if let Some(path) = rfd::FileDialog::new().pick_folder() {
                                        self.enc_sender = path.display().to_string();
                                    }
                                }
                                ui.end_row();

                                // Recipient Public Key
                                ui.label("Recipient Public Keys:");
                                ui.text_edit_singleline(&mut self.enc_recipient);
                                if ui.button("Select").clicked() {
                                    if let Some(path) = rfd::FileDialog::new().pick_folder() {
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
                        ui.strong("Open Encrypted Container (v6)");
                        ui.add_space(8.0);

                        egui::Grid::new("decrypt_grid")
                            .num_columns(3)
                            .spacing([10.0, 12.0])
                            .show(ui, |ui| {
                                // Vault File
                                ui.label("Vault File (.qvault):");
                                ui.text_edit_singleline(&mut self.dec_vault);
                                if ui.button("Browse").clicked() {
                                    if let Some(path) = rfd::FileDialog::new()
                                        .add_filter("QuantumVault Archive", &["qvault"])
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

                                // Sender Public Key
                                ui.label("Sender Public Keys:");
                                ui.text_edit_singleline(&mut self.dec_sender_pub);
                                if ui.button("Select").clicked() {
                                    if let Some(path) = rfd::FileDialog::new().pick_folder() {
                                        self.dec_sender_pub = path.display().to_string();
                                    }
                                }
                                ui.end_row();

                                // My Identity (Recipient)
                                ui.label("My Identity (Recipient):");
                                ui.text_edit_singleline(&mut self.dec_recipient);
                                if ui.button("Select").clicked() {
                                    if let Some(path) = rfd::FileDialog::new().pick_folder() {
                                        self.dec_recipient = path.display().to_string();
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
