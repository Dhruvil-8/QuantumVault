import customtkinter as ctk
from tkinter import filedialog, messagebox
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
import quantum_engine

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class QuantumVaultApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Quantum Vault v1.0")
        self.geometry("700x550")
        self.resizable(False, False)
        
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.sidebar_frame = ctk.CTkFrame(self, width=140, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, rowspan=4, sticky="nsew")
        
        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="QUANTUM\nVAULT", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.btn_gen_keys = ctk.CTkButton(self.sidebar_frame, text="Generate Identity", command=self.generate_identity)
        self.btn_gen_keys.grid(row=1, column=0, padx=20, pady=10)

        self.btn_mode_lock = ctk.CTkButton(self.sidebar_frame, text="Lock File", fg_color="transparent", border_width=2, text_color=("gray10", "#DCE4EE"), command=self.show_lock_frame)
        self.btn_mode_lock.grid(row=2, column=0, padx=20, pady=10)

        self.btn_mode_unlock = ctk.CTkButton(self.sidebar_frame, text="Unlock File", fg_color="transparent", border_width=2, text_color=("gray10", "#DCE4EE"), command=self.show_unlock_frame)
        self.btn_mode_unlock.grid(row=3, column=0, padx=20, pady=10)

        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")

        self.selected_file = None
        self.key_paths = {"c_pub": None, "q_pub": None, "c_priv": None, "q_priv": None}
        self.show_lock_frame()

    def show_lock_frame(self):
        self.clear_frame()
        self.reset_variables()
        
        ctk.CTkLabel(self.main_frame, text="LOCK FILE", font=ctk.CTkFont(size=24)).pack(pady=20)
        ctk.CTkButton(self.main_frame, text="1. Select File to Encrypt", command=self.select_target_file).pack(pady=10)
        self.lbl_file_status = ctk.CTkLabel(self.main_frame, text="No file selected", text_color="gray")
        self.lbl_file_status.pack(pady=5)

        ctk.CTkButton(self.main_frame, text="2. Select Recipient Keys (Folder)", command=self.select_recipient_keys).pack(pady=10)
        self.lbl_key_status = ctk.CTkLabel(self.main_frame, text="Keys not loaded", text_color="gray")
        self.lbl_key_status.pack(pady=5)

        ctk.CTkButton(self.main_frame, text="ENCRYPT NOW", fg_color="red", height=40, font=ctk.CTkFont(weight="bold"), command=self.run_encryption).pack(pady=40)

    def show_unlock_frame(self):
        self.clear_frame()
        self.reset_variables()
        
        ctk.CTkLabel(self.main_frame, text="UNLOCK VAULT", font=ctk.CTkFont(size=24)).pack(pady=20)
        ctk.CTkButton(self.main_frame, text="1. Select .qvault File", command=self.select_vault_file).pack(pady=10)
        self.lbl_file_status = ctk.CTkLabel(self.main_frame, text="No file selected", text_color="gray")
        self.lbl_file_status.pack(pady=5)

        ctk.CTkButton(self.main_frame, text="2. Select Your Identity Folder", command=self.select_private_keys).pack(pady=10)
        self.lbl_key_status = ctk.CTkLabel(self.main_frame, text="Keys not loaded", text_color="gray")
        self.lbl_key_status.pack(pady=5)

        ctk.CTkButton(self.main_frame, text="DECRYPT NOW", fg_color="green", height=40, font=ctk.CTkFont(weight="bold"), command=self.run_decryption).pack(pady=40)

    def clear_frame(self):
        for widget in self.main_frame.winfo_children():
            widget.destroy()

    def reset_variables(self):
        self.selected_file = None
        self.key_paths = {"c_pub": None, "q_pub": None, "c_priv": None, "q_priv": None}

    def generate_identity(self):
        folder = filedialog.askdirectory(title="Select Folder to Save New Keys")
        if folder:
            try:
                q_pub, q_priv = quantum_engine.get_kyber_keys()
                c_priv_obj = x25519.X25519PrivateKey.generate()
                c_priv = c_priv_obj.private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption())
                c_pub = c_priv_obj.public_key().public_bytes_raw()

                with open(os.path.join(folder, "id_quantum.pub"), "wb") as f: f.write(q_pub)
                with open(os.path.join(folder, "id_quantum.priv"), "wb") as f: f.write(q_priv)
                with open(os.path.join(folder, "id_classic.pub"), "wb") as f: f.write(c_pub)
                with open(os.path.join(folder, "id_classic.priv"), "wb") as f: f.write(c_priv)

                messagebox.showinfo("Success", "Identity created successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to generate identity: {str(e)}")

    def select_target_file(self):
        self.selected_file = filedialog.askopenfilename()
        if self.selected_file:
            self.lbl_file_status.configure(text=os.path.basename(self.selected_file), text_color="white")

    def select_vault_file(self):
        self.selected_file = filedialog.askopenfilename(filetypes=[("Quantum Vault", "*.qvault")])
        if self.selected_file:
            self.lbl_file_status.configure(text=os.path.basename(self.selected_file), text_color="white")

    def select_recipient_keys(self):
        folder = filedialog.askdirectory(title="Select Folder containing Public Keys")
        if folder:
            try:
                p1 = os.path.join(folder, "id_classic.pub")
                p2 = os.path.join(folder, "id_quantum.pub")
                if not os.path.exists(p1) or not os.path.exists(p2): raise FileNotFoundError("Missing Public Key files")
                
                with open(p1, "rb") as f: self.key_paths["c_pub"] = f.read()
                with open(p2, "rb") as f: self.key_paths["q_pub"] = f.read()
                self.lbl_key_status.configure(text="Public Keys Loaded", text_color="green")
            except:
                self.lbl_key_status.configure(text="Error loading keys", text_color="red")

    def select_private_keys(self):
        folder = filedialog.askdirectory(title="Select Folder containing Private Keys")
        if folder:
            try:
                p1 = os.path.join(folder, "id_classic.priv")
                p2 = os.path.join(folder, "id_quantum.priv")
                if not os.path.exists(p1) or not os.path.exists(p2): raise FileNotFoundError("Missing Private Key files")

                with open(p1, "rb") as f: 
                    self.key_paths["c_priv"] = x25519.X25519PrivateKey.from_private_bytes(f.read())
                with open(p2, "rb") as f: 
                    self.key_paths["q_priv"] = f.read()
                self.lbl_key_status.configure(text="Private Keys Loaded", text_color="green")
            except:
                self.lbl_key_status.configure(text="Error loading keys", text_color="red")

    def run_encryption(self):
        if self.selected_file and self.key_paths["c_pub"]:
            try:
                quantum_engine.lock_vault(self.selected_file, self.key_paths["c_pub"], self.key_paths["q_pub"])
                messagebox.showinfo("Success", f"File Locked!\nSaved as: {os.path.basename(self.selected_file)}.qvault")
            except Exception as e:
                messagebox.showerror("Error", f"Encryption failed: {str(e)}")

    def run_decryption(self):
        if self.selected_file and self.key_paths["c_priv"]:
            try:
                # Capture the saved filename from the engine
                saved_name = quantum_engine.unlock_vault(self.selected_file, self.key_paths["c_priv"], self.key_paths["q_priv"])
                messagebox.showinfo("Success", f"File Unlocked!\nSaved as: {os.path.basename(saved_name)}")
            except Exception as e:
                messagebox.showerror("Error", f"Decryption failed: {str(e)}")

if __name__ == "__main__":
    app = QuantumVaultApp()
    app.mainloop()