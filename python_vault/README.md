# Quantum Vault: File Encryption

Quantum Vault is a local-first, cross-platform file encryption tool designed to protect sensitive data against the "Harvest Now, Decrypt Later" threat posed by future Quantum Computers.

It utilizes a Hybrid Cryptosystem, wrapping battle-tested Classical algorithms (X25519) inside NIST-standard Post-Quantum algorithms (Kyber-1024). This ensures that even if one cryptographic layer is broken in the future, the data remains secure.

## Development Methodology

**AI & Tools:** Code generated using Google Gemini 3 Pro & Gemini 3 Flash (via Google AI Studio).

**Role of the Developer:** My role was guiding the architecture, asking the right questions, and providing iterative feedback to refine the implementation and solve challenges.

## Technical Architecture

The application uses a "Defense in Depth" strategy. Keys are ephemeral (generated per session) and derived using a hybrid mix.

| Layer | Algorithm | Purpose |
| :--- | :--- | :--- |
| **1. Classic** | **X25519** (Elliptic Curve) | Standard Diffie-Hellman key exchange. |
| **2. Quantum** | **CRYSTALS-Kyber-1024** | NIST-Standard Lattice-based Key Encapsulation. |
| **3. Derivation** | **HKDF-SHA3-256** | Mixes both secrets into a uniform 32-byte key. |
| **4. Encryption** | **AES-256-GCM** | Authenticated encryption for the file payload. |

## Prerequisites

To build and run this project, you need:
*   Python 3.10 or higher.
*   A C Compiler (GCC, Clang, or MSVC).
*   CMake (Build tool).

## Build Instructions

### 1. Compile the Quantum Engine (liboqs)
This project depends on liboqs, a C library. You must compile the binary for your specific operating system.

**For Windows:**
1.  Clone the library: git clone https://github.com/open-quantum-safe/liboqs.git
2.  Navigate to the folder and create a build directory.
3.  Run CMake: cmake -G "Unix Makefiles" .. -DBUILD_SHARED_LIBS=ON -DOQS_USE_OPENSSL=OFF -DOQS_BUILD_ONLY_LIB=ON
4.  Compile: make -j4
5.  Action: Locate liboqs.dll in the build/bin folder and copy it to the root of this project.

**For Linux / macOS:**
Follow the same steps as above. The output file will be liboqs.so (Linux) or liboqs.dylib (macOS). Copy this file to the project root.

### 2. Install Python Dependencies
pip install -r requirements.txt

## Creating the Executable (.exe)

To distribute this application to users who do not have Python installed, you can bundle it into a standalone executable using PyInstaller.

1.  Ensure liboqs.dll (or your OS equivalent) is in the project folder.
2.  Open your terminal and run the following command:

**Windows Command:**
pyinstaller --noconfirm --onefile --windowed --add-data "liboqs.dll;." --name "QuantumVault" quantum_gui.py

**Linux/Mac Command:**
pyinstaller --noconfirm --onefile --windowed --add-data "liboqs.so:." --name "QuantumVault" quantum_gui.py

The final application will be found in the dist folder.

## Usage Guide

Run the script (python quantum_gui.py) or the executable.

### 1. Identity Generation
*   Click Generate Identity.
*   Select a secure folder (e.g., an external USB drive).
*   The tool generates a Classic Keypair and a Quantum Keypair.

### 2. Encryption (Lock)
*   Select the target file.
*   Select the folder containing the Public Keys of the recipient.
*   Click Encrypt.
*   The output is a .qvault container.

### 3. Decryption (Unlock)
*   Select the .qvault file.
*   Select the folder containing your Private Keys.
*   Click Decrypt.
*   The tool authenticates the data and restores the original file with its original extension.

## Limitations & Roadmap

**Current Limitations:**
*   Memory Usage: The encryption engine loads the full file into RAM. Do not encrypt files larger than your available system memory.
*   Key Recovery: If private key files are lost, the data cannot be recovered.

**Future Improvements:**
*   Stream Processing: Refactor engine to process files in chunks, enabling support for large files (1TB+).
*   Mobile Support:support Android and iOS.
*   Digital Signatures: Implement Dilithium for sender authentication.

# ⚠️ Security Disclaimer and Testing Status

**Status:** Experimental / Proof of Concept

This project is currently in the **Testing and Evaluation** phase. While it implements mathematically sound hybrid cryptography (NIST-standard Kyber-1024 and X25519), the following should be noted:

1. **No Professional Audit:** This codebase has not been audited by professional cryptographers or security researchers.
2. **Experimental Implementation:** This tool was developed using an AI-orchestrated methodology. While functional testing has been successful, it has not undergone rigorous edge-case testing or side-channel attack analysis.
3. **Usage:** This software is intended for research, educational, and personal evaluation purposes.