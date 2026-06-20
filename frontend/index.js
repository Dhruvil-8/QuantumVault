document.addEventListener('DOMContentLoaded', () => {
    // Prevent form submission behavior
    const form = document.getElementById('file-ops-form');
    if (form) {
        form.addEventListener('submit', (e) => e.preventDefault());
    }

    // Check if running inside Tauri
    const isTauri = window.__TAURI__ !== undefined;
    if (!isTauri) {
        showStatus('identity-status', 'Warning: Running outside of Tauri container. Native APIs are mock-only.', 'info');
        showStatus('ops-status', 'Warning: Running outside of Tauri container. Native APIs are mock-only.', 'info');
    }

    // Tauri APIs (fallbacks if running in standard browser)
    const dialog = isTauri ? window.__TAURI__.dialog : {
        open: async (opts) => prompt(`[Mock Dialog] Select ${opts.directory ? 'directory' : 'file'}:`),
        save: async () => prompt('[Mock Dialog] Select save path:')
    };

    const invoke = isTauri ? window.__TAURI__.tauri.invoke : async (cmd, args) => {
        console.log(`[Mock Invoke] ${cmd}:`, args);
        return new Promise(resolve => setTimeout(() => resolve(`Mock ${cmd} Success`), 1000));
    };

    // State
    let mode = 'encrypt'; // 'encrypt' | 'decrypt'

    // DOM Elements
    const btnGenerateIdentity = document.getElementById('btn-generate-identity');
    const identityPathInput = document.getElementById('identity-path');
    const identityStatus = document.getElementById('identity-status');

    const tabEncrypt = document.getElementById('tab-encrypt');
    const tabDecrypt = document.getElementById('tab-decrypt');

    const lblSourceFile = document.getElementById('lbl-source-file');
    const lblOutputFile = document.getElementById('lbl-output-file');
    const lblSenderKey = document.getElementById('lbl-sender-key');
    const lblRecipientKey = document.getElementById('lbl-recipient-key');

    const inputFile = document.getElementById('input-file');
    const outputFile = document.getElementById('output-file');
    const senderKeyPath = document.getElementById('sender-key-path');
    const recipientKeyPath = document.getElementById('recipient-key-path');

    const btnBrowseInput = document.getElementById('btn-browse-input');
    const btnBrowseOutput = document.getElementById('btn-browse-output');
    const btnSelectSender = document.getElementById('btn-select-sender');
    const btnSelectRecipient = document.getElementById('btn-select-recipient');

    const btnExecute = document.getElementById('btn-execute');
    const opsStatus = document.getElementById('ops-status');

    // Tab Switching Logic
    tabEncrypt.addEventListener('click', () => setMode('encrypt'));
    tabDecrypt.addEventListener('click', () => setMode('decrypt'));

    function setMode(newMode) {
        mode = newMode;

        // Reset state & fields to prevent mismatch
        inputFile.value = '';
        outputFile.value = '';
        senderKeyPath.value = '';
        recipientKeyPath.value = '';
        hideStatus('ops-status');

        if (mode === 'encrypt') {
            tabEncrypt.classList.add('active');
            tabDecrypt.classList.remove('active');

            lblSourceFile.textContent = 'Source File';
            inputFile.placeholder = 'Select a file...';

            lblOutputFile.textContent = 'Output Vault (.qvault)';
            outputFile.placeholder = 'Choose where to save...';

            lblSenderKey.textContent = 'My Identity (Sender)';
            lblRecipientKey.textContent = 'Recipient Public Key (Encryption Dir)';

            btnExecute.textContent = 'Encrypt File';
        } else {
            tabDecrypt.classList.add('active');
            tabEncrypt.classList.remove('active');

            lblSourceFile.textContent = 'Vault File';
            inputFile.placeholder = 'Select encrypted .qvault file...';

            lblOutputFile.textContent = 'Output File';
            outputFile.placeholder = 'Choose where to save decrypted file...';

            lblSenderKey.textContent = 'Sender Public Key (Signing Dir)';
            lblRecipientKey.textContent = 'My Identity (Recipient)';

            btnExecute.textContent = 'Decrypt File';
        }
    }

    // Directory/File Browser Pickers
    btnGenerateIdentity.addEventListener('click', async () => {
        try {
            const selected = await dialog.open({ directory: true, multiple: false, title: 'Select Directory to Save Identity' });
            if (selected) {
                identityPathInput.value = selected;
                showStatus('identity-status', 'Generating post-quantum identity...', 'info');

                const response = await invoke('generate_identity', { baseDir: selected });
                showStatus('identity-status', response, 'success');
            }
        } catch (err) {
            showStatus('identity-status', `Error: ${err}`, 'error');
        }
    });

    btnBrowseInput.addEventListener('click', async () => {
        const title = mode === 'encrypt' ? 'Select File to Encrypt' : 'Select Vault File to Decrypt';
        const selected = await dialog.open({ multiple: false, title });
        if (selected) {
            inputFile.value = selected;
        }
    });

    btnBrowseOutput.addEventListener('click', async () => {
        try {
            let defaultName = 'vault.qvault';
            let filters = [];
            
            if (mode === 'encrypt') {
                if (inputFile.value) {
                    const lastSlash = Math.max(inputFile.value.lastIndexOf('/'), inputFile.value.lastIndexOf('\\'));
                    let filename = lastSlash !== -1 ? inputFile.value.substring(lastSlash + 1) : inputFile.value;
                    defaultName = `${filename}.qvault`;
                } else {
                    defaultName = 'vault.qvault';
                }
                filters = [{
                    name: 'QuantumVault Files',
                    extensions: ['qvault']
                }];
            } else {
                defaultName = 'decrypted_file';
                if (inputFile.value) {
                    // Ingest the input file name and strip the .qvault extension
                    const lastSlash = Math.max(inputFile.value.lastIndexOf('/'), inputFile.value.lastIndexOf('\\'));
                    let filename = lastSlash !== -1 ? inputFile.value.substring(lastSlash + 1) : inputFile.value;
                    if (filename.toLowerCase().endsWith('.qvault')) {
                        defaultName = filename.substring(0, filename.length - 7);
                        
                        // Ingest the original extension (e.g. song.mp3 -> mp3)
                        const lastDot = defaultName.lastIndexOf('.');
                        if (lastDot !== -1 && lastDot < defaultName.length - 1) {
                            const ext = defaultName.substring(lastDot + 1);
                            filters = [{
                                name: `Decrypted ${ext.toUpperCase()} File`,
                                extensions: [ext]
                            }];
                        }
                    } else {
                        defaultName = filename;
                    }
                }
            }

            const selected = await dialog.save({
                defaultPath: defaultName,
                filters: filters
            });
            if (selected) {
                let finalPath = selected;
                if (mode === 'encrypt' && !finalPath.toLowerCase().endsWith('.qvault')) {
                    finalPath += '.qvault';
                }
                outputFile.value = finalPath;
            }
        } catch (err) {
            console.error(err);
        }
    });

    btnSelectSender.addEventListener('click', async () => {
        const title = mode === 'encrypt' ? 'Select My Identity Folder (Sender)' : 'Select Sender Public Key Folder (Signing)';
        const selected = await dialog.open({ directory: true, multiple: false, title });
        if (selected) {
            senderKeyPath.value = selected;
        }
    });

    btnSelectRecipient.addEventListener('click', async () => {
        const title = mode === 'encrypt' ? 'Select Recipient Public Key Folder (Encryption)' : 'Select My Identity Folder (Recipient)';
        const selected = await dialog.open({ directory: true, multiple: false, title });
        if (selected) {
            recipientKeyPath.value = selected;
        }
    });

    // Execute encrypt/decrypt operations
    btnExecute.addEventListener('click', async () => {
        // Validate inputs
        if (!inputFile.value || !outputFile.value || !senderKeyPath.value || !recipientKeyPath.value) {
            showStatus('ops-status', 'Please select all required paths first.', 'error');
            return;
        }

        try {
            showStatus('ops-status', 'Processing... Please wait.', 'info');

            let finalOutput = outputFile.value;
            if (mode === 'encrypt') {
                if (!finalOutput.toLowerCase().endsWith('.qvault')) {
                    finalOutput += '.qvault';
                    outputFile.value = finalOutput;
                }
            } else {
                // If decrypting, check if user provided an extension. If not, auto-append from input file.
                const lastDot = inputFile.value.lastIndexOf('.');
                if (lastDot !== -1 && inputFile.value.toLowerCase().endsWith('.qvault')) {
                    const withoutQvault = inputFile.value.substring(0, lastDot);
                    const originalDot = withoutQvault.lastIndexOf('.');
                    if (originalDot !== -1) {
                        const originalExt = withoutQvault.substring(originalDot);
                        const lastSlash = Math.max(finalOutput.lastIndexOf('/'), finalOutput.lastIndexOf('\\'));
                        const filename = lastSlash !== -1 ? finalOutput.substring(lastSlash + 1) : finalOutput;
                        if (!filename.includes('.')) {
                            finalOutput += originalExt;
                            outputFile.value = finalOutput;
                        }
                    }
                }
            }

            if (mode === 'encrypt') {
                const response = await invoke('encrypt_file', {
                    input: inputFile.value,
                    output: finalOutput,
                    senderPath: senderKeyPath.value,
                    recipientPubPath: recipientKeyPath.value
                });
                showStatus('ops-status', response, 'success');
            } else {
                const response = await invoke('decrypt_file', {
                    vaultPath: inputFile.value,
                    outputPath: finalOutput,
                    recipientPath: recipientKeyPath.value,
                    senderPubPath: senderKeyPath.value
                });
                showStatus('ops-status', response, 'success');
            }
        } catch (err) {
            showStatus('ops-status', `Error: ${err}`, 'error');
        }
    });

    // Helper functions for status box reporting
    function showStatus(elementId, message, type) {
        const box = document.getElementById(elementId);
        box.textContent = message;
        box.className = `status-box ${type}`;
    }

    function hideStatus(elementId) {
        const box = document.getElementById(elementId);
        box.className = 'status-box hidden';
        box.textContent = '';
    }
});
