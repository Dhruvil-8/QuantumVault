use wasm_bindgen::prelude::*;
use quantumvault_core::{PQIdentity, PQPublicKey, PQFile};

#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

fn to_js_err(e: quantumvault_core::QVError) -> JsValue {
    JsValue::from_str(&e.to_string())
}

#[wasm_bindgen]
pub struct Identity {
    inner: PQIdentity,
}

#[wasm_bindgen]
impl Identity {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<Identity, JsValue> {
        PQIdentity::generate()
            .map(|inner| Identity { inner })
            .map_err(to_js_err)
    }

    pub fn export_public(&self) -> Result<Vec<u8>, JsValue> {
        self.inner.export_public().map_err(to_js_err)
    }

    pub fn export_public_b64(&self) -> Result<String, JsValue> {
        self.inner.export_public_b64().map_err(to_js_err)
    }

    /// Export secret key as bytes.
    /// WARNING: These are raw secret key bytes. Encrypt before storing or transmitting.
    /// In a browser context, consider using the Web Crypto API for secure storage.
    pub fn export_secret(&self) -> Result<Vec<u8>, JsValue> {
        self.inner.export_secret().map_err(to_js_err)
    }

    pub fn from_secret_bytes(data: &[u8]) -> Result<Identity, JsValue> {
        PQIdentity::from_secret_bytes(data)
            .map(|inner| Identity { inner })
            .map_err(to_js_err)
    }
}

#[wasm_bindgen]
pub struct PublicKey {
    inner: PQPublicKey,
}

#[wasm_bindgen]
impl PublicKey {
    #[wasm_bindgen(constructor)]
    pub fn new(data: &[u8]) -> Result<PublicKey, JsValue> {
        PQPublicKey::from_bytes(data)
            .map(|inner| PublicKey { inner })
            .map_err(to_js_err)
    }

    pub fn from_b64(s: &str) -> Result<PublicKey, JsValue> {
        PQPublicKey::from_b64(s)
            .map(|inner| PublicKey { inner })
            .map_err(to_js_err)
    }

    /// Returns a BLAKE3 fingerprint string for out-of-band key verification.
    /// Format: "QV:xxxx:xxxx:xxxx:xxxx"
    pub fn fingerprint(&self) -> Result<String, JsValue> {
        self.inner.fingerprint().map_err(to_js_err)
    }
}

#[wasm_bindgen]
pub fn encrypt(data: &[u8], recipient: &PublicKey) -> Result<Vec<u8>, JsValue> {
    PQFile::encrypt(data, &recipient.inner).map_err(to_js_err)
}

#[wasm_bindgen]
pub fn encrypt_signed(data: &[u8], recipient: &PublicKey, sender: &Identity) -> Result<Vec<u8>, JsValue> {
    PQFile::encrypt_and_sign(data, &recipient.inner, &sender.inner).map_err(to_js_err)
}

#[wasm_bindgen]
pub fn decrypt(envelope: &[u8], recipient: &Identity) -> Result<Vec<u8>, JsValue> {
    PQFile::decrypt_and_verify(envelope, &recipient.inner, None).map_err(to_js_err)
}

#[wasm_bindgen]
pub fn decrypt_verified(envelope: &[u8], recipient: &Identity, sender: &PublicKey) -> Result<Vec<u8>, JsValue> {
    PQFile::decrypt_and_verify(envelope, &recipient.inner, Some(&sender.inner)).map_err(to_js_err)
}
