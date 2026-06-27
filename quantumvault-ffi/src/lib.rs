use std::ffi::{c_char, CStr, CString};
use quantumvault_core::{PQIdentity, PQPublicKey, PQFile};

/// Opaque handle types
pub struct QVIdentityHandle(PQIdentity);
pub struct QVPublicKeyHandle(PQPublicKey);

/// Result codes
#[repr(C)]
pub enum QVStatus {
    Ok          = 0,
    Error       = 1,
    InvalidArg  = 2,
    BufferSmall = 3,
}

/// Generate a new identity. Caller owns the returned handle.
/// Free with qv_identity_free().
#[no_mangle]
pub extern "C" fn qv_identity_generate() -> *mut QVIdentityHandle {
    match PQIdentity::generate() {
        Ok(id) => Box::into_raw(Box::new(QVIdentityHandle(id))),
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn qv_identity_free(handle: *mut QVIdentityHandle) {
    if !handle.is_null() {
        unsafe { drop(Box::from_raw(handle)); }
    }
}

/// Export public key bytes into caller-provided buffer.
/// If buf is NULL or buf_len is too small, writes required length to out_len and returns BufferSmall.
#[no_mangle]
pub extern "C" fn qv_identity_export_public(
    handle:  *const QVIdentityHandle,
    buf:     *mut u8,
    buf_len: usize,
    out_len: *mut usize,
) -> QVStatus {
    if handle.is_null() || out_len.is_null() { return QVStatus::InvalidArg; }
    let id = unsafe { &(*handle).0 };
    match id.export_public() {
        Err(_) => QVStatus::Error,
        Ok(bytes) => {
            unsafe { *out_len = bytes.len(); }
            if buf.is_null() || buf_len < bytes.len() {
                return QVStatus::BufferSmall;
            }
            unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, bytes.len()); }
            QVStatus::Ok
        }
    }
}

/// Export secret key bytes into caller-provided buffer.
#[no_mangle]
pub extern "C" fn qv_identity_export_secret(
    handle:  *const QVIdentityHandle,
    buf:     *mut u8,
    buf_len: usize,
    out_len: *mut usize,
) -> QVStatus {
    if handle.is_null() || out_len.is_null() { return QVStatus::InvalidArg; }
    let id = unsafe { &(*handle).0 };
    match id.export_secret() {
        Err(_) => QVStatus::Error,
        Ok(bytes) => {
            unsafe { *out_len = bytes.len(); }
            if buf.is_null() || buf_len < bytes.len() {
                return QVStatus::BufferSmall;
            }
            unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, bytes.len()); }
            QVStatus::Ok
        }
    }
}

/// Load identity from secret key bytes.
#[no_mangle]
pub extern "C" fn qv_identity_from_secret_bytes(
    buf:     *const u8,
    buf_len: usize,
) -> *mut QVIdentityHandle {
    if buf.is_null() || buf_len == 0 { return std::ptr::null_mut(); }
    let slice = unsafe { std::slice::from_raw_parts(buf, buf_len) };
    match PQIdentity::from_secret_bytes(slice) {
        Ok(id) => Box::into_raw(Box::new(QVIdentityHandle(id))),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Load public key from bytes.
#[no_mangle]
pub extern "C" fn qv_public_key_from_bytes(
    buf:     *const u8,
    buf_len: usize,
) -> *mut QVPublicKeyHandle {
    if buf.is_null() || buf_len == 0 { return std::ptr::null_mut(); }
    let slice = unsafe { std::slice::from_raw_parts(buf, buf_len) };
    match PQPublicKey::from_bytes(slice) {
        Ok(pk) => Box::into_raw(Box::new(QVPublicKeyHandle(pk))),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Free public key handle.
#[no_mangle]
pub extern "C" fn qv_public_key_free(handle: *mut QVPublicKeyHandle) {
    if !handle.is_null() {
        unsafe { drop(Box::from_raw(handle)); }
    }
}

/// Encrypt data.
#[no_mangle]
pub extern "C" fn qv_encrypt(
    data:       *const u8,
    data_len:   usize,
    recipient:  *const QVPublicKeyHandle,
    sender:     *const QVIdentityHandle,
    buf:        *mut u8,
    buf_len:    usize,
    out_len:    *mut usize,
) -> QVStatus {
    if data.is_null() || recipient.is_null() || out_len.is_null() { return QVStatus::InvalidArg; }
    let data_slice = unsafe { std::slice::from_raw_parts(data, data_len) };
    let rec_key = unsafe { &(*recipient).0 };
    
    let res = if sender.is_null() {
        PQFile::encrypt(data_slice, rec_key)
    } else {
        let send_id = unsafe { &(*sender).0 };
        PQFile::encrypt_and_sign(data_slice, rec_key, send_id)
    };

    match res {
        Err(_) => QVStatus::Error,
        Ok(bytes) => {
            unsafe { *out_len = bytes.len(); }
            if buf.is_null() || buf_len < bytes.len() {
                return QVStatus::BufferSmall;
            }
            unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, bytes.len()); }
            QVStatus::Ok
        }
    }
}

/// Decrypt data.
#[no_mangle]
pub extern "C" fn qv_decrypt(
    envelope:      *const u8,
    envelope_len:  usize,
    recipient:     *const QVIdentityHandle,
    sender_pub:    *const QVPublicKeyHandle,
    buf:           *mut u8,
    buf_len:       *mut usize,
) -> QVStatus {
    if envelope.is_null() || recipient.is_null() || buf_len.is_null() { return QVStatus::InvalidArg; }
    let env_slice = unsafe { std::slice::from_raw_parts(envelope, envelope_len) };
    let rec_id = unsafe { &(*recipient).0 };
    let send_key = if sender_pub.is_null() {
        None
    } else {
        Some(unsafe { &(*sender_pub).0 })
    };

    match PQFile::decrypt_and_verify(env_slice, rec_id, send_key) {
        Err(_) => QVStatus::Error,
        Ok(bytes) => {
            let required_len = bytes.len();
            let current_len = unsafe { *buf_len };
            unsafe { *buf_len = required_len; }
            if buf.is_null() || current_len < required_len {
                return QVStatus::BufferSmall;
            }
            unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, required_len); }
            QVStatus::Ok
        }
    }
}

/// Sign data.
#[no_mangle]
pub extern "C" fn qv_sign(
    data:      *const u8,
    data_len:  usize,
    identity:  *const QVIdentityHandle,
    buf:       *mut u8,
    buf_len:   usize,
    out_len:   *mut usize,
) -> QVStatus {
    if data.is_null() || identity.is_null() || out_len.is_null() { return QVStatus::InvalidArg; }
    let data_slice = unsafe { std::slice::from_raw_parts(data, data_len) };
    let id = unsafe { &(*identity).0 };

    match quantumvault_core::sign(id, data_slice) {
        Err(_) => QVStatus::Error,
        Ok(bytes) => {
            unsafe { *out_len = bytes.len(); }
            if buf.is_null() || buf_len < bytes.len() {
                return QVStatus::BufferSmall;
            }
            unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, bytes.len()); }
            QVStatus::Ok
        }
    }
}

/// Verify signature.
#[no_mangle]
pub extern "C" fn qv_verify(
    data:        *const u8,
    data_len:    usize,
    signature:   *const u8,
    sig_len:     usize,
    public_key:  *const QVPublicKeyHandle,
) -> QVStatus {
    if data.is_null() || signature.is_null() || public_key.is_null() { return QVStatus::InvalidArg; }
    let data_slice = unsafe { std::slice::from_raw_parts(data, data_len) };
    let sig_slice = unsafe { std::slice::from_raw_parts(signature, sig_len) };
    let pk = unsafe { &(*public_key).0 };

    match quantumvault_core::verify(pk, data_slice, sig_slice) {
        Ok(_) => QVStatus::Ok,
        Err(_) => QVStatus::Error,
    }
}
