use pyo3::prelude::*;
use pyo3::exceptions::PyValueError;
use quantumvault_core::{PQIdentity, PQPublicKey, PQFile, KeyMeta};

fn qverr(e: quantumvault_core::QVError) -> PyErr {
    PyValueError::new_err(e.to_string())
}

#[pyclass(name = "Identity")]
struct PyIdentity {
    inner: PQIdentity,
}

#[pymethods]
impl PyIdentity {
    /// Generate a new random hybrid keypair.
    #[new]
    #[pyo3(signature = (label=None))]
    fn new(label: Option<String>) -> PyResult<Self> {
        let meta = KeyMeta { label, ..Default::default() };
        let inner = PQIdentity::generate_with_meta(meta).map_err(qverr)?;
        Ok(Self { inner })
    }

    /// Get the corresponding public key.
    #[getter]
    fn public_key(&self) -> PyResult<PyPublicKey> {
        let pub_bytes = self.inner.export_public().map_err(qverr)?;
        let pub_key = PQPublicKey::from_bytes(&pub_bytes).map_err(qverr)?;
        Ok(PyPublicKey { inner: pub_key })
    }

    /// Export public key as bytes. Safe to share.
    fn export_public(&self) -> PyResult<Vec<u8>> {
        self.inner.export_public().map_err(qverr)
    }

    /// Export public key as base64 string. Safe to share.
    fn export_public_b64(&self) -> PyResult<String> {
        self.inner.export_public_b64().map_err(qverr)
    }

    /// Export secret key as bytes. Encrypt before storing.
    fn export_secret(&self) -> PyResult<Vec<u8>> {
        self.inner.export_secret().map_err(qverr)
    }

    /// Load identity from previously exported secret key bytes.
    #[staticmethod]
    fn from_secret_bytes(data: &[u8]) -> PyResult<Self> {
        let inner = PQIdentity::from_secret_bytes(data).map_err(qverr)?;
        Ok(Self { inner })
    }
}

#[pyclass(name = "PublicKey")]
struct PyPublicKey {
    inner: PQPublicKey,
}

#[pymethods]
impl PyPublicKey {
    /// Load public key from bytes.
    #[new]
    fn new(data: &[u8]) -> PyResult<Self> {
        let inner = PQPublicKey::from_bytes(data).map_err(qverr)?;
        Ok(Self { inner })
    }

    /// Load public key from base64 string.
    #[staticmethod]
    fn from_b64(s: &str) -> PyResult<Self> {
        let inner = PQPublicKey::from_b64(s).map_err(qverr)?;
        Ok(Self { inner })
    }

    /// Get a BLAKE3 fingerprint for out-of-band key verification.
    fn fingerprint(&self) -> PyResult<String> {
        self.inner.fingerprint().map_err(qverr)
    }
}

/// Encrypt bytes for a recipient, optionally signing with sender's identity.
#[pyfunction]
#[pyo3(signature = (data, recipient, sender=None))]
fn encrypt(
    data:      &[u8],
    recipient: &PyPublicKey,
    sender:    Option<&PyIdentity>,
) -> PyResult<Vec<u8>> {
    match sender {
        Some(s) => PQFile::encrypt_and_sign(data, &recipient.inner, &s.inner).map_err(qverr),
        None    => PQFile::encrypt(data, &recipient.inner).map_err(qverr),
    }
}

/// Decrypt an envelope, optionally verifying sender's signature.
#[pyfunction]
#[pyo3(signature = (envelope, recipient, sender_public=None))]
fn decrypt(
    envelope:      &[u8],
    recipient:     &PyIdentity,
    sender_public: Option<&PyPublicKey>,
) -> PyResult<Vec<u8>> {
    PQFile::decrypt_and_verify(
        envelope,
        &recipient.inner,
        sender_public.map(|s| &s.inner),
    ).map_err(qverr)
}

/// Sign bytes with a private key. Returns detached signature bytes.
#[pyfunction]
fn sign(data: &[u8], identity: &PyIdentity) -> PyResult<Vec<u8>> {
    quantumvault_core::sign(&identity.inner, data).map_err(qverr)
}

/// Verify a detached signature. Raises ValueError if invalid.
#[pyfunction]
fn verify(data: &[u8], signature: &[u8], public_key: &PyPublicKey) -> PyResult<()> {
    quantumvault_core::verify(&public_key.inner, data, signature).map_err(qverr)
}

#[pymodule]
fn _quantumvault(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyIdentity>()?;
    m.add_class::<PyPublicKey>()?;
    m.add_function(wrap_pyfunction!(encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(sign, m)?)?;
    m.add_function(wrap_pyfunction!(verify, m)?)?;
    m.add("__version__", "0.2.0")?;
    Ok(())
}
