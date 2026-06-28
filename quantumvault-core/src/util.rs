use std::path::Path;
use std::fs::OpenOptions;
use std::io::Write;
use crate::error::{QVError, QVResult};

/// Writes data to a file securely. On Unix systems, sets permissions to 0o600 for secrets, or 0o644 for public data.
pub fn write_secure_file<P: AsRef<Path>, C: AsRef<[u8]>>(
    path: P,
    content: C,
    _is_secret: bool,
) -> QVResult<()> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mode = if _is_secret { 0o600 } else { 0o644 };
        options.mode(mode);
    }

    let mut file = options.open(path).map_err(QVError::Io)?;
    file.write_all(content.as_ref()).map_err(QVError::Io)?;
    Ok(())
}
