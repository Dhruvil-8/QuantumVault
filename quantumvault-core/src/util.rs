use std::path::Path;
use std::fs::OpenOptions;
use std::io::Write;
use crate::error::{QVError, QVResult};

/// Writes data to a file securely.
///
/// On Unix systems, sets permissions to 0o600 for secrets, or 0o644 for public data.
/// On Windows, uses restrictive ACLs for secret files (owner-only access).
pub fn write_secure_file<P: AsRef<Path>, C: AsRef<[u8]>>(
    path: P,
    content: C,
    is_secret: bool,
) -> QVResult<()> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mode = if is_secret { 0o600 } else { 0o644 };
        options.mode(mode);
    }

    let mut file = options.open(path.as_ref()).map_err(QVError::Io)?;
    file.write_all(content.as_ref()).map_err(QVError::Io)?;

    // S5: On Windows, restrict secret files to owner-only access
    #[cfg(windows)]
    if is_secret {
        restrict_windows_permissions(path.as_ref())?;
    }

    Ok(())
}

/// On Windows, use `icacls` to restrict file permissions to the current user only.
/// This removes inherited permissions and grants full control only to the owner.
#[cfg(windows)]
fn restrict_windows_permissions(path: &Path) -> QVResult<()> {
    use std::process::Command;

    let path_str = path.to_string_lossy();

    // Remove inherited permissions and grant only the current user full control
    let output = Command::new("icacls")
        .args([
            &*path_str,
            "/inheritance:r",           // Remove inherited permissions
            "/grant:r",
            &format!("{}:(F)", whoami()), // Grant full control to current user only
        ])
        .output()
        .map_err(QVError::Io)?;

    if !output.status.success() {
        // Non-fatal: log a warning but don't fail the operation.
        // The file was still written successfully; ACL hardening is best-effort.
        eprintln!(
            "Warning: Could not restrict file permissions for '{}': {}",
            path_str,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(())
}

/// Get the current Windows username in DOMAIN\User format for ACL commands.
#[cfg(windows)]
fn whoami() -> String {
    use std::process::Command;
    Command::new("whoami")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "%USERNAME%".to_string())
}
