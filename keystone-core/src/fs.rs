//! Owner-only files for secrets, account data, revocations, and logs.
//!
//! Owner-only means mode 0600 on unix. On Windows it means a protected
//! DACL granting full control to the current user and nobody else; new
//! files are created inside a private staging directory whose inheritable
//! owner-only entry applies at creation, so no other principal can ever
//! hold a handle to them.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use uuid::Uuid;

/// Replace `path` with `bytes` atomically: the data goes to a sibling
/// file that is owner-only from creation, is fsynced, and is renamed over
/// `path`; on unix the parent directory is fsynced after the rename.
/// Readers see the old contents or the new, never a partial file.
pub fn write_owner_only_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let (staging, mut file) = Staging::create(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    // Windows cannot rename a file that still has an open handle.
    drop(file);
    fs::rename(&staging.file, path)?;
    drop(staging);
    #[cfg(unix)]
    File::open(parent_dir(path))?.sync_all()?;
    Ok(())
}

/// Open `path` for appending, creating it owner-only when missing. An
/// existing file is narrowed to owner-only before the handle is returned
/// (on Windows, inherited entries are removed; explicit entries an
/// administrator added stay).
pub fn open_append_owner_only(path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(path)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        Ok(file)
    }
    #[cfg(windows)]
    {
        match OpenOptions::new().append(true).open(path) {
            Ok(file) => {
                windows::restrict_file(path)?;
                Ok(file)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let (staging, file) = Staging::create(path)?;
                drop(file);
                // A hard link never replaces: a file that appeared meanwhile wins.
                let linked = match fs::hard_link(&staging.file, path) {
                    Ok(()) => true,
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => false,
                    Err(e) => return Err(e),
                };
                drop(staging);
                let file = OpenOptions::new().append(true).open(path)?;
                if !linked {
                    windows::restrict_file(path)?;
                }
                Ok(file)
            }
            Err(e) => Err(e),
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        OpenOptions::new().append(true).create(true).open(path)
    }
}

/// A new, empty, owner-only file next to its target, removed on drop
/// unless it was renamed away.
struct Staging {
    file: PathBuf,
    /// Windows only: the private directory holding `file`.
    dir: Option<PathBuf>,
}

impl Staging {
    fn create(target: &Path) -> io::Result<(Self, File)> {
        let mut name = target
            .file_name()
            .map(|n| n.to_os_string())
            .unwrap_or_default();
        name.push(format!(
            ".{}.{}.tmp",
            std::process::id(),
            Uuid::new_v4().simple()
        ));
        let sibling = target.with_file_name(name);

        #[cfg(windows)]
        {
            fs::create_dir(&sibling)?;
            let staging = Self {
                file: sibling.join("staged"),
                dir: Some(sibling),
            };
            windows::restrict_dir(staging.dir.as_deref().expect("set above"))?;
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&staging.file)?;
            // Explicit and protected, so the file stays owner-only wherever it moves.
            windows::restrict_file(&staging.file)?;
            Ok((staging, file))
        }
        #[cfg(not(windows))]
        {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
            let file = options.open(&sibling)?;
            Ok((
                Self {
                    file: sibling,
                    dir: None,
                },
                file,
            ))
        }
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.file);
        if let Some(dir) = &self.dir {
            let _ = fs::remove_dir(dir);
        }
    }
}

#[cfg(unix)]
fn parent_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

#[cfg(windows)]
mod windows {
    use std::io;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::OnceLock;

    /// Replace inherited entries with a single explicit full-control
    /// entry for the process token's user. Only ever narrows access.
    pub(super) fn restrict_file(path: &Path) -> io::Result<()> {
        let grant = format!("*{}:F", user_sid()?);
        icacls(path, &["/inheritance:r", "/grant:r", &grant])
    }

    /// Same as `restrict_file`, with the entry inherited by everything
    /// created inside the directory.
    pub(super) fn restrict_dir(path: &Path) -> io::Result<()> {
        let grant = format!("*{}:(OI)(CI)F", user_sid()?);
        icacls(path, &["/inheritance:r", "/grant:r", &grant])
    }

    /// The SID of the process token's user, which is right under
    /// LocalSystem and virtual service accounts where the user name
    /// variables are not. Failures are not cached, so a later call retries.
    fn user_sid() -> io::Result<&'static str> {
        static SID: OnceLock<String> = OnceLock::new();
        if let Some(sid) = SID.get() {
            return Ok(sid);
        }
        let out = Command::new(system32("whoami.exe"))
            .args(["/user", "/fo", "csv", "/nh"])
            .output()?;
        if !out.status.success() {
            return Err(io::Error::other(format!(
                "whoami /user failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        let sid = parse_whoami_sid(&String::from_utf8_lossy(&out.stdout)).ok_or_else(|| {
            io::Error::other("whoami /user printed no SID; cannot build an owner-only ACL")
        })?;
        Ok(SID.get_or_init(|| sid))
    }

    /// The SID column of `whoami /user /fo csv /nh` output
    /// (`"domain\user","S-1-5-..."`), if it is a well-formed SID.
    fn parse_whoami_sid(output: &str) -> Option<String> {
        let line = output.lines().map(str::trim).find(|l| !l.is_empty())?;
        let (_, last) = line.rsplit_once(',')?;
        let sid = last.strip_prefix('"')?.strip_suffix('"')?;
        let rest = sid.strip_prefix("S-1-")?;
        let well_formed = rest
            .split('-')
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()));
        well_formed.then(|| sid.to_string())
    }

    /// A tool from the system directory, never resolved through PATH.
    fn system32(exe: &str) -> PathBuf {
        let system_root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
        PathBuf::from(system_root).join("System32").join(exe)
    }

    fn icacls(path: &Path, args: &[&str]) -> io::Result<()> {
        let out = Command::new(system32("icacls.exe"))
            .arg(path)
            .args(args)
            .output()?;
        if out.status.success() {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "icacls {args:?} failed on {}: {}{}",
                path.display(),
                String::from_utf8_lossy(&out.stdout).trim(),
                String::from_utf8_lossy(&out.stderr).trim()
            )))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::parse_whoami_sid;

        #[test]
        fn parses_the_sid_column() {
            assert_eq!(
                parse_whoami_sid(
                    "\"host\\admin\",\"S-1-5-21-1901149633-1796372241-3346877469-1000\"\r\n"
                )
                .as_deref(),
                Some("S-1-5-21-1901149633-1796372241-3346877469-1000")
            );
            assert_eq!(
                parse_whoami_sid("\r\n\"nt authority\\system\",\"S-1-5-18\"\r\n").as_deref(),
                Some("S-1-5-18")
            );
        }

        #[test]
        fn rejects_anything_that_is_not_a_sid() {
            for bad in [
                "",
                "\"host\\admin\"",
                "\"host\\admin\",S-1-5-18",
                "\"host\\admin\",\"S-1-\"",
                "\"host\\admin\",\"S-1-5--18\"",
                "\"host\\admin\",\"S-2-5-18\"",
                "\"host\\admin\",\"S-1-5-18 Everyone\"",
                "\"host\\admin\",\"*S-1-1-0\"",
            ] {
                assert_eq!(parse_whoami_sid(bad), None, "{bad:?}");
            }
        }

        #[test]
        fn the_running_user_resolves_to_a_sid() {
            assert!(super::user_sid().unwrap().starts_with("S-1-"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("keystone-fs-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The access-control entries on `path`, one string per principal.
    #[cfg(windows)]
    fn acl_entries(path: &Path) -> Vec<String> {
        let out = std::process::Command::new("icacls")
            .arg(path)
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout).replace(&*path.to_string_lossy(), "");
        text.lines()
            .map(str::trim)
            .filter(|line| line.contains(":("))
            .map(String::from)
            .collect()
    }

    fn assert_owner_only(path: &Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        #[cfg(windows)]
        {
            let entries = acl_entries(path);
            let user = std::env::var("USERNAME").unwrap();
            assert_eq!(
                entries.len(),
                1,
                "extra principals on {path:?}: {entries:?}"
            );
            assert!(entries[0].contains(&user), "{entries:?}");
            assert!(
                !entries[0].contains("(I)"),
                "entry is inherited: {entries:?}"
            );
        }
    }

    #[test]
    fn atomic_write_replaces_owner_only_and_leaves_no_staging() {
        let dir = scratch_dir();
        let path = dir.join("secret.json");
        fs::write(&path, b"old").unwrap();

        write_owner_only_atomic(&path, b"new contents").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"new contents");
        assert_owner_only(&path);
        write_owner_only_atomic(&path, b"again").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"again");

        let names: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, ["secret.json"]);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn append_creates_owner_only_and_appends() {
        let dir = scratch_dir();
        let path = dir.join("downloads.log");
        open_append_owner_only(&path)
            .unwrap()
            .write_all(b"one\n")
            .unwrap();
        assert_owner_only(&path);
        open_append_owner_only(&path)
            .unwrap()
            .write_all(b"two\n")
            .unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"one\ntwo\n");
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn append_narrows_an_existing_file() {
        let dir = scratch_dir();
        let path = dir.join("existing.log");
        fs::write(&path, b"kept\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        }
        open_append_owner_only(&path)
            .unwrap()
            .write_all(b"added\n")
            .unwrap();
        assert_owner_only(&path);
        assert_eq!(fs::read(&path).unwrap(), b"kept\nadded\n");
        fs::remove_dir_all(&dir).unwrap();
    }
}
