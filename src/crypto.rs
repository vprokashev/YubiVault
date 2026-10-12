use crate::model::{MAX_BYTES, validate_fingerprint};
use anyhow::{Context, Result, ensure};
use std::os::windows::process::CommandExt;
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct Cancellation {
    cancelled: Arc<AtomicBool>,
    card: Option<(Arc<AtomicU64>, u64)>,
}
impl Default for Cancellation {
    fn default() -> Self {
        Self::new()
    }
}
impl Cancellation {
    pub fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            card: None,
        }
    }
    pub fn with_card(epoch: Arc<AtomicU64>, expected: u64) -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            card: Some((epoch, expected)),
        }
    }
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }
    pub fn check(&self) -> Result<()> {
        ensure!(
            !self.cancelled.load(Ordering::SeqCst)
                && self
                    .card
                    .as_ref()
                    .is_none_or(|(epoch, expected)| epoch.load(Ordering::SeqCst) == *expected),
            "Сеанс отменён: откройте хранилище заново"
        );
        Ok(())
    }
}

pub trait Crypto: Send + Sync {
    fn recipient(&self) -> &str;
    fn encrypt(&self, data: &[u8], cancel: &Cancellation) -> Result<Vec<u8>>;
    fn decrypt(&self, data: &[u8], cancel: &Cancellation) -> Result<Zeroizing<Vec<u8>>>;
}

pub struct Gpg {
    exe: PathBuf,
    recipient: String,
    home: Option<PathBuf>,
}
struct Output {
    success: bool,
    data: Zeroizing<Vec<u8>>,
    status: Zeroizing<Vec<u8>>,
}

impl Gpg {
    /// Read-only card inspection. Never generates, exports, or installs keys.
    pub fn on_card(exe: PathBuf, cancel: &Cancellation) -> Result<Self> {
        let mut gpg = Self {
            exe,
            recipient: String::new(),
            home: None,
        };
        let card = gpg.run(&["--with-colons", "--card-status"], &[], cancel)?;
        ensure!(
            card.success,
            "GnuPG не обнаружил OpenPGP-карту. Проверьте GnuPG, scdaemon и подключение YubiKey"
        );
        let text = std::str::from_utf8(&card.data).context("Некорректный ответ GnuPG")?;
        let (fingerprint, serial) = card_identity(text)?;
        gpg.recipient = fingerprint;
        let keys = gpg.run(
            &[
                "--with-colons",
                "--with-keygrip",
                "--list-secret-keys",
                &gpg.recipient,
            ],
            &[],
            cancel,
        )?;
        ensure!(
            keys.success
                && card_stub_matches(std::str::from_utf8(&keys.data)?, &gpg.recipient, &serial),
            "Ключ шифрования карты отсутствует в GnuPG либо доступен как программный ключ. Нужны публичный ключ и ссылка на ключ карты"
        );
        // Prove the private-key operation works before creating any vault files.
        let challenge = Zeroizing::new(uuid::Uuid::new_v4().as_bytes().to_vec());
        let encrypted = gpg.encrypt(&challenge, cancel)?;
        ensure!(
            *gpg.decrypt(&encrypted, cancel)? == *challenge,
            "Проверка ключа карты не пройдена"
        );
        cancel.check()?;
        Ok(gpg)
    }

    fn run(&self, args: &[&str], input: &[u8], cancel: &Cancellation) -> Result<Output> {
        cancel.check()?;
        ensure!(
            input.len() as u64 <= MAX_BYTES,
            "Превышен размер входных данных"
        );
        let mut command = Command::new(&self.exe);
        command.creation_flags(0x08000000).args([
            "--no-options",
            "--batch",
            "--no-tty",
            "--status-fd",
            "2",
            "--no-auto-key-retrieve",
            "--auto-key-locate",
            "local",
            "--max-output",
            "67108864",
        ]);
        if let Some(home) = &self.home {
            command.arg("--homedir").arg(command_path(&self.exe, home));
        } else if let Some(home) = std::env::var_os("GNUPGHOME") {
            command.env("GNUPGHOME", command_path(&self.exe, Path::new(&home)));
        }
        command
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child = command.spawn().context("Не удалось запустить gpg.exe")?;
        struct Running(std::process::Child);
        impl Drop for Running {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = Running(child);
        let mut stdin = child.0.stdin.take().context("Нет входного канала GnuPG")?;
        let stdout = child
            .0
            .stdout
            .take()
            .context("Нет выходного канала GnuPG")?;
        let stderr = child.0.stderr.take().context("Нет канала статуса GnuPG")?;
        let bytes = Zeroizing::new(input.to_vec());
        let writer = thread::spawn(move || stdin.write_all(&bytes));
        let reader = thread::spawn(move || read_pipe(stdout, MAX_BYTES));
        let statuses = thread::spawn(move || read_pipe(stderr, 1024 * 1024));
        let started = Instant::now();
        let result = loop {
            if let Err(error) = cancel.check() {
                break Err(error);
            }
            if started.elapsed() > Duration::from_secs(180) {
                break Err(anyhow::anyhow!("Истекло время ожидания GnuPG/PIN"));
            }
            match child.0.try_wait() {
                Ok(Some(status)) => break Ok(status.success()),
                Ok(None) => thread::sleep(Duration::from_millis(20)),
                Err(_) => break Err(anyhow::anyhow!("Не удалось дождаться GnuPG")),
            }
        };
        if result.is_err() {
            let _ = child.0.kill();
            let _ = child.0.wait();
        }
        let written = writer
            .join()
            .map_err(|_| anyhow::anyhow!("Сбой входного канала GnuPG"));
        let data = reader
            .join()
            .map_err(|_| anyhow::anyhow!("Сбой выходного канала GnuPG"))?;
        let status = statuses
            .join()
            .map_err(|_| anyhow::anyhow!("Сбой канала статуса GnuPG"))?;
        let success = result?;
        written?.context("GnuPG закрыл входной канал")?;
        cancel.check()?;
        Ok(Output {
            success,
            data: data?,
            status: status?,
        })
    }
}

impl Crypto for Gpg {
    fn recipient(&self) -> &str {
        &self.recipient
    }
    fn encrypt(&self, data: &[u8], cancel: &Cancellation) -> Result<Vec<u8>> {
        let recipient = format!("{}!", self.recipient);
        let mut output = self.run(
            &[
                "--trust-model",
                "always",
                "--recipient",
                &recipient,
                "--compress-algo",
                "none",
                "--output",
                "-",
                "--encrypt",
            ],
            data,
            cancel,
        )?;
        let status = std::str::from_utf8(&output.status)?;
        ensure!(
            output.success && has_status(status, "END_ENCRYPTION"),
            "GnuPG не смог зашифровать данные"
        );
        Ok(std::mem::take(&mut *output.data))
    }
    fn decrypt(&self, data: &[u8], cancel: &Cancellation) -> Result<Zeroizing<Vec<u8>>> {
        let output = self.run(&["--output", "-", "--decrypt"], data, cancel)?;
        verify_decryption(
            output.success,
            std::str::from_utf8(&output.status)?,
            &self.recipient,
        )?;
        cancel.check()?;
        Ok(output.data)
    }
}

fn read_pipe(mut pipe: impl Read, limit: u64) -> Result<Zeroizing<Vec<u8>>> {
    let mut output = Zeroizing::new(Vec::new());
    let mut buffer = Zeroizing::new([0u8; 8192]);
    let mut overflow = false;
    loop {
        let n = pipe.read(&mut *buffer).context("Ошибка канала GnuPG")?;
        if n == 0 {
            break;
        }
        if output.len() as u64 + n as u64 <= limit && !overflow {
            output.extend_from_slice(&buffer[..n]);
        } else {
            overflow = true;
        } // Keep draining to avoid blocking the subprocess.
    }
    ensure!(!overflow, "Ответ GnuPG превышает допустимый размер");
    Ok(output)
}
fn has_status(text: &str, key: &str) -> bool {
    text.lines().any(|line| {
        line.strip_prefix("[GNUPG:] ")
            .and_then(|s| s.split_whitespace().next())
            == Some(key)
    })
}
fn verify_decryption(success: bool, status: &str, recipient: &str) -> Result<()> {
    let key = status
        .lines()
        .filter_map(|l| l.strip_prefix("[GNUPG:] DECRYPTION_KEY "))
        .any(|l| {
            l.split_whitespace()
                .next()
                .is_some_and(|fpr| fpr.eq_ignore_ascii_case(recipient))
        });
    let aead = status
        .lines()
        .filter_map(|l| l.strip_prefix("[GNUPG:] DECRYPTION_INFO "))
        .any(|l| {
            l.split_whitespace()
                .nth(2)
                .is_some_and(|value| value.parse::<u32>().is_ok_and(|v| v != 0))
        });
    ensure!(
        success
            && key
            && has_status(status, "DECRYPTION_OKAY")
            && has_status(status, "END_DECRYPTION")
            && (has_status(status, "GOODMDC") || aead)
            && !["BADMDC", "ERRMDC", "DECRYPTION_FAILED", "FAILURE", "ERROR"]
                .iter()
                .any(|s| has_status(status, s)),
        "Расшифровка не подтверждена GnuPG: проверьте карту, PIN и целостность файла"
    );
    Ok(())
}
fn card_identity(text: &str) -> Result<(String, String)> {
    // GnuPG 2.4 prints the OpenPGP version/vendor records without an
    // application header; newer releases also print openpgp-card:.
    ensure!(
        text.lines().any(|l| l == "openpgp-card:")
            || (text.lines().any(|l| l.starts_with("version:"))
                && text.lines().any(|l| l.starts_with("vendor:"))),
        "Нужна карта с приложением OpenPGP"
    );
    let fingerprint = text
        .lines()
        .find_map(|l| l.strip_prefix("fpr:").and_then(|s| s.split(':').nth(1)))
        .context("На карте нет ключа шифрования")?
        .to_ascii_uppercase();
    validate_fingerprint(&fingerprint)?;
    let serial = text
        .lines()
        .find_map(|l| l.strip_prefix("serial:").and_then(|s| s.split(':').next()))
        .context("Нет номера карты")?
        .to_ascii_uppercase();
    ensure!(
        serial.len() == 8 && serial.bytes().all(|b| b.is_ascii_hexdigit()),
        "Некорректный номер карты"
    );
    Ok((fingerprint, serial))
}
fn card_stub_matches(text: &str, fingerprint: &str, serial: &str) -> bool {
    let mut candidate = false;
    for line in text.lines() {
        let fields: Vec<_> = line.split(':').collect();
        match fields.first().copied() {
            Some("sec" | "ssb") => {
                let token = fields.get(14).copied().unwrap_or("");
                candidate = fields
                    .get(11)
                    .is_some_and(|caps| caps.contains('e') && !caps.contains('D'))
                    && !matches!(fields.get(1).copied(), Some("r" | "e" | "d"))
                    && token.len() >= 8
                    && token.bytes().all(|b| b.is_ascii_hexdigit())
                    && token.len() == 32
                    && token[..12].eq_ignore_ascii_case("D27600012401")
                    && token[20..28].eq_ignore_ascii_case(serial);
            }
            Some("fpr")
                if candidate
                    && fields
                        .get(9)
                        .is_some_and(|fpr| fpr.eq_ignore_ascii_case(fingerprint)) =>
            {
                return true;
            }
            _ => {}
        }
    }
    false
}

pub fn find_gpg() -> PathBuf {
    for path in [
        r"C:\Program Files\GnuPG\bin\gpg.exe",
        r"C:\Program Files (x86)\GnuPG\bin\gpg.exe",
        r"C:\Program Files\Git\usr\bin\gpg.exe",
    ] {
        if Path::new(path).is_file() {
            return path.into();
        }
    }
    "gpg.exe".into()
}

// Git ships the MSYS build of GnuPG, which expects /c/... paths rather than
// native C:\... paths. Native GnuPG accepts forward slashes too.
fn command_path(exe: &Path, value: &Path) -> String {
    let path = value.to_string_lossy().replace('\\', "/");
    if exe
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase()
        .ends_with("/usr/bin/gpg.exe")
        && path.as_bytes().get(1) == Some(&b':')
        && path.as_bytes().get(2) == Some(&b'/')
    {
        format!("/{}{}", path[..1].to_ascii_lowercase(), &path[2..])
    } else {
        path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn status_requires_integrity_correct_key_and_process_success() {
        let fpr = "0123456789ABCDEF0123456789ABCDEF01234567";
        let status = format!(
            "[GNUPG:] DECRYPTION_KEY {fpr} {fpr} -\n[GNUPG:] DECRYPTION_OKAY\n[GNUPG:] GOODMDC\n[GNUPG:] END_DECRYPTION\n"
        );
        assert!(verify_decryption(true, &status, fpr).is_ok());
        assert!(verify_decryption(false, &status, fpr).is_err());
        assert!(verify_decryption(true, &status.replace("GOODMDC", "BADMDC"), fpr).is_err());
        assert!(
            verify_decryption(true, &status, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF").is_err()
        );
    }
    #[test]
    fn card_epoch_invalidates_session_even_after_reinsertion() {
        let epoch = Arc::new(AtomicU64::new(1));
        let cancel = Cancellation::with_card(epoch.clone(), 1);
        epoch.fetch_add(2, Ordering::SeqCst);
        assert!(cancel.check().is_err());
    }
    #[test]
    fn card_slot_and_stub_must_match_including_serial() {
        let fpr = "0123456789ABCDEF0123456789ABCDEF01234567";
        let card = format!(
            "version:0304:\nvendor:0006:Yubico:\nserial:12345678:\nfpr:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:{fpr}:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:\n"
        );
        assert_eq!(
            card_identity(&card).unwrap(),
            (fpr.into(), "12345678".into())
        );
        let mut fields = vec![""; 16];
        fields[0] = "ssb";
        fields[1] = "u";
        fields[11] = "e";
        fields[14] = "D2760001240103040006123456780000";
        let stub = format!("{}\nfpr:::::::::{fpr}:\n", fields.join(":"));
        assert!(card_stub_matches(&stub, fpr, "12345678"));
        assert!(!card_stub_matches(&stub, fpr, "00000000"));
        fields[14] = "+";
        assert!(!card_stub_matches(
            &format!("{}\nfpr:::::::::{fpr}:\n", fields.join(":")),
            fpr,
            "12345678"
        ));
    }
    #[test]
    #[ignore = "read-only inspection of the connected OpenPGP card, no PIN or secret decryption"]
    fn connected_card_metadata_matches_gpg_stub() {
        let monitor = crate::platform::CardMonitor::start(eframe::egui::Context::default());
        let started = Instant::now();
        while !monitor.available() && started.elapsed() < Duration::from_secs(3) {
            thread::sleep(Duration::from_millis(25));
        }
        let mut gpg = Gpg {
            exe: find_gpg(),
            recipient: String::new(),
            home: None,
        };
        let cancel = monitor
            .cancellation()
            .expect("Windows PC/SC must observe the connected card");
        let card = gpg
            .run(&["--with-colons", "--card-status"], &[], &cancel)
            .unwrap();
        assert!(card.success, "GnuPG could not read the connected card");
        let (fingerprint, serial) =
            card_identity(std::str::from_utf8(&card.data).unwrap()).unwrap();
        gpg.recipient = fingerprint;
        let keys = gpg
            .run(
                &["--with-colons", "--list-secret-keys", &gpg.recipient],
                &[],
                &cancel,
            )
            .unwrap();
        assert!(
            keys.success
                && card_stub_matches(
                    std::str::from_utf8(&keys.data).unwrap(),
                    &gpg.recipient,
                    &serial
                ),
            "card encryption key requires its public certificate and hardware stub in this GnuPG installation"
        );
        cancel
            .check()
            .expect("GnuPG connection allocation must not invalidate the card session");
    }
    #[test]
    #[ignore = "creates a disposable GnuPG key in a temporary, isolated home"]
    fn actual_gpg_roundtrip_and_tampering() {
        let temp = tempfile::tempdir().unwrap();
        let exe = find_gpg();
        let home = command_path(&exe, temp.path());
        struct StopAgent {
            exe: PathBuf,
            home: String,
        }
        impl Drop for StopAgent {
            fn drop(&mut self) {
                let _ = Command::new(self.exe.with_file_name("gpgconf.exe"))
                    .args(["--homedir", &self.home, "--kill", "all"])
                    .output();
            }
        }
        let _stop = StopAgent {
            exe: exe.clone(),
            home: home.clone(),
        };
        let generated = Command::new(&exe)
            .args([
                "--no-options",
                "--batch",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--homedir",
            ])
            .arg(&home)
            .args([
                "--quick-generate-key",
                "YubiVault synthetic test",
                "rsa2048",
                "encr",
                "0",
            ])
            .output()
            .unwrap();
        assert!(
            generated.status.success(),
            "disposable key generation failed: {}",
            String::from_utf8_lossy(&generated.stderr)
        );
        let listed = Command::new(&exe)
            .args(["--no-options", "--homedir"])
            .arg(&home)
            .args(["--with-colons", "--list-keys"])
            .output()
            .unwrap();
        let fpr = std::str::from_utf8(&listed.stdout)
            .unwrap()
            .lines()
            .find_map(|l| l.strip_prefix("fpr:").and_then(|_| l.split(':').nth(9)))
            .unwrap()
            .to_owned();
        let gpg = Gpg {
            exe: exe.clone(),
            recipient: fpr,
            home: Some(temp.path().into()),
        };
        let cancel = Cancellation::new();
        let plain = b"SYNTHETIC ONLY\r\n  second line\n\n";
        let mut encrypted = gpg.encrypt(plain, &cancel).unwrap();
        assert_eq!(&**gpg.decrypt(&encrypted, &cancel).unwrap(), plain);
        let end = encrypted.len() - 12;
        encrypted[end] ^= 1;
        assert!(gpg.decrypt(&encrypted, &cancel).is_err());
        cancel.cancel();
        assert!(gpg.encrypt(plain, &cancel).is_err());
        // Full storage round trip through the same real GnuPG backend.
        let crypto: Arc<dyn Crypto> = Arc::new(gpg);
        let root = temp.path().join("synthetic-vault");
        let mut vault =
            crate::store::Vault::create(&root, crypto.clone(), Cancellation::new()).unwrap();
        let entry = vault
            .save(None, "Synthetic", std::str::from_utf8(plain).unwrap())
            .unwrap()
            .entry;
        vault
            .save(Some(entry), "Synthetic", "changed\n synthetic only")
            .unwrap();
        vault
            .save(None, "synthetic", "case-sensitive synthetic entry")
            .unwrap();
        drop(vault);
        std::fs::write(root.join("index.gpg"), b"damaged synthetic catalogue").unwrap();
        let vault = crate::store::Vault::open(&root, crypto, Cancellation::new()).unwrap();
        let versions = &vault
            .catalog
            .entries
            .iter()
            .find(|e| e.id == entry)
            .unwrap()
            .versions;
        assert_eq!(
            vault
                .read_version(entry, versions[1].id)
                .unwrap()
                .secret
                .as_bytes(),
            plain
        );
        assert_eq!(
            vault.read_version(entry, versions[0].id).unwrap().secret,
            "changed\n synthetic only"
        );
        for item in std::fs::read_dir(root.join("objects")).unwrap() {
            let cipher = std::fs::read(item.unwrap().path()).unwrap();
            assert!(!cipher.windows(plain.len()).any(|w| w == plain));
        }
    }
}
