use crate::{
    crypto::{Cancellation, Crypto},
    model::{Catalog, Entry, FORMAT, HISTORY, MAX_BYTES, Record, Version, validate_name},
    platform,
};
use anyhow::{Context, Result, bail, ensure};
use chrono::Utc;
use fs2::FileExt;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

pub struct Vault {
    root: PathBuf,
    pub catalog: Catalog,
    crypto: Arc<dyn Crypto>,
    cancel: Cancellation,
    _lock: File,
}

pub struct Saved {
    pub changed: bool,
    pub maintenance_pending: bool,
    pub entry: Uuid,
}

impl Vault {
    pub fn create(root: &Path, crypto: Arc<dyn Crypto>, cancel: Cancellation) -> Result<Self> {
        let (root, lock) = prepare(root)?;
        ensure!(
            !root.join("index.gpg").exists() && !root.join("index.bak.gpg").exists(),
            "Хранилище уже существует: используйте «Открыть»"
        );
        ensure!(
            fs::read_dir(root.join("objects"))?.next().is_none(),
            "Папка уже содержит данные; выберите пустое хранилище"
        );
        cancel.check()?;
        let catalog = Catalog::empty(crypto.recipient().to_owned());
        let encoded =
            Zeroizing::new(serde_json::to_vec(&catalog).context("Не удалось подготовить каталог")?);
        let cipher = crypto.encrypt(&encoded, &cancel)?;
        write_new(&root.join("index.bak.gpg"), &cipher)?;
        cancel.check()?;
        write_new(&root.join("index.gpg"), &cipher)?;
        Ok(Self {
            root,
            catalog,
            crypto,
            cancel,
            _lock: lock,
        })
    }

    pub fn open(root: &Path, crypto: Arc<dyn Crypto>, cancel: Cancellation) -> Result<Self> {
        ensure!(root.is_dir(), "Папка хранилища не найдена");
        let (root, lock) = prepare(root)?;
        let load = |name: &str| -> Result<Catalog> {
            cancel.check()?;
            let data = read_bounded(&root.join(name))?;
            let plain = crypto.decrypt(&data, &cancel)?;
            let catalog: Catalog =
                serde_json::from_slice(&plain).context("Некорректный зашифрованный каталог")?;
            catalog.validate()?;
            ensure!(
                catalog.recipient.eq_ignore_ascii_case(crypto.recipient()),
                "Каталог зашифрован для другого ключа"
            );
            validate_objects(&root, &catalog)?;
            Ok(catalog)
        };
        let primary = load("index.gpg");
        let catalog = match primary {
            Ok(catalog) => catalog,
            Err(primary_error) => {
                cancel.check()?;
                let catalog = load("index.bak.gpg").map_err(|_| primary_error)?;
                cancel.check()?;
                if root.join("index.gpg").exists() {
                    // Preserve a damaged/unsupported candidate; never silently overwrite it.
                    let preserved = root.join(format!("index.preserved.{}.gpg", Uuid::new_v4()));
                    fs::copy(root.join("index.gpg"), &preserved)?;
                    OpenOptions::new()
                        .write(true)
                        .open(&preserved)?
                        .sync_all()?;
                }
                let candidate = root.join(format!("index.next.{}.gpg", Uuid::new_v4()));
                write_new(&candidate, &read_bounded(&root.join("index.bak.gpg"))?)?;
                platform::replace_file(&candidate, &root.join("index.gpg"), None)?;
                catalog
            }
        };
        let mut vault = Self {
            root,
            catalog,
            crypto,
            cancel,
            _lock: lock,
        };
        // A current, verified catalog wins over uncommitted replacement files.
        // Cleanup is allowed only after both stable catalog copies refer to it.
        let _ = vault.checkpoint_and_cleanup();
        Ok(vault)
    }

    pub fn read_version(&self, entry: Uuid, version: Uuid) -> Result<Record> {
        self.cancel.check()?;
        let entry = self
            .catalog
            .entries
            .iter()
            .find(|e| e.id == entry)
            .context("Запись не найдена")?;
        let reference = entry
            .versions
            .iter()
            .find(|v| v.id == version)
            .context("Версия не найдена")?;
        let cipher = read_bounded(&object_path(&self.root, version))?;
        ensure!(digest(&cipher) == reference.sha256, "Повреждён файл версии");
        let plain = self.crypto.decrypt(&cipher, &self.cancel)?;
        let record: Record =
            serde_json::from_slice(&plain).context("Некорректная версия записи")?;
        ensure!(
            record.format == FORMAT
                && record.vault == self.catalog.vault
                && record.entry == entry.id
                && record.version == version,
            "Версия не соответствует каталогу"
        );
        if entry.versions[0].id == version {
            ensure!(
                record.name == entry.name,
                "Имя записи не соответствует каталогу"
            );
        }
        self.cancel.check()?;
        Ok(record)
    }

    pub fn save(&mut self, entry_id: Option<Uuid>, name: &str, secret: &str) -> Result<Saved> {
        self.save_at(entry_id, name, secret, |_| Ok(()))
    }

    fn save_at(
        &mut self,
        entry_id: Option<Uuid>,
        name: &str,
        secret: &str,
        mut stage: impl FnMut(&str) -> Result<()>,
    ) -> Result<Saved> {
        self.cancel.check()?;
        validate_name(name)?;
        let id = entry_id.unwrap_or_else(Uuid::new_v4);
        ensure!(
            !self
                .catalog
                .entries
                .iter()
                .any(|e| e.name == name && e.id != id),
            "Это имя уже используется"
        );
        if let Some(entry_id) = entry_id {
            let entry = self
                .catalog
                .entries
                .iter()
                .find(|e| e.id == entry_id)
                .context("Запись не найдена")?;
            let previous = self.read_version(entry_id, entry.versions[0].id)?;
            if previous.name == name && previous.secret == secret {
                return Ok(Saved {
                    changed: false,
                    maintenance_pending: false,
                    entry: id,
                });
            }
        }
        // Bring the recovery copy up to date before starting another commit.
        // Failure here aborts rather than accumulating unbounded stale snapshots.
        self.checkpoint_and_cleanup()?;
        stage("before_object")?;
        let version = Uuid::new_v4();
        let record = Record {
            format: FORMAT,
            vault: self.catalog.vault,
            entry: id,
            version,
            name: name.to_owned(),
            secret: secret.to_owned(),
        };
        let plain =
            Zeroizing::new(serde_json::to_vec(&record).context("Не удалось подготовить запись")?);
        ensure!(
            plain.len() as u64 <= MAX_BYTES,
            "Запись превышает допустимый размер 64 МиБ"
        );
        let cipher = self.crypto.encrypt(&plain, &self.cancel)?;
        self.cancel.check()?;
        write_new(&object_path(&self.root, version), &cipher)?;
        stage("after_object")?;
        let mut next = self.catalog.clone();
        next.generation = next
            .generation
            .checked_add(1)
            .context("Переполнение поколения каталога")?;
        let reference = Version {
            id: version,
            saved_at: Utc::now(),
            sha256: digest(&cipher),
        };
        if let Some(entry) = next.entries.iter_mut().find(|e| e.id == id) {
            entry.name.zeroize();
            entry.name = name.to_owned();
            entry.versions.insert(0, reference);
            entry.versions.truncate(HISTORY + 1);
        } else {
            next.entries.push(Entry {
                id,
                name: name.to_owned(),
                versions: vec![reference],
            });
        }
        next.validate()?;
        let encoded =
            Zeroizing::new(serde_json::to_vec(&next).context("Не удалось подготовить каталог")?);
        let next_cipher = self.crypto.encrypt(&encoded, &self.cancel)?;
        let candidate = self.root.join(format!("index.next.{}.gpg", Uuid::new_v4()));
        write_new(&candidate, &next_cipher)?;
        stage("after_catalog")?;
        self.cancel.check()?;
        stage("before_commit")?;
        let backup = self.root.join(format!("index.swap.{}.gpg", Uuid::new_v4()));
        platform::replace_file(&candidate, &self.root.join("index.gpg"), Some(&backup))?;
        // Commit point. Errors after this point must not pretend the save failed.
        self.catalog = next;
        let maintenance_pending = stage("after_commit")
            .and_then(|_| self.checkpoint_and_cleanup())
            .is_err();
        Ok(Saved {
            changed: true,
            maintenance_pending,
            entry: id,
        })
    }

    fn checkpoint_and_cleanup(&mut self) -> Result<()> {
        self.cancel.check()?;
        validate_objects(&self.root, &self.catalog)?;
        let primary = read_bounded(&self.root.join("index.gpg"))?;
        let backup_candidate = self
            .root
            .join(format!("index.backup.{}.gpg", Uuid::new_v4()));
        write_new(&backup_candidate, &primary)?;
        self.cancel.check()?;
        platform::replace_file(&backup_candidate, &self.root.join("index.bak.gpg"), None)?;
        let referenced = self.catalog.referenced_versions();
        // Only UUID-named files in this vault's canonical objects directory.
        for object in fs::read_dir(self.root.join("objects"))? {
            self.cancel.check()?;
            let object = object?;
            let path = object.path();
            if path.extension().and_then(|e| e.to_str()) != Some("gpg")
                || !object.file_type()?.is_file()
            {
                continue;
            }
            let Some(id) = path
                .file_stem()
                .and_then(|s| s.to_str())
                .and_then(|s| Uuid::parse_str(s).ok())
            else {
                continue;
            };
            if !referenced.contains(&id) {
                fs::remove_file(path)?;
            }
        }
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if ["index.next.", "index.swap.", "index.backup."]
                .iter()
                .any(|prefix| {
                    name.strip_prefix(prefix)
                        .and_then(|s| s.strip_suffix(".gpg"))
                        .is_some_and(|s| Uuid::parse_str(s).is_ok())
                })
                && entry.file_type()?.is_file()
            {
                fs::remove_file(entry.path())?;
            }
        }
        Ok(())
    }
}

fn prepare(root: &Path) -> Result<(PathBuf, File)> {
    fs::create_dir_all(root).context("Не удалось создать папку хранилища")?;
    let root = fs::canonicalize(root)?;
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(root.join("vault.lock"))?;
    lock.try_lock_exclusive()
        .context("Хранилище уже открыто другим экземпляром")?;
    fs::create_dir_all(root.join("objects"))?;
    let objects = fs::canonicalize(root.join("objects"))?;
    ensure!(
        objects.parent() == Some(root.as_path()),
        "Папка objects должна находиться внутри хранилища"
    );
    Ok((root, lock))
}

fn object_path(root: &Path, id: Uuid) -> PathBuf {
    root.join("objects").join(format!("{id}.gpg"))
}
fn digest(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}

fn validate_objects(root: &Path, catalog: &Catalog) -> Result<()> {
    for entry in &catalog.entries {
        for version in &entry.versions {
            let cipher = read_bounded(&object_path(root, version.id))?;
            ensure!(
                digest(&cipher) == version.sha256,
                "Каталог ссылается на повреждённую версию"
            );
        }
    }
    Ok(())
}

fn write_new(path: &Path, data: &[u8]) -> Result<()> {
    ensure!(
        data.len() as u64 <= MAX_BYTES,
        "Файл превышает допустимый размер"
    );
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .context("Не удалось создать зашифрованный файл")?;
    file.write_all(data)
        .context("Не удалось записать зашифрованный файл")?;
    file.sync_all()
        .context("Не удалось сбросить зашифрованный файл на диск")?;
    Ok(())
}

fn read_bounded(path: &Path) -> Result<Vec<u8>> {
    let file = File::open(path).context("Зашифрованный файл не найден")?;
    ensure!(
        file.metadata()?.len() <= MAX_BYTES,
        "Зашифрованный файл слишком большой"
    );
    let mut data = vec![];
    file.take(MAX_BYTES + 1).read_to_end(&mut data)?;
    if data.len() as u64 > MAX_BYTES {
        bail!("Зашифрованный файл слишком большой");
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixtureCrypto;
    impl Crypto for FixtureCrypto {
        fn recipient(&self) -> &str {
            "0123456789ABCDEF0123456789ABCDEF01234567"
        }
        fn encrypt(&self, data: &[u8], cancel: &Cancellation) -> Result<Vec<u8>> {
            cancel.check()?;
            Ok(data.iter().map(|b| b ^ 0xa5).collect())
        }
        fn decrypt(&self, data: &[u8], cancel: &Cancellation) -> Result<Zeroizing<Vec<u8>>> {
            cancel.check()?;
            Ok(Zeroizing::new(data.iter().map(|b| b ^ 0xa5).collect()))
        }
    }
    fn create(root: &Path) -> Vault {
        Vault::create(root, Arc::new(FixtureCrypto), Cancellation::new()).unwrap()
    }
    fn reopen(root: &Path) -> Vault {
        Vault::open(root, Arc::new(FixtureCrypto), Cancellation::new()).unwrap()
    }

    #[test]
    fn names_are_case_sensitive_and_multiline_is_exact() {
        let temp = tempfile::tempdir().unwrap();
        let mut vault = create(temp.path());
        let value = "  token\r\nsecond = value\n\n";
        let a = vault.save(None, "GitHub", value).unwrap().entry;
        vault.save(None, "github", "other").unwrap();
        assert!(vault.save(None, "GitHub", "duplicate").is_err());
        let version = vault
            .catalog
            .entries
            .iter()
            .find(|e| e.id == a)
            .unwrap()
            .versions[0]
            .id;
        assert_eq!(vault.read_version(a, version).unwrap().secret, value);
        assert!(!vault.save(Some(a), "GitHub", value).unwrap().changed);
        drop(vault);
        assert_eq!(reopen(temp.path()).catalog.entries.len(), 2);
        for item in fs::read_dir(temp.path().join("objects")).unwrap() {
            let bytes = fs::read(item.unwrap().path()).unwrap();
            assert!(!bytes.windows(value.len()).any(|w| w == value.as_bytes()));
        }
    }

    #[test]
    fn retention_and_rename_preserve_record_identity() {
        let temp = tempfile::tempdir().unwrap();
        let mut vault = create(temp.path());
        let id = vault.save(None, "first", "0").unwrap().entry;
        for n in 1..=9 {
            vault.save(Some(id), "renamed", &n.to_string()).unwrap();
        }
        let versions = &vault.catalog.entries[0].versions;
        assert_eq!(versions.len(), 6);
        let expected: Vec<_> = (4..=9).rev().map(|n| n.to_string()).collect();
        for (version, text) in versions.iter().zip(expected) {
            assert_eq!(vault.read_version(id, version.id).unwrap().secret, text);
        }
        assert_eq!(
            fs::read_dir(temp.path().join("objects")).unwrap().count(),
            6
        );
        drop(vault);
        let reopened = reopen(temp.path());
        assert_eq!(reopened.catalog.entries[0].id, id);
        assert_eq!(reopened.catalog.entries[0].name, "renamed");
    }

    #[test]
    fn interrupted_commits_recover_whole_old_or_new_state() {
        for stop in [
            "before_object",
            "after_object",
            "after_catalog",
            "before_commit",
            "after_commit",
        ] {
            let temp = tempfile::tempdir().unwrap();
            let mut vault = create(temp.path());
            let id = vault.save(None, "entry", "old").unwrap().entry;
            let result = vault.save_at(Some(id), "changed", "new", |stage| {
                if stage == stop {
                    bail!("simulated interruption");
                }
                Ok(())
            });
            assert_eq!(result.is_ok(), stop == "after_commit");
            drop(vault);
            let vault = reopen(temp.path());
            let entry = &vault.catalog.entries[0];
            let current = vault.read_version(id, entry.versions[0].id).unwrap();
            assert_eq!(
                current.secret,
                if stop == "after_commit" { "new" } else { "old" }
            );
            assert_eq!(
                entry.name,
                if stop == "after_commit" {
                    "changed"
                } else {
                    "entry"
                }
            );
        }
    }

    #[test]
    fn recovery_copy_survives_missing_or_corrupt_primary() {
        for corruption in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let mut vault = create(temp.path());
            let id = vault.save(None, "entry", "secret").unwrap().entry;
            drop(vault);
            if corruption {
                fs::write(temp.path().join("index.gpg"), b"damaged").unwrap();
            } else {
                fs::remove_file(temp.path().join("index.gpg")).unwrap();
            }
            let vault = reopen(temp.path());
            let v = vault.catalog.entries[0].versions[0].id;
            assert_eq!(vault.read_version(id, v).unwrap().secret, "secret");
        }
    }

    #[test]
    fn exclusive_writer_and_cancel_do_not_lose_committed_data() {
        let temp = tempfile::tempdir().unwrap();
        let mut vault = create(temp.path());
        vault.save(None, "entry", "old").unwrap();
        assert!(Vault::open(temp.path(), Arc::new(FixtureCrypto), Cancellation::new()).is_err());
        vault.cancel.cancel();
        assert!(vault.save(None, "discarded", "new").is_err());
        drop(vault);
        assert_eq!(reopen(temp.path()).catalog.entries.len(), 1);
    }
}
