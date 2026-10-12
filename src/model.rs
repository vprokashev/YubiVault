use anyhow::{Result, bail, ensure};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use uuid::Uuid;
use zeroize::Zeroize;

pub const FORMAT: u32 = 1;
pub const HISTORY: usize = 5;
pub const MAX_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    pub format: u32,
    pub vault: Uuid,
    pub recipient: String,
    pub generation: u64,
    pub entries: Vec<Entry>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub id: Uuid,
    pub name: String,
    /// Current version first, then at most five older versions.
    pub versions: Vec<Version>,
}

impl Drop for Entry {
    fn drop(&mut self) {
        self.name.zeroize();
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Version {
    pub id: Uuid,
    pub saved_at: DateTime<Utc>,
    pub sha256: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub format: u32,
    pub vault: Uuid,
    pub entry: Uuid,
    pub version: Uuid,
    pub name: String,
    pub secret: String,
}

impl Drop for Record {
    fn drop(&mut self) {
        self.name.zeroize();
        self.secret.zeroize();
    }
}

impl Catalog {
    pub fn empty(recipient: String) -> Self {
        Self {
            format: FORMAT,
            vault: Uuid::new_v4(),
            recipient,
            generation: 0,
            entries: vec![],
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(self.format == FORMAT, "Неподдерживаемый формат каталога");
        ensure!(!self.vault.is_nil(), "Некорректный идентификатор хранилища");
        validate_fingerprint(&self.recipient)?;
        let mut names = HashSet::new();
        let mut entries = HashSet::new();
        let mut versions = HashSet::new();
        for entry in &self.entries {
            validate_name(&entry.name)?;
            ensure!(names.insert(&entry.name), "Повторяющееся имя в каталоге");
            ensure!(
                !entry.id.is_nil() && entries.insert(entry.id),
                "Некорректная запись каталога"
            );
            ensure!(
                !entry.versions.is_empty() && entry.versions.len() <= HISTORY + 1,
                "Некорректная история записи"
            );
            for version in &entry.versions {
                ensure!(
                    !version.id.is_nil() && versions.insert(version.id),
                    "Повторяющаяся версия"
                );
                ensure!(
                    version.sha256.len() == 64
                        && version.sha256.bytes().all(|b| b.is_ascii_hexdigit()),
                    "Некорректная контрольная сумма"
                );
            }
        }
        Ok(())
    }

    pub fn referenced_versions(&self) -> HashSet<Uuid> {
        self.entries
            .iter()
            .flat_map(|e| e.versions.iter().map(|v| v.id))
            .collect()
    }
}

pub fn validate_name(name: &str) -> Result<()> {
    ensure!(!name.trim().is_empty(), "Введите имя записи");
    ensure!(
        !name.contains(['\r', '\n', '\0']),
        "Имя должно занимать одну строку"
    );
    Ok(())
}

pub fn validate_fingerprint(value: &str) -> Result<()> {
    if !matches!(value.len(), 40 | 64) || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("Укажите полный отпечаток OpenPGP-ключа шифрования");
    }
    Ok(())
}
