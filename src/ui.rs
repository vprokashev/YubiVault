use crate::{
    crypto::{Cancellation, Crypto, Gpg, find_gpg},
    model::{Catalog, Record},
    platform::{self, CardMonitor, Clipboard},
    store::Vault,
};
use anyhow::Result;
use chrono::Local;
use eframe::egui::{self, TextBuffer};
use raw_window_handle::{HasWindowHandle, RawWindowHandle};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex, mpsc},
    thread,
    time::Duration,
};
use uuid::Uuid;
use windows_sys::Win32::Foundation::HWND;
use zeroize::{Zeroize, Zeroizing};

pub fn run() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([960.0, 650.0])
            .with_min_inner_size([700.0, 480.0]),
        ..Default::default()
    };
    eframe::run_native(
        "YubiVault",
        options,
        Box::new(|cc| Ok(Box::new(App::new(cc)))),
    )
}

struct Sensitive(Zeroizing<String>);
impl Sensitive {
    fn new(text: &str) -> Self {
        Self(Zeroizing::new(text.to_owned()))
    }
    fn byte_index(&self, char_index: usize) -> usize {
        self.0
            .char_indices()
            .nth(char_index)
            .map_or(self.0.len(), |(index, _)| index)
    }
}
impl TextBuffer for Sensitive {
    fn type_id(&self) -> std::any::TypeId {
        std::any::TypeId::of::<Self>()
    }
    fn is_mutable(&self) -> bool {
        true
    }
    fn as_str(&self) -> &str {
        &self.0
    }
    fn insert_text(&mut self, text: &str, index: egui::epaint::text::CharIndex) -> usize {
        let at = self.byte_index(index.0);
        let mut next = Zeroizing::new(String::with_capacity(self.0.len() + text.len()));
        next.push_str(&self.0[..at]);
        next.push_str(text);
        next.push_str(&self.0[at..]);
        self.0 = next;
        text.chars().count()
    }
    fn delete_char_range(&mut self, range: std::ops::Range<egui::epaint::text::CharIndex>) {
        let (start, end) = (self.byte_index(range.start.0), self.byte_index(range.end.0));
        let mut next = Zeroizing::new(String::with_capacity(
            self.0.len().saturating_sub(end.saturating_sub(start)),
        ));
        next.push_str(&self.0[..start]);
        next.push_str(&self.0[end..]);
        self.0 = next;
    }
}

struct Editor {
    entry: Option<Uuid>,
    version: Option<Uuid>,
    readonly: bool,
    name: Sensitive,
    secret: Sensitive,
    original_name: Zeroizing<String>,
    original_secret: Zeroizing<String>,
    widget: Uuid,
}
impl Editor {
    fn new() -> Self {
        Self {
            entry: None,
            version: None,
            readonly: false,
            name: Sensitive::new(""),
            secret: Sensitive::new(""),
            original_name: Zeroizing::new(String::new()),
            original_secret: Zeroizing::new(String::new()),
            widget: Uuid::new_v4(),
        }
    }
    fn from_record(record: &Record, readonly: bool) -> Self {
        Self {
            entry: Some(record.entry),
            version: Some(record.version),
            readonly,
            name: Sensitive::new(&record.name),
            secret: Sensitive::new(&record.secret),
            original_name: Zeroizing::new(record.name.clone()),
            original_secret: Zeroizing::new(record.secret.clone()),
            widget: Uuid::new_v4(),
        }
    }
    fn dirty(&self) -> bool {
        !self.readonly
            && (self.name.as_str() != self.original_name.as_str()
                || self.secret.as_str() != self.original_secret.as_str())
    }
}

#[derive(Clone)]
enum Action {
    Select(Uuid, Uuid),
    New,
    Close,
    Lock,
}
enum Message {
    Opened(Vault),
    Loaded(Record, bool),
    Saved(Catalog, Uuid, bool, bool),
}
struct Job {
    receive: mpsc::Receiver<Result<Message>>,
    cancel: Cancellation,
}

struct App {
    hwnd: HWND,
    protected: bool,
    protection_error: String,
    monitor: CardMonitor,
    clipboard: Clipboard,
    path: String,
    gpg: String,
    session: Option<Arc<Mutex<Vault>>>,
    catalog: Option<Catalog>,
    cancel: Option<Cancellation>,
    editor: Option<Editor>,
    job: Option<Job>,
    pending: Option<Action>,
    confirming: bool,
    closing: bool,
    search: Sensitive,
    status: String,
}
impl App {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        cc.egui_ctx.set_visuals(egui::Visuals::dark());
        let hwnd = match cc.window_handle().map(|h| h.as_raw()) {
            Ok(RawWindowHandle::Win32(handle)) => handle.hwnd.get() as HWND,
            _ => std::ptr::null_mut(),
        };
        let protection = platform::protect_window(hwnd);
        let protected = protection.is_ok();
        let protection_error = protection.err().map_or(String::new(), |e| e.to_string());
        let root = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        Self {
            hwnd,
            protected,
            protection_error,
            monitor: CardMonitor::start(cc.egui_ctx.clone()),
            clipboard: Clipboard::new(hwnd),
            path: root
                .join("YubiVault")
                .join("vault")
                .to_string_lossy()
                .into_owned(),
            gpg: find_gpg().to_string_lossy().into_owned(),
            session: None,
            catalog: None,
            cancel: None,
            editor: None,
            job: None,
            pending: None,
            confirming: false,
            closing: false,
            search: Sensitive::new(""),
            status: String::new(),
        }
    }

    fn reset(&mut self, ctx: &egui::Context, reason: &str) {
        if let Some(cancel) = self.cancel.take() {
            cancel.cancel();
        }
        if let Some(job) = self.job.take() {
            job.cancel.cancel();
        }
        self.editor = None;
        self.catalog = None;
        self.session = None;
        self.pending = None;
        self.confirming = false;
        self.search = Sensitive::new("");
        self.clipboard.clear();
        ctx.memory_mut(|memory| {
            memory.data.clear();
            memory.caches = Default::default();
        });
        ctx.output_mut(|output| {
            for command in &mut output.commands {
                if let egui::OutputCommand::CopyText(text) = command {
                    text.zeroize();
                }
            }
            output.commands.clear();
            output.events.clear();
        });
        self.status = reason.to_owned();
        ctx.request_repaint();
    }

    fn start_job(
        &mut self,
        ctx: &egui::Context,
        cancel: Cancellation,
        work: impl FnOnce() -> Result<Message> + Send + 'static,
    ) {
        let (send, receive) = mpsc::channel();
        let context = ctx.clone();
        let check = cancel.clone();
        thread::spawn(move || {
            let result = work().and_then(|message| {
                check.check()?;
                Ok(message)
            });
            let _ = send.send(result);
            context.request_repaint();
        });
        self.job = Some(Job { receive, cancel });
        self.status.clear();
    }

    fn open(&mut self, ctx: &egui::Context, create: bool) {
        if !self.protected {
            return;
        }
        let cancel = match self.monitor.cancellation() {
            Ok(c) => c,
            Err(e) => {
                self.status = e.to_string();
                return;
            }
        };
        self.cancel = Some(cancel.clone());
        let (root, exe, worker_cancel) = (
            PathBuf::from(&self.path),
            PathBuf::from(&self.gpg),
            cancel.clone(),
        );
        self.start_job(ctx, cancel, move || {
            let crypto: Arc<dyn Crypto> = Arc::new(Gpg::on_card(exe, &worker_cancel)?);
            let vault = if create {
                Vault::create(&root, crypto, worker_cancel)?
            } else {
                Vault::open(&root, crypto, worker_cancel)?
            };
            Ok(Message::Opened(vault))
        });
    }

    fn request(&mut self, ctx: &egui::Context, action: Action) {
        if self.job.is_some() {
            return;
        }
        if self.editor.as_ref().is_some_and(Editor::dirty) {
            self.pending = Some(action);
            self.confirming = true;
        } else {
            self.perform(ctx, action);
        }
    }
    fn perform(&mut self, ctx: &egui::Context, action: Action) {
        self.confirming = false;
        self.pending = None;
        match action {
            Action::New => {
                self.editor = Some(Editor::new());
                self.status.clear();
            }
            Action::Lock => self.reset(ctx, "Хранилище закрыто"),
            Action::Close => {
                self.reset(ctx, "");
                self.closing = true;
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            Action::Select(entry, version) => {
                let Some(vault) = self.session.clone() else {
                    return;
                };
                let Some(cancel) = self.cancel.clone() else {
                    return;
                };
                self.editor = None;
                self.start_job(ctx, cancel, move || {
                    let vault = vault.lock().map_err(|_| anyhow::anyhow!("Сбой сеанса"))?;
                    // Saving before a pending navigation can turn its target
                    // from current into history. Derive read-only from the
                    // committed catalog, rather than stale UI state.
                    let readonly = vault
                        .catalog
                        .entries
                        .iter()
                        .find(|e| e.id == entry)
                        .and_then(|e| e.versions.first())
                        .is_none_or(|v| v.id != version);
                    let record = vault.read_version(entry, version)?;
                    Ok(Message::Loaded(record, readonly))
                });
            }
        }
    }

    fn save(&mut self, ctx: &egui::Context) {
        let (Some(editor), Some(vault), Some(cancel)) =
            (&self.editor, self.session.clone(), self.cancel.clone())
        else {
            return;
        };
        if self.job.is_some() || editor.readonly {
            return;
        }
        let (id, name, secret) = (
            editor.entry,
            Zeroizing::new(editor.name.as_str().to_owned()),
            Zeroizing::new(editor.secret.as_str().to_owned()),
        );
        self.confirming = false;
        self.start_job(ctx, cancel, move || {
            let mut vault = vault.lock().map_err(|_| anyhow::anyhow!("Сбой сеанса"))?;
            let saved = vault.save(id, &name, &secret)?;
            Ok(Message::Saved(
                vault.catalog.clone(),
                saved.entry,
                saved.changed,
                saved.maintenance_pending,
            ))
        });
    }

    fn poll(&mut self, ctx: &egui::Context) {
        self.clipboard.tick();
        if self
            .cancel
            .as_ref()
            .is_some_and(|c| c.check().is_err() || !self.monitor.available())
        {
            self.reset(
                ctx,
                "Карта извлечена или изменилось подключение: сеанс очищен",
            );
            return;
        }
        if self.protected && !platform::is_protected(self.hwnd) {
            self.protected = false;
            self.protection_error = "Windows больше не подтверждает защиту окна".into();
            self.reset(ctx, "Сеанс закрыт из-за ошибки защиты окна");
            return;
        }
        let message = self.job.as_ref().and_then(|j| match j.receive.try_recv() {
            Ok(result) => Some(result),
            Err(mpsc::TryRecvError::Disconnected) => {
                Some(Err(anyhow::anyhow!("Фоновая операция остановлена")))
            }
            Err(mpsc::TryRecvError::Empty) => None,
        });
        if let Some(message) = message {
            self.job = None;
            // Recheck after receiving: a card change cannot resurrect the session.
            if self.cancel.as_ref().is_some_and(|c| c.check().is_err()) {
                self.reset(ctx, "Карта извлечена: сеанс очищен");
                return;
            }
            match message {
                Err(error) => {
                    self.status = error.to_string();
                    self.pending = None;
                    self.confirming = false;
                    if self.session.is_none() {
                        self.cancel = None;
                    }
                }
                Ok(Message::Opened(vault)) => {
                    self.catalog = Some(vault.catalog.clone());
                    self.session = Some(Arc::new(Mutex::new(vault)));
                    self.status = "Хранилище открыто".into();
                }
                Ok(Message::Loaded(record, readonly)) => {
                    self.editor = Some(Editor::from_record(&record, readonly))
                }
                Ok(Message::Saved(catalog, entry, changed, maintenance)) => {
                    if let Some(editor) = &mut self.editor {
                        editor.entry = Some(entry);
                        editor.version = catalog
                            .entries
                            .iter()
                            .find(|e| e.id == entry)
                            .map(|e| e.versions[0].id);
                        editor.original_name = Zeroizing::new(editor.name.as_str().to_owned());
                        editor.original_secret = Zeroizing::new(editor.secret.as_str().to_owned());
                    }
                    self.catalog = Some(catalog);
                    self.status = if maintenance { "Сохранено. Очистка старых зашифрованных файлов отложена до следующего открытия" } else if changed { "Сохранено" } else { "Изменений нет" }.into();
                    if let Some(action) = self.pending.take() {
                        self.perform(ctx, action);
                    }
                }
            }
        }
        if ctx.input(|i| i.viewport().close_requested()) && !self.closing {
            if self.job.is_some() || self.editor.as_ref().is_some_and(Editor::dirty) {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                if self.job.is_none() {
                    self.pending = Some(Action::Close);
                    self.confirming = true;
                }
            } else {
                self.reset(ctx, "");
                self.closing = true;
            }
        }
        ctx.request_repaint_after(Duration::from_millis(100));
    }

    fn locked_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("YubiVault");
        ui.label("Секреты на вашей OpenPGP-карте");
        ui.add_space(22.0);
        if !self.protected {
            ui.colored_label(egui::Color32::LIGHT_RED, &self.protection_error);
            ui.label("Открытие секретов заблокировано. Защита окна Windows должна быть включена.");
            return;
        }
        ui.label("Папка хранилища");
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut self.path).desired_width(600.0));
            if ui.button("Выбрать…").clicked()
                && let Some(path) = rfd::FileDialog::new().pick_folder()
            {
                self.path = path.to_string_lossy().into_owned();
            }
        });
        ui.add_space(12.0);
        ui.label("GnuPG (gpg.exe)");
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut self.gpg).desired_width(600.0));
            if ui.button("Выбрать…").clicked()
                && let Some(path) = rfd::FileDialog::new()
                    .add_filter("GnuPG", &["exe"])
                    .pick_file()
            {
                self.gpg = path.to_string_lossy().into_owned();
            }
        });
        ui.add_space(16.0);
        ui.label(if self.monitor.available() { "Карта подключена. GnuPG проверит её ключ; подтвердите PIN или касание, если потребуется." } else { "Подключите одну YubiKey с OpenPGP. Ожидание службы смарт-карт Windows…" });
        ui.add_space(12.0);
        let ctx = ui.ctx().clone();
        ui.horizontal(|ui| {
            let enabled = self.monitor.available();
            if ui
                .add_enabled(enabled, egui::Button::new("Открыть"))
                .clicked()
            {
                self.open(&ctx, false);
            }
            if ui
                .add_enabled(enabled, egui::Button::new("Создать хранилище"))
                .clicked()
            {
                self.open(&ctx, true);
            }
        });
        ui.add_space(24.0);
        ui.weak("Ключ определяется с карты автоматически. Приложение не меняет настройки YubiKey.");
    }

    fn vault_ui(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        let mut action = None;
        ui.horizontal(|ui| {
            ui.heading("YubiVault");
            if ui.button("Добавить").clicked() {
                action = Some(Action::New);
            }
            if ui.button("Закрыть хранилище").clicked() {
                action = Some(Action::Lock);
            }
            ui.weak("Защита захвата Windows включена");
        });
        ui.separator();
        ui.columns(2, |columns| {
            columns[0].label("Имена");
            let output = egui::TextEdit::singleline(&mut self.search)
                .hint_text("Поиск по имени")
                .show(&mut columns[0]);
            clear_undo(&ctx, output.response.id);
            columns[0].add_space(8.0);
            egui::ScrollArea::vertical()
                .id_salt("records")
                .max_height(450.0)
                .show(&mut columns[0], |ui| {
                    if let Some(catalog) = &self.catalog {
                        let mut entries: Vec<_> = catalog.entries.iter().collect();
                        entries.sort_by(|a, b| a.name.cmp(&b.name));
                        for entry in entries {
                            if !entry.name.contains(self.search.as_str()) {
                                continue;
                            }
                            let selected = self
                                .editor
                                .as_ref()
                                .is_some_and(|e| e.entry == Some(entry.id));
                            if ui.selectable_label(selected, &entry.name).clicked() {
                                action = Some(Action::Select(entry.id, entry.versions[0].id));
                            }
                        }
                    }
                });
            let ui = &mut columns[1];
            if let Some(editor) = &mut self.editor {
                ui.label(if editor.readonly {
                    "История · только чтение"
                } else if editor.entry.is_none() {
                    "Новая запись"
                } else {
                    "Текущая версия"
                });
                ui.label("Имя");
                let name = egui::TextEdit::singleline(&mut editor.name)
                    .id_salt((editor.widget, "name"))
                    .interactive(!editor.readonly)
                    .desired_width(f32::INFINITY)
                    .show(ui);
                clear_undo(&ctx, name.response.id);
                ui.label("Пароль / текст");
                egui::ScrollArea::both()
                    .id_salt((editor.widget, "text_scroll"))
                    .max_height(280.0)
                    .show(ui, |ui| {
                        let text = egui::TextEdit::multiline(&mut editor.secret)
                            .id_salt((editor.widget, "secret"))
                            .font(egui::TextStyle::Monospace)
                            .interactive(!editor.readonly)
                            .desired_rows(12)
                            .desired_width(f32::INFINITY)
                            .show(ui);
                        clear_undo(&ctx, text.response.id);
                    });
                let mut save = false;
                ui.horizontal(|ui| {
                    if ui.button("Скопировать").clicked() {
                        self.status = match self.clipboard.copy(editor.secret.as_str()) {
                            Ok(()) => "Скопировано · очистка через 20 секунд".into(),
                            Err(e) => e.to_string(),
                        };
                    }
                    if !editor.readonly {
                        save = ui
                            .add_enabled(editor.dirty(), egui::Button::new("Сохранить · Ctrl+S"))
                            .clicked();
                        if ui.button("Отменить правки").clicked() {
                            editor.name = Sensitive::new(&editor.original_name);
                            editor.secret = Sensitive::new(&editor.original_secret);
                            editor.widget = Uuid::new_v4();
                        }
                    }
                });
                let entry_id = editor.entry;
                let selected_version = editor.version;
                if let (Some(entry_id), Some(catalog)) = (entry_id, &self.catalog)
                    && let Some(entry) = catalog.entries.iter().find(|e| e.id == entry_id)
                {
                    ui.add_space(12.0);
                    ui.label("Версии");
                    for (index, version) in entry.versions.iter().enumerate() {
                        let suffix = if index == 0 { " · текущая" } else { "" };
                        let date = format!(
                            "{}{suffix}",
                            version
                                .saved_at
                                .with_timezone(&Local)
                                .format("%d.%m.%Y %H:%M:%S%.3f")
                        );
                        if ui
                            .selectable_label(selected_version == Some(version.id), date)
                            .clicked()
                        {
                            action = Some(Action::Select(entry_id, version.id));
                        }
                    }
                }
                if save {
                    self.save(&ctx);
                }
            } else {
                ui.label("Выберите запись или добавьте новую.");
            }
        });
        if ctx.input_mut(|i| i.consume_key(egui::Modifiers::CTRL, egui::Key::S)) {
            self.save(&ctx);
        }
        if let Some(action) = action {
            self.request(&ctx, action);
        }
    }

    fn confirmation(&mut self, ctx: &egui::Context) {
        if !self.confirming {
            return;
        }
        let mut choice = 0;
        egui::Modal::new(egui::Id::new("unsaved_changes")).show(ctx, |ui| {
            ui.heading("Сохранить изменения?");
            ui.label("В записи есть несохранённые правки.");
            ui.horizontal(|ui| {
                if ui.button("Сохранить").clicked() {
                    choice = 1;
                }
                if ui.button("Отбросить").clicked() {
                    choice = 2;
                }
                if ui.button("Остаться").clicked() {
                    choice = 3;
                }
            });
        });
        match choice {
            1 => self.save(ctx),
            2 => {
                if let Some(action) = self.pending.take() {
                    self.perform(ctx, action);
                }
            }
            3 => {
                self.pending = None;
                self.confirming = false;
            }
            _ => {}
        }
    }

    fn secure_output(&mut self, ctx: &egui::Context) {
        let commands = ctx.output_mut(|output| {
            output.events.clear();
            std::mem::take(&mut output.commands)
        });
        for command in commands {
            if let egui::OutputCommand::CopyText(mut text) = command {
                // Includes Ctrl+C/Ctrl+X from text widgets; never use eframe's
                // ordinary clipboard path, which has no exclusion markers.
                if self.protected
                    && self.cancel.as_ref().is_none_or(|c| c.check().is_ok())
                    && let Err(e) = self.clipboard.copy(&text)
                {
                    self.status = e.to_string();
                }
                text.zeroize();
            }
        }
    }
}

fn clear_undo(ctx: &egui::Context, id: egui::Id) {
    if let Some(mut state) = egui::TextEdit::load_state(ctx, id) {
        state.clear_undoer();
        state.store(ctx, id);
    }
}
impl eframe::App for App {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll(ctx);
    }
    fn ui(&mut self, root: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = root.ctx().clone();
        egui::CentralPanel::default().show(root, |ui| {
            if self.session.is_some() && !ctx.input(|i| i.focused) {
                ui.heading("YubiVault");
                ui.label("Содержимое скрыто: верните фокус окну.");
            } else {
                let busy = self.job.is_some();
                ui.add_enabled_ui(!busy && !self.confirming, |ui| {
                    if self.session.is_some() {
                        self.vault_ui(ui);
                    } else {
                        self.locked_ui(ui);
                    }
                });
                if busy {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label("Ожидание GnuPG / карты…");
                    });
                }
            }
            ui.add_space(10.0);
            ui.label(&self.status);
        });
        self.confirmation(&ctx);
        self.secure_output(&ctx);
    }
    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        if let Some(cancel) = &self.cancel {
            cancel.cancel();
        }
        if let Some(job) = &self.job {
            job.cancel.cancel();
        }
        self.clipboard.clear();
        self.editor = None;
        self.catalog = None;
        self.session = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct FixtureCrypto;
    impl Crypto for FixtureCrypto {
        fn recipient(&self) -> &str {
            "0123456789ABCDEF0123456789ABCDEF01234567"
        }
        fn encrypt(&self, data: &[u8], _: &Cancellation) -> Result<Vec<u8>> {
            Ok(data.iter().map(|v| v ^ 0xa5).collect())
        }
        fn decrypt(&self, data: &[u8], _: &Cancellation) -> Result<Zeroizing<Vec<u8>>> {
            Ok(Zeroizing::new(data.iter().map(|v| v ^ 0xa5).collect()))
        }
    }
    fn fixture() -> App {
        let hwnd = std::ptr::null_mut();
        App {
            hwnd,
            protected: false,
            protection_error: String::new(),
            monitor: CardMonitor::fixture(),
            clipboard: Clipboard::new(hwnd),
            path: String::new(),
            gpg: String::new(),
            session: None,
            catalog: None,
            cancel: None,
            editor: None,
            job: None,
            pending: None,
            confirming: false,
            closing: false,
            search: Sensitive::new(""),
            status: String::new(),
        }
    }
    fn painted_text(shape: &egui::epaint::Shape, text: &mut String) {
        match shape {
            egui::epaint::Shape::Text(t) => {
                text.push_str(&t.galley.job.text);
                text.push('\n');
            }
            egui::epaint::Shape::Vec(shapes) => {
                for shape in shapes {
                    painted_text(shape, text);
                }
            }
            _ => {}
        }
    }
    fn render(app: &mut App, ctx: &egui::Context, focused: bool) -> String {
        let output = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(960.0, 650.0),
                )),
                focused,
                ..Default::default()
            },
            |ui| {
                eframe::App::ui(app, ui, &mut eframe::Frame::_new_kittest());
            },
        );
        let mut text = String::new();
        for shape in &output.shapes {
            painted_text(&shape.shape, &mut text);
        }
        output.drop_without_applying_deltas();
        text
    }
    #[test]
    fn rendered_secret_is_hidden_on_focus_loss_and_removed_after_reset() {
        let temp = tempfile::tempdir().unwrap();
        let vault =
            Vault::create(temp.path(), Arc::new(FixtureCrypto), Cancellation::new()).unwrap();
        let mut app = fixture();
        app.protected = true;
        app.catalog = Some(vault.catalog.clone());
        app.session = Some(Arc::new(Mutex::new(vault)));
        let mut editor = Editor::new();
        editor.secret = Sensitive::new("SYNTHETIC_FOCUS_SENTINEL");
        app.editor = Some(editor);
        let ctx = egui::Context::default();
        assert!(render(&mut app, &ctx, true).contains("SYNTHETIC_FOCUS_SENTINEL"));
        assert!(!render(&mut app, &ctx, false).contains("SYNTHETIC_FOCUS_SENTINEL"));
        app.reset(&ctx, "removed");
        assert!(!render(&mut app, &ctx, true).contains("SYNTHETIC_FOCUS_SENTINEL"));
    }
    #[test]
    fn pending_navigation_to_former_current_version_becomes_readonly() {
        let temp = tempfile::tempdir().unwrap();
        let mut vault =
            Vault::create(temp.path(), Arc::new(FixtureCrypto), Cancellation::new()).unwrap();
        let entry = vault.save(None, "name", "previous").unwrap().entry;
        let version = vault.catalog.entries[0].versions[0].id;
        vault.save(Some(entry), "renamed", "new current").unwrap();
        let mut app = fixture();
        app.catalog = Some(vault.catalog.clone());
        app.session = Some(Arc::new(Mutex::new(vault)));
        app.cancel = Some(Cancellation::new());
        app.perform(&egui::Context::default(), Action::Select(entry, version));
        let result = app
            .job
            .take()
            .unwrap()
            .receive
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap();
        match result {
            Message::Loaded(record, readonly) => {
                assert!(readonly);
                assert_eq!(record.secret, "previous");
            }
            _ => panic!("expected a loaded history version"),
        }
    }
    #[test]
    fn missing_capture_protection_prevents_unlock() {
        let mut app = fixture();
        let ctx = egui::Context::default();
        app.open(&ctx, true);
        assert!(app.job.is_none() && app.cancel.is_none() && app.session.is_none());
    }
    #[test]
    fn dirty_navigation_requires_a_choice_and_reset_discards_everything() {
        let ctx = egui::Context::default();
        let mut app = fixture();
        let mut editor = Editor::new();
        editor.secret = Sensitive::new("unsaved synthetic text");
        app.editor = Some(editor);
        app.request(&ctx, Action::New);
        assert!(app.confirming && matches!(app.pending, Some(Action::New)));
        assert_eq!(
            app.editor.as_ref().unwrap().secret.as_str(),
            "unsaved synthetic text"
        );
        app.reset(&ctx, "card removed");
        assert!(
            app.editor.is_none()
                && app.catalog.is_none()
                && app.session.is_none()
                && app.pending.is_none()
                && !app.confirming
        );
    }
    #[test]
    fn late_worker_result_cannot_reopen_a_removed_card_session() {
        let ctx = egui::Context::default();
        let mut app = fixture();
        let cancel = app.monitor.cancellation().unwrap();
        app.cancel = Some(cancel.clone());
        let (release, gate) = mpsc::channel();
        app.start_job(&ctx, cancel, move || {
            gate.recv().unwrap();
            Ok(Message::Loaded(
                Record {
                    format: 1,
                    vault: Uuid::new_v4(),
                    entry: Uuid::new_v4(),
                    version: Uuid::new_v4(),
                    name: "synthetic".into(),
                    secret: "late secret".into(),
                },
                false,
            ))
        });
        app.monitor
            .epoch
            .fetch_add(2, std::sync::atomic::Ordering::SeqCst);
        app.poll(&ctx);
        release.send(()).unwrap();
        thread::sleep(Duration::from_millis(25));
        app.poll(&ctx);
        assert!(
            app.editor.is_none()
                && app.session.is_none()
                && app.job.is_none()
                && app.cancel.is_none()
        );
    }
    #[test]
    fn editor_tracks_exact_changes_and_history_is_readonly() {
        let record = Record {
            format: 1,
            vault: Uuid::new_v4(),
            entry: Uuid::new_v4(),
            version: Uuid::new_v4(),
            name: "name".into(),
            secret: " a\r\nb\n".into(),
        };
        let mut editor = Editor::from_record(&record, false);
        assert!(!editor.dirty());
        editor
            .secret
            .insert_text(" ", egui::epaint::text::CharIndex(0));
        assert!(editor.dirty());
        assert!(!Editor::from_record(&record, true).dirty());
    }
    #[test]
    fn secure_buffer_edits_unicode_without_trimming() {
        let mut text = Sensitive::new(" aЖ\r\n");
        text.insert_text("字", egui::epaint::text::CharIndex(3));
        assert_eq!(text.as_str(), " aЖ字\r\n");
        text.delete_char_range(egui::epaint::text::CharIndex(2)..egui::epaint::text::CharIndex(4));
        assert_eq!(text.as_str(), " a\r\n");
    }
}
