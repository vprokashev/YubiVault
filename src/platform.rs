use crate::crypto::Cancellation;
use anyhow::{Result, ensure};
use std::{
    ffi::c_void,
    os::windows::ffi::OsStrExt,
    path::Path,
    ptr::{null, null_mut},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{GlobalFree, HWND},
    Graphics::Dwm::DwmIsCompositionEnabled,
    Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW, ReplaceFileW,
    },
    System::{DataExchange::*, Memory::*},
    UI::WindowsAndMessaging::*,
};
use zeroize::Zeroizing;

fn wide(value: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}

pub fn replace_file(from: &Path, to: &Path, backup: Option<&Path>) -> Result<()> {
    let source = wide(from);
    let target = wide(to);
    let backup = backup.map(wide);
    // All callers flush complete ciphertext and use paths on the same volume.
    let ok = unsafe {
        if to.exists() {
            ReplaceFileW(
                target.as_ptr(),
                source.as_ptr(),
                backup.as_ref().map_or(null(), |v| v.as_ptr()),
                0,
                null(),
                null(),
            )
        } else {
            MoveFileExW(
                source.as_ptr(),
                target.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        }
    };
    ensure!(
        ok != 0,
        "Не удалось переключить зашифрованный каталог ({})",
        std::io::Error::last_os_error()
    );
    Ok(())
}

// HWND is an opaque kernel-managed identifier. These APIs validate handles;
// they do not dereference Rust memory, including for null/invalid HWNDs.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn protect_window(hwnd: HWND) -> Result<()> {
    let mut enabled = 0;
    ensure!(
        unsafe { DwmIsCompositionEnabled(&mut enabled) } >= 0 && enabled != 0,
        "Защита от захвата требует работающего DWM"
    );
    ensure!(
        unsafe { SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE) } != 0,
        "Windows не включила защиту окна ({})",
        std::io::Error::last_os_error()
    );
    ensure!(is_protected(hwnd), "Windows не подтвердила защиту окна");
    Ok(())
}
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn is_protected(hwnd: HWND) -> bool {
    let mut affinity = 0;
    unsafe {
        GetWindowDisplayAffinity(hwnd, &mut affinity) != 0 && affinity == WDA_EXCLUDEFROMCAPTURE
    }
}

struct ClipboardOpen;
impl ClipboardOpen {
    fn new(hwnd: HWND) -> Result<Self> {
        ensure!(
            unsafe { OpenClipboard(hwnd) } != 0,
            "Буфер обмена занят; повторите копирование"
        );
        Ok(Self)
    }
}
impl Drop for ClipboardOpen {
    fn drop(&mut self) {
        unsafe {
            CloseClipboard();
        }
    }
}

/// Sequence + owner is checked while the clipboard is locked, avoiding a race
/// with replacement by another program. No plaintext is kept for comparison.
pub struct Clipboard {
    hwnd: HWND,
    owned: Option<(u32, Instant)>,
}
impl Clipboard {
    pub fn new(hwnd: HWND) -> Self {
        Self { hwnd, owned: None }
    }
    pub fn copy(&mut self, text: &str) -> Result<()> {
        ensure!(
            !text.contains('\0'),
            "Буфер Windows не поддерживает нулевой символ внутри текста"
        );
        let _open = ClipboardOpen::new(self.hwnd)?;
        ensure!(
            unsafe { EmptyClipboard() } != 0,
            "Не удалось подготовить буфер обмена"
        );
        let result = (|| -> Result<()> {
            // Register exclusions before publishing the Unicode secret.
            for (name, value) in [
                ("ExcludeClipboardContentFromMonitorProcessing", 1u32),
                ("CanIncludeInClipboardHistory", 0),
                ("CanUploadToCloudClipboard", 0),
            ] {
                let name = wide(name);
                let format = unsafe { RegisterClipboardFormatW(name.as_ptr()) };
                ensure!(format != 0, "Не удалось исключить данные из истории буфера");
                publish(format, &value.to_ne_bytes())?;
            }
            let text = Zeroizing::new(text.encode_utf16().chain(Some(0)).collect::<Vec<_>>());
            let bytes =
                unsafe { std::slice::from_raw_parts(text.as_ptr().cast::<u8>(), text.len() * 2) };
            publish(13, bytes)?;
            Ok(())
        })();
        if result.is_err() {
            unsafe {
                EmptyClipboard();
            }
            self.owned = None;
            return result;
        }
        // Closing can advance the clipboard sequence; sample after CloseClipboard.
        drop(_open);
        self.owned = Some((
            unsafe { GetClipboardSequenceNumber() },
            Instant::now() + Duration::from_secs(20),
        ));
        Ok(())
    }
    pub fn tick(&mut self) {
        if self
            .owned
            .is_some_and(|(_, deadline)| Instant::now() >= deadline)
        {
            self.clear();
        }
    }
    pub fn clear(&mut self) {
        let Some((sequence, _)) = self.owned else {
            return;
        };
        self.owned = Some((sequence, Instant::now()));
        if let Ok(_open) = ClipboardOpen::new(self.hwnd) {
            if unsafe {
                GetClipboardSequenceNumber() == sequence
                    && GetClipboardOwner() == self.hwnd
                    && EmptyClipboard() == 0
            } {
                return;
            }
            self.owned = None;
        }
        // If busy, retain the marker and retry on the next frame.
    }
}
impl Drop for Clipboard {
    fn drop(&mut self) {
        self.clear();
    }
}

fn publish(format: u32, data: &[u8]) -> Result<()> {
    let memory = unsafe { GlobalAlloc(GMEM_MOVEABLE, data.len()) };
    ensure!(!memory.is_null(), "Не удалось выделить буфер обмена");
    let pointer = unsafe { GlobalLock(memory) };
    if pointer.is_null() {
        unsafe {
            GlobalFree(memory);
        }
        anyhow::bail!("Не удалось открыть память буфера");
    }
    unsafe {
        std::ptr::copy_nonoverlapping(data.as_ptr(), pointer.cast::<u8>(), data.len());
        GlobalUnlock(memory);
    }
    if unsafe { SetClipboardData(format, memory) }.is_null() {
        unsafe {
            let pointer = GlobalLock(memory);
            if !pointer.is_null() {
                std::ptr::write_bytes(pointer, 0, data.len());
                GlobalUnlock(memory);
            }
            GlobalFree(memory);
        }
        anyhow::bail!("Windows отклонила копирование");
    }
    Ok(()) // Ownership transferred to Windows.
}

// PC/SC types use pointer-sized SCARDCONTEXT and 32-bit DWORD/LONG on Windows.
#[repr(C)]
struct ReaderState {
    reader: *const u16,
    user: *mut c_void,
    current: u32,
    event: u32,
    atr_len: u32,
    atr: [u8; 36],
}
#[link(name = "winscard")]
unsafe extern "system" {
    fn SCardEstablishContext(
        scope: u32,
        reserved1: *const c_void,
        reserved2: *const c_void,
        context: *mut usize,
    ) -> i32;
    fn SCardReleaseContext(context: usize) -> i32;
    fn SCardListReadersW(
        context: usize,
        groups: *const u16,
        readers: *mut u16,
        count: *mut u32,
    ) -> i32;
    fn SCardGetStatusChangeW(
        context: usize,
        timeout: u32,
        states: *mut ReaderState,
        count: u32,
    ) -> i32;
}

pub struct CardMonitor {
    pub epoch: Arc<AtomicU64>,
    present: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
}
impl CardMonitor {
    #[cfg(test)]
    pub fn fixture() -> Self {
        Self {
            epoch: Arc::new(AtomicU64::new(1)),
            present: Arc::new(AtomicBool::new(true)),
            stop: Arc::new(AtomicBool::new(false)),
        }
    }
    pub fn start(ctx: eframe::egui::Context) -> Self {
        let epoch = Arc::new(AtomicU64::new(0));
        let present = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let (worker_epoch, worker_present, worker_stop) =
            (epoch.clone(), present.clone(), stop.clone());
        thread::spawn(move || {
            let mut context = 0;
            let mut previous: Vec<(Vec<u16>, u32, Vec<u8>)> = vec![];
            while !worker_stop.load(Ordering::SeqCst) {
                if context == 0
                    && unsafe { SCardEstablishContext(0, null(), null(), &mut context) } != 0
                {
                    context = 0;
                }
                let observed = if context == 0 {
                    Err(anyhow::anyhow!("PC/SC недоступен"))
                } else {
                    poll_readers(context, &previous)
                };
                let states = match observed {
                    Ok(states) => states,
                    Err(_) => {
                        if context != 0 {
                            unsafe {
                                SCardReleaseContext(context);
                            }
                            context = 0;
                        }
                        vec![]
                    }
                };
                let available = states
                    .iter()
                    .filter(|(_, flags, _)| flags & 0x20 != 0 && flags & (0x4 | 0x8) == 0)
                    .count()
                    == 1;
                // GnuPG may take an exclusive PC/SC connection. Allocation and
                // power flags must not masquerade as card removal.
                if card_identity(&states) != card_identity(&previous)
                    || available != worker_present.load(Ordering::SeqCst)
                {
                    worker_present.store(available, Ordering::SeqCst);
                    worker_epoch.fetch_add(1, Ordering::SeqCst);
                    ctx.request_repaint();
                }
                previous = states;
                if previous.is_empty() {
                    thread::sleep(Duration::from_millis(150));
                }
            }
            if context != 0 {
                unsafe {
                    SCardReleaseContext(context);
                }
            }
        });
        Self {
            epoch,
            present,
            stop,
        }
    }
    pub fn available(&self) -> bool {
        self.present.load(Ordering::SeqCst)
    }
    pub fn cancellation(&self) -> Result<Cancellation> {
        ensure!(
            self.available(),
            "Подключите одну OpenPGP-карту. Для контроля извлечения нужна служба смарт-карт Windows"
        );
        let epoch = self.epoch.load(Ordering::SeqCst);
        ensure!(self.available(), "Карта извлечена");
        Ok(Cancellation::with_card(self.epoch.clone(), epoch))
    }
}
impl Drop for CardMonitor {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

type ReaderSnapshot = (Vec<u16>, u32, Vec<u8>);
fn card_identity(states: &[ReaderSnapshot]) -> Vec<ReaderSnapshot> {
    states
        .iter()
        .map(|(name, flags, atr)| (name.clone(), flags & 0xffff003c, atr.clone()))
        .collect()
}

fn poll_readers(context: usize, previous: &[ReaderSnapshot]) -> Result<Vec<ReaderSnapshot>> {
    let mut count = 0;
    let status = unsafe { SCardListReadersW(context, null(), null_mut(), &mut count) };
    if status as u32 == 0x8010002e {
        return Ok(vec![]);
    }
    ensure!(status == 0 && count <= 65536, "Ошибка списка считывателей");
    let mut buffer = vec![0u16; count as usize];
    ensure!(
        unsafe { SCardListReadersW(context, null(), buffer.as_mut_ptr(), &mut count) } == 0,
        "Изменился список считывателей"
    );
    let names: Vec<Vec<u16>> = buffer
        .split(|c| *c == 0)
        .filter(|s| !s.is_empty())
        .map(|s| s.iter().copied().chain(Some(0)).collect())
        .collect();
    if names.is_empty() {
        return Ok(vec![]);
    }
    let mut states: Vec<_> = names
        .iter()
        .map(|name| ReaderState {
            reader: name.as_ptr(),
            user: null_mut(),
            current: previous
                .iter()
                .find(|(n, _, _)| n == name)
                .map_or(0, |(_, flags, _)| *flags),
            event: 0,
            atr_len: 0,
            atr: [0; 36],
        })
        .collect();
    let status =
        unsafe { SCardGetStatusChangeW(context, 150, states.as_mut_ptr(), states.len() as u32) };
    if status as u32 == 0x8010000a {
        return Ok(previous.to_vec());
    }
    ensure!(status == 0, "Ошибка состояния карты");
    Ok(names
        .into_iter()
        .zip(states)
        .map(|(name, state)| {
            (
                name,
                state.event & !2,
                state.atr[..(state.atr_len as usize).min(36)].to_vec(),
            )
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::{Graphics::Gdi::*, System::LibraryLoader::GetModuleHandleW};
    fn test_window() -> HWND {
        let class = wide("YubiVaultSyntheticChecks");
        let instance = unsafe { GetModuleHandleW(null()) };
        let wc = WNDCLASSW {
            lpfnWndProc: Some(DefWindowProcW),
            hInstance: instance,
            lpszClassName: class.as_ptr(),
            hbrBackground: unsafe { CreateSolidBrush(0x0037c9e3) },
            ..Default::default()
        };
        unsafe {
            RegisterClassW(&wc);
        }
        let hwnd = unsafe {
            CreateWindowExW(
                WS_EX_TOPMOST,
                class.as_ptr(),
                wide("Synthetic only").as_ptr(),
                WS_POPUP | WS_VISIBLE,
                80,
                80,
                128,
                128,
                null_mut(),
                null_mut(),
                instance,
                null(),
            )
        };
        assert!(!hwnd.is_null());
        unsafe {
            UpdateWindow(hwnd);
        }
        hwnd
    }
    fn sample_screen() -> u32 {
        unsafe {
            let screen = GetDC(null_mut());
            let memory = CreateCompatibleDC(screen);
            let bitmap = CreateCompatibleBitmap(screen, 1, 1);
            let previous = SelectObject(memory, bitmap);
            assert_ne!(
                BitBlt(memory, 0, 0, 1, 1, screen, 100, 100, SRCCOPY | CAPTUREBLT),
                0
            );
            let color = GetPixel(memory, 0, 0);
            SelectObject(memory, previous);
            DeleteObject(bitmap);
            DeleteDC(memory);
            ReleaseDC(null_mut(), screen);
            color
        }
    }
    #[test]
    fn connection_allocation_does_not_invalidate_card_identity() {
        let initial = vec![(vec![65, 0], 0x10020, vec![1, 2, 3])];
        let in_use = vec![(vec![65, 0], 0x101a0, vec![1, 2, 3])];
        let reinserted = vec![(vec![65, 0], 0x30020, vec![1, 2, 3])];
        assert_eq!(card_identity(&initial), card_identity(&in_use));
        assert_ne!(card_identity(&initial), card_identity(&reinserted));
    }
    #[test]
    #[ignore = "requires an interactive Windows desktop; captures one synthetic pixel only"]
    fn native_capture_protection() {
        let hwnd = test_window();
        thread::sleep(Duration::from_millis(300));
        let ordinary = sample_screen();
        assert_eq!(ordinary, 0x0037c9e3);
        protect_window(hwnd).unwrap();
        thread::sleep(Duration::from_millis(300));
        assert_ne!(
            sample_screen(),
            ordinary,
            "standard GDI capture must exclude the synthetic window"
        );
        assert!(is_protected(hwnd));
        assert!(protect_window(null_mut()).is_err());
        unsafe {
            DestroyWindow(hwnd);
        }
    }
    #[test]
    #[ignore = "uses the system clipboard with synthetic text only"]
    fn clipboard_preserves_replacement_and_excludes_history() {
        let hwnd = test_window();
        let mut clipboard = Clipboard::new(hwnd);
        clipboard.copy("synthetic\r\n  multiline\n").unwrap();
        {
            let _open = ClipboardOpen::new(hwnd).unwrap();
            for (name, expected) in [
                ("CanIncludeInClipboardHistory", 0u32),
                ("CanUploadToCloudClipboard", 0),
                ("ExcludeClipboardContentFromMonitorProcessing", 1),
            ] {
                let format = unsafe { RegisterClipboardFormatW(wide(name).as_ptr()) };
                let data = unsafe { GetClipboardData(format) };
                let pointer = unsafe { GlobalLock(data) }.cast::<u32>();
                assert!(!pointer.is_null());
                assert_eq!(unsafe { *pointer }, expected);
                unsafe {
                    GlobalUnlock(data);
                }
            }
            assert_ne!(
                unsafe {
                    IsClipboardFormatAvailable(RegisterClipboardFormatW(
                        wide("CanIncludeInClipboardHistory").as_ptr(),
                    ))
                },
                0
            );
            let data = unsafe { GetClipboardData(13) };
            let ptr = unsafe { GlobalLock(data) } as *const u16;
            assert!(!ptr.is_null());
            let expected: Vec<_> = "synthetic\r\n  multiline\n"
                .encode_utf16()
                .chain(Some(0))
                .collect();
            assert_eq!(
                unsafe { std::slice::from_raw_parts(ptr, expected.len()) },
                expected
            );
            unsafe {
                GlobalUnlock(data);
            }
        }
        clipboard.clear();
        assert_eq!(unsafe { IsClipboardFormatAvailable(13) }, 0);
        clipboard.copy("expiry").unwrap();
        if let Some((sequence, _)) = clipboard.owned {
            clipboard.owned = Some((sequence, Instant::now() - Duration::from_secs(1)));
        }
        clipboard.tick();
        assert_eq!(unsafe { IsClipboardFormatAvailable(13) }, 0);
        clipboard.copy("owned").unwrap();
        {
            let _open = ClipboardOpen::new(hwnd).unwrap();
            unsafe {
                EmptyClipboard();
            }
            let other: Vec<u8> = "replacement"
                .encode_utf16()
                .chain(Some(0))
                .flat_map(u16::to_ne_bytes)
                .collect();
            publish(13, &other).unwrap();
        }
        clipboard.clear();
        assert_ne!(unsafe { IsClipboardFormatAvailable(13) }, 0);
        // Clean only this synthetic replacement, while still owning it.
        {
            let _open = ClipboardOpen::new(hwnd).unwrap();
            unsafe {
                EmptyClipboard();
            }
        }
        unsafe {
            DestroyWindow(hwnd);
        }
    }
}
