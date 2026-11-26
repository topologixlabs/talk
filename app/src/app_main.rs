//! The Tauri app shell, shared by the Mac and iPhone builds.

use serde_json::Value;
use std::sync::Mutex;
use crate::App;
use tauri::Manager;

// Runs off the main thread so connecting to a device never freezes the window.
#[tauri::command(async)]
fn cmd(state: tauri::State<'_, Mutex<App>>, name: String, args: Value) -> Result<Value, String> {
    state.lock().map_err(|_| "app state unavailable".to_string())?.command(&name, &args)
}

/// Opens the installed WhatsApp app with the text ready. The person picks who
/// receives it and presses send there, so Talk never sends anything by itself.
#[tauri::command(async)]
fn share_whatsapp(text: String) -> Result<(), String> {
    let url = crate::whatsapp_share_url(&text)?;
    let opened = std::process::Command::new("/usr/bin/open")
        .arg(&url)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|_| "Could not open WhatsApp".to_string())?;
    if opened.success() {
        Ok(())
    } else {
        Err("WhatsApp is not installed on this Mac".to_string())
    }
}

/// Opens Apple's Messages compose window with the text ready. The person chooses the
/// recipient and presses send, so Talk cannot send or read anything in Messages.
#[cfg(target_os = "macos")]
fn open_message_compose(text: &str) -> Result<(), String> {
    use objc2::{rc::Retained, runtime::AnyObject};
    use objc2_app_kit::{NSSharingService, NSSharingServiceNameComposeMessage};
    use objc2_foundation::{NSArray, NSString};

    let item: Retained<AnyObject> = Retained::into_super(Retained::into_super(NSString::from_str(text)));
    let items = NSArray::from_retained_slice(&[item]);
    // Safety: runs on the main thread, with a name and item list provided by AppKit types.
    unsafe {
        let service = NSSharingService::sharingServiceNamed(NSSharingServiceNameComposeMessage)
            .ok_or("Messages is not available on this Mac")?;
        if !service.canPerformWithItems(Some(&items)) {
            return Err("Messages cannot share this text".to_string());
        }
        service.performWithItems(&items);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
#[tauri::command(async)]
fn share_imessage(app: tauri::AppHandle, text: String) -> Result<(), String> {
    let text = crate::clean_share_text(&text)?.to_string();
    let (done, result) = std::sync::mpsc::channel();
    app.run_on_main_thread(move || {
        let _ = done.send(open_message_compose(&text));
    })
    .map_err(|_| "Could not open Messages".to_string())?;
    result.recv().map_err(|_| "Could not open Messages".to_string())?
}

#[cfg(not(target_os = "macos"))]
#[tauri::command(async)]
fn share_imessage(_text: String) -> Result<(), String> {
    Err("iMessage sharing is only available on Apple devices".to_string())
}

/// Starts Talk on macOS, and on iOS through the mobile entry point.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let dir = match option_env!("TALK_TEST_DATA_DIR") {
                Some(test_dir) => std::path::PathBuf::from(test_dir),
                None => app.path().app_data_dir()?,
            };
            std::fs::create_dir_all(&dir)?;
            app.manage(Mutex::new(App::new(dir)));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![cmd, share_whatsapp, share_imessage])
        .build(tauri::generate_context!())
        .expect("Talk could not start")
        .run(|handle, event| {
            if let tauri::RunEvent::Exit = event {
                if let Ok(mut app) = handle.state::<Mutex<App>>().lock() {
                    app.shutdown();
                }
            }
        });
}
