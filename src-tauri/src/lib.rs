//! Library entry point for Tauri
//! Contains the main run() function that sets up the Tauri application.

mod commands;
mod db;
mod ffi;

/// Check for CAP_NET_RAW and request elevation via pkexec if missing.
/// On success, re-execs the binary so the new file capability takes effect.
/// No-op on non-Linux platforms.
#[cfg(target_os = "linux")]
fn ensure_capture_capability() {
    // CAP_NET_RAW = capability bit 13
    let has_cap = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("CapEff:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|hex| u64::from_str_radix(hex, 16).ok())
        })
        .map(|caps| (caps & (1u64 << 13)) != 0)
        .unwrap_or(false);

    if has_cap {
        return;
    }

    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return,
    };

    println!("[cap] CAP_NET_RAW not set — requesting elevation to enable packet capture...");

    let status = std::process::Command::new("pkexec")
        .args(["setcap", "cap_net_raw,cap_net_admin=eip", exe.to_str().unwrap_or("")])
        .status();

    match status {
        Ok(s) if s.success() => {
            println!("[cap] Capability set — restarting...");
            use std::os::unix::process::CommandExt;
            let args: Vec<String> = std::env::args().collect();
            // exec() replaces the current process — no return on success
            let err = std::process::Command::new(&exe).args(&args[1..]).exec();
            eprintln!("[cap] Re-exec failed: {}", err);
            std::process::exit(1);
        }
        Ok(_) => eprintln!("[cap] pkexec setcap failed — packet capture may not work"),
        Err(e) => eprintln!("[cap] pkexec unavailable: {e} — run: sudo setcap cap_net_raw,cap_net_admin=eip {}", exe.display()),
    }
}

/// Run the Tauri application
pub fn run() {
    #[cfg(target_os = "linux")]
    ensure_capture_capability();

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .setup(|app| {
            // Initialize SQLite database in the app data directory.
            // Non-fatal: if DB init fails, capture still works (just no recording).
            use tauri::Manager;
            let data_dir = app.path().app_data_dir().unwrap_or_else(|_| {
                // Fallback: platform-appropriate data directory
                #[cfg(target_os = "windows")]
                {
                    std::env::var("APPDATA")
                        .map(|p| std::path::PathBuf::from(p).join("SV-Subscriber"))
                        .unwrap_or_else(|_| std::path::PathBuf::from("./data"))
                }
                #[cfg(not(target_os = "windows"))]
                {
                    std::env::var("XDG_DATA_HOME")
                        .map(|p| std::path::PathBuf::from(p).join("sv-subscriber"))
                        .unwrap_or_else(|_| {
                            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
                            std::path::PathBuf::from(home)
                                .join(".local/share/sv-subscriber")
                        })
                }
            });
            std::fs::create_dir_all(&data_dir).ok();
            let db_path = data_dir.join("sv_data.db");

            match db::initialize(db_path) {
                Ok(_) => println!("[app] SQLite database ready"),
                Err(e) => eprintln!("[app] Warning: SQLite init failed: {} — recording disabled", e),
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // Subscriber commands
            commands::init_subscriber,
            commands::poll_data,
            commands::reset,
            commands::get_frame_detail,
            commands::set_phasor_mode,
            // CSV phasor logger commands
            commands::csv_start,
            commands::csv_stop,
            commands::csv_status,
            // Capture commands
            commands::list_interfaces,
            commands::capture_open,
            commands::capture_start,
            commands::capture_stop,
            commands::capture_close,
            commands::get_capture_stats,
            commands::get_timestamp_info,
            // Database commands
            commands::db_start_session,
            commands::db_end_session,
            commands::db_list_sessions,
            commands::db_get_session_frames,
            commands::db_delete_session,
            commands::db_get_info,
            commands::db_export_pcap,
        ])
        .run(tauri::generate_context!())
        .expect("error while running SV Subscriber application");
}
