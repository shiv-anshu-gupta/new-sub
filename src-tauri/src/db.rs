//! SQLite persistent storage for SV capture sessions and frame data
//!
//! Stores decoded SV frames alongside the in-memory display pipeline.
//! The live data path (SPSC ring → display buffer → poll_data) is untouched.
//! SQLite runs as a parallel persistence layer:
//!
//! ```text
//! Drain Thread → Display Buffer → poll_data() → Caller (existing, unchanged)
//!                                      │
//!                                      └──► SQLite (when recording)
//!                                            ├── sessions table (metadata)
//!                                            └── frames table (decoded data)
//! ```
//!
//! Design constraints:
//!   - ZERO overhead on poll_data when recording is off (atomic bool check)
//!   - Batch inserts in transactions (500 frames/batch) for write throughput
//!   - WAL mode for non-blocking reads during writes
//!   - Non-fatal: DB failures don't crash the capture pipeline
//!
//! Data stored per frame (from poll_data lean JSON):
//!   frame_index, svID, smpCnt, channelCount, channels (JSON), errors,
//!   analysis flags/expected/actual/gap/missing range
//!
//! Thread safety:
//!   - Global Mutex<Database> for all DB operations
//!   - AtomicBool RECORDING flag for zero-cost is_recording() check

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

use rusqlite::{params, Connection};
use serde::Deserialize;
use serde_json::Value;

// ============================================================================
// Global State
// ============================================================================

/// Global database instance — initialized once at app startup via setup hook.
/// Protected by Mutex for thread-safe access from Tauri command handlers.
static DB: OnceLock<Mutex<Database>> = OnceLock::new();

/// Fast recording flag — checked by poll_data on every call.
/// AtomicBool load is ~1 CPU cycle vs Mutex lock (~50ns). When recording is off,
/// poll_data has zero SQLite overhead.
static RECORDING: AtomicBool = AtomicBool::new(false);

// ============================================================================
// Types
// ============================================================================

/// SQLite database wrapper with session state and batch buffer.
pub struct Database {
    conn: Connection,

    /// Active session ID (Some when recording, None when idle)
    active_session_id: Option<i64>,

    /// Pending frames accumulated between flushes
    pending_frames: Vec<Value>,

    /// Number of frames to accumulate before flushing to SQLite
    batch_size: usize,

    /// Path to the SQLite database file (for info/diagnostics)
    db_path: PathBuf,
}

/// Configuration for a new capture session — sent on capture start.
/// Field names map to camelCase in JavaScript (via serde rename).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionConfig {
    /// Stream ID being captured (e.g., "MU01")
    pub sv_id: String,
    /// Maximum smpCnt before wrap (e.g., 3999 for 4000 Hz)
    pub smp_cnt_max: u16,
    /// Network interface name
    pub interface_name: String,
    /// 'continuous' or 'timed'
    pub capture_mode: String,
    /// Configured duration in seconds (for timed mode)
    pub duration_sec: u32,
    /// 'none', 'count', or 'infinite'
    pub repeat_mode: String,
    /// Number of repeats (for count mode)
    pub repeat_count: u32,
}

/// Summary data sent when capture stops.
/// Used to finalize the session record with actual results.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionSummary {
    /// Total frames received (from C++ analysis.totalFrames)
    pub frame_count: u64,
    /// Total duration in ms (wall clock from first packet to stop)
    pub duration_ms: u64,
    /// Active data time in ms (excludes stall periods)
    pub data_time_ms: u64,
    /// Average frame rate (frames per second)
    pub avg_frame_rate: f64,
    /// Analysis: missing sequence count
    pub missing_count: u64,
    /// Analysis: out-of-order count
    pub ooo_count: u64,
    /// Analysis: duplicate smpCnt count
    pub duplicate_count: u64,
    /// Analysis: decode error count
    pub error_count: u64,
}

// ============================================================================
// Schema
// ============================================================================

const SCHEMA_SQL: &str = "
    CREATE TABLE IF NOT EXISTS sessions (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        start_time_ms   INTEGER NOT NULL,
        end_time_ms     INTEGER DEFAULT 0,
        duration_ms     INTEGER DEFAULT 0,
        data_time_ms    INTEGER DEFAULT 0,
        frame_count     INTEGER DEFAULT 0,
        stored_frames   INTEGER DEFAULT 0,
        avg_frame_rate  REAL DEFAULT 0,
        sv_id           TEXT NOT NULL DEFAULT '',
        smp_cnt_max     INTEGER DEFAULT 0,
        interface_name  TEXT DEFAULT '',
        capture_mode    TEXT DEFAULT 'continuous',
        duration_config INTEGER DEFAULT 0,
        repeat_mode     TEXT DEFAULT 'none',
        repeat_count    INTEGER DEFAULT 0,
        missing_count   INTEGER DEFAULT 0,
        ooo_count       INTEGER DEFAULT 0,
        duplicate_count INTEGER DEFAULT 0,
        error_count     INTEGER DEFAULT 0,
        notes           TEXT DEFAULT ''
    );

    CREATE TABLE IF NOT EXISTS frames (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id      INTEGER NOT NULL,
        frame_index     INTEGER NOT NULL,
        sv_id           TEXT DEFAULT '',
        smp_cnt         INTEGER NOT NULL,
        channel_count   INTEGER DEFAULT 0,
        channels_json   TEXT DEFAULT '[]',
        errors          INTEGER DEFAULT 0,
        error_str       TEXT DEFAULT '',
        analysis_flags  INTEGER DEFAULT 0,
        expected_smp    INTEGER DEFAULT 0,
        actual_smp      INTEGER DEFAULT 0,
        gap_size        INTEGER DEFAULT 0,
        missing_from    INTEGER DEFAULT 0,
        missing_to      INTEGER DEFAULT 0,
        FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_frames_session
        ON frames(session_id);
    CREATE INDEX IF NOT EXISTS idx_frames_session_index
        ON frames(session_id, frame_index);
    CREATE INDEX IF NOT EXISTS idx_frames_analysis
        ON frames(session_id, analysis_flags)
        WHERE analysis_flags != 0;
";

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the global database at the given path.
/// Called once from the Tauri setup hook. Creates tables if they don't exist.
///
/// # Errors
/// Returns Err if SQLite connection or schema creation fails.
pub fn initialize(path: PathBuf) -> Result<(), String> {
    let conn =
        Connection::open(&path).map_err(|e| format!("SQLite open '{}' failed: {}", path.display(), e))?;

    // Performance pragmas — WAL mode allows concurrent readers during writes
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous  = NORMAL;
         PRAGMA cache_size   = -8000;
         PRAGMA temp_store   = MEMORY;
         PRAGMA foreign_keys = ON;",
    )
    .map_err(|e| format!("SQLite pragma setup failed: {}", e))?;

    // Create schema (idempotent — IF NOT EXISTS on everything)
    conn.execute_batch(SCHEMA_SQL)
        .map_err(|e| format!("SQLite schema creation failed: {}", e))?;

    let db = Database {
        conn,
        active_session_id: None,
        pending_frames: Vec::with_capacity(500),
        batch_size: 500,
        db_path: path.clone(),
    };

    DB.set(Mutex::new(db))
        .map_err(|_| "Database already initialized".to_string())?;

    println!("[db] SQLite initialized at {}", path.display());
    Ok(())
}

// ============================================================================
// Fast Recording Check (used by poll_data hot path)
// ============================================================================

/// Check if recording is active. Single atomic load — zero overhead.
/// Called by `poll_data` on every poll cycle.
#[inline]
pub fn is_recording() -> bool {
    RECORDING.load(Ordering::Relaxed)
}

// ============================================================================
// Session Management
// ============================================================================

/// Start a new capture session and begin recording frames.
/// Creates a session row and sets the RECORDING flag.
pub fn start_session(config: SessionConfig) -> Result<i64, String> {
    with_db(|db| {
        // Flush any leftover frames from a previous interrupted session
        let _ = db.flush_pending();

        let now = now_ms();

        db.conn
            .execute(
                "INSERT INTO sessions (
                    start_time_ms, sv_id, smp_cnt_max, interface_name,
                    capture_mode, duration_config, repeat_mode, repeat_count
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    now,
                    config.sv_id,
                    config.smp_cnt_max,
                    config.interface_name,
                    config.capture_mode,
                    config.duration_sec,
                    config.repeat_mode,
                    config.repeat_count,
                ],
            )
            .map_err(|e| format!("Failed to create session: {}", e))?;

        let session_id = db.conn.last_insert_rowid();
        db.active_session_id = Some(session_id);
        db.pending_frames.clear();

        // Enable recording — poll_data will start storing frames
        RECORDING.store(true, Ordering::Release);

        println!(
            "[db] Session #{} started — recording enabled (svID='{}', interface='{}')",
            session_id, config.sv_id, config.interface_name
        );

        Ok(session_id)
    })
}

/// End the active capture session. Flushes pending frames, updates session
/// row with summary statistics, and disables recording.
pub fn end_session(session_id: i64, summary: SessionSummary) -> Result<(), String> {
    // Disable recording FIRST — stops new frames from entering the pipeline
    RECORDING.store(false, Ordering::Release);

    with_db(|db| {
        // Flush any remaining buffered frames
        let _ = db.flush_pending();

        let now = now_ms();

        // Count actual stored frames for this session
        let stored_frames: i64 = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM frames WHERE session_id = ?1",
                params![session_id],
                |row| row.get(0),
            )
            .unwrap_or(0);

        // Update session with summary data
        db.conn
            .execute(
                "UPDATE sessions SET
                    end_time_ms     = ?1,
                    duration_ms     = ?2,
                    data_time_ms    = ?3,
                    frame_count     = ?4,
                    stored_frames   = ?5,
                    avg_frame_rate  = ?6,
                    missing_count   = ?7,
                    ooo_count       = ?8,
                    duplicate_count = ?9,
                    error_count     = ?10
                 WHERE id = ?11",
                params![
                    now,
                    summary.duration_ms,
                    summary.data_time_ms,
                    summary.frame_count,
                    stored_frames,
                    summary.avg_frame_rate,
                    summary.missing_count,
                    summary.ooo_count,
                    summary.duplicate_count,
                    summary.error_count,
                    session_id,
                ],
            )
            .map_err(|e| format!("Failed to update session: {}", e))?;

        db.active_session_id = None;

        println!(
            "[db] Session #{} ended — {} frames stored ({} total received)",
            session_id, stored_frames, summary.frame_count
        );

        Ok(())
    })
}

// ============================================================================
// Frame Storage (called from poll_data when recording)
// ============================================================================

/// Store frames from a poll_data response into the batch buffer.
/// Automatically flushes to SQLite when the batch is full.
///
/// This is called from `poll_data` on every poll cycle when recording is active.
/// The frames are the lean JSON objects from C++:
/// ```json
/// { "index": 42, "svID": "MU01", "smpCnt": 1234, "channelCount": 8,
///   "channels": [...], "errors": 0, "errorStr": "",
///   "analysis": { "flags": 0, "expected": 1234, ... } }
/// ```
pub fn store_poll_frames(frames: &[Value]) {
    // Try to acquire lock — if contended, skip this batch (non-blocking)
    let db_lock = match DB.get() {
        Some(db) => db,
        None => return,
    };
    let mut db = match db_lock.try_lock() {
        Ok(guard) => guard,
        Err(_) => return, // Lock contended — skip, don't block poll_data
    };

    if db.active_session_id.is_none() {
        return;
    }

    for frame in frames {
        db.pending_frames.push(frame.clone());
    }

    // Flush when batch is full
    if db.pending_frames.len() >= db.batch_size {
        if let Err(e) = db.flush_pending() {
            eprintln!("[db] Frame flush error: {}", e);
        }
    }
}

// ============================================================================
// Query: List Sessions
// ============================================================================

/// List all capture sessions, newest first.
/// Returns a JSON array of session objects (without frame data).
pub fn list_sessions() -> Result<Value, String> {
    with_db(|db| {
        let mut stmt = db
            .conn
            .prepare(
                "SELECT id, start_time_ms, end_time_ms, duration_ms, data_time_ms,
                        frame_count, stored_frames, avg_frame_rate,
                        sv_id, smp_cnt_max, interface_name,
                        capture_mode, duration_config, repeat_mode, repeat_count,
                        missing_count, ooo_count, duplicate_count, error_count, notes
                 FROM sessions
                 ORDER BY id DESC",
            )
            .map_err(|e| format!("Query prepare failed: {}", e))?;

        let rows = stmt
            .query_map([], |row| {
                Ok(serde_json::json!({
                    "id":             row.get::<_, i64>(0)?,
                    "startTimeMs":    row.get::<_, i64>(1)?,
                    "endTimeMs":      row.get::<_, i64>(2)?,
                    "durationMs":     row.get::<_, i64>(3)?,
                    "dataTimeMs":     row.get::<_, i64>(4)?,
                    "frameCount":     row.get::<_, i64>(5)?,
                    "storedFrames":   row.get::<_, i64>(6)?,
                    "avgFrameRate":   row.get::<_, f64>(7)?,
                    "svId":           row.get::<_, String>(8)?,
                    "smpCntMax":      row.get::<_, i64>(9)?,
                    "interfaceName":  row.get::<_, String>(10)?,
                    "captureMode":    row.get::<_, String>(11)?,
                    "durationConfig": row.get::<_, i64>(12)?,
                    "repeatMode":     row.get::<_, String>(13)?,
                    "repeatCount":    row.get::<_, i64>(14)?,
                    "missingCount":   row.get::<_, i64>(15)?,
                    "oooCount":       row.get::<_, i64>(16)?,
                    "duplicateCount": row.get::<_, i64>(17)?,
                    "errorCount":     row.get::<_, i64>(18)?,
                    "notes":          row.get::<_, String>(19)?,
                }))
            })
            .map_err(|e| format!("Query execution failed: {}", e))?;

        let mut sessions = Vec::new();
        for row in rows {
            match row {
                Ok(val) => sessions.push(val),
                Err(e) => eprintln!("[db] Row read error: {}", e),
            }
        }

        Ok(serde_json::json!({ "sessions": sessions }))
    })
}

// ============================================================================
// Query: Session Frames (paginated)
// ============================================================================

/// Get frames for a session with pagination.
/// Returns up to `limit` frames starting from `offset`, ordered by frame_index.
pub fn get_session_frames(session_id: i64, limit: u32, offset: u32) -> Result<Value, String> {
    with_db(|db| {
        // Get total frame count for this session
        let total: i64 = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM frames WHERE session_id = ?1",
                params![session_id],
                |row| row.get(0),
            )
            .unwrap_or(0);

        let mut stmt = db
            .conn
            .prepare(
                "SELECT frame_index, sv_id, smp_cnt, channel_count, channels_json,
                        errors, error_str, analysis_flags, expected_smp, actual_smp,
                        gap_size, missing_from, missing_to
                 FROM frames
                 WHERE session_id = ?1
                 ORDER BY frame_index ASC
                 LIMIT ?2 OFFSET ?3",
            )
            .map_err(|e| format!("Query prepare failed: {}", e))?;

        let rows = stmt
            .query_map(params![session_id, limit, offset], |row| {
                // Parse channels_json back to array
                let channels_str: String = row.get(4)?;
                let channels: Value =
                    serde_json::from_str(&channels_str).unwrap_or(Value::Array(vec![]));

                Ok(serde_json::json!({
                    "index":        row.get::<_, i64>(0)?,
                    "svID":         row.get::<_, String>(1)?,
                    "smpCnt":       row.get::<_, i64>(2)?,
                    "channelCount": row.get::<_, i64>(3)?,
                    "channels":     channels,
                    "errors":       row.get::<_, i64>(5)?,
                    "errorStr":     row.get::<_, String>(6)?,
                    "analysis": {
                        "flags":       row.get::<_, i64>(7)?,
                        "expected":    row.get::<_, i64>(8)?,
                        "actual":      row.get::<_, i64>(9)?,
                        "gapSize":     row.get::<_, i64>(10)?,
                        "missingFrom": row.get::<_, i64>(11)?,
                        "missingTo":   row.get::<_, i64>(12)?,
                    }
                }))
            })
            .map_err(|e| format!("Query execution failed: {}", e))?;

        let mut frames = Vec::new();
        for row in rows {
            match row {
                Ok(val) => frames.push(val),
                Err(e) => eprintln!("[db] Frame row error: {}", e),
            }
        }

        Ok(serde_json::json!({
            "sessionId": session_id,
            "total": total,
            "limit": limit,
            "offset": offset,
            "frames": frames,
        }))
    })
}

// ============================================================================
// Delete Session
// ============================================================================

/// Delete a session and all its frames (CASCADE via foreign key).
pub fn delete_session(session_id: i64) -> Result<(), String> {
    with_db(|db| {
        // Delete frames first (in case foreign key cascade isn't working)
        db.conn
            .execute(
                "DELETE FROM frames WHERE session_id = ?1",
                params![session_id],
            )
            .map_err(|e| format!("Failed to delete frames: {}", e))?;

        let changes = db
            .conn
            .execute(
                "DELETE FROM sessions WHERE id = ?1",
                params![session_id],
            )
            .map_err(|e| format!("Failed to delete session: {}", e))?;

        if changes == 0 {
            return Err(format!("Session {} not found", session_id));
        }

        // Reclaim disk space
        let _ = db.conn.execute_batch("PRAGMA incremental_vacuum;");

        println!("[db] Session #{} deleted", session_id);
        Ok(())
    })
}

// ============================================================================
// Database Info / Diagnostics
// ============================================================================

/// Get database information: path, file size, total sessions, total frames.
pub fn get_db_info() -> Result<Value, String> {
    with_db(|db| {
        let total_sessions: i64 = db
            .conn
            .query_row("SELECT COUNT(*) FROM sessions", [], |row| row.get(0))
            .unwrap_or(0);

        let total_frames: i64 = db
            .conn
            .query_row("SELECT COUNT(*) FROM frames", [], |row| row.get(0))
            .unwrap_or(0);

        // Get file size
        let file_size = std::fs::metadata(&db.db_path)
            .map(|m| m.len())
            .unwrap_or(0);

        let is_recording = RECORDING.load(Ordering::Relaxed);
        let active_session = db.active_session_id;

        Ok(serde_json::json!({
            "dbPath":          db.db_path.to_string_lossy(),
            "fileSizeBytes":   file_size,
            "fileSizeMB":      format!("{:.2}", file_size as f64 / (1024.0 * 1024.0)),
            "totalSessions":   total_sessions,
            "totalFrames":     total_frames,
            "isRecording":     is_recording,
            "activeSessionId": active_session,
        }))
    })
}

// ============================================================================
// Internal: Database impl
// ============================================================================

impl Database {
    /// Flush all pending frames to SQLite in a single transaction.
    /// Uses prepared statement caching for maximum insert throughput.
    fn flush_pending(&mut self) -> Result<(), String> {
        if self.pending_frames.is_empty() {
            return Ok(());
        }

        let session_id = match self.active_session_id {
            Some(id) => id,
            None => {
                self.pending_frames.clear();
                return Ok(());
            }
        };

        let frame_count = self.pending_frames.len();

        // Use a transaction for batch insert — orders of magnitude faster
        // than individual inserts (SQLite commits per-statement without tx)
        let tx = self
            .conn
            .transaction()
            .map_err(|e| format!("Transaction begin failed: {}", e))?;

        {
            let mut stmt = tx
                .prepare_cached(
                    "INSERT INTO frames (
                        session_id, frame_index, sv_id, smp_cnt, channel_count,
                        channels_json, errors, error_str,
                        analysis_flags, expected_smp, actual_smp,
                        gap_size, missing_from, missing_to
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                )
                .map_err(|e| format!("Prepare insert failed: {}", e))?;

            for frame in &self.pending_frames {
                let analysis = &frame["analysis"];

                // Serialize channels array to JSON string
                let channels_json = frame["channels"].to_string();

                stmt.execute(params![
                    session_id,
                    frame["index"].as_i64().unwrap_or(0),
                    frame["svID"].as_str().unwrap_or(""),
                    frame["smpCnt"].as_i64().unwrap_or(0),
                    frame["channelCount"].as_i64().unwrap_or(0),
                    channels_json,
                    frame["errors"].as_i64().unwrap_or(0),
                    frame["errorStr"].as_str().unwrap_or(""),
                    analysis["flags"].as_i64().unwrap_or(0),
                    analysis["expected"].as_i64().unwrap_or(0),
                    analysis["actual"].as_i64().unwrap_or(0),
                    analysis["gapSize"].as_i64().unwrap_or(0),
                    analysis["missingFrom"].as_i64().unwrap_or(0),
                    analysis["missingTo"].as_i64().unwrap_or(0),
                ])
                .map_err(|e| format!("Frame insert failed: {}", e))?;
            }
        } // stmt dropped here — releases borrow on tx

        tx.commit()
            .map_err(|e| format!("Transaction commit failed: {}", e))?;

        self.pending_frames.clear();

        // Suppressed: at 4000 fps / batch_size 500, this fired 8×/sec.
        // Session-level stats are already logged at session start/stop.
        Ok(())
    }
}

// ============================================================================
// Internal Helpers
// ============================================================================

/// Execute a closure with mutable access to the global Database.
/// Handles "not initialized" and "lock poisoned" errors gracefully.
fn with_db<F, R>(f: F) -> Result<R, String>
where
    F: FnOnce(&mut Database) -> Result<R, String>,
{
    let db = DB.get().ok_or("Database not initialized")?;
    let mut guard = db
        .lock()
        .map_err(|e| format!("Database lock poisoned: {}", e))?;
    f(&mut *guard)
}

/// Get current time as milliseconds since Unix epoch.
/// Equivalent to JavaScript's Date.now().
fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

// ============================================================================
// PCAP Export — Reconstruct IEC 61850-9-2LE packets from SQLite data
// ============================================================================

/// Export a session's frames as a PCAP file.
///
/// Reconstructs valid SV Ethernet frames from the decoded data stored in SQLite.
/// The PCAP file can be opened in Wireshark for analysis.
///
/// Reconstruction uses reasonable defaults for fields not stored:
///   - Dst MAC: 01:0C:CD:04:00:00 (standard SV multicast)
///   - Src MAC: 00:00:00:00:00:00
///   - APPID: 0x4000
///   - confRev: 1, smpSynch: 0
///   - Quality: 0x00000000 (good) for all channels
///   - Timestamps: synthesized from session start + frame position × sample interval
///
/// Returns the absolute path to the saved .pcap file.
pub fn export_pcap(session_id: i64, output_path: &str) -> Result<String, String> {
    with_db(|db| {
        // Get session metadata for timestamp calculation
        let (start_time_ms, smp_cnt_max, _sv_id): (i64, i64, String) = db
            .conn
            .query_row(
                "SELECT start_time_ms, smp_cnt_max, sv_id FROM sessions WHERE id = ?1",
                params![session_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|e| format!("Session {} not found: {}", session_id, e))?;

        let sample_rate = if smp_cnt_max > 0 { smp_cnt_max + 1 } else { 80 };
        let sample_interval_us: f64 = 1_000_000.0 / sample_rate as f64;

        // Read all frames for this session
        let mut stmt = db
            .conn
            .prepare(
                "SELECT frame_index, sv_id, smp_cnt, channel_count, channels_json
                 FROM frames
                 WHERE session_id = ?1
                 ORDER BY frame_index ASC",
            )
            .map_err(|e| format!("Query prepare failed: {}", e))?;

        struct FrameRow {
            _frame_index: i64,
            sv_id: String,
            smp_cnt: u16,
            channel_count: u8,
            channels: Vec<i32>,
        }

        let rows = stmt
            .query_map(params![session_id], |row| {
                let channels_str: String = row.get(4)?;
                let channels: Vec<i32> = serde_json::from_str(&channels_str).unwrap_or_default();
                Ok(FrameRow {
                    _frame_index: row.get(0)?,
                    sv_id: row.get(1)?,
                    smp_cnt: row.get::<_, i32>(2)? as u16,
                    channel_count: row.get::<_, i32>(3)? as u8,
                    channels,
                })
            })
            .map_err(|e| format!("Query failed: {}", e))?;

        let frames: Vec<FrameRow> = rows.filter_map(|r| r.ok()).collect();

        if frames.is_empty() {
            return Err(format!("No frames found for session {}", session_id));
        }

        // Build PCAP file in memory
        let mut pcap = Vec::with_capacity(frames.len() * 150);

        // ── PCAP Global Header (24 bytes) ──
        pcap.extend_from_slice(&0xA1B2C3D4u32.to_le_bytes()); // magic
        pcap.extend_from_slice(&2u16.to_le_bytes());           // version major
        pcap.extend_from_slice(&4u16.to_le_bytes());           // version minor
        pcap.extend_from_slice(&0i32.to_le_bytes());           // thiszone
        pcap.extend_from_slice(&0u32.to_le_bytes());           // sigfigs
        pcap.extend_from_slice(&65535u32.to_le_bytes());       // snaplen
        pcap.extend_from_slice(&1u32.to_le_bytes());           // network (LINKTYPE_ETHERNET)

        // Base timestamp from session start
        let base_ts_sec = start_time_ms / 1000;
        let base_ts_usec = (start_time_ms % 1000) * 1000;

        for (i, frame) in frames.iter().enumerate() {
            // Build the SV Ethernet packet for this frame
            let packet = build_sv_packet(
                &frame.sv_id,
                frame.smp_cnt,
                frame.channel_count,
                &frame.channels,
            );

            // Synthesize timestamp: session_start + frame_position × sample_interval
            let offset_us = (i as f64) * sample_interval_us;
            let ts_total_us = (base_ts_sec as f64 * 1_000_000.0)
                + (base_ts_usec as f64)
                + offset_us;
            let ts_sec = (ts_total_us / 1_000_000.0) as u32;
            let ts_usec = (ts_total_us as u64 % 1_000_000) as u32;

            let pkt_len = packet.len() as u32;

            // ── PCAP Packet Record Header (16 bytes) ──
            pcap.extend_from_slice(&ts_sec.to_le_bytes());   // ts_sec
            pcap.extend_from_slice(&ts_usec.to_le_bytes());  // ts_usec
            pcap.extend_from_slice(&pkt_len.to_le_bytes());  // incl_len
            pcap.extend_from_slice(&pkt_len.to_le_bytes());  // orig_len

            // ── Packet data ──
            pcap.extend_from_slice(&packet);
        }

        // Write PCAP file
        let path = if output_path.is_empty() {
            // Default: save next to the database
            let dir = db.db_path.parent().unwrap_or(std::path::Path::new("."));
            let filename = format!("sv_session_{}.pcap", session_id);
            dir.join(filename).to_string_lossy().to_string()
        } else {
            output_path.to_string()
        };

        std::fs::write(&path, &pcap)
            .map_err(|e| format!("Failed to write PCAP file '{}': {}", path, e))?;

        let frame_count = frames.len();
        let file_size_kb = pcap.len() / 1024;
        println!(
            "[db] PCAP exported: session #{}, {} frames, {} KB → {}",
            session_id, frame_count, file_size_kb, path
        );

        Ok(path)
    })
}

/// Build a complete IEC 61850-9-2LE Ethernet frame from decoded data.
///
/// Packet structure:
/// ```text
/// [Ethernet: 14B] [SV Header: 8B] [savPdu: BER-encoded ASDU]
/// ```
fn build_sv_packet(sv_id: &str, smp_cnt: u16, channel_count: u8, channels: &[i32]) -> Vec<u8> {
    let sv_id_bytes = sv_id.as_bytes();
    let ch_count = channel_count as usize;

    // ── Build seqData content: channels × (4B value BE + 4B quality BE) ──
    let seq_data_len = ch_count * 8;
    let mut seq_data = Vec::with_capacity(seq_data_len);
    for i in 0..ch_count {
        let val = if i < channels.len() { channels[i] } else { 0 };
        seq_data.extend_from_slice(&val.to_be_bytes());      // value (big-endian int32)
        seq_data.extend_from_slice(&0u32.to_be_bytes());     // quality (good = 0)
    }

    // ── Build ASDU content ──
    let mut asdu_content = Vec::with_capacity(128);

    // svID [0x80]
    asdu_content.push(0x80);
    ber_encode_length(&mut asdu_content, sv_id_bytes.len());
    asdu_content.extend_from_slice(sv_id_bytes);

    // smpCnt [0x82] — 2 bytes big-endian
    asdu_content.push(0x82);
    asdu_content.push(0x02);
    asdu_content.extend_from_slice(&smp_cnt.to_be_bytes());

    // confRev [0x83] — 4 bytes big-endian (default: 1)
    asdu_content.push(0x83);
    asdu_content.push(0x04);
    asdu_content.extend_from_slice(&1u32.to_be_bytes());

    // smpSynch [0x85] — 1 byte (default: 0 = not synchronized)
    asdu_content.push(0x85);
    asdu_content.push(0x01);
    asdu_content.push(0x00);

    // seqData [0x87]
    asdu_content.push(0x87);
    ber_encode_length(&mut asdu_content, seq_data.len());
    asdu_content.extend_from_slice(&seq_data);

    // ── Build ASDU TLV [0x30] ──
    let mut asdu_tlv = Vec::with_capacity(asdu_content.len() + 4);
    asdu_tlv.push(0x30);
    ber_encode_length(&mut asdu_tlv, asdu_content.len());
    asdu_tlv.extend_from_slice(&asdu_content);

    // ── Build seqASDU TLV [0xA2] ──
    let mut seq_asdu_tlv = Vec::with_capacity(asdu_tlv.len() + 4);
    seq_asdu_tlv.push(0xA2);
    ber_encode_length(&mut seq_asdu_tlv, asdu_tlv.len());
    seq_asdu_tlv.extend_from_slice(&asdu_tlv);

    // ── Build savPdu content: noASDU + seqASDU ──
    let mut sav_pdu_content = Vec::with_capacity(seq_asdu_tlv.len() + 4);
    // noASDU [0x80] = 1
    sav_pdu_content.push(0x80);
    sav_pdu_content.push(0x01);
    sav_pdu_content.push(0x01);
    sav_pdu_content.extend_from_slice(&seq_asdu_tlv);

    // ── Build savPdu TLV [0x60] ──
    let mut sav_pdu = Vec::with_capacity(sav_pdu_content.len() + 4);
    sav_pdu.push(0x60);
    ber_encode_length(&mut sav_pdu, sav_pdu_content.len());
    sav_pdu.extend_from_slice(&sav_pdu_content);

    // ── SV Header (8 bytes) ──
    let sv_length = (8 + sav_pdu.len()) as u16; // APPID to end
    let mut sv_header = Vec::with_capacity(8);
    sv_header.extend_from_slice(&0x4000u16.to_be_bytes()); // APPID
    sv_header.extend_from_slice(&sv_length.to_be_bytes());  // Length
    sv_header.extend_from_slice(&0u16.to_be_bytes());       // Reserved1
    sv_header.extend_from_slice(&0u16.to_be_bytes());       // Reserved2

    // ── Ethernet Header (14 bytes) ──
    let total_len = 14 + 8 + sav_pdu.len();
    let mut packet = Vec::with_capacity(total_len);

    // Dst MAC: 01:0C:CD:04:00:00 (IEC 61850 SV multicast)
    packet.extend_from_slice(&[0x01, 0x0C, 0xCD, 0x04, 0x00, 0x00]);
    // Src MAC: 00:00:00:00:00:00 (placeholder)
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    // EtherType: 0x88BA (SV)
    packet.extend_from_slice(&0x88BAu16.to_be_bytes());

    // SV Header + savPdu
    packet.extend_from_slice(&sv_header);
    packet.extend_from_slice(&sav_pdu);

    packet
}

/// Encode a BER length field.
/// - length < 128: 1 byte (short form)
/// - 128..255: 2 bytes (0x81, length)
/// - 256..65535: 3 bytes (0x82, high, low)
fn ber_encode_length(buf: &mut Vec<u8>, length: usize) {
    if length < 128 {
        buf.push(length as u8);
    } else if length < 256 {
        buf.push(0x81);
        buf.push(length as u8);
    } else {
        buf.push(0x82);
        buf.push((length >> 8) as u8);
        buf.push((length & 0xFF) as u8);
    }
}
