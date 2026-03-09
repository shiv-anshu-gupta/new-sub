//! SV Subscriber — Tauri Service Application
//!
//! Architecture:
//!   Service API → Tauri invoke() → Rust commands → C++ FFI → JSON
//!
//! All heavy processing (SV decoding, analysis, Npcap capture) runs in C++.
//! Rust is a thin bridge.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    sv_subscriber_app::run();
}
