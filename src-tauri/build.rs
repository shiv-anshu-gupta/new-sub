//! Build script for SV Subscriber Tauri app
//!
//! Compiles the C++ native library (sv_subscriber_static) and links it
//! into the Rust binary so Tauri commands can call C++ functions via FFI.
//!
//! Intel MKL is used for hardware-accelerated FFT in phasor computation.
//!
//! Platform paths:
//!   Windows: C:\Program Files (x86)\Intel\oneAPI\mkl\latest
//!   Linux:   /opt/intel/oneapi/mkl/latest

fn main() {
    // --- Tauri build ---
    tauri_build::build();

    // --- Intel MKL paths (platform-aware) ---
    #[cfg(target_os = "windows")]
    let mkl_root = r"C:\Program Files (x86)\Intel\oneAPI\mkl\latest".to_string();

    #[cfg(target_os = "linux")]
    let mkl_root = std::env::var("MKLROOT")
        .unwrap_or_else(|_| "/opt/intel/oneapi/mkl/latest".to_string());

    let mkl_include = format!("{}/include", mkl_root);

    #[cfg(target_os = "windows")]
    let mkl_lib = format!(r"{}\lib", mkl_root);

    #[cfg(target_os = "linux")]
    let mkl_lib = format!("{}/lib/intel64", mkl_root);

    // Verify MKL is installed
    let mkl_header = std::path::Path::new(&mkl_include).join("mkl_dfti.h");
    if !mkl_header.exists() {
        panic!(
            "Intel MKL not found at {}.\n\
             On Linux:   sudo apt install intel-oneapi-mkl-devel  (after adding Intel repo)\n\
             On Windows: Install Intel oneAPI Base Toolkit (MKL component)\n\
             Download:   https://www.intel.com/content/www/us/en/developer/tools/oneapi/base-toolkit-download.html",
            mkl_root
        );
    }

    // --- Compile C++ native library ---
    let native_dir = std::path::Path::new("../native");

    cc::Build::new()
        .cpp(true)
        .std("c++17")
        .include(native_dir.join("include"))
        .include(&mkl_include)                              // MKL headers (mkl_dfti.h)
        .file(native_dir.join("src/asn1_ber_decoder.cc"))
        .file(native_dir.join("src/sv_decoder_impl.cc"))
        .file(native_dir.join("src/sv_subscriber.cc"))
        .file(native_dir.join("src/sv_capture_impl.cc"))
        .file(native_dir.join("src/sv_highperf.cc"))
        .file(native_dir.join("src/sv_phasor.cc"))          // Phasor computation (MKL FFT)
        .file(native_dir.join("src/sv_phasor_csv.cc"))      // Dual-mode phasor CSV logger
        .define("_CRT_SECURE_NO_WARNINGS", None)
        .warnings(false)
        .opt_level(3)     // Max optimization for hot-path decode + FFT
        .compile("sv_native");

    // --- Link Intel MKL libraries (sequential, single-threaded) ---
    // Using lp64 interface (32-bit int indices — standard for most use cases)
    // Sequential threading (no OpenMP dependency — simpler, sufficient for our FFT sizes)
    #[cfg(target_os = "windows")]
    {
        println!("cargo:rustc-link-search=native={}", mkl_lib);
        println!("cargo:rustc-link-lib=mkl_intel_lp64");
        println!("cargo:rustc-link-lib=mkl_sequential");
        println!("cargo:rustc-link-lib=mkl_core");
    }

    #[cfg(target_os = "linux")]
    {
        println!("cargo:rustc-link-search=native={}", mkl_lib);
        println!("cargo:rustc-link-lib=static=mkl_intel_lp64");
        println!("cargo:rustc-link-lib=static=mkl_sequential");
        println!("cargo:rustc-link-lib=static=mkl_core");
        println!("cargo:rustc-link-lib=pthread");
        println!("cargo:rustc-link-lib=m");
        println!("cargo:rustc-link-lib=dl");
    }

    // --- Link platform system libraries ---
    #[cfg(target_os = "windows")]
    {
        println!("cargo:rustc-link-lib=iphlpapi");
        println!("cargo:rustc-link-lib=ws2_32");
        println!("cargo:rustc-link-lib=psapi");  // GetProcessMemoryInfo for CSV perf logging
    }

    #[cfg(target_os = "linux")]
    {
        println!("cargo:rustc-link-lib=pcap");
    }

    // Rebuild if C++ sources change
    println!("cargo:rerun-if-changed=../native/src/");
    println!("cargo:rerun-if-changed=../native/include/");
}
