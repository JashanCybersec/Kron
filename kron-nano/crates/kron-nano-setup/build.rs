// build.rs — kron-nano-setup
//
// Two jobs:
//  1. Copy the kron-nano binary into OUT_DIR so main.rs can include_bytes! it.
//     On Windows CI: set KRON_NANO_BIN to the compiled kron-nano.exe path.
//     On dev / non-Windows: creates a zero-byte placeholder so compilation succeeds.
//  2. Embed the UAC elevation manifest into the .exe (Windows only).

use std::{env, fs, path::PathBuf};

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let embedded_dst = out_dir.join("kron-nano-embedded.exe");

    // ── Locate source binary ────────────────────────────────────────────────
    let bin_src = env::var("KRON_NANO_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            // Fallback: workspace target/release relative to this manifest
            let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
            manifest
                .join("..")   // crates/
                .join("..")   // kron-nano/
                .join("target")
                .join("release")
                .join("kron-nano.exe")
        });

    if bin_src.exists() {
        fs::copy(&bin_src, &embedded_dst).expect("Failed to copy kron-nano binary");
        println!("cargo:warning=Embedding kron-nano from {}", bin_src.display());
    } else {
        // Placeholder: installer will abort with a clear message if this ships
        fs::write(&embedded_dst, b"PLACEHOLDER__REBUILD_WITH_KRON_NANO_BIN").unwrap();
        println!(
            "cargo:warning=kron-nano binary not found at {}. \
             Set KRON_NANO_BIN env var or build kron-nano first.",
            bin_src.display()
        );
    }

    println!("cargo:rustc-env=KRON_NANO_EMBEDDED={}", embedded_dst.display());
    println!("cargo:rerun-if-env-changed=KRON_NANO_BIN");
    println!("cargo:rerun-if-changed={}", bin_src.display());

    // ── Embed Windows manifest (UAC + compatibility) — Windows builds only ──
    #[cfg(target_os = "windows")]
    {
        let mut res = winres::WindowsResource::new();
        res.set_manifest_file("setup.manifest");
        // Optional: set icon  →  res.set_icon("assets/kron.ico");
        res.compile().expect("Failed to compile Windows resources");
    }
}
