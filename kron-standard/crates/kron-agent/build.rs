//! Build script for kron-agent.
//!
//! On Linux, compiles the three eBPF C programs in `bpf/` using clang and
//! links them into a single ELF object `kron_agent.bpf.o` placed in `OUT_DIR`.
//! The userspace loader includes this object via `include_bytes_aligned!`.
//!
//! On non-Linux hosts (Windows, macOS), the eBPF compilation step is skipped
//! entirely. The eBPF module is cfg-gated so the binary still compiles and
//! can be used for testing non-eBPF code paths.
//!
//! # Requirements (Linux CI)
//!
//! - `clang` ≥ 12 on PATH
//! - `llvm-strip` (optional — strips debug sections to reduce binary size)
//! - `/sys/kernel/btf/vmlinux` readable (for CO-RE BTF)
//!
//! # Build flow
//!
//! 1. Each `.bpf.c` file is compiled separately to `.bpf.o`.
//! 2. The three `.bpf.o` files are linked with `llvm-link` into one combined
//!    `kron_agent.bpf.o`.
//! 3. `llvm-strip` removes DWARF debug sections (reduces binary size, optional).

#[cfg(target_os = "linux")]
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::process::Command;

fn main() {
    // Tell Cargo to re-run this script only when the bpf/ directory changes.
    println!("cargo:rerun-if-changed=bpf/");
    println!("cargo:rerun-if-changed=build.rs");

    // eBPF compilation is Linux-only.
    #[cfg(target_os = "linux")]
    compile_ebpf_programs();
}

#[cfg(target_os = "linux")]
fn compile_ebpf_programs() {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR must be set by Cargo"));
    let bpf_dir = PathBuf::from("bpf");

    let programs = ["process_create", "network_connect", "file_access"];

    // Check that clang is available.
    if !command_exists("clang") {
        panic!(
            "clang not found on PATH. Install LLVM (apt: clang-14, or brew install llvm) \
            to compile eBPF programs.\n\
            On Ubuntu 22.04: sudo apt-get install -y clang llvm"
        );
    }

    let mut object_files: Vec<PathBuf> = Vec::new();

    for prog in &programs {
        let src = bpf_dir.join(format!("{prog}.bpf.c"));
        let obj = out_dir.join(format!("{prog}.bpf.o"));

        let status = Command::new("clang")
            // Target eBPF.
            .args(["-target", "bpf"])
            // Optimise for size.
            .arg("-O2")
            // CO-RE: debug info required for BTF.
            .arg("-g")
            // Suppress non-portable inline warning.
            .arg("-D__TARGET_ARCH_x86")
            // Include the bpf/ directory for headers.
            .arg(format!("-I{}", bpf_dir.display()))
            // System bpf headers (libbpf-dev on Ubuntu).
            .args(["-I", "/usr/include/bpf"])
            .args(["-I", "/usr/local/include/bpf"])
            // Only output an object file (no link).
            .arg("-c")
            .arg(&src)
            .arg("-o")
            .arg(&obj)
            .status()
            .unwrap_or_else(|e| panic!("Failed to run clang: {e}"));

        if !status.success() {
            panic!(
                "clang failed to compile {}. Exit code: {:?}",
                src.display(),
                status.code()
            );
        }

        object_files.push(obj);
    }

    // Link the three object files into one combined eBPF ELF.
    let combined = out_dir.join("kron_agent.bpf.o");

    if command_exists("llvm-link") {
        let mut cmd = Command::new("llvm-link");
        for obj in &object_files {
            cmd.arg(obj);
        }
        cmd.arg("-o").arg(&combined);
        let status = cmd.status().expect("llvm-link failed to start");
        if !status.success() {
            panic!("llvm-link failed with exit code {:?}", status.code());
        }
    } else {
        // Fallback: use the first object file if llvm-link is not available.
        // This only works correctly if there is a single source; in practice
        // all three programs share one ring buffer map so they must be linked.
        // Emit a build warning instead of panicking so CI can report it clearly.
        eprintln!(
            "cargo:warning=llvm-link not found; using process_create.bpf.o only. \
            Install llvm-link for full multi-program eBPF support."
        );
        std::fs::copy(&object_files[0], &combined).expect("cannot copy eBPF object as fallback");
    }

    // Strip debug sections to reduce binary size (optional).
    if command_exists("llvm-strip") {
        let _ = Command::new("llvm-strip")
            .args(["-g", combined.to_str().expect("valid path")])
            .status();
    }

    println!("cargo:rustc-env=KRON_EBPF_OBJ={}", combined.display());
}

/// Returns `true` if the given command exists on PATH.
#[cfg(target_os = "linux")]
fn command_exists(cmd: &str) -> bool {
    Command::new("which")
        .arg(cmd)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
