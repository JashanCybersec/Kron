// kron-nano-setup — Windows installer
//
// The kron-nano binary is embedded at compile time by build.rs.
// On first run Windows prompts for UAC (requireAdministrator manifest).
// The installer then:
//   1. Extracts kron-nano.exe  →  C:\Program Files\KronNano\
//   2. Creates data directories in C:\ProgramData\KronNano\
//   3. Generates an RSA-2048 JWT key pair (pure Rust, no openssl.exe needed)
//   4. Writes a ready-to-run kron.toml with a default tenant UUID
//   5. Registers KronNano as a Windows Service (auto-start, restart-on-failure)
//   6. Opens inbound firewall rules for all KRON ports
//   7. Starts the service
//   8. Opens http://localhost:8080 in the default browser

#![forbid(unsafe_code)]

// ── Embedded kron-nano binary (injected by build.rs) ────────────────────────
const KRON_NANO_BIN: &[u8] = include_bytes!(env!("KRON_NANO_EMBEDDED"));

fn main() {
    #[cfg(not(target_os = "windows"))]
    {
        eprintln!("kron-nano-setup only runs on Windows.");
        std::process::exit(1);
    }

    #[cfg(target_os = "windows")]
    {
        if let Err(e) = installer::run() {
            eprintln!("\n  [ERROR] {e:#}");
            eprintln!("\n  Press Enter to exit...");
            let _ = std::io::stdin().read_line(&mut String::new());
            std::process::exit(1);
        }
    }
}

// ── All Windows-specific installer logic ─────────────────────────────────────
#[cfg(target_os = "windows")]
mod installer {
    use super::KRON_NANO_BIN;
    use anyhow::{bail, Context, Result};
    use colored::Colorize;
    use rsa::{
        pkcs1::EncodeRsaPrivateKey,
        pkcs8::{EncodePublicKey, LineEnding},
        RsaPrivateKey,
    };
    use std::{
        io::Read,
        path::{Path, PathBuf},
        process::Command,
    };
    use uuid::Uuid;
    use winreg::{enums::*, RegKey};

    // ── Paths ─────────────────────────────────────────────────────────────────
    const INSTALL_DIR: &str = r"C:\Program Files\KronNano";
    const DATA_DIR: &str = r"C:\ProgramData\KronNano";
    const SERVICE_NAME: &str = "KronNano";
    const SERVICE_DISPLAY: &str = "KRON Nano SIEM";
    const SERVICE_DESC: &str =
        "KRON Nano — single-binary SIEM with embedded DuckDB storage.";

    // ── Printer helpers ───────────────────────────────────────────────────────
    fn step(msg: &str) {
        println!("  {}  {}", "▶".cyan().bold(), msg);
    }
    fn ok(msg: &str) {
        println!("  {}  {}", "✓".green().bold(), msg);
    }
    fn warn(msg: &str) {
        println!("  {}  {}", "!".yellow().bold(), msg.yellow());
    }

    // ── Entry point ───────────────────────────────────────────────────────────
    pub fn run() -> Result<()> {
        // Enable ANSI colours on Windows 10+
        colored::control::set_override(true);

        print_banner();
        guard_placeholder()?;

        let install_dir = PathBuf::from(INSTALL_DIR);
        let data_dir = PathBuf::from(DATA_DIR);
        let bin_path = install_dir.join("kron-nano.exe");
        let config_path = data_dir.join("kron.toml");
        let key_path = data_dir.join("jwt.key");
        let pub_path = data_dir.join("jwt.pub");

        stop_existing_service();
        create_directories(&install_dir, &data_dir)?;
        extract_binary(&bin_path)?;
        generate_rsa_keys(&key_path, &pub_path)?;
        let tenant_id = Uuid::new_v4().to_string();
        write_config(&config_path, &data_dir, &key_path, &pub_path, &tenant_id)?;
        add_firewall_rules();
        install_service(&bin_path, &config_path, &data_dir)?;
        set_service_recovery()?;
        start_service()?;
        add_to_path(&install_dir)?;
        print_success(&config_path, &data_dir, &tenant_id);

        // Give the service a moment before opening the browser
        std::thread::sleep(std::time::Duration::from_secs(3));
        let _ = Command::new("cmd")
            .args(["/c", "start", "", "http://localhost:8080"])
            .spawn();

        println!("\n  Press Enter to close this window...");
        let _ = std::io::stdin().read_line(&mut String::new());
        Ok(())
    }

    // ── Sanity-check embedded binary isn't the build placeholder ─────────────
    fn guard_placeholder() -> Result<()> {
        if KRON_NANO_BIN.starts_with(b"PLACEHOLDER") {
            bail!(
                "This installer was built without an embedded kron-nano binary.\n\
                 Build kron-nano first (cargo build --release -p kron-nano),\n\
                 then rebuild kron-nano-setup with KRON_NANO_BIN set."
            );
        }
        Ok(())
    }

    // ── Banner ────────────────────────────────────────────────────────────────
    fn print_banner() {
        println!();
        println!("  {}", "██╗  ██╗██████╗  ██████╗ ███╗   ██╗".bright_cyan());
        println!("  {}", "██║ ██╔╝██╔══██╗██╔═══██╗████╗  ██║".bright_cyan());
        println!("  {}", "█████╔╝ ██████╔╝██║   ██║██╔██╗ ██║".bright_cyan());
        println!("  {}", "██╔═██╗ ██╔══██╗██║   ██║██║╚██╗██║".bright_cyan());
        println!(
            "  {}  {}",
            "██║  ██╗██║  ██║╚██████╔╝██║ ╚████║".bright_cyan(),
            "Nano".white().bold()
        );
        println!("  {}", "╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝".bright_cyan());
        println!();
        println!(
            "  {}",
            "Windows Installer — installing as a Windows Service".white()
        );
        println!("  {}", "─".repeat(56).dark_grey());
        println!();
    }

    // ── Stop + delete existing service if present ─────────────────────────────
    fn stop_existing_service() {
        let status = Command::new("sc.exe")
            .args(["query", SERVICE_NAME])
            .output();
        if status.map(|o| o.status.success()).unwrap_or(false) {
            step("Stopping existing service...");
            let _ = Command::new("sc.exe")
                .args(["stop", SERVICE_NAME])
                .output();
            std::thread::sleep(std::time::Duration::from_secs(2));
            let _ = Command::new("sc.exe")
                .args(["delete", SERVICE_NAME])
                .output();
            std::thread::sleep(std::time::Duration::from_secs(1));
            ok("Existing service removed");
        }
    }

    // ── Create directory layout ───────────────────────────────────────────────
    fn create_directories(install_dir: &Path, data_dir: &Path) -> Result<()> {
        step("Creating directories...");
        let dirs = [
            install_dir.to_path_buf(),
            data_dir.to_path_buf(),
            data_dir.join("data"),
            data_dir.join("bus"),
            data_dir.join("rules"),
            data_dir.join("models"),
            data_dir.join("archive"),
            data_dir.join("migrations"),
            data_dir.join("logs"),
        ];
        for d in &dirs {
            std::fs::create_dir_all(d)
                .with_context(|| format!("create_dir_all({d:?})"))?;
        }
        ok("Directories created");
        Ok(())
    }

    // ── Extract embedded kron-nano.exe ────────────────────────────────────────
    fn extract_binary(bin_path: &Path) -> Result<()> {
        step("Extracting kron-nano.exe...");
        std::fs::write(bin_path, KRON_NANO_BIN)
            .with_context(|| format!("write binary to {bin_path:?}"))?;
        ok(format!("Binary written to {}", bin_path.display()).as_str());
        Ok(())
    }

    // ── RSA-2048 key pair (pure Rust — no openssl.exe required) ──────────────
    fn generate_rsa_keys(key_path: &Path, pub_path: &Path) -> Result<()> {
        if key_path.exists() {
            ok("JWT keys already exist — skipping generation");
            return Ok(());
        }

        step("Generating RSA-2048 JWT key pair...");
        let mut rng = rand::rngs::OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048)
            .context("RSA key generation failed")?;
        let public_key = private_key.to_public_key();

        let private_pem = private_key
            .to_pkcs1_pem(LineEnding::CRLF)
            .context("PKCS#1 private key encoding failed")?;
        let public_pem = public_key
            .to_public_key_pem(LineEnding::CRLF)
            .context("SPKI public key encoding failed")?;

        std::fs::write(key_path, private_pem.as_bytes())
            .with_context(|| format!("write private key to {key_path:?}"))?;
        std::fs::write(pub_path, public_pem.as_bytes())
            .with_context(|| format!("write public key to {pub_path:?}"))?;

        // Restrict private key: remove inheritance, grant only SYSTEM + current user
        restrict_file_acl(key_path);

        ok("RSA-2048 key pair generated");
        Ok(())
    }

    /// Remove "Everyone" read access from the private key via icacls.
    fn restrict_file_acl(path: &Path) {
        let p = path.display().to_string();
        // Remove all inherited permissions, grant SYSTEM and Administrators full control
        let _ = Command::new("icacls")
            .args([&p, "/inheritance:r", "/grant:r", "SYSTEM:(F)", "/grant:r", "Administrators:(F)"])
            .output();
    }

    // ── Write kron.toml ───────────────────────────────────────────────────────
    fn write_config(
        config_path: &Path,
        data_dir: &Path,
        key_path: &Path,
        pub_path: &Path,
        tenant_id: &str,
    ) -> Result<()> {
        if config_path.exists() {
            ok("Existing kron.toml found — skipping");
            return Ok(());
        }

        step("Writing kron.toml...");

        // TOML requires forward slashes or escaped backslashes
        let d  = data_dir.display().to_string().replace('\\', "\\\\");
        let kp = key_path.display().to_string().replace('\\', "\\\\");
        let pp = pub_path.display().to_string().replace('\\', "\\\\");

        let config = format!(
            r#"# KRON Nano — Windows configuration
# Generated by kron-nano-setup on {date}
# Edit this file then restart the service: Restart-Service KronNano

mode = "nano"

[duckdb]
path                        = "{d}\\data\\events.duckdb"
memory_limit_mb             = 2048
threads                     = 4
migrations_dir              = "{d}\\migrations"
cold_archive_dir            = "{d}\\archive"
cold_storage_retention_days = 180
cold_archive_interval_hours = 24

[embedded_bus]
data_dir                    = "{d}\\bus"
max_wal_size_mb             = 512
sync_writes                 = true
max_retry_count             = 3
backpressure_lag_threshold  = 100000

[auth]
jwt_private_key_path        = "{kp}"
jwt_public_key_path         = "{pp}"
jwt_expiry_secs             = 28800
max_failed_attempts         = 5
lockout_duration_secs       = 900

[collector]
grpc_addr                   = "0.0.0.0:50051"
http_addr                   = "0.0.0.0:8081"
syslog_udp_addr             = "0.0.0.0:514"
syslog_tcp_addr             = "0.0.0.0:6514"
heartbeat_timeout_secs      = 90
metrics_addr                = "0.0.0.0:9101"

[normalizer]
raw_tenant_ids              = ["{tenant_id}"]
geoip_db_path               = "{d}\\GeoLite2-City.mmdb"
asset_cache_ttl_secs        = 300
asset_cache_size            = 10000
metrics_addr                = "0.0.0.0:9102"

[stream]
rules_dir                   = "{d}\\rules"
models_dir                  = "{d}\\models"
alert_threshold             = 70
tenant_ids                  = ["{tenant_id}"]

[alert]
# Configure notification credentials via the dashboard after install.
whatsapp_token              = ""
whatsapp_phone_id           = ""
sms_api_key                 = ""
sms_sender_id               = "KRNSEC"
smtp_host                   = "smtp.example.com"
smtp_port                   = 587
smtp_username               = ""
smtp_password               = ""
smtp_from                   = "alerts@kron.local"
max_notifications_per_hour  = 10

[api]
listen_addr                 = "0.0.0.0:8080"
max_body_bytes              = 10485760
cors_origins                = ["*"]

[telemetry]
log_level                   = "info"
metrics_addr                = "0.0.0.0:9100"
"#,
            date = chrono_now(),
            d = d,
            kp = kp,
            pp = pp,
            tenant_id = tenant_id,
        );

        std::fs::write(config_path, config)
            .with_context(|| format!("write config to {config_path:?}"))?;
        ok(format!("Config written to {}", config_path.display()).as_str());
        Ok(())
    }

    fn chrono_now() -> String {
        // Simple timestamp without pulling in chrono dep
        use std::time::{SystemTime, UNIX_EPOCH};
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // Format as YYYY-MM-DD HH:MM (UTC approximation — good enough for a comment)
        let mins  = secs / 60;
        let hours = mins  / 60;
        let days  = hours / 24;
        let years_since_epoch = days / 365;
        let year  = 1970 + years_since_epoch;
        format!("{year}-??-?? (UTC)")  // approximate; fine for a config comment
    }

    // ── Firewall rules ────────────────────────────────────────────────────────
    fn add_firewall_rules() {
        step("Configuring Windows Firewall...");
        let rules: &[(&str, &str, &str)] = &[
            ("KronNano-API",          "TCP", "8080"),
            ("KronNano-Collector-HTTP","TCP", "8081"),
            ("KronNano-gRPC",         "TCP", "50051"),
            ("KronNano-Syslog-UDP",   "UDP", "514"),
            ("KronNano-Syslog-TLS",   "TCP", "6514"),
            ("KronNano-Metrics",      "TCP", "9100"),
        ];
        for (name, proto, port) in rules {
            // Delete stale rule first (idempotent)
            let _ = Command::new("netsh")
                .args(["advfirewall", "firewall", "delete", "rule", &format!("name={name}")])
                .output();
            let _ = Command::new("netsh")
                .args([
                    "advfirewall", "firewall", "add", "rule",
                    &format!("name={name}"),
                    "dir=in",
                    "action=allow",
                    &format!("protocol={proto}"),
                    &format!("localport={port}"),
                    "profile=any",
                    "enable=yes",
                ])
                .output();
        }
        ok("Firewall rules configured");
    }

    // ── Install Windows Service ───────────────────────────────────────────────
    fn install_service(bin_path: &Path, config_path: &Path, data_dir: &Path) -> Result<()> {
        step(format!("Installing '{SERVICE_NAME}' Windows Service...").as_str());

        let bin_str    = bin_path.display().to_string();
        let config_str = config_path.display().to_string();
        let bin_cmd    = format!(r#""{bin_str}" --config "{config_str}""#);

        // sc create
        let out = Command::new("sc.exe")
            .args([
                "create", SERVICE_NAME,
                &format!("binPath= {bin_cmd}"),
                &format!("DisplayName= {SERVICE_DISPLAY}"),
                "start= auto",
                "obj= LocalSystem",
            ])
            .output()
            .context("sc.exe create failed")?;

        if !out.status.success() {
            let msg = String::from_utf8_lossy(&out.stderr);
            bail!("sc.exe create returned error: {msg}");
        }

        // sc description
        let _ = Command::new("sc.exe")
            .args(["description", SERVICE_NAME, SERVICE_DESC])
            .output();

        // Store environment variables in the service registry key
        set_service_env(data_dir, config_path)?;

        ok(format!("Service '{SERVICE_NAME}' installed").as_str());
        Ok(())
    }

    fn set_service_env(data_dir: &Path, config_path: &Path) -> Result<()> {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let svc_path = format!(r"SYSTEM\CurrentControlSet\Services\{SERVICE_NAME}");
        let svc_key = hklm
            .open_subkey_with_flags(&svc_path, KEY_SET_VALUE)
            .with_context(|| format!("open registry key {svc_path}"))?;

        let env_vars: Vec<String> = vec![
            format!("KRON_CONFIG={}", config_path.display()),
            format!("KRON_DATA_DIR={}", data_dir.display()),
            "KRON_LOG_LEVEL=info".to_string(),
            "RUST_LOG=kron_nano=info".to_string(),
        ];
        svc_key
            .set_value("Environment", &env_vars.as_slice())
            .context("set service Environment registry value")?;
        Ok(())
    }

    // ── Failure/recovery: restart after 5 s, up to 3 times per day ───────────
    fn set_service_recovery() -> Result<()> {
        let out = Command::new("sc.exe")
            .args([
                "failure", SERVICE_NAME,
                "reset=", "86400",
                "actions=", "restart/5000/restart/5000/restart/5000",
            ])
            .output()
            .context("sc.exe failure")?;
        if !out.status.success() {
            warn("Could not set service recovery actions — non-fatal");
        }
        Ok(())
    }

    // ── Start the service ─────────────────────────────────────────────────────
    fn start_service() -> Result<()> {
        step("Starting service...");
        let out = Command::new("sc.exe")
            .args(["start", SERVICE_NAME])
            .output()
            .context("sc.exe start")?;
        if out.status.success() {
            ok("Service started");
        } else {
            warn("Service did not start immediately — check Event Viewer if the dashboard doesn't open.");
        }
        Ok(())
    }

    // ── Add install dir to system PATH ────────────────────────────────────────
    fn add_to_path(install_dir: &Path) -> Result<()> {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let env_key = hklm
            .open_subkey_with_flags(
                r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
                KEY_SET_VALUE | KEY_QUERY_VALUE,
            )
            .context("open Environment registry key")?;

        let current: String = env_key.get_value("Path").unwrap_or_default();
        let dir_str = install_dir.display().to_string();

        if !current.to_lowercase().contains(&dir_str.to_lowercase()) {
            let new_path = format!("{current};{dir_str}");
            env_key
                .set_value("Path", &new_path)
                .context("update PATH registry value")?;
            ok("Added to system PATH");
        } else {
            ok("Already in system PATH");
        }
        Ok(())
    }

    // ── Final success banner ──────────────────────────────────────────────────
    fn print_success(config_path: &Path, data_dir: &Path, tenant_id: &str) {
        // Attempt to get the machine's local IP
        let ip = get_local_ip().unwrap_or_default();

        println!();
        println!("  {}", "╔══════════════════════════════════════════════════════════╗".green());
        println!("  {}", "║          KRON Nano installed successfully!               ║".green());
        println!("  {}", "╚══════════════════════════════════════════════════════════╝".green());
        println!();
        println!("  {}  {}", "Service".dark_grey(),  SERVICE_NAME.white().bold());
        println!("  {}   {}", "Config".dark_grey(),  config_path.display().to_string().white());
        println!("  {}     {}", "Data".dark_grey(),  data_dir.display().to_string().white());
        println!("  {}   {}", "Tenant".dark_grey(),  tenant_id.bright_cyan());
        println!();
        println!("  {}  {}", "Dashboard:".dark_grey(), "http://localhost:8080".bright_cyan().underline());
        if !ip.is_empty() {
            println!("  {}  {}", "Network:  ".dark_grey(), format!("http://{ip}:8080").bright_cyan().underline());
        }
        println!();
        println!("  {}", "Service commands:".dark_grey());
        println!("  {}  Stop-Service KronNano", "Stop    →".dark_grey());
        println!("  {}  Start-Service KronNano", "Start   →".dark_grey());
        println!("  {}  Get-EventLog -LogName Application -Source KronNano -Newest 50", "Logs    →".dark_grey());
        println!("  {}  .\\uninstall.ps1", "Remove  →".dark_grey());
        println!();
    }

    fn get_local_ip() -> Option<String> {
        // Quick UDP trick — connect to external IP (doesn't send data) to find local IP
        use std::net::UdpSocket;
        let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
        socket.connect("8.8.8.8:80").ok()?;
        let addr = socket.local_addr().ok()?;
        Some(addr.ip().to_string())
    }
}
