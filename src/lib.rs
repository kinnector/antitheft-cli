use clap::{Parser, Subcommand};
use tokio::net::UnixStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use serde::{Serialize, Deserialize};
use std::path::Path;

#[derive(Parser, Debug)]
#[command(name = "antitheft-cli", about = "Command-line interface for Kinnector EDR Agent")]
struct Cli {
    #[arg(short, long, default_value = "/var/run/kinnector/control.sock", help = "Path to agent control socket")]
    socket: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    #[command(about = "Check the daemon run state and current rule version")]
    Status,
    #[command(about = "Reload or view local prevention rules database")]
    Rules {
        #[command(subcommand)]
        action: RulesAction,
    },
    #[command(about = "Stream local agent log events")]
    Logs {
        #[arg(short, long, help = "Follow log output in real time")]
        follow: bool,

        #[arg(short, long, help = "Filter by severity (ALERT, WARN, INFO)")]
        severity: Option<String>,

        #[arg(short, long, help = "Filter by category (wallet, browser_db, user_keystores, etc.)")]
        category: Option<String>,
    },
    #[command(about = "View or release active containments")]
    Contain {
        #[command(subcommand)]
        action: ContainAction,
    },
    #[command(name = "lsm-enable", about = "Configure GRUB boot loader to enable BPF LSM and trigger reboot")]
    LsmEnable,
    #[command(about = "List currently active and tracked processes in telemetry state")]
    Ps,
    #[command(about = "Grant a temporary trust bypass to a contained process")]
    TrustOnce {
        #[arg(help = "PID of the process to trust once")]
        pid: u32,
    },
    #[command(about = "Print the version details of the CLI, agent, and rules database")]
    Version,
    #[command(about = "Interactively triage suspended/contained processes")]
    Triage {
        #[arg(help = "PID of the process tree to triage")]
        pid: u32,
    },
}

#[derive(Subcommand, Debug)]
enum RulesAction {
    #[command(about = "Reload the rules database from /etc/kinnector/rules.db")]
    Reload,
    #[command(about = "List currently loaded sensitive files paths and category flags")]
    List,
}

#[derive(Subcommand, Debug)]
enum ContainAction {
    #[command(about = "Release containment (resume suspended process tree)")]
    Release {
        #[arg(help = "Root PID of the suspended process tree to release")]
        pid: u32,
    },
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type", content = "payload")]
enum CliRequest {
    Status,
    ReloadRules,
    ReleaseContainment { pid: u32 },
    ListProcesses,
    ListRules,
    TrustOnce { pid: u32 },
    AllowProcessTree { pid: u32 },
    KillProcessTree { pid: u32 },
    DenyProcessTree { pid: u32 },
    Subscribe,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "status", content = "payload")]
enum CliResponse {
    Success(serde_json::Value),
    Error(String),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ProcessInfo {
    pid: u32,
    ppid: u32,
    exe: String,
    cmdline: String,
    env: std::collections::HashMap<String, String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Alert {
    ts: String,
    severity: String,
    category: String,
    rule_path: String,
    process: ProcessInfo,
    action: String,
    message: String,
}

fn print_alert(alert: &Alert) {
    let severity_color = match alert.severity.as_str() {
        "ALERT" => "\x1b[1;31mALERT\x1b[0m",
        "WARN" => "\x1b[1;33mWARN\x1b[0m",
        "INFO" => "\x1b[1;34mINFO\x1b[0m",
        _ => &alert.severity,
    };

    println!(
        "[{}] [{}] [{}] {}",
        alert.ts,
        severity_color,
        alert.category,
        alert.message
    );
    if alert.process.pid > 0 {
        println!(
            "  Process: {} (PID: {}, PPID: {})",
            alert.process.exe,
            alert.process.pid,
            alert.process.ppid
        );
        if !alert.process.cmdline.is_empty() {
            println!("  Command: {}", alert.process.cmdline);
        }
        if !alert.process.env.is_empty() {
            let mut sorted_keys: Vec<&String> = alert.process.env.keys().collect();
            sorted_keys.sort();
            let env_line = sorted_keys.iter()
                .map(|k| format!("{}={}", k, alert.process.env.get(*k).unwrap()))
                .collect::<Vec<String>>()
                .join(", ");
            println!("  Env:     \x1b[36m{}\x1b[0m", env_line);
        }
        println!("  Action: \x1b[1;33m{}\x1b[0m", alert.action);
    }
    println!();
}

fn alert_matches(alert: &Alert, severity: &Option<String>, category: &Option<String>) -> bool {
    if let Some(ref s) = severity {
        if alert.severity.to_lowercase() != s.to_lowercase() {
            return false;
        }
    }
    if let Some(ref c) = category {
        if alert.category.to_lowercase() != c.to_lowercase() {
            return false;
        }
    }
    true
}

fn raw_line_matches(line: &str, severity: &Option<String>, category: &Option<String>) -> bool {
    if let Some(ref s) = severity {
        if !line.to_lowercase().contains(&s.to_lowercase()) {
            return false;
        }
    }
    if let Some(ref c) = category {
        if !line.to_lowercase().contains(&c.to_lowercase()) {
            return false;
        }
    }
    true
}

fn process_line(line: &str, severity: &Option<String>, category: &Option<String>) {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return;
    }
    if let Ok(alert) = serde_json::from_str::<Alert>(trimmed) {
        if alert_matches(&alert, severity, category) {
            print_alert(&alert);
        }
    } else {
        if raw_line_matches(trimmed, severity, category) {
            println!("{}", trimmed);
        }
    }
}

enum TriageAction {
    Allow,
    TrustOnce,
    Kill,
    Deny,
}

struct RawMode;

impl RawMode {
    fn enable() -> Option<libc::termios> {
        unsafe {
            let mut raw: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(libc::STDIN_FILENO, &mut raw) != 0 {
                return None;
            }
            let original = raw.clone();
            libc::cfmakeraw(&mut raw);
            raw.c_oflag |= libc::OPOST;
            if libc::tcsetattr(libc::STDIN_FILENO, libc::TCSAFLUSH, &raw) != 0 {
                return None;
            }
            Some(original)
        }
    }

    fn disable(original: libc::termios) {
        unsafe {
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSAFLUSH, &original);
        }
    }
}

struct RawModeGuard(libc::termios);
impl Drop for RawModeGuard {
    fn drop(&mut self) {
        RawMode::disable(self.0);
    }
}

enum Key {
    Char(char),
    Up,
    Down,
    Enter,
    Esc,
    Unknown,
}

fn read_key() -> Key {
    use std::io::Read;
    let mut buffer = [0; 1];
    let mut stdin = std::io::stdin();
    if stdin.read(&mut buffer).is_err() {
        return Key::Unknown;
    }

    if buffer[0] == 0x1b {
        let mut seq = [0; 2];
        let mut pollfd = libc::pollfd {
            fd: libc::STDIN_FILENO,
            events: libc::POLLIN,
            revents: 0,
        };
        let ret = unsafe { libc::poll(&mut pollfd, 1, 50) };
        if ret > 0 && (pollfd.revents & libc::POLLIN) != 0 {
            if stdin.read(&mut seq).is_ok() {
                if seq[0] == b'[' {
                    match seq[1] {
                        b'A' => return Key::Up,
                        b'B' => return Key::Down,
                        _ => return Key::Unknown,
                    }
                }
            }
        }
        return Key::Esc;
    }

    if buffer[0] == 0x0d || buffer[0] == 0x0a {
        Key::Enter
    } else {
        Key::Char(buffer[0] as char)
    }
}

fn print_process_node(
    pid: u32,
    children_map: &std::collections::HashMap<u32, Vec<serde_json::Value>>,
    proc_map: &std::collections::HashMap<u32, &serde_json::Value>,
    prefix: &str,
    is_last: bool,
) {
    if let Some(p) = proc_map.get(&pid) {
        let exe = p.get("exe").and_then(|v| v.as_str()).unwrap_or("");
        let cmdline = p.get("cmdline").and_then(|v| v.as_str()).unwrap_or("");
        let contained = p.get("contained").and_then(|v| v.as_bool()).unwrap_or(false);

        let status_str = if contained {
            "\x1b[1;31m[SUSPENDED]\x1b[0m "
        } else {
            "\x1b[1;32m[TRACKING]\x1b[0m "
        };

        let marker = if is_last { "└─ " } else { "├─ " };
        println!(
            "{}{}{}{} (PID: {}) [Cmd: {}]",
            prefix, marker, status_str, exe, pid, cmdline
        );

        if let Some(children) = children_map.get(&pid) {
            let next_prefix = format!("{}{}", prefix, if is_last { "   " } else { "│  " });
            let len = children.len();
            for (idx, child) in children.iter().enumerate() {
                let child_pid = child.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                print_process_node(
                    child_pid,
                    children_map,
                    proc_map,
                    &next_prefix,
                    idx == len - 1,
                );
            }
        }
    }
}

fn render_process_tree(processes: &[serde_json::Value], target_pid: Option<u32>) {
    let mut children_map = std::collections::HashMap::new();
    let mut proc_map = std::collections::HashMap::new();
    let mut all_pids = std::collections::HashSet::new();

    for p in processes {
        if let Some(pid) = p.get("pid").and_then(|v| v.as_u64()) {
            let pid = pid as u32;
            proc_map.insert(pid, p);
            all_pids.insert(pid);
            if let Some(ppid) = p.get("ppid").and_then(|v| v.as_u64()) {
                let ppid = ppid as u32;
                children_map.entry(ppid).or_insert_with(Vec::new).push(p.clone());
            }
        }
    }

    for children in children_map.values_mut() {
        children.sort_by_key(|c| c.get("pid").and_then(|v| v.as_u64()).unwrap_or(0));
    }

    if let Some(t_pid) = target_pid {
        if proc_map.contains_key(&t_pid) {
            print_process_node(t_pid, &children_map, &proc_map, "", true);
        } else {
            println!("Process PID {} not found in active telemetry.", t_pid);
        }
    } else {
        let mut roots = Vec::new();
        for pid in &all_pids {
            let mut is_root = true;
            if let Some(p) = proc_map.get(pid) {
                if let Some(ppid) = p.get("ppid").and_then(|v| v.as_u64()) {
                    let ppid = ppid as u32;
                    if ppid > 0 && all_pids.contains(&ppid) {
                        is_root = false;
                    }
                }
            }
            if is_root {
                roots.push(*pid);
            }
        }
        roots.sort();
        let len = roots.len();
        for (idx, root_pid) in roots.iter().enumerate() {
            print_process_node(*root_pid, &children_map, &proc_map, "", idx == len - 1);
        }
    }
}

fn collect_and_print_process_node(
    pid: u32,
    children_map: &std::collections::HashMap<u32, Vec<serde_json::Value>>,
    proc_map: &std::collections::HashMap<u32, &serde_json::Value>,
    prefix: &str,
    is_last: bool,
    selected_pid: u32,
    ordered_pids: &mut Vec<u32>,
) {
    if let Some(p) = proc_map.get(&pid) {
        ordered_pids.push(pid);
        let node_idx = ordered_pids.len();

        let exe = p.get("exe").and_then(|v| v.as_str()).unwrap_or("");
        let cmdline = p.get("cmdline").and_then(|v| v.as_str()).unwrap_or("");
        let contained = p.get("contained").and_then(|v| v.as_bool()).unwrap_or(false);

        let status_str = if contained {
            "\x1b[1;31m[SUSPENDED]\x1b[0m "
        } else {
            "\x1b[1;32m[TRACKING]\x1b[0m "
        };

        let is_selected = pid == selected_pid;
        let select_start = if is_selected { "\x1b[1;7m" } else { "" };
        let select_end = if is_selected { "\x1b[0m" } else { "" };

        let marker = if is_last { "└─ " } else { "├─ " };
        println!(
            "[{}] {}{}{}{}{}{} [Cmd: {}]",
            node_idx, prefix, marker, select_start, status_str, exe, select_end, cmdline
        );

        if let Some(children) = children_map.get(&pid) {
            let next_prefix = format!("{}{}", prefix, if is_last { "   " } else { "│  " });
            let len = children.len();
            for (idx, child) in children.iter().enumerate() {
                let child_pid = child.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                collect_and_print_process_node(
                    child_pid,
                    children_map,
                    proc_map,
                    &next_prefix,
                    idx == len - 1,
                    selected_pid,
                    ordered_pids,
                );
            }
        }
    }
}

async fn connect_to_agent(socket_path: &str) -> UnixStream {
    match UnixStream::connect(socket_path).await {
        Ok(stream) => stream,
        Err(e) => {
            eprintln!(
                "Error: Cannot connect to Kinnector Agent socket at '{}'.\n\
                 Please ensure the 'kinnector-agent' daemon is running and you have sufficient permissions.\n\
                 (Details: {})",
                socket_path, e
            );
            std::process::exit(1);
        }
    }
}

pub async fn run_cli() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::parse();

    match args.command {
        Commands::Status => {
            let socket_path = Path::new(&args.socket);
            if !socket_path.exists() {
                println!("Daemon status: Stopped (Control socket does not exist)");
                return Ok(());
            }

            let mut stream = match UnixStream::connect(socket_path).await {
                Ok(s) => s,
                Err(_) => {
                    println!("Daemon status: Stopped (Cannot connect to control socket)");
                    return Ok(());
                }
            };

            let req = CliRequest::Status;
            let req_bytes = serde_json::to_vec(&req)?;
            stream.write_all(&req_bytes).await?;
            stream.shutdown().await?;

            let mut resp_bytes = Vec::new();
            stream.read_to_end(&mut resp_bytes).await?;

            let resp: CliResponse = serde_json::from_slice(&resp_bytes)?;
            match resp {
                CliResponse::Success(val) => {
                    println!("Daemon status: Running");
                    if let Some(daemon_version) = val.get("daemon_version") {
                        println!("Daemon Version: v{}", daemon_version.as_str().unwrap_or(""));
                    }
                    if let Some(rules_version) = val.get("rules_version") {
                        println!("Active Rules Version: {}", rules_version);
                    }
                    if let Some(rules_timestamp) = val.get("rules_timestamp") {
                        println!("Rules Epoch Timestamp: {}", rules_timestamp);
                    }
                    if let Some(active_processes) = val.get("active_processes") {
                        println!("Active Processes Tracked: {}", active_processes);
                    }
                    if let Some(lsm_active) = val.get("lsm_active").and_then(|v| v.as_bool()) {
                        if lsm_active {
                            println!("LSM Security Mode: Enabled (Kernel enforced)");
                        } else {
                            println!("LSM Security Mode: Disabled (User-mode fallback)");
                            println!("\n[!] WARNING: BPF LSM is disabled. Run 'sudo antitheft-cli lsm-enable' to configure GRUB and enable it.");
                        }
                    }
                }
                CliResponse::Error(err) => {
                    println!("Error querying status: {}", err);
                }
            }
        }
        Commands::Rules { action } => {
            match action {
                RulesAction::Reload => {
                    let mut stream = connect_to_agent(&args.socket).await;
                    let req = CliRequest::ReloadRules;
                    let req_bytes = serde_json::to_vec(&req)?;
                    stream.write_all(&req_bytes).await?;
                    stream.shutdown().await?;

                    let mut resp_bytes = Vec::new();
                    stream.read_to_end(&mut resp_bytes).await?;

                    let resp: CliResponse = serde_json::from_slice(&resp_bytes)?;
                    match resp {
                        CliResponse::Success(val) => {
                            if let Some(msg) = val.get("message") {
                                println!("Success: {}", msg.as_str().unwrap_or(""));
                            } else {
                                println!("Success: Rules reloaded successfully");
                            }
                        }
                        CliResponse::Error(err) => {
                            println!("Error: {}", err);
                        }
                    }
                }
                RulesAction::List => {
                    let mut stream = connect_to_agent(&args.socket).await;
                    let req = CliRequest::ListRules;
                    let req_bytes = serde_json::to_vec(&req)?;
                    stream.write_all(&req_bytes).await?;
                    stream.shutdown().await?;

                    let mut resp_bytes = Vec::new();
                    stream.read_to_end(&mut resp_bytes).await?;

                    let resp: CliResponse = serde_json::from_slice(&resp_bytes)?;
                    match resp {
                        CliResponse::Success(val) => {
                            if let Some(rules) = val.get("rules").and_then(|v| v.as_array()) {
                                println!("{:<60} | {:<20}", "Monitored File Path Pattern", "Category Flags");
                                println!("{}", "-".repeat(85));
                                for r in rules {
                                    let path = r.get("path").and_then(|v| v.as_str()).unwrap_or("");
                                    let flags = r.get("category_flags").and_then(|v| v.as_u64()).unwrap_or(0);
                                    let mut cat_names = Vec::new();
                                    if (flags & 0x01) != 0 { cat_names.push("browser_db"); }
                                    if (flags & 0x04) != 0 { cat_names.push("wallet"); }
                                    if (flags & 0x08) != 0 { cat_names.push("app_data"); }
                                    if (flags & 0x10) != 0 { cat_names.push("ssh_keys"); }
                                    if (flags & 0x20) != 0 { cat_names.push("user_keystores"); }
                                    if (flags & 0x40) != 0 { cat_names.push("ai_agents"); }
                                    if (flags & 0x80) != 0 { cat_names.push("web_process"); }
                                    if (flags & 0x100) != 0 { cat_names.push("system_update"); }
                                    if (flags & 0x200) != 0 { cat_names.push("persistence_path"); }
                                    if (flags & 0x400) != 0 { cat_names.push("protected_binary"); }
                                    println!("{:<60} | {:#04x} ({})", path, flags, cat_names.join(", "));
                                }
                            } else {
                                println!("No loaded sensitive rules found.");
                            }
                        }
                        CliResponse::Error(err) => {
                            println!("Error listing rules: {}", err);
                        }
                    }
                }
            }
        }
        Commands::Logs { follow, severity, category } => {
            let log_path = "/var/log/kinnector/alerts.log";
            let mut file_opt = None;
            let mut line_accumulator = String::new();

            match tokio::fs::File::open(log_path).await {
                Ok(mut file) => {
                    let mut initial_bytes = Vec::new();
                    if file.read_to_end(&mut initial_bytes).await.is_ok() && !initial_bytes.is_empty() {
                        line_accumulator.push_str(&String::from_utf8_lossy(&initial_bytes));
                        let mut lines: Vec<&str> = line_accumulator.split('\n').collect();
                        let last = lines.pop().unwrap_or("");
                        for l in lines {
                            process_line(l, &severity, &category);
                        }
                        line_accumulator = last.to_string();
                    }
                    file_opt = Some(file);
                }
                Err(e) => {
                    println!("[!] Note: Could not read historical logs from {} ({})", log_path, e);
                }
            }

            if follow {
                // Try to connect to control socket for streaming
                match UnixStream::connect(&args.socket).await {
                    Ok(mut stream) => {
                        let req = CliRequest::Subscribe;
                        let req_bytes = serde_json::to_vec(&req)?;
                        stream.write_all(&req_bytes).await?;

                        use tokio::io::{BufReader, AsyncBufReadExt};
                        let mut reader = BufReader::new(stream);
                        let mut line = String::new();

                        // Read subscription confirmation first (Q-4 fix)
                        if reader.read_line(&mut line).await? > 0 {
                            if let Ok(resp) = serde_json::from_str::<CliResponse>(&line) {
                                if let CliResponse::Error(err) = resp {
                                    eprintln!("Error subscribing to alerts: {}", err);
                                    return Ok(());
                                }
                            }
                            line.clear();
                        }

                        // Stream live alerts
                        while reader.read_line(&mut line).await? > 0 {
                            process_line(&line, &severity, &category);
                            line.clear();
                        }
                    }
                    Err(e) => {
                        if let Some(mut file) = file_opt {
                            println!("[!] Warning: Failed to connect to agent control socket ({}), falling back to file polling.", e);
                            use tokio::io::AsyncSeekExt;
                            // Make sure we seek to the end (L-8 fix)
                            let mut offset = file.seek(std::io::SeekFrom::End(0)).await.unwrap_or(0);
                            loop {
                                tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;
                                let metadata = tokio::fs::metadata(log_path).await;
                                if let Ok(meta) = metadata {
                                    let len = meta.len();
                                    if len > offset {
                                        let mut new_bytes = vec![0; (len - offset) as usize];
                                        if file.seek(std::io::SeekFrom::Start(offset)).await.is_ok() {
                                            use tokio::io::AsyncReadExt;
                                            if file.read_exact(&mut new_bytes).await.is_ok() {
                                                line_accumulator.push_str(&String::from_utf8_lossy(&new_bytes));
                                                let mut lines: Vec<&str> = line_accumulator.split('\n').collect();
                                                let last = lines.pop().unwrap_or("");
                                                for l in lines {
                                                    process_line(l, &severity, &category);
                                                }
                                                line_accumulator = last.to_string();
                                                offset = len;
                                            }
                                        }
                                    }
                                }
                            }
                        } else {
                            println!("Error: Cannot connect to agent control socket ({}) and logs file is unavailable.", e);
                        }
                    }
                }
            } else if !line_accumulator.is_empty() {
                process_line(&line_accumulator, &severity, &category);
            }
        }
        Commands::Contain { action } => {
            match action {
                ContainAction::Release { pid } => {
                    let mut stream = connect_to_agent(&args.socket).await;
                    let req = CliRequest::ReleaseContainment { pid };
                    let req_bytes = serde_json::to_vec(&req)?;
                    stream.write_all(&req_bytes).await?;
                    stream.shutdown().await?;

                    let mut resp_bytes = Vec::new();
                    stream.read_to_end(&mut resp_bytes).await?;

                    let resp: CliResponse = serde_json::from_slice(&resp_bytes)?;
                    match resp {
                        CliResponse::Success(val) => {
                            if let Some(msg) = val.get("message") {
                                println!("Success: {}", msg.as_str().unwrap_or(""));
                            } else {
                                println!("Success: Containment released for PID {}", pid);
                            }
                        }
                        CliResponse::Error(err) => {
                            println!("Error releasing containment: {}", err);
                        }
                    }
                }
            }
        }
        Commands::Ps => {
            let mut stream = connect_to_agent(&args.socket).await;
            let req = CliRequest::ListProcesses;
            let req_bytes = serde_json::to_vec(&req)?;
            stream.write_all(&req_bytes).await?;
            stream.shutdown().await?;

            let mut resp_bytes = Vec::new();
            stream.read_to_end(&mut resp_bytes).await?;

            let resp: CliResponse = serde_json::from_slice(&resp_bytes)?;
            match resp {
                CliResponse::Success(val) => {
                    if let Some(processes) = val.get("processes").and_then(|v| v.as_array()) {
                        if !processes.is_empty() {
                            render_process_tree(processes, None);
                        } else {
                            println!("No active tracked processes found.");
                        }
                    } else {
                        println!("No active tracked processes found.");
                    }
                }
                CliResponse::Error(err) => {
                    println!("Error listing processes: {}", err);
                }
            }
        }
        Commands::TrustOnce { pid } => {
            let mut stream = connect_to_agent(&args.socket).await;
            let req = CliRequest::TrustOnce { pid };
            let req_bytes = serde_json::to_vec(&req)?;
            stream.write_all(&req_bytes).await?;
            stream.shutdown().await?;

            let mut resp_bytes = Vec::new();
            stream.read_to_end(&mut resp_bytes).await?;

            let resp: CliResponse = serde_json::from_slice(&resp_bytes)?;
            match resp {
                CliResponse::Success(val) => {
                    if let Some(msg) = val.get("message") {
                        println!("Success: {}", msg.as_str().unwrap_or(""));
                    } else {
                        println!("Success: Process PID {} trusted successfully", pid);
                    }
                }
                CliResponse::Error(err) => {
                    println!("Error granting trust bypass: {}", err);
                }
            }
        }
        Commands::Version => {
            println!("Kinnector EDR CLI Tool v{}", env!("CARGO_PKG_VERSION"));
            
            // Query version info from status
            let socket_path = Path::new(&args.socket);
            if socket_path.exists() {
                if let Ok(mut stream) = UnixStream::connect(socket_path).await {
                    let req = CliRequest::Status;
                    if let Ok(req_bytes) = serde_json::to_vec(&req) {
                        let _ = stream.write_all(&req_bytes).await;
                        let _ = stream.shutdown().await;
                        let mut resp_bytes = Vec::new();
                        if stream.read_to_end(&mut resp_bytes).await.is_ok() {
                            if let Ok(CliResponse::Success(val)) = serde_json::from_slice(&resp_bytes) {
                                if let Some(daemon_version) = val.get("daemon_version") {
                                    println!("Daemon Binary Version: v{}", daemon_version.as_str().unwrap_or(""));
                                }
                                if let Some(rules_version) = val.get("rules_version") {
                                    println!("Rules Database Version: {}", rules_version);
                                }
                                if let Some(rules_timestamp) = val.get("rules_timestamp").and_then(|v| v.as_u64()) {
                                    println!("Rules Compiled Epoch: {}", rules_timestamp);
                                }
                                if let Some(lsm_active) = val.get("lsm_active").and_then(|v| v.as_bool()) {
                                    println!("BPF LSM Enforced: {}", lsm_active);
                                }
                            }
                        }
                    }
                }
            }
        }
        Commands::LsmEnable => {
            // Check for root privileges
            if unsafe { libc::getuid() } != 0 {
                eprintln!("Error: This command must be run with root privileges (sudo).");
                std::process::exit(1);
            }

            // Check if LSM is already enabled
            let lsm_path = "/sys/kernel/security/lsm";
            if let Ok(content) = std::fs::read_to_string(lsm_path) {
                if content.contains("bpf") {
                    println!("BPF LSM is already enabled on this system (Active LSMs: {}). No configuration changes needed.", content.trim());
                    return Ok(());
                }
            }

            // Path to GRUB config
            let grub_path = "/etc/default/grub";
            if !Path::new(grub_path).exists() {
                eprintln!("Error: GRUB configuration file not found at {}.", grub_path);
                std::process::exit(1);
            }

            println!("Configuring GRUB to enable BPF LSM...");
            let content = std::fs::read_to_string(grub_path)?;
            let mut lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
            let mut modified = false;

            for line in lines.iter_mut() {
                if line.starts_with("GRUB_CMDLINE_LINUX_DEFAULT=") {
                    // Extract quote characters
                    if let Some(first_quote) = line.find('"') {
                        if let Some(last_quote) = line.rfind('"') {
                            if first_quote != last_quote {
                                let mut params = line[first_quote+1..last_quote].to_string();
                                if params.contains("lsm=") {
                                    // Parse current lsm modules and append bpf if not present
                                    if !params.contains("bpf") {
                                        if let Some(lsm_idx) = params.find("lsm=") {
                                            let rest = &params[lsm_idx..];
                                            let end_idx = rest.find(' ').unwrap_or(rest.len());
                                            let lsm_val = &rest[..end_idx]; // e.g. "lsm=apparmor,yama"
                                            let new_lsm_val = format!("{},bpf", lsm_val);
                                            params = params.replace(lsm_val, &new_lsm_val);
                                        }
                                    }
                                } else {
                                    // Append lsm=landlock,lockdown,yama,integrity,apparmor,bpf
                                    if !params.is_empty() {
                                        params.push(' ');
                                    }
                                    params.push_str("lsm=landlock,lockdown,yama,integrity,apparmor,bpf");
                                }
                                *line = format!("GRUB_CMDLINE_LINUX_DEFAULT=\"{}\"", params);
                                modified = true;
                                break;
                            }
                        }
                    }
                }
            }

            if !modified {
                eprintln!("Error: Could not find GRUB_CMDLINE_LINUX_DEFAULT variable in {}.", grub_path);
                std::process::exit(1);
            }

            // 1. Create a backup of the original GRUB configuration file
            let backup_path = format!("{}.bak", grub_path);
            std::fs::copy(grub_path, &backup_path)?;
            println!("Backup created at {}.", backup_path);

            // 2. Write modified grub config atomically using a temporary file in the same directory
            let tmp_path = format!("{}.tmp", grub_path);
            std::fs::write(&tmp_path, lines.join("\n") + "\n")?;
            std::fs::rename(&tmp_path, grub_path)?;
            println!("GRUB configuration updated atomically in {}.", grub_path);

            // Run update-grub or grub-mkconfig
            println!("Running update-grub to regenerate boot config...");
            let status = std::process::Command::new("update-grub").status();
            let success = match status {
                Ok(s) => s.success(),
                Err(_) => {
                    // Try fallback grub-mkconfig/grub2-mkconfig
                    let fallback_status = std::process::Command::new("grub-mkconfig")
                        .args(&["-o", "/boot/grub/grub.cfg"])
                        .status();
                    match fallback_status {
                        Ok(s) => s.success(),
                        Err(_) => {
                            let fallback_grub2 = std::process::Command::new("grub2-mkconfig")
                                .args(&["-o", "/boot/grub2/grub.cfg"])
                                .status();
                            fallback_grub2.map(|s| s.success()).unwrap_or(false)
                        }
                    }
                }
            };

            if !success {
                eprintln!("Warning: Failed to execute grub boot loader configuration update. Please run 'sudo update-grub' manually.");
            } else {
                println!("GRUB boot configuration regenerated successfully.");
            }

            // Ask the user to reboot
            use std::io::{self, Write};
            print!("\nGRUB configuration updated. A system reboot is required to activate BPF LSM.\nReboot now? [y/N]: ");
            io::stdout().flush().unwrap();
            let mut input = String::new();
            io::stdin().read_line(&mut input).unwrap();
            if input.trim().to_lowercase() == "y" {
                println!("Rebooting system...");
                let _ = std::process::Command::new("reboot").status();
            } else {
                println!("Please reboot the system manually to apply changes and activate BPF LSM.");
            }
        }
        Commands::Triage { pid } => {
            let mut selected_pid = pid;
            let mut final_action = None;

            // Raw-mode context block
            {
                let original_termios = RawMode::enable();
                let _guard = original_termios.map(RawModeGuard);

                loop {
                    // 1. Fetch active processes
                    let mut stream = connect_to_agent(&args.socket).await;
                    let req = CliRequest::ListProcesses;
                    let req_bytes = serde_json::to_vec(&req)?;
                    stream.write_all(&req_bytes).await?;
                    stream.shutdown().await?;

                    let mut resp_bytes = Vec::new();
                    stream.read_to_end(&mut resp_bytes).await?;

                    let mut processes_list = Vec::new();
                    if let Ok(CliResponse::Success(val)) = serde_json::from_slice::<CliResponse>(&resp_bytes) {
                        if let Some(processes) = val.get("processes").and_then(|v| v.as_array()) {
                            processes_list = processes.clone();
                        }
                    }

                    if processes_list.is_empty() {
                        println!("Error: Could not retrieve process list from agent.");
                        break;
                    }

                    // Build a quick lookup map
                    let mut proc_map = std::collections::HashMap::new();
                    for p in &processes_list {
                        if let Some(p_pid) = p.get("pid").and_then(|v| v.as_u64()) {
                            proc_map.insert(p_pid as u32, p);
                        }
                    }

                    // Clear screen and draw menu
                    print!("\x1B[2J\x1B[H");
                    use std::io::Write;
                    std::io::stdout().flush().unwrap();

                    // Draw rich process info above the list
                    if let Some(p) = proc_map.get(&selected_pid) {
                        let exe = p.get("exe").and_then(|v| v.as_str()).unwrap_or("");
                        let cmdline = p.get("cmdline").and_then(|v| v.as_str()).unwrap_or("");
                        let ppid = p.get("ppid").and_then(|v| v.as_u64()).unwrap_or(0);
                        let contained = p.get("contained").and_then(|v| v.as_bool()).unwrap_or(false);

                        println!("============================================================");
                        println!("              KINNECTOR EDR INTERACTIVE TRIAGE              ");
                        println!("============================================================");
                        println!("Selected Process Details:");
                        println!("  Executable:   {}", exe);
                        println!("  PID:          {}", selected_pid);
                        println!("  PPID:         {}", ppid);
                        println!("  Command Line: {}", cmdline);
                        println!("  Status:       {}", if contained { "\x1b[1;31mCONTAINED (Suspended)\x1b[0m" } else { "\x1b[1;32mTRACKING\x1b[0m" });

                        println!("  Environment Variables:");
                        if let Some(env_map) = p.get("env").and_then(|v| v.as_object()) {
                            if !env_map.is_empty() {
                                let mut sorted_keys: Vec<&String> = env_map.keys().collect();
                                sorted_keys.sort();
                                for k in sorted_keys {
                                    let val = env_map.get(k).unwrap();
                                    let val_str = val.as_str().map(|s| s.to_string()).unwrap_or_else(|| val.to_string());
                                    println!("    \x1b[36m{}={}\x1b[0m", k, val_str);
                                }
                            } else {
                                println!("    (No environment variables captured)");
                            }
                        } else {
                            println!("    (No environment variables captured)");
                        }
                    } else {
                        println!("============================================================");
                        println!("              KINNECTOR EDR INTERACTIVE TRIAGE              ");
                        println!("============================================================");
                        println!("Selected process PID {} not found in active telemetry.", selected_pid);
                    }

                    println!("------------------------------------------------------------");
                    println!("Active Threat Process Tree (Arrow Keys ↑/↓ to Walk):");

                    // Construct children map for tree hierarchy
                    let mut children_map = std::collections::HashMap::new();
                    for p in &processes_list {
                        if let Some(p_pid) = p.get("pid").and_then(|v| v.as_u64()) {
                            let _p_pid = p_pid as u32;
                            if let Some(ppid) = p.get("ppid").and_then(|v| v.as_u64()) {
                                let ppid = ppid as u32;
                                children_map.entry(ppid).or_insert_with(Vec::new).push(p.clone());
                            }
                        }
                    }
                    for children in children_map.values_mut() {
                        children.sort_by_key(|c| c.get("pid").and_then(|v| v.as_u64()).unwrap_or(0));
                    }

                    let mut ordered_pids = Vec::new();
                    collect_and_print_process_node(
                        pid,
                        &children_map,
                        &proc_map,
                        "",
                        true,
                        selected_pid,
                        &mut ordered_pids,
                    );

                    println!("------------------------------------------------------------");
                    println!("Triage Actions:");
                    println!("  [A] Allow & Resume tree      - Approve process tree permanently");
                    println!("  [T] Trust Once tree          - Grant temporary trust bypass");
                    println!("  [K] Kill Process Tree        - Terminate target process tree");
                    println!("  [D] Deny & Block tree        - Register binary in persistent user denylist and kill");
                    println!("  [Q] Quit Triage              - Exit menu (leave process suspended)");
                    println!("============================================================");

                    let key = read_key();
                    match key {
                        Key::Up => {
                            if let Some(pos) = ordered_pids.iter().position(|&x| x == selected_pid) {
                                if pos > 0 {
                                    selected_pid = ordered_pids[pos - 1];
                                }
                            }
                        }
                        Key::Down => {
                            if let Some(pos) = ordered_pids.iter().position(|&x| x == selected_pid) {
                                if pos < ordered_pids.len() - 1 {
                                    selected_pid = ordered_pids[pos + 1];
                                }
                            }
                        }
                        Key::Char('a') | Key::Char('A') => {
                            final_action = Some(TriageAction::Allow);
                            break;
                        }
                        Key::Char('t') | Key::Char('T') => {
                            final_action = Some(TriageAction::TrustOnce);
                            break;
                        }
                        Key::Char('k') | Key::Char('K') => {
                            final_action = Some(TriageAction::Kill);
                            break;
                        }
                        Key::Char('d') | Key::Char('D') => {
                            final_action = Some(TriageAction::Deny);
                            break;
                        }
                        Key::Char('q') | Key::Char('Q') | Key::Esc => {
                            break;
                        }
                        _ => {}
                    }
                }
            } // Raw mode disabled automatically here!

            // Perform triage action in normal terminal mode
            if let Some(action) = final_action {
                match action {
                    TriageAction::Allow => {
                        let mut stream = connect_to_agent(&args.socket).await;
                        let req = CliRequest::AllowProcessTree { pid };
                        let req_bytes = serde_json::to_vec(&req)?;
                        stream.write_all(&req_bytes).await?;
                        stream.shutdown().await?;

                        let mut resp_bytes = Vec::new();
                        stream.read_to_end(&mut resp_bytes).await?;
                        if let Ok(CliResponse::Success(val)) = serde_json::from_slice::<CliResponse>(&resp_bytes) {
                            if let Some(msg) = val.get("message") {
                                println!("Success: {}", msg.as_str().unwrap_or(""));
                            } else {
                                println!("Success: Process allowed and resumed.");
                            }
                        } else {
                            println!("Error: Failed to allow process tree.");
                        }
                    }
                    TriageAction::TrustOnce => {
                        let mut stream = connect_to_agent(&args.socket).await;
                        let req = CliRequest::TrustOnce { pid };
                        let req_bytes = serde_json::to_vec(&req)?;
                        stream.write_all(&req_bytes).await?;
                        stream.shutdown().await?;

                        let mut resp_bytes = Vec::new();
                        stream.read_to_end(&mut resp_bytes).await?;
                        if let Ok(CliResponse::Success(val)) = serde_json::from_slice::<CliResponse>(&resp_bytes) {
                            if let Some(msg) = val.get("message") {
                                println!("Success: {}", msg.as_str().unwrap_or(""));
                            } else {
                                println!("Success: Process PID {} trusted once.", pid);
                            }
                        } else {
                            println!("Error: Failed to trust once.");
                        }
                    }
                    TriageAction::Kill => {
                        let mut stream = connect_to_agent(&args.socket).await;
                        let req = CliRequest::KillProcessTree { pid };
                        let req_bytes = serde_json::to_vec(&req)?;
                        stream.write_all(&req_bytes).await?;
                        stream.shutdown().await?;

                        let mut resp_bytes = Vec::new();
                        stream.read_to_end(&mut resp_bytes).await?;
                        if let Ok(CliResponse::Success(val)) = serde_json::from_slice::<CliResponse>(&resp_bytes) {
                            if let Some(msg) = val.get("message") {
                                println!("Success: {}", msg.as_str().unwrap_or(""));
                            } else {
                                println!("Success: Process tree terminated.");
                            }
                        } else {
                            println!("Error: Failed to terminate process tree.");
                        }
                    }
                    TriageAction::Deny => {
                        let mut stream = connect_to_agent(&args.socket).await;
                        let req = CliRequest::DenyProcessTree { pid };
                        let req_bytes = serde_json::to_vec(&req)?;
                        stream.write_all(&req_bytes).await?;
                        stream.shutdown().await?;

                        let mut resp_bytes = Vec::new();
                        stream.read_to_end(&mut resp_bytes).await?;
                        if let Ok(CliResponse::Success(val)) = serde_json::from_slice::<CliResponse>(&resp_bytes) {
                            if let Some(msg) = val.get("message") {
                                println!("Success: {}", msg.as_str().unwrap_or(""));
                            } else {
                                println!("Success: Process tree registered in persistent user denylist and terminated.");
                            }
                        } else {
                            println!("Error: Failed to deny process tree.");
                        }
                    }
                }
            } else {
                println!("Triage aborted. Process remains suspended.");
            }
        }
    }

    Ok(())
}
