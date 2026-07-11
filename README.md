# Kinnector CLI

Kinnector CLI is the terminal-based command-line interface for monitoring, querying, and administering the local Kinnector Agent EDR daemon.

---

## What it protects

Security daemons running in the background are hard to audit and control without specialized interfaces. 

Kinnector CLI gives administrators, DevOps engineers, and system operators direct, immediate control over local host protection. It streams live alert feeds, inspects tracked process trees, reloads security policies, and manages process containment actions directly from the terminal.

---

## Why existing tools are insufficient

Most enterprise EDR command-line utilities are complex, difficult to navigate, and force operators to use heavy cloud dashboards to perform simple tasks like releasing a process from containment or checking rule statuses.

Kinnector CLI is built for rapid, terminal-first administration. It communicates directly with the local daemon via JSON-RPC, presenting system information in clean, scan-friendly tables without complex query languages or remote round-trips.

---

## Core Commands and Capabilities

### 1. Host State & Telemetry Monitoring
* **`status`**: Check the daemon's active state, BPF LSM enforcement mode, and the loaded rules database version.
* **`ps`**: List all active processes tracked by the EDR heuristics engine, displaying their parent-child relationships and containment state (`TRACKING` vs `CONTAINED`).
* **`logs`**: Tail security alerts and system events in real-time.
  * `-f`, `--follow`: Stream and follow new alerts as they occur.
  * `-s`, `--severity <LEVEL>`: Filter alerts by severity (`INFO`, `WARN`, `ALERT`, `CRITICAL`).
  * `-c`, `--category <NAME>`: Filter by threat category (e.g., `credential_access`, `persistence_path`).

### 2. Rule & Containment Administration
* **`rules list`**: Display all active security rules, monitoring targets, and file categories.
* **`rules reload`**: Instruct the daemon to hot-reload and cryptographically validate the signed ruleset at `/etc/kinnector/rules.db`.
* **`contain release <PID>`**: Release an active containment lock (SIGSTOP) on a process tree and resume execution.
* **`trust-once <PID>`**: Temporarily clear a process's monitoring triggers and reset its threshold flags.
* **`lsm-enable`**: Helper command to configure GRUB boot parameters, enabling the BPF LSM module on Linux (requires reboot).

---

## How it works

Kinnector CLI interfaces with the EDR runtime through two low-overhead channels:

1. **Control IPC**: Command requests are serialized as JSON-RPC messages and sent over the local Unix domain socket at `/var/run/kinnector/control.sock`.
2. **Alerts Streaming**: The log tailing engine reads directly from the structured JSON Lines log at `/var/log/kinnector/alerts.log`, formatting events on-the-fly for clean console presentation.

---

## Build and Installation

### Prerequisites
* Rust toolchain (Rust 1.75+)

### Compiling
Build and install the binary directly from source to your Cargo bin directory:

```bash
cargo install --path .
```