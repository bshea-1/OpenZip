# OpenZip

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](#)
[![Platforms](https://img.shields.io/badge/platforms-macOS_%7C_Linux_%7C_Windows-informational.svg)](#installation)
[![License](https://img.shields.io/badge/license-Open_Source-brightgreen.svg)](#)

**OpenZip** (`openzip`) is a fast, free, cross-platform file archiver written in Rust with hardware SIMD-accelerated compression (`LZMA2`, `BCJ`, `Delta`, and hardware `CRC-32` / `SHA-256`). It creates and extracts standard `.7z` archives on **Windows**, **macOS**, and **Linux** (both **ARM64** and **x86_64**).

---

## OpenZip vs. 7-Zip vs. WinRAR

Live-benchmarked on a **58.61 MiB** mixed corpus (C/Rust source code, native ARM64 executables, 16-bit PCM WAV audio, NDJSON logs, and high-entropy binary data) plus a **16.00 MiB** incompressible stream on 10-core Apple Silicon (default normal compression: `openzip a -mx5`, `7zz a -mx5`, `rar a -m3 -s` v7.01):

| Feature / Metric | **OpenZip (`openzip` 1.0.0)** | **7-Zip (`26.00`)** | **WinRAR / RAR (`7.01`)** |
| :--- | :--- | :--- | :--- |
| **License & Price** | **Free & Open Source** | Free & Open Source | Paid / Trialware (\$29) |
| **Compression Speed (`58.61 MiB`)** | **543.6 ms (`107.8 MiB/s`)** | 3,645.4 ms (`16.1 MiB/s`) | 670.5 ms (`87.4 MiB/s`) |
| **Extraction Speed (`58.61 MiB`)** | **94.5 ms (`620.1 MiB/s`)** | 141.7 ms (`413.7 MiB/s`) | 113.0 ms (`518.8 MiB/s`) |
| **Archive Verify Speed (`58.61 MiB`)** | **74.0 ms (`792.5 MiB/s`)** | 119.3 ms (`491.3 MiB/s`) | 65.9 ms (`889.4 MiB/s`) |
| **Incompressible Stream (`16.00 MiB`)** | **15.6 ms (`1,023.7 MiB/s`)** | 517.9 ms (`30.9 MiB/s`) | 261.7 ms (`61.1 MiB/s`) |
| **Compressed Size (`58.61 MiB`)** | **12.53 MiB (`21.38%`)** | 10.73 MiB (`18.31%`) | 11.09 MiB (`18.92%`) |
| **Memory Safety** | **Rust** + SIMD C/ASM kernels | Legacy C++ | Proprietary C++ |
| **Native OS Support** | **Windows, macOS, Linux** | Windows, Linux, macOS (CLI) | Windows (CLI only on macOS/Linux) |

---

## Installation

### Prerequisites
- [Rust Toolchain](https://rustup.rs/) (`cargo` and `rustc`)
- A C compiler (`clang` on macOS/Linux, `cl.exe` or `clang` on Windows)

### Build & Install from Source

```bash
git clone https://github.com/bshea-1/OpenZip.git
cd OpenZip
cargo install --path .
```

Or build the standalone release binary directly in `./target/release/openzip`:

```bash
cargo build --release
```

### Quick Usage

```bash
# Compress files or folders into an archive
openzip a archive.7z folder/ file1.txt

# Extract an archive (preserving directory structure)
openzip x archive.7z -oextracted_folder

# List contents of an archive
openzip l archive.7z

# Verify archive integrity
openzip t archive.7z

# Run built-in speed benchmark
openzip bench
```
