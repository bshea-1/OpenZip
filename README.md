# OpenZip

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/bshea-1/OpenZip/releases/tag/v1.0.0)
[![Platforms](https://img.shields.io/badge/platforms-macOS_%7C_Linux_%7C_Windows-informational.svg)](#installation)
[![License](https://img.shields.io/badge/license-Open_Source-brightgreen.svg)](#)

**OpenZip** (`openzip`) is a fast, free, cross-platform file archiver written in Rust with hardware SIMD-accelerated compression (`LZMA2`, `DEFLATE`, `BCJ`, `Delta`, and hardware `CRC-32` / `SHA-256`). It creates, verifies, lists, and extracts standard **`.7z`**, **`.zip`**, **`.tar.gz`** / **`.tgz`**, **`.tar`**, and **`.gz`** archives—including **password-protected `.7z` (`AES-256` + `SHA-256`, including encrypted headers)** and **password-protected `.zip` (`WinZip AES-128/192/256` & `ZipCrypto`)**—on **Windows**, **macOS**, and **Linux** (both **ARM64** and **x86_64**).

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

Pre-built installers and binaries for all platforms are available on the [**Releases**](https://github.com/bshea-1/OpenZip/releases/tag/v1.0.0) page:

### macOS (Apple Silicon & Intel)
- **Disk Image (`.dmg` — Drag & Drop to Applications)**: [**`OpenZip-1.0.0-macos.dmg`**](https://github.com/bshea-1/OpenZip/releases/download/v1.0.0/OpenZip-1.0.0-macos.dmg)
- **Installer Package (`.pkg` — Installs `/Applications/OpenZip.app` + CLI)**: [**`OpenZip-1.0.0-macos-universal.pkg`**](https://github.com/bshea-1/OpenZip/releases/download/v1.0.0/OpenZip-1.0.0-macos-universal.pkg)
- **One-Line Terminal Install**:
  ```bash
  curl -fsSL https://github.com/bshea-1/OpenZip/releases/download/v1.0.0/install.sh | sh
  ```

### Windows (`x86_64`)
- **Setup Installer (`.exe`)**: Download and run [**`OpenZip-1.0.0-windows-x86_64-setup.exe`**](https://github.com/bshea-1/OpenZip/releases/download/v1.0.0/OpenZip-1.0.0-windows-x86_64-setup.exe)
- **Portable ZIP**: Download [**`openzip-v1.0.0-windows-x86_64.zip`**](https://github.com/bshea-1/OpenZip/releases/download/v1.0.0/openzip-v1.0.0-windows-x86_64.zip) (includes `openzip.exe` and `install.ps1`)

### Linux (`x86_64` & `ARM64`)
- **Debian / Ubuntu (`.deb`)**:
  - `x86_64`: [**`openzip_1.0.0_amd64.deb`**](https://github.com/bshea-1/OpenZip/releases/download/v1.0.0/openzip_1.0.0_amd64.deb) (`sudo dpkg -i openzip_1.0.0_amd64.deb`)
  - `ARM64`: [**`openzip_1.0.0_arm64.deb`**](https://github.com/bshea-1/OpenZip/releases/download/v1.0.0/openzip_1.0.0_arm64.deb) (`sudo dpkg -i openzip_1.0.0_arm64.deb`)
- **One-Line Terminal Install (Static MUSL Binary)**:
  ```bash
  curl -fsSL https://github.com/bshea-1/OpenZip/releases/download/v1.0.0/install.sh | sh
  ```

### Build from Source

```bash
git clone https://github.com/bshea-1/OpenZip.git
cd OpenZip
cargo install --path .
```

---

## Quick Usage

```bash
# Compress files or folders into .7z, .zip, .tar.gz, .tar, or .gz
openzip a archive.7z folder/ file1.txt
openzip a archive.zip folder/ file1.txt
openzip a archive.tar.gz folder/ file1.txt

# Create password-protected archives (AES-256 for .7z and WinZip AES-256 / ZipCrypto for .zip)
openzip a -pMySecretPassword secure.7z folder/
openzip a -pMySecretPassword secure.zip folder/

# Extract any supported archive (preserving directory structure)
openzip x archive.7z -oextracted_folder
openzip x -pMySecretPassword secure.zip -oextracted_folder

# List or verify archive contents
openzip l archive.7z
openzip t -pMySecretPassword secure.7z

# Run built-in speed benchmark
openzip bench
```
