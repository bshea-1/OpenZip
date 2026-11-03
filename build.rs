use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn find_llvm_ar() -> String {
    let home = env::var("HOME").unwrap_or_default();
    let rustup_llvm_ar = format!(
        "{}/.rustup/toolchains/stable-aarch64-apple-darwin/lib/rustlib/aarch64-apple-darwin/bin/llvm-ar",
        home
    );
    if Path::new(&rustup_llvm_ar).exists() {
        return rustup_llvm_ar;
    }
    "ar".to_string()
}

fn find_llvm_readobj() -> Option<String> {
    let home = env::var("HOME").unwrap_or_default();
    let p = format!(
        "{}/.rustup/toolchains/stable-aarch64-apple-darwin/lib/rustlib/aarch64-apple-darwin/bin/llvm-readobj",
        home
    );
    if Path::new(&p).exists() {
        Some(p)
    } else {
        None
    }
}

fn setup_windows_cross_libs(out_dir: &Path, cc: &str, llvm_ar: &str) {
    let crt_src = out_dir.join("mingw_crt.c");
    let crt_code = r#"
extern int __cdecl __getmainargs(int*, char***, char***, int, int*);
extern void __cdecl exit(int);
extern int main(int argc, char** argv);

void __main(void) {}
void _pei386_runtime_relocator(void) {}

int mainCRTStartup(void) {
    int argc = 0;
    char** argv = 0;
    char** envp = 0;
    int new_mode = 0;
    __getmainargs(&argc, &argv, &envp, 0, &new_mode);
    int ret = main(argc, argv);
    exit(ret);
    return ret;
}

unsigned int _tls_index = 0;
__attribute__((section(".tls"))) char _tls_start = 0;
__attribute__((section(".tls$ZZZ"))) char _tls_end = 0;
static unsigned long long tls_callbacks = 0;

struct IMAGE_TLS_DIRECTORY64 {
    unsigned long long StartAddressOfRawData;
    unsigned long long EndAddressOfRawData;
    unsigned long long AddressOfIndex;
    unsigned long long AddressOfCallBacks;
    unsigned int SizeOfZeroFill;
    unsigned int Characteristics;
};

__attribute__((section(".rdata$T")))
const struct IMAGE_TLS_DIRECTORY64 _tls_used = {
    (unsigned long long)&_tls_start,
    (unsigned long long)&_tls_end,
    (unsigned long long)&_tls_index,
    (unsigned long long)&tls_callbacks,
    0, 0
};

void _Unwind_Resume(void* a) { (void)a; exit(101); }
unsigned long long _Unwind_GetTextRelBase(void* a) { (void)a; return 0; }
unsigned long long _Unwind_GetDataRelBase(void* a) { (void)a; return 0; }
void* _Unwind_GetLanguageSpecificData(void* a) { (void)a; return 0; }
unsigned long long _Unwind_GetIPInfo(void* a, int* b) { (void)a; if (b) *b = 0; return 0; }
unsigned long long _Unwind_GetRegionStart(void* a) { (void)a; return 0; }
void _Unwind_SetGR(void* a, int b, unsigned long long c) { (void)a; (void)b; (void)c; }
void _Unwind_SetIP(void* a, unsigned long long b) { (void)a; (void)b; }
int _GCC_specific_handler(void) { return 0; }
"#;
    fs::write(&crt_src, crt_code).expect("Failed to write mingw_crt.c");
    let crt_obj = out_dir.join("mingw_crt.o");
    let status = Command::new(cc)
        .args(["--target=x86_64-pc-windows-gnu", "-O2", "-c"])
        .arg(&crt_src)
        .arg("-o")
        .arg(&crt_obj)
        .status()
        .expect("Failed to compile mingw_crt.c");
    assert!(status.success(), "mingw_crt.c compilation failed");

    for lib_name in ["libmingw32.a", "libmingwex.a", "libunwind.a", "libgcc.a", "libgcc_eh.a", "libgcc_s.a"] {
        let lib_p = out_dir.join(lib_name);
        let _ = fs::remove_file(&lib_p);
        let st = Command::new(llvm_ar)
            .arg("crs")
            .arg(&lib_p)
            .arg(&crt_obj)
            .status()
            .expect("Failed to run llvm-ar for mingw stub");
        assert!(st.success());
    }

    let dlltool_path = out_dir.join("llvm-dlltool");
    let _ = fs::remove_file(&dlltool_path);
    #[cfg(unix)]
    {
        let _ = std::os::unix::fs::symlink(llvm_ar, &dlltool_path);
    }

    let wine_dll_dir = Path::new("/Applications/Wine Stable.app/Contents/Resources/wine/lib/wine/x86_64-windows");
    if let Some(readobj) = find_llvm_readobj() {
        if wine_dll_dir.exists() && dlltool_path.exists() {
            for dll in ["kernel32", "ntdll", "userenv", "ws2_32", "dbghelp", "msvcrt", "user32", "advapi32", "bcrypt", "synchronization"] {
                let dll_file = wine_dll_dir.join(format!("{}.dll", dll));
                if !dll_file.exists() {
                    continue;
                }
                let output = Command::new(&readobj)
                    .arg("--coff-exports")
                    .arg(&dll_file)
                    .output()
                    .expect("Failed to run llvm-readobj");
                let stdout = String::from_utf8_lossy(&output.stdout);
                let mut def_content = format!("LIBRARY {}.dll\nEXPORTS\n", dll);
                for line in stdout.lines() {
                    let trimmed = line.trim();
                    if let Some(rest) = trimmed.strip_prefix("Name:") {
                        let sym = rest.trim();
                        if !sym.is_empty() {
                            def_content.push_str("  ");
                            def_content.push_str(sym);
                            def_content.push('\n');
                        }
                    }
                }
                let def_path = out_dir.join(format!("{}.def", dll));
                fs::write(&def_path, def_content).expect("Failed to write .def file");
                let imp_lib = out_dir.join(format!("lib{}.dll.a", dll));
                let _ = fs::remove_file(&imp_lib);
                let st = Command::new(&dlltool_path)
                    .args(["-m", "i386:x86-64", "-d"])
                    .arg(&def_path)
                    .arg("-l")
                    .arg(&imp_lib)
                    .status()
                    .expect("Failed to run llvm-dlltool");
                assert!(st.success(), "llvm-dlltool failed for {}", dll);
            }
        }
    }
}

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let host = env::var("HOST").unwrap_or_default();
    let target = env::var("TARGET").unwrap_or_default();
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();

    let is_cross_os = (host.contains("apple-darwin") && target_os != "macos")
        || (host.contains("linux") && target_os != "linux")
        || (host.contains("windows") && target_os != "windows");

    let mut c_files: Vec<&str> = vec![
        "C/OzCrc.c",
        "C/OzCrcOpt.c",
        "C/XzCrc64.c",
        "C/XzCrc64Opt.c",
        "C/Sha256.c",
        "C/Sha256Opt.c",
        "C/Alloc.c",
        "C/CpuArch.c",
        "C/LzFind.c",
        "C/LzFindOpt.c",
        "C/LzmaEnc.c",
        "C/Lzma2Enc.c",
        "C/OzStream.c",
        "C/LzmaDec.c",
        "C/Lzma2Dec.c",
        "C/Bra.c",
        "C/Bra86.c",
        "C/BraIA64.c",
        "C/Bcj2.c",
        "C/Delta.c",
        "C/OzBuf.c",
        "C/OzArcIn.c",
        "C/OzDec.c",
        "C/Ppmd7.c",
        "C/Ppmd7Dec.c",
        "c_bridge.c",
    ];

    if !is_cross_os {
        c_files.extend_from_slice(&[
            "C/Threads.c",
            "C/LzFindMt.c",
            "C/MtCoder.c",
            "C/MtDec.c",
        ]);
    }

    for f in &c_files {
        println!("cargo:rerun-if-changed={}", f);
    }
    println!("cargo:rerun-if-changed=C/CpuArch.h");

    let is_msvc = target_env == "msvc" && !host.contains("apple-darwin");
    let mut obj_files = Vec::new();

    if is_msvc {
        let cl = env::var("CC").unwrap_or_else(|_| "cl.exe".to_string());
        for src in &c_files {
            let stem = Path::new(src).file_stem().unwrap().to_str().unwrap();
            let obj = out_dir.join(format!("{}.obj", stem));
            let mut cmd = Command::new(&cl);
            cmd.args(["/nologo", "/c", "/O2", "/Oi", "/Ot", "/MT", "/IC"])
                .arg(src)
                .arg(format!("/Fo{}", obj.display()));
            let status = cmd.status().expect("Failed to run MSVC cl.exe");
            assert!(status.success(), "cl.exe failed on {}", src);
            obj_files.push(obj);
        }
        let lib_path = out_dir.join("openzip_c_kernels.lib");
        let mut lib_cmd = Command::new("lib.exe");
        lib_cmd.arg("/nologo").arg(format!("/OUT:{}", lib_path.display()));
        for obj in &obj_files {
            lib_cmd.arg(obj);
        }
        let status = lib_cmd.status().expect("Failed to run lib.exe");
        assert!(status.success(), "lib.exe failed");
    } else {
        let cc = env::var("CC").unwrap_or_else(|_| {
            if host.contains("apple-darwin") {
                "clang".to_string()
            } else {
                "cc".to_string()
            }
        });

        let mut base_flags: Vec<String> = vec![
            "-c".into(),
            "-O3".into(),
            "-fomit-frame-pointer".into(),
            "-funroll-loops".into(),
            "-IC".into(),
            "-D_FILE_OFFSET_BITS=64".into(),
            "-D_LARGEFILE_SOURCE".into(),
        ];

        if is_cross_os {
            let clang_target = if target_os == "windows" {
                "x86_64-pc-windows-gnu".to_string()
            } else {
                target.clone()
            };
            base_flags.push(format!("--target={}", clang_target));
            base_flags.push("-isystem".into());
            base_flags.push("C/cross_libc".into());
            base_flags.push("-DZ7_ST".into());
        } else {
            if target != host && target_os == "macos" {
                base_flags.push(format!("--target={}", target));
            }
            base_flags.push("-D_REENTRANT".into());
        }

        if target_arch == "aarch64" {
            if target_os == "macos" {
                base_flags.push("-march=armv8.4-a+crypto+sha3+fp16+dotprod".into());
                base_flags.push("-mmacosx-version-min=11.0".into());
            } else {
                base_flags.push("-march=armv8-a+crc+crypto".into());
            }
            base_flags.push("-DZ7_LZMA_DEC_OPT".into());
        } else if target_arch == "x86_64" {
            if target_os == "macos" {
                base_flags.push("-mmacosx-version-min=11.0".into());
            }
            base_flags.push("-mpclmul".into());
            base_flags.push("-msse4.1".into());
            base_flags.push("-mavx2".into());
        }

        for src in &c_files {
            let stem = Path::new(src).file_stem().unwrap().to_str().unwrap();
            let obj = out_dir.join(format!("{}.o", stem));
            let mut cmd = Command::new(&cc);
            cmd.args(&base_flags).arg(src).arg("-o").arg(&obj);
            let status = cmd.status().expect("Failed to invoke C compiler");
            assert!(status.success(), "C compiler failed on {}", src);
            obj_files.push(obj);
        }

        if target_arch == "aarch64" {
            let asm_src = "Asm/arm64/LzmaDecOpt.S";
            println!("cargo:rerun-if-changed={}", asm_src);
            let obj = out_dir.join("LzmaDecOpt.o");
            let mut cmd = Command::new(&cc);
            cmd.args(&base_flags).arg(asm_src).arg("-o").arg(&obj);
            let status = cmd.status().expect("Failed to assemble LzmaDecOpt.S");
            assert!(status.success(), "Assembler failed on LzmaDecOpt.S");
            obj_files.push(obj);
        }

        let ar_bin = if is_cross_os {
            find_llvm_ar()
        } else {
            "ar".to_string()
        };

        let lib_path = out_dir.join("libopenzip_c_kernels.a");
        let _ = fs::remove_file(&lib_path);
        let mut ar_cmd = Command::new(&ar_bin);
        ar_cmd.arg("crs").arg(&lib_path);
        for obj in &obj_files {
            ar_cmd.arg(obj);
        }
        let status = ar_cmd.status().expect("Failed to run archiver");
        assert!(status.success(), "archiver failed");

        if is_cross_os && target_os == "windows" {
            setup_windows_cross_libs(&out_dir, &cc, &ar_bin);
        }

        if target_os != "windows" && !target_env.contains("musl") {
            println!("cargo:rustc-link-lib=pthread");
        }
    }

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=openzip_c_kernels");
}
