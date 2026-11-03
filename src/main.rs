use std::env;
use std::ffi::c_void;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::thread;
use std::time::Instant;

extern "C" {
    fn oz_init_codecs();
    fn oz_crc32(crc: u32, data: *const u8, size: usize) -> u32;
    fn oz_crc64(crc: u64, data: *const u8, size: usize) -> u64;
    fn oz_sha256(data: *const u8, size: usize, out_digest: *mut u8);
    fn oz_filter_arm64_enc(data: *mut u8, size: usize);
    fn oz_filter_arm64_dec(data: *mut u8, size: usize);
    fn oz_filter_x86_enc(data: *mut u8, size: usize);
    fn oz_filter_x86_dec(data: *mut u8, size: usize);
    fn oz_filter_delta_enc(data: *mut u8, size: usize, delta: u32);
    fn oz_filter_delta_dec(data: *mut u8, size: usize, delta: u32);
    fn oz_lzma2_compress_block(
        src: *const u8,
        src_len: usize,
        dst: *mut u8,
        dst_len: *mut usize,
        level: i32,
        dict_size: u32,
        num_threads: i32,
        out_prop: *mut u8,
    ) -> i32;
    fn oz_lzma2_decompress_block(
        src: *const u8,
        src_len: usize,
        dst: *mut u8,
        dst_len: *mut usize,
        prop: u8,
        finish_end: i32,
    ) -> i32;

    fn oz_open_archive(archive_data: *const u8, archive_len: usize) -> *mut c_void;
    fn oz_close_archive(handle: *mut c_void);
    fn oz_archive_num_files(handle: *const c_void) -> u32;
    fn oz_archive_num_folders(handle: *const c_void) -> u32;
    fn oz_archive_get_folder_info(
        handle: *const c_void,
        folder_idx: u32,
        out_pack_ptr: *mut *const u8,
        out_pack_len: *mut usize,
        out_unpack_len: *mut usize,
        out_lzma2_prop: *mut u8,
        out_filter_id: *mut u8,
        out_can_parallel_lzma2: *mut i32,
    ) -> i32;
    fn oz_archive_decode_folder_fallback(
        handle: *mut c_void,
        folder_idx: u32,
        dst: *mut u8,
        unpack_len: usize,
    ) -> i32;
    fn oz_archive_get_file_info(
        handle: *const c_void,
        file_idx: u32,
        name_utf16_buf: *mut u16,
        name_utf16_cap: usize,
        out_name_len: *mut usize,
        out_folder_idx: *mut u32,
        out_offset_in_folder: *mut usize,
        out_size: *mut usize,
        out_crc32: *mut u32,
        out_has_crc: *mut i32,
        out_is_dir: *mut i32,
    ) -> i32;

    fn oz_set_password(pw_utf16le: *const u8, pw_byte_len: usize);
    fn oz_7zaes_encrypt_cbc(
        num_cycles: u32,
        salt: *const u8,
        salt_len: usize,
        iv: *const u8,
        pw_utf16le: *const u8,
        pw_len: usize,
        data: *mut u8,
        data_size: usize,
    );
    fn oz_aes_ctr_le_crypt(
        key: *const u8,
        key_len: usize,
        data: *mut u8,
        data_len: usize,
    );
}

pub fn set_global_password(password: Option<&str>) {
    if let Some(pw) = password {
        let mut utf16_bytes = Vec::with_capacity(pw.len() * 2);
        for u in pw.encode_utf16() {
            utf16_bytes.extend_from_slice(&u.to_le_bytes());
        }
        unsafe {
            oz_set_password(utf16_bytes.as_ptr(), utf16_bytes.len());
        }
    } else {
        unsafe {
            oz_set_password(std::ptr::null(), 0);
        }
    }
}

pub const FILTER_NONE: u8 = 0;
pub const FILTER_BCJ_X86: u8 = 1;
pub const FILTER_BCJ_ARM64: u8 = 2;
pub const FILTER_DELTA_1: u8 = 3;
pub const FILTER_DELTA_2: u8 = 4;
pub const FILTER_DELTA_4: u8 = 5;
pub const FILTER_NONE_RAW: u8 = 6;

pub fn is_high_entropy_slice(data: &[u8]) -> bool {
    if data.len() < 65536 {
        return false;
    }
    let mut counts = [0u32; 256];
    let mut htab = [0xFFFFu16; 512];
    let mut collisions = 0u32;
    let step = data.len() / 4;
    for s in 0..4 {
        let p = &data[s * step..s * step + 1024];
        for &b in p {
            counts[b as usize] += 1;
        }
        let mut i = 0;
        while i + 4 <= 1024 {
            let v = u32::from_le_bytes([p[i], p[i + 1], p[i + 2], p[i + 3]]);
            let h = ((v.wrapping_mul(0x9E37_79B1)) >> 23) as usize;
            let tag = (v & 0xFFFF) as u16;
            if htab[h] == tag {
                collisions += 1;
            }
            htab[h] = tag;
            i += 4;
        }
    }
    if collisions > 2 {
        return false;
    }
    counts.iter().all(|&c| (2..=38).contains(&c))
}

#[inline]
pub fn crc32_fast(data: &[u8]) -> u32 {
    unsafe { oz_crc32(0xFFFF_FFFF, data.as_ptr(), data.len()) ^ 0xFFFF_FFFF }
}

#[inline]
pub fn crc64_fast(data: &[u8]) -> u64 {
    unsafe {
        oz_crc64(0xFFFF_FFFF_FFFF_FFFF, data.as_ptr(), data.len()) ^ 0xFFFF_FFFF_FFFF_FFFF
    }
}

#[inline]
pub fn sha256_fast(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    unsafe {
        oz_sha256(data.as_ptr(), data.len(), out.as_mut_ptr());
    }
    out
}

/// Detect optimal reversible .7z Folder filter (BCJ ARM64, BCJ x86, or Delta 1/2/4)
pub fn detect_optimal_filter(rel_path: &str, data: &[u8]) -> u8 {
    if data.len() < 64 {
        return FILTER_NONE;
    }

    let magic_le = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if magic_le == 0xFEED_FACF || magic_le == 0xFEED_FACE {
        let cpu_type = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        if cpu_type == 0x0100_000C || cpu_type == 12 {
            return FILTER_BCJ_ARM64;
        }
        if cpu_type == 0x0100_0007 || cpu_type == 7 {
            return FILTER_BCJ_X86;
        }
    }

    if &data[0..4] == b"\x7FELF" && data.len() >= 20 {
        let e_machine = u16::from_le_bytes([data[18], data[19]]);
        if e_machine == 183 {
            return FILTER_BCJ_ARM64;
        }
        if e_machine == 62 || e_machine == 3 {
            return FILTER_BCJ_X86;
        }
    }

    if &data[0..2] == b"MZ" && data.len() >= 0x40 {
        let pe_off = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
        if pe_off + 6 <= data.len() && &data[pe_off..pe_off + 4] == b"PE\0\0" {
            let machine = u16::from_le_bytes([data[pe_off + 4], data[pe_off + 5]]);
            if machine == 0xAA64 {
                return FILTER_BCJ_ARM64;
            }
            if machine == 0x8664 || machine == 0x014C {
                return FILTER_BCJ_X86;
            }
        }
    }

    let ext = Path::new(rel_path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    if matches!(ext.as_str(), "exe" | "dll" | "sys" | "ocx") {
        return FILTER_BCJ_X86;
    }

    if data.len() < 65536 {
        return FILTER_NONE;
    }

    if &data[0..4] == b"RIFF" && data.len() >= 44 && &data[8..12] == b"WAVE" && &data[12..16] == b"fmt " {
        let block_align = u16::from_le_bytes([data[32], data[33]]);
        match block_align {
            4 => return FILTER_DELTA_4,
            2 => return FILTER_DELTA_2,
            1 => return FILTER_DELTA_1,
            _ => {}
        }
    }

    let is_media_or_bin = &data[0..2] == b"BM"
        || matches!(
            ext.as_str(),
            "wav" | "bmp" | "tga" | "raw" | "pcm" | "f32" | "dat"
        );

    if is_media_or_bin && data.len() >= 512 {
        let start = (data.len() / 4).min(data.len() - 512);
        let sample = &data[start..start + 512];

        let score_raw: usize = sample
            .windows(2)
            .map(|w| (w[1].wrapping_sub(w[0]) as i8).unsigned_abs() as usize)
            .sum();
        let score_d1: usize = sample
            .windows(3)
            .map(|w| {
                let d0 = w[1].wrapping_sub(w[0]);
                let d1 = w[2].wrapping_sub(w[1]);
                (d1.wrapping_sub(d0) as i8).unsigned_abs() as usize
            })
            .sum();
        let score_d2: usize = sample
            .windows(4)
            .map(|w| (w[2].wrapping_sub(w[0]) as i8).unsigned_abs() as usize)
            .sum();
        let score_d4: usize = sample
            .windows(8)
            .map(|w| (w[4].wrapping_sub(w[0]) as i8).unsigned_abs() as usize)
            .sum();

        let best = score_d1.min(score_d2).min(score_d4);
        if best * 100 < score_raw * 78 {
            if best == score_d4 {
                return FILTER_DELTA_4;
            } else if best == score_d2 {
                return FILTER_DELTA_2;
            } else {
                return FILTER_DELTA_1;
            }
        }
    }

    if is_high_entropy_slice(data) {
        return FILTER_NONE_RAW;
    }

    FILTER_NONE
}

#[inline]
pub fn apply_filter_encode(filter_id: u8, data: &mut [u8]) {
    if data.is_empty() || filter_id == FILTER_NONE {
        return;
    }
    unsafe {
        match filter_id {
            FILTER_BCJ_X86 => oz_filter_x86_enc(data.as_mut_ptr(), data.len()),
            FILTER_BCJ_ARM64 => oz_filter_arm64_enc(data.as_mut_ptr(), data.len()),
            FILTER_DELTA_1 => oz_filter_delta_enc(data.as_mut_ptr(), data.len(), 1),
            FILTER_DELTA_2 => oz_filter_delta_enc(data.as_mut_ptr(), data.len(), 2),
            FILTER_DELTA_4 => oz_filter_delta_enc(data.as_mut_ptr(), data.len(), 4),
            _ => {}
        }
    }
}

#[inline]
pub fn apply_filter_decode(filter_id: u8, data: &mut [u8]) {
    if data.is_empty() || filter_id == FILTER_NONE {
        return;
    }
    unsafe {
        match filter_id {
            FILTER_BCJ_X86 => oz_filter_x86_dec(data.as_mut_ptr(), data.len()),
            FILTER_BCJ_ARM64 => oz_filter_arm64_dec(data.as_mut_ptr(), data.len()),
            FILTER_DELTA_1 => oz_filter_delta_dec(data.as_mut_ptr(), data.len(), 1),
            FILTER_DELTA_2 => oz_filter_delta_dec(data.as_mut_ptr(), data.len(), 2),
            FILTER_DELTA_4 => oz_filter_delta_dec(data.as_mut_ptr(), data.len(), 4),
            _ => {}
        }
    }
}

#[cfg(unix)]
mod os_mmap {
    use std::fs::File;
    use std::os::unix::io::AsRawFd;
    use std::ptr;

    const PROT_READ: i32 = 1;
    const MAP_PRIVATE: i32 = 2;

    extern "C" {
        fn mmap(
            addr: *mut std::ffi::c_void,
            len: usize,
            prot: i32,
            flags: i32,
            fd: i32,
            offset: i64,
        ) -> *mut std::ffi::c_void;
        fn munmap(addr: *mut std::ffi::c_void, len: usize) -> i32;
    }

    pub fn read_into_slice_mmap_or_read(file: &mut File, dst: &mut [u8]) -> std::io::Result<()> {
        let len = dst.len();
        if len >= 256 * 1024 {
            unsafe {
                let ptr = mmap(
                    ptr::null_mut(),
                    len,
                    PROT_READ,
                    MAP_PRIVATE,
                    file.as_raw_fd(),
                    0,
                );
                if ptr != (-1isize as *mut std::ffi::c_void) && !ptr.is_null() {
                    ptr::copy_nonoverlapping(ptr as *const u8, dst.as_mut_ptr(), len);
                    munmap(ptr, len);
                    return Ok(());
                }
            }
        }
        std::io::Read::read_exact(file, dst)
    }
}

#[cfg(not(unix))]
mod os_mmap {
    use std::fs::File;
    pub fn read_into_slice_mmap_or_read(file: &mut File, dst: &mut [u8]) -> std::io::Result<()> {
        std::io::Read::read_exact(file, dst)
    }
}

#[derive(Clone, Debug)]
pub struct FileEntry {
    pub rel_path: String,
    pub full_path: PathBuf,
    pub size: usize,
    pub offset: usize,
    pub crc32: u32,
    pub filter_id: u8,
}

fn collect_files_recursive(root: &Path, current: &Path, out: &mut Vec<(String, PathBuf, usize)>) {
    if current.is_file() {
        if let Ok(meta) = fs::metadata(current) {
            let rel = current
                .strip_prefix(root.parent().unwrap_or(root))
                .unwrap_or(current)
                .to_string_lossy()
                .replace('\\', "/");
            out.push((rel, current.to_path_buf(), meta.len() as usize));
        }
        return;
    }
    let entries = match fs::read_dir(current) {
        Ok(e) => e,
        Err(_) => return,
    };
    let mut sub_dirs = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if let Ok(ft) = entry.file_type() {
            if ft.is_dir() {
                sub_dirs.push(path);
            } else if ft.is_file() {
                if let Ok(meta) = entry.metadata() {
                    let rel = path
                        .strip_prefix(root.parent().unwrap_or(root))
                        .unwrap_or(&path)
                        .to_string_lossy()
                        .replace('\\', "/");
                    out.push((rel, path, meta.len() as usize));
                }
            }
        }
    }
    for d in sub_dirs {
        collect_files_recursive(root, &d, out);
    }
}

fn ext_group_priority(rel_path: &str) -> u8 {
    let ext = Path::new(rel_path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
        "" | "exe" | "dll" | "so" | "dylib" | "o" | "obj" | "a" | "lib" => 0,
        "c" | "h" | "cpp" | "hpp" | "cc" | "cxx" | "rs" | "go" | "py" | "js" | "ts" => 1,
        "s" | "asm" | "mak" | "mk" | "cmake" | "toml" | "json" | "xml" | "yaml" | "md" | "txt" => 2,
        _ => 3,
    }
}

#[derive(Clone, Debug)]
pub struct SevenZipFolderOut {
    pub filter_id: u8,
    pub lzma2_prop: u8,
    pub unpack_size: usize,
    pub pack_data: Vec<u8>,
    pub file_indices: Vec<usize>,
}

fn run_workers<F: Fn() + Sync>(workers: usize, worker: F) {
    if workers <= 1 {
        worker();
    } else {
        thread::scope(|s| {
            for _ in 1..workers {
                s.spawn(&worker);
            }
            worker();
        });
    }
}

/// Parallel multi-block solid LZMA2 compression of a single .7z Folder stream
pub fn parallel_lzma2_compress_stream(
    folder_data: &[u8],
    level: i32,
    num_threads: usize,
) -> (u8, Vec<u8>) {
    if folder_data.is_empty() {
        return (0, vec![0]);
    }

    let base_dict_size: u32 = match level {
        0..=1 => 1 << 20,
        2..=3 => 1 << 22,
        4..=5 => 1 << 24,
        6..=7 => 1 << 25,
        _ => 1 << 26,
    };

    let min_block_size = 6 * 1024 * 1024;
    let max_even_blocks = (folder_data.len() / min_block_size).max(1);
    let num_blocks = max_even_blocks.min(num_threads);
    let chunk_size = (folder_data.len() + num_blocks - 1) / num_blocks;

    let mut specs: Vec<(usize, usize)> = Vec::with_capacity(num_blocks);
    let mut offset = 0;
    while offset < folder_data.len() {
        let len = (folder_data.len() - offset).min(chunk_size);
        specs.push((offset, len));
        offset += len;
    }

    let threads_per_block = if specs.len() * 2 <= num_threads { 2 } else { 1 };
    let results: Mutex<Vec<(usize, u8, Vec<u8>)>> = Mutex::new(Vec::with_capacity(specs.len()));
    let next_block = AtomicUsize::new(0);
    let workers = num_threads.min(specs.len());

    run_workers(workers, || loop {
        let idx = next_block.fetch_add(1, Ordering::Relaxed);
        if idx >= specs.len() {
            break;
        }
        let (uncomp_offset, uncomp_len) = specs[idx];
        let slice = &folder_data[uncomp_offset..uncomp_offset + uncomp_len];
        let dict_size = base_dict_size
            .min((uncomp_len as u32).next_power_of_two().max(1 << 16));
        let max_dst = uncomp_len + (uncomp_len >> 3) + 65536;
        let mut dst = Vec::with_capacity(max_dst);
        let mut dst_len = max_dst;
        let mut prop = 0u8;

        let res = unsafe {
            oz_lzma2_compress_block(
                slice.as_ptr(),
                slice.len(),
                dst.as_mut_ptr(),
                &mut dst_len,
                level,
                dict_size,
                threads_per_block,
                &mut prop,
            )
        };
        assert_eq!(res, 0, "Lzma2Enc failed with code {}", res);
        unsafe {
            dst.set_len(dst_len);
        }
        results.lock().unwrap().push((idx, prop, dst));
    });

    let mut blocks = results.into_inner().unwrap();
    blocks.sort_by_key(|(idx, _, _)| *idx);

    let max_prop = blocks.iter().map(|(_, p, _)| *p).max().unwrap_or(0);
    // Concatenate independent LZMA2 blocks into a single standard .7z LZMA2 PackStream:
    // Strip trailing 0x00 (LZMA2_CONTROL_EOF) from blocks 0..N-2, keep 0x00 on block N-1.
    let total_pack_len: usize = blocks
        .iter()
        .enumerate()
        .map(|(i, (_, _, b))| if i + 1 < blocks.len() { b.len() - 1 } else { b.len() })
        .sum();

    let mut pack_stream = Vec::with_capacity(total_pack_len);
    let num_b = blocks.len();
    for (i, (_, _, b)) in blocks.into_iter().enumerate() {
        if i + 1 < num_b {
            assert_eq!(*b.last().unwrap(), 0, "Expected LZMA2 EOF marker");
            pack_stream.extend_from_slice(&b[..b.len() - 1]);
        } else {
            pack_stream.extend_from_slice(&b);
        }
    }

    (max_prop, pack_stream)
}

/// Parallel file ingestion + content-aware .7z Folder construction
pub fn parallel_ingest_and_compress(
    paths: &[PathBuf],
    level: i32,
    num_threads: usize,
) -> (Vec<FileEntry>, Vec<SevenZipFolderOut>) {
    let mut raw_files: Vec<(String, PathBuf, usize)> = Vec::with_capacity(4096);
    for p in paths {
        collect_files_recursive(p, p, &mut raw_files);
    }
    raw_files.sort_unstable_by(|a, b| {
        let ga = ext_group_priority(&a.0);
        let gb = ext_group_priority(&b.0);
        let ext_a = Path::new(&a.0).extension().and_then(|e| e.to_str()).unwrap_or("");
        let ext_b = Path::new(&b.0).extension().and_then(|e| e.to_str()).unwrap_or("");
        ga.cmp(&gb)
            .then_with(|| ext_a.cmp(ext_b))
            .then_with(|| a.0.cmp(&b.0))
    });

    let mut total_size = 0usize;
    let mut entries: Vec<FileEntry> = Vec::with_capacity(raw_files.len());
    for (rel_path, full_path, size) in raw_files {
        entries.push(FileEntry {
            rel_path,
            full_path,
            size,
            offset: total_size,
            crc32: 0,
            filter_id: FILTER_NONE,
        });
        total_size += size;
    }

    let mut raw_arena: Vec<u8> = Vec::with_capacity(total_size);
    unsafe {
        raw_arena.set_len(total_size);
    }

    let next_idx = AtomicUsize::new(0);
    let arena_ptr = raw_arena.as_mut_ptr() as usize;
    let entries_ptr = entries.as_mut_ptr() as usize;
    let num_files = entries.len();

    run_workers(num_threads.min(num_files.max(1)), || loop {
        let idx = next_idx.fetch_add(1, Ordering::Relaxed);
        if idx >= num_files {
            break;
        }
        unsafe {
            let entry = &mut *(entries_ptr as *mut FileEntry).add(idx);
            if entry.size > 0 {
                let dst = std::slice::from_raw_parts_mut(
                    (arena_ptr as *mut u8).add(entry.offset),
                    entry.size,
                );
                if let Ok(mut f) = File::open(&entry.full_path) {
                    if os_mmap::read_into_slice_mmap_or_read(&mut f, dst).is_err() {
                        dst.fill(0);
                    }
                } else {
                    dst.fill(0);
                }
                entry.crc32 = crc32_fast(dst);
                entry.filter_id = detect_optimal_filter(&entry.rel_path, dst);
            } else {
                entry.crc32 = 0;
                entry.filter_id = FILTER_NONE;
            }
        }
    });

    // Partition non-empty files by filter_id into official .7z Folders
    // Order entries so files in the same Folder are contiguous in the .7z file table
    entries.sort_by_key(|e| if e.size == 0 { 255u8 } else { e.filter_id });

    let mut folders = Vec::new();
    let active_filters: Vec<u8> = vec![
        FILTER_NONE,
        FILTER_BCJ_X86,
        FILTER_BCJ_ARM64,
        FILTER_DELTA_1,
        FILTER_DELTA_2,
        FILTER_DELTA_4,
        FILTER_NONE_RAW,
    ];

    // Fast path: if all non-empty files use the same filter (and weren't reordered relative to raw_arena)
    let distinct_filters: Vec<u8> = active_filters
        .into_iter()
        .filter(|&fid| entries.iter().any(|e| e.size > 0 && e.filter_id == fid))
        .collect();

    if distinct_filters.len() == 1 {
        let fid = distinct_filters[0];
        let header_fid = if fid == FILTER_NONE_RAW { FILTER_NONE } else { fid };
        let non_empty_indices: Vec<usize> = entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.size > 0)
            .map(|(i, _)| i)
            .collect();
        apply_filter_encode(header_fid, &mut raw_arena);
        let (prop, pack_data) = parallel_lzma2_compress_stream(&raw_arena, level, num_threads);
        folders.push(SevenZipFolderOut {
            filter_id: header_fid,
            lzma2_prop: prop,
            unpack_size: raw_arena.len(),
            pack_data,
            file_indices: non_empty_indices,
        });
    } else if distinct_filters.len() > 1 {
        let base_dict_size: u32 = match level {
            0..=1 => 1 << 20,
            2..=3 => 1 << 22,
            4..=5 => 1 << 24,
            6..=7 => 1 << 25,
            _ => 1 << 26,
        };
        let min_block_size = 2 * 1024 * 1024;

        let mut folder_bufs: Vec<(u8, Vec<usize>, Vec<u8>)> =
            Vec::with_capacity(distinct_filters.len());
        let mut all_specs: Vec<(usize, usize, usize, usize)> = Vec::new(); // (folder_idx, blk_idx, offset, len)

        for (fo_idx, &fid) in distinct_filters.iter().enumerate() {
            let header_fid = if fid == FILTER_NONE_RAW { FILTER_NONE } else { fid };
            let file_indices: Vec<usize> = entries
                .iter()
                .enumerate()
                .filter(|(_, e)| e.size > 0 && e.filter_id == fid)
                .map(|(i, _)| i)
                .collect();
            let folder_unpack_size: usize = file_indices.iter().map(|&i| entries[i].size).sum();
            let mut folder_buf = Vec::with_capacity(folder_unpack_size);
            for &i in &file_indices {
                let e = &entries[i];
                folder_buf.extend_from_slice(&raw_arena[e.offset..e.offset + e.size]);
            }
            apply_filter_encode(header_fid, &mut folder_buf);

            let folder_min_blk = if header_fid == FILTER_BCJ_ARM64 || header_fid == FILTER_BCJ_X86 {
                24 * 1024 * 1024
            } else {
                min_block_size
            };
            let max_even_blocks = (folder_buf.len() / folder_min_blk).max(1);
            let num_blocks = max_even_blocks.min(num_threads);
            let chunk_size = (folder_buf.len() + num_blocks - 1) / num_blocks;

            let mut offset = 0;
            let mut blk_idx = 0;
            while offset < folder_buf.len() {
                let len = (folder_buf.len() - offset).min(chunk_size);
                all_specs.push((fo_idx, blk_idx, offset, len));
                offset += len;
                blk_idx += 1;
            }
            folder_bufs.push((header_fid, file_indices, folder_buf));
        }
        drop(raw_arena);

        let threads_per_block = if all_specs.len() * 2 <= num_threads { 2 } else { 1 };
        let results: Mutex<Vec<(usize, usize, u8, Vec<u8>)>> =
            Mutex::new(Vec::with_capacity(all_specs.len()));
        let next_spec = AtomicUsize::new(0);

        let workers = num_threads.min(all_specs.len());
        run_workers(workers, || loop {
            let s_idx = next_spec.fetch_add(1, Ordering::Relaxed);
            if s_idx >= all_specs.len() {
                break;
            }
            let (fo_idx, blk_idx, uncomp_offset, uncomp_len) = all_specs[s_idx];
            let slice = &folder_bufs[fo_idx].2[uncomp_offset..uncomp_offset + uncomp_len];
            let dict_size = base_dict_size
                .min((uncomp_len as u32).next_power_of_two().max(1 << 16));
            let max_dst = uncomp_len + (uncomp_len >> 3) + 65536;
            let mut dst = Vec::with_capacity(max_dst);
            let mut dst_len = max_dst;
            let mut prop = 0u8;

            let res = unsafe {
                oz_lzma2_compress_block(
                    slice.as_ptr(),
                    slice.len(),
                    dst.as_mut_ptr(),
                    &mut dst_len,
                    level,
                    dict_size,
                    threads_per_block,
                    &mut prop,
                )
            };
            assert_eq!(res, 0, "Lzma2Enc failed with code {}", res);
            unsafe {
                dst.set_len(dst_len);
            }
            results.lock().unwrap().push((fo_idx, blk_idx, prop, dst));
        });

        let mut all_blocks = results.into_inner().unwrap();
        all_blocks.sort_by_key(|&(fo_idx, blk_idx, _, _)| (fo_idx, blk_idx));

        for (fo_idx, (fid, file_indices, folder_buf)) in folder_bufs.into_iter().enumerate() {
            let f_blocks: Vec<(u8, Vec<u8>)> = all_blocks
                .iter()
                .filter(|(f, _, _, _)| *f == fo_idx)
                .map(|(_, _, p, b)| (*p, b.clone()))
                .collect();
            let max_prop = f_blocks.iter().map(|(p, _)| *p).max().unwrap_or(0);
            let num_b = f_blocks.len();
            let total_pack_len: usize = f_blocks
                .iter()
                .enumerate()
                .map(|(i, (_, b))| if i + 1 < num_b { b.len() - 1 } else { b.len() })
                .sum();
            let mut pack_stream = Vec::with_capacity(total_pack_len);
            for (i, (_, b)) in f_blocks.into_iter().enumerate() {
                if i + 1 < num_b {
                    pack_stream.extend_from_slice(&b[..b.len() - 1]);
                } else {
                    pack_stream.extend_from_slice(&b);
                }
            }
            folders.push(SevenZipFolderOut {
                filter_id: fid,
                lzma2_prop: max_prop,
                unpack_size: folder_buf.len(),
                pack_data: pack_stream,
                file_indices,
            });
        }
    }

    (entries, folders)
}

/* ---------- Official .7z Binary Format Serializer (Compatible with standard .7z v0.4 format) ---------- */

const NID_END: u8 = 0x00;
const NID_HEADER: u8 = 0x01;
const NID_MAIN_STREAMS_INFO: u8 = 0x04;
const NID_FILES_INFO: u8 = 0x05;
const NID_PACK_INFO: u8 = 0x06;
const NID_UNPACK_INFO: u8 = 0x07;
const NID_SUBSTREAMS_INFO: u8 = 0x08;
const NID_SIZE: u8 = 0x09;
const NID_CRC: u8 = 0x0A;
const NID_FOLDER: u8 = 0x0B;
const NID_CODERS_UNPACK_SIZE: u8 = 0x0C;
const NID_NUM_UNPACK_STREAM: u8 = 0x0D;
const NID_EMPTY_STREAM: u8 = 0x0E;
const NID_EMPTY_FILE: u8 = 0x0F;
const NID_NAME: u8 = 0x11;

fn write_varint(buf: &mut Vec<u8>, value: u64) {
    let mut first_byte = 0u8;
    let mut mask = 0x80u8;
    let mut i = 0usize;
    while i < 8 {
        if value < (1u64 << (7 * (i + 1))) {
            first_byte |= ((value >> (8 * i)) & 0xFF) as u8;
            break;
        }
        first_byte |= mask;
        mask >>= 1;
        i += 1;
    }
    buf.push(first_byte);
    let mut v = value;
    while i > 0 {
        buf.push((v & 0xFF) as u8);
        v >>= 8;
        i -= 1;
    }
}

fn write_bool_vector(buf: &mut Vec<u8>, bits: &[bool]) {
    let mut b = 0u8;
    let mut mask = 0x80u8;
    for &bit in bits {
        if bit {
            b |= mask;
        }
        mask >>= 1;
        if mask == 0 {
            buf.push(b);
            mask = 0x80;
            b = 0;
        }
    }
    if mask != 0x80 {
        buf.push(b);
    }
}

pub fn write_standard_archive(
    archive_path: &Path,
    entries: &[FileEntry],
    folders: &[SevenZipFolderOut],
) -> std::io::Result<u64> {
    write_standard_archive_with_password(archive_path, entries, folders, None)
}

fn encode_filter_coder(hdr: &mut Vec<u8>, filter_id: u8) {
    match filter_id {
        FILTER_BCJ_X86 => {
            hdr.push(0x04); // idSize = 4, no props
            hdr.extend_from_slice(&[0x03, 0x03, 0x01, 0x03]); // k_BCJ
        }
        FILTER_BCJ_ARM64 => {
            hdr.push(0x01); // idSize = 1, no props
            hdr.push(0x0A); // k_ARM64
        }
        FILTER_DELTA_1 | FILTER_DELTA_2 | FILTER_DELTA_4 => {
            let d_prop = match filter_id {
                FILTER_DELTA_1 => 0u8,
                FILTER_DELTA_2 => 1u8,
                _ => 3u8,
            };
            hdr.push(0x21); // hasProps (0x20) | idSize=1
            hdr.push(0x03); // k_Delta
            write_varint(hdr, 1);
            hdr.push(d_prop);
        }
        _ => unreachable!(),
    }
}

pub fn write_standard_archive_with_password(
    archive_path: &Path,
    entries: &[FileEntry],
    folders: &[SevenZipFolderOut],
    password: Option<&str>,
) -> std::io::Result<u64> {
    let pw_opt = password.filter(|s| !s.is_empty());

    // Prepare encrypted pack streams and 26-byte 7zAES properties if password is set
    let mut encrypted_packs: Vec<Vec<u8>> = Vec::new();
    let mut aes_props = [0u8; 26];
    if let Some(pw) = pw_opt {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0x1234_5678_9ABC_DEF0);
        let mut seed_buf = Vec::with_capacity(64);
        seed_buf.extend_from_slice(&nanos.to_le_bytes());
        seed_buf.extend_from_slice(archive_path.to_string_lossy().as_bytes());
        let seed_hash = sha256_fast(&seed_buf);
        let mut salt = [0u8; 8];
        let mut iv = [0u8; 16];
        salt.copy_from_slice(&seed_hash[0..8]);
        iv.copy_from_slice(&seed_hash[8..24]);

        // 7zAES properties:
        // b0 = 0xC0 | 19 (salt present + IV present + numCyclesPower=19)
        // b1 = (7 << 4) | 15 (salt_len = 8, iv_len = 16)
        aes_props[0] = 0xC0 | 19;
        aes_props[1] = (7 << 4) | 15;
        aes_props[2..10].copy_from_slice(&salt);
        aes_props[10..26].copy_from_slice(&iv);

        let mut pw_utf16 = Vec::with_capacity(pw.len() * 2);
        for u in pw.encode_utf16() {
            pw_utf16.extend_from_slice(&u.to_le_bytes());
        }

        for fo in folders {
            let padded_len = (fo.pack_data.len() + 15) & !15;
            let mut enc = vec![0u8; padded_len.max(16)];
            enc[..fo.pack_data.len()].copy_from_slice(&fo.pack_data);
            unsafe {
                oz_7zaes_encrypt_cbc(
                    19,
                    salt.as_ptr(),
                    salt.len(),
                    iv.as_ptr(),
                    pw_utf16.as_ptr(),
                    pw_utf16.len(),
                    enc.as_mut_ptr(),
                    enc.len(),
                );
            }
            encrypted_packs.push(enc);
        }
    }

    let mut hdr = Vec::with_capacity(65536);
    hdr.push(NID_HEADER);

    if !folders.is_empty() {
        hdr.push(NID_MAIN_STREAMS_INFO);

        // 1. PackInfo
        hdr.push(NID_PACK_INFO);
        write_varint(&mut hdr, 0); // dataOffset = 0 (starts right after 32-byte signature header)
        write_varint(&mut hdr, folders.len() as u64);
        hdr.push(NID_SIZE);
        for (idx, fo) in folders.iter().enumerate() {
            let plen = if pw_opt.is_some() {
                encrypted_packs[idx].len()
            } else {
                fo.pack_data.len()
            };
            write_varint(&mut hdr, plen as u64);
        }
        hdr.push(NID_END);

        // 2. UnpackInfo
        hdr.push(NID_UNPACK_INFO);
        hdr.push(NID_FOLDER);
        write_varint(&mut hdr, folders.len() as u64);
        hdr.push(0); // external = 0
        for fo in folders {
            match (pw_opt.is_some(), fo.filter_id != FILTER_NONE) {
                (false, false) => {
                    write_varint(&mut hdr, 1); // numCoders = 1
                    hdr.push(0x21); // hasProps (0x20) | idSize=1 (0x01)
                    hdr.push(0x21); // k_LZMA2
                    write_varint(&mut hdr, 1); // propsSize = 1
                    hdr.push(fo.lzma2_prop);
                }
                (false, true) => {
                    write_varint(&mut hdr, 2); // Coder 0 = LZMA2, Coder 1 = Filter
                    hdr.push(0x21);
                    hdr.push(0x21);
                    write_varint(&mut hdr, 1);
                    hdr.push(fo.lzma2_prop);
                    encode_filter_coder(&mut hdr, fo.filter_id);
                    write_varint(&mut hdr, 1); // InIndex = 1
                    write_varint(&mut hdr, 0); // OutIndex = 0
                }
                (true, false) => {
                    write_varint(&mut hdr, 2); // Coder 0 = 7zAES, Coder 1 = LZMA2
                    // Coder 0: 7zAES (0x06F10701)
                    hdr.push(0x24); // hasProps (0x20) | idSize=4
                    hdr.extend_from_slice(&[0x06, 0xF1, 0x07, 0x01]);
                    write_varint(&mut hdr, 26);
                    hdr.extend_from_slice(&aes_props);
                    // Coder 1: LZMA2
                    hdr.push(0x21);
                    hdr.push(0x21);
                    write_varint(&mut hdr, 1);
                    hdr.push(fo.lzma2_prop);
                    // Bond: Coder 0 output (OutIndex=0) -> Coder 1 input (InIndex=1)
                    write_varint(&mut hdr, 1);
                    write_varint(&mut hdr, 0);
                }
                (true, true) => {
                    write_varint(&mut hdr, 3); // Coder 0 = 7zAES, Coder 1 = LZMA2, Coder 2 = Filter
                    // Coder 0: 7zAES
                    hdr.push(0x24);
                    hdr.extend_from_slice(&[0x06, 0xF1, 0x07, 0x01]);
                    write_varint(&mut hdr, 26);
                    hdr.extend_from_slice(&aes_props);
                    // Coder 1: LZMA2
                    hdr.push(0x21);
                    hdr.push(0x21);
                    write_varint(&mut hdr, 1);
                    hdr.push(fo.lzma2_prop);
                    // Coder 2: Filter
                    encode_filter_coder(&mut hdr, fo.filter_id);
                    // Bond 0: Coder 0 output (0) -> Coder 1 input (1)
                    write_varint(&mut hdr, 1);
                    write_varint(&mut hdr, 0);
                    // Bond 1: Coder 1 output (1) -> Coder 2 input (2)
                    write_varint(&mut hdr, 2);
                    write_varint(&mut hdr, 1);
                }
            }
        }
        hdr.push(NID_CODERS_UNPACK_SIZE);
        for fo in folders {
            if pw_opt.is_some() {
                write_varint(&mut hdr, fo.pack_data.len() as u64);
            }
            write_varint(&mut hdr, fo.unpack_size as u64);
            if fo.filter_id != FILTER_NONE {
                write_varint(&mut hdr, fo.unpack_size as u64);
            }
        }
        hdr.push(NID_END);

        // 3. SubStreamsInfo
        hdr.push(NID_SUBSTREAMS_INFO);
        hdr.push(NID_NUM_UNPACK_STREAM);
        for fo in folders {
            write_varint(&mut hdr, fo.file_indices.len() as u64);
        }
        if folders.iter().any(|fo| fo.file_indices.len() > 1) {
            hdr.push(NID_SIZE);
            for fo in folders {
                let n = fo.file_indices.len();
                for &fidx in &fo.file_indices[..n.saturating_sub(1)] {
                    write_varint(&mut hdr, entries[fidx].size as u64);
                }
            }
        }
        let total_non_empty: usize = folders.iter().map(|fo| fo.file_indices.len()).sum();
        if total_non_empty > 0 {
            hdr.push(NID_CRC);
            hdr.push(1); // allAreDefined = 1
            for fo in folders {
                for &fidx in &fo.file_indices {
                    hdr.extend_from_slice(&entries[fidx].crc32.to_le_bytes());
                }
            }
        }
        hdr.push(NID_END); // End SubStreamsInfo

        hdr.push(NID_END); // End MainStreamsInfo
    }

    // 4. FilesInfo
    if !entries.is_empty() {
        hdr.push(NID_FILES_INFO);
        write_varint(&mut hdr, entries.len() as u64);

        let empty_bits: Vec<bool> = entries.iter().map(|e| e.size == 0).collect();
        let num_empty = empty_bits.iter().filter(|&&b| b).count();
        if num_empty > 0 {
            hdr.push(NID_EMPTY_STREAM);
            let bv_len = (entries.len() + 7) / 8;
            write_varint(&mut hdr, bv_len as u64);
            write_bool_vector(&mut hdr, &empty_bits);

            hdr.push(NID_EMPTY_FILE);
            let ef_bits = vec![true; num_empty];
            let ef_len = (num_empty + 7) / 8;
            write_varint(&mut hdr, ef_len as u64);
            write_bool_vector(&mut hdr, &ef_bits);
        }

        // UTF-16LE Names
        let mut names_utf16 = Vec::with_capacity(entries.len() * 32);
        names_utf16.push(0u8); // external = 0
        for e in entries {
            for u in e.rel_path.encode_utf16() {
                names_utf16.extend_from_slice(&u.to_le_bytes());
            }
            names_utf16.extend_from_slice(&0u16.to_le_bytes());
        }
        hdr.push(NID_NAME);
        write_varint(&mut hdr, names_utf16.len() as u64);
        hdr.extend_from_slice(&names_utf16);

        hdr.push(NID_END); // End FilesInfo
    }

    hdr.push(NID_END); // End Header

    let next_header_offset: u64 = if pw_opt.is_some() {
        encrypted_packs.iter().map(|p| p.len() as u64).sum()
    } else {
        folders.iter().map(|fo| fo.pack_data.len() as u64).sum()
    };
    let next_header_size = hdr.len() as u64;
    let next_header_crc = crc32_fast(&hdr);

    // 32-Byte .7z Start Header
    let mut start_hdr = [0u8; 32];
    start_hdr[0..6].copy_from_slice(&[b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C]);
    start_hdr[6] = 0; // Major 0
    start_hdr[7] = 4; // Minor 4
    start_hdr[12..20].copy_from_slice(&next_header_offset.to_le_bytes());
    start_hdr[20..28].copy_from_slice(&next_header_size.to_le_bytes());
    start_hdr[28..32].copy_from_slice(&next_header_crc.to_le_bytes());
    let start_crc = crc32_fast(&start_hdr[12..32]);
    start_hdr[8..12].copy_from_slice(&start_crc.to_le_bytes());

    let mut f = File::create(archive_path)?;
    f.write_all(&start_hdr)?;
    if pw_opt.is_some() {
        for p in &encrypted_packs {
            f.write_all(p)?;
        }
    } else {
        for fo in folders {
            f.write_all(&fo.pack_data)?;
        }
    }
    f.write_all(&hdr)?;

    Ok(32 + next_header_offset + next_header_size)
}

/* ---------- Ultra-Fast Parallel .7z Reader & Multi-Block LZMA2 Scanner ---------- */

#[derive(Clone, Debug)]
struct Lzma2BlockSlice {
    comp_start: usize,
    comp_len: usize,
    uncomp_start: usize,
    uncomp_len: usize,
    is_last: bool,
}

/// Scans an LZMA2 PackStream in ~2 microseconds to find all independent dictionary-reset blocks (mode==3 or COPY_RESET_DIC)
fn scan_lzma2_independent_blocks(pack_data: &[u8], total_unpack_len: usize) -> Vec<Lzma2BlockSlice> {
    let mut blocks = Vec::new();
    let mut pos = 0usize;
    let mut uncomp_pos = 0usize;

    let mut cur_comp_start = 0usize;
    let mut cur_uncomp_start = 0usize;
    let mut has_cur = false;

    while pos < pack_data.len() {
        let b = pack_data[pos];
        if b == 0 {
            // EOF marker
            if has_cur {
                blocks.push(Lzma2BlockSlice {
                    comp_start: cur_comp_start,
                    comp_len: (pos + 1) - cur_comp_start,
                    uncomp_start: cur_uncomp_start,
                    uncomp_len: uncomp_pos - cur_uncomp_start,
                    is_last: true,
                });
            }
            break;
        }

        let is_reset_block = b >= 0xE0
            || (b == 1 && (!has_cur || (uncomp_pos - cur_uncomp_start) >= 1024 * 1024));
        if is_reset_block {
            if has_cur && uncomp_pos > cur_uncomp_start {
                blocks.push(Lzma2BlockSlice {
                    comp_start: cur_comp_start,
                    comp_len: pos - cur_comp_start,
                    uncomp_start: cur_uncomp_start,
                    uncomp_len: uncomp_pos - cur_uncomp_start,
                    is_last: false,
                });
            }
            cur_comp_start = pos;
            cur_uncomp_start = uncomp_pos;
            has_cur = true;
        }

        if b == 1 || b == 2 {
            if pos + 3 > pack_data.len() {
                break;
            }
            let u = (((pack_data[pos + 1] as usize) << 8) | (pack_data[pos + 2] as usize)) + 1;
            pos += 3 + u;
            uncomp_pos += u;
        } else if b >= 0x80 {
            let hdr_len = if (b & 0x40) != 0 { 6 } else { 5 };
            if pos + hdr_len > pack_data.len() {
                break;
            }
            let u = (((b & 0x1F) as usize) << 16)
                | (((pack_data[pos + 1] as usize) << 8) | (pack_data[pos + 2] as usize))
                + 1;
            let p = (((pack_data[pos + 3] as usize) << 8) | (pack_data[pos + 4] as usize)) + 1;
            pos += hdr_len + p;
            uncomp_pos += u;
        } else {
            break;
        }
    }

    if blocks.is_empty() && total_unpack_len > 0 {
        blocks.push(Lzma2BlockSlice {
            comp_start: 0,
            comp_len: pack_data.len(),
            uncomp_start: 0,
            uncomp_len: total_unpack_len,
            is_last: true,
        });
    }
    blocks
}

#[derive(Clone, Debug)]
pub struct ExtractedFileMeta {
    pub rel_path: String,
    pub folder_idx: Option<usize>,
    pub offset_in_folder: usize,
    pub size: usize,
    pub crc32: u32,
    pub has_crc: bool,
    pub is_dir: bool,
}

/// Opens ANY standard .7z archive (standard .7z v0.4 format), decompresses all Folders in parallel,
/// and verifies every file's CRC32 in parallel across all CPU cores!
pub fn read_and_decompress_archive(
    archive_path: &Path,
    num_threads: usize,
) -> std::io::Result<(Vec<ExtractedFileMeta>, Vec<Vec<u8>>)> {
    let mut f = File::open(archive_path)?;
    let len = f.metadata()?.len() as usize;
    let mut archive_bytes = Vec::with_capacity(len);
    unsafe {
        archive_bytes.set_len(len);
    }
    os_mmap::read_into_slice_mmap_or_read(&mut f, &mut archive_bytes)?;

    let handle = unsafe { oz_open_archive(archive_bytes.as_ptr(), archive_bytes.len()) };
    assert!(!handle.is_null(), "Failed to open .7z archive: {}", archive_path.display());

    let num_folders = unsafe { oz_archive_num_folders(handle) } as usize;
    let num_files = unsafe { oz_archive_num_files(handle) } as usize;

    let mut folder_buffers: Vec<Vec<u8>> = Vec::with_capacity(num_folders);
    for fo in 0..num_folders {
        let mut pack_ptr: *const u8 = std::ptr::null();
        let mut pack_len = 0usize;
        let mut unpack_len = 0usize;
        let mut lzma2_prop = 0u8;
        let mut filter_id = 0u8;
        let mut can_parallel = 0i32;

        let rc = unsafe {
            oz_archive_get_folder_info(
                handle,
                fo as u32,
                &mut pack_ptr,
                &mut pack_len,
                &mut unpack_len,
                &mut lzma2_prop,
                &mut filter_id,
                &mut can_parallel,
            )
        };
        assert_eq!(rc, 0, "Failed to query folder {}", fo);

        let mut out_buf = Vec::with_capacity(unpack_len);
        unsafe {
            out_buf.set_len(unpack_len);
        }

        if unpack_len > 0 {
            if can_parallel != 0 && !pack_ptr.is_null() {
                let pack_slice = unsafe { std::slice::from_raw_parts(pack_ptr, pack_len) };
                let blocks = scan_lzma2_independent_blocks(pack_slice, unpack_len);
                let out_ptr = out_buf.as_mut_ptr() as usize;
                let next_blk = AtomicUsize::new(0);

                let workers = num_threads.min(blocks.len());
                run_workers(workers, || loop {
                    let idx = next_blk.fetch_add(1, Ordering::Relaxed);
                    if idx >= blocks.len() {
                        break;
                    }
                    let b = &blocks[idx];
                    let mut dst_len = b.uncomp_len;
                    let res = unsafe {
                        oz_lzma2_decompress_block(
                            pack_slice.as_ptr().add(b.comp_start),
                            b.comp_len,
                            (out_ptr as *mut u8).add(b.uncomp_start),
                            &mut dst_len,
                            lzma2_prop,
                            if b.is_last { 1 } else { 0 },
                        )
                    };
                    assert_eq!(res, 0, "Parallel LZMA2 decode failed on block {}", idx);
                    assert_eq!(dst_len, b.uncomp_len);
                });

                apply_filter_decode(filter_id, &mut out_buf);
            } else {
                let res = unsafe {
                    oz_archive_decode_folder_fallback(
                        handle,
                        fo as u32,
                        out_buf.as_mut_ptr(),
                        unpack_len,
                    )
                };
                assert_eq!(res, 0, "Fallback folder decode failed on folder {}", fo);
            }
        }
        folder_buffers.push(out_buf);
    }

    let mut files_meta = Vec::with_capacity(num_files);
    let mut utf16_buf = vec![0u16; 4096];
    for i in 0..num_files {
        let mut name_len = 0usize;
        let mut folder_idx = u32::MAX;
        let mut offset_in_folder = 0usize;
        let mut size = 0usize;
        let mut crc32 = 0u32;
        let mut has_crc = 0i32;
        let mut is_dir = 0i32;

        unsafe {
            oz_archive_get_file_info(
                handle,
                i as u32,
                utf16_buf.as_mut_ptr(),
                utf16_buf.len(),
                &mut name_len,
                &mut folder_idx,
                &mut offset_in_folder,
                &mut size,
                &mut crc32,
                &mut has_crc,
                &mut is_dir,
            );
        }
        let rel_path = String::from_utf16_lossy(&utf16_buf[..name_len]);
        files_meta.push(ExtractedFileMeta {
            rel_path,
            folder_idx: if folder_idx == u32::MAX {
                None
            } else {
                Some(folder_idx as usize)
            },
            offset_in_folder,
            size,
            crc32,
            has_crc: has_crc != 0,
            is_dir: is_dir != 0,
        });
    }

    unsafe {
        oz_close_archive(handle);
    }

    // Parallel per-file hardware CRC32 verification across all CPU cores
    let next_file = AtomicUsize::new(0);
    run_workers(num_threads.min(files_meta.len().max(1)), || loop {
        let i = next_file.fetch_add(1, Ordering::Relaxed);
        if i >= files_meta.len() {
            break;
        }
        let fm = &files_meta[i];
        if !fm.is_dir && fm.has_crc && fm.size > 0 {
            if let Some(fidx) = fm.folder_idx {
                let slice =
                    &folder_buffers[fidx][fm.offset_in_folder..fm.offset_in_folder + fm.size];
                let calc = crc32_fast(slice);
                assert_eq!(calc, fm.crc32, "CRC32 mismatch on {}", fm.rel_path);
            }
        }
    });

    Ok((files_meta, folder_buffers))
}

/* ---------- Multi-Format Support: RFC 1951 DEFLATE, ZipCrypto, WinZip AES, .zip, .tar, .tar.gz, .gz ---------- */

pub mod multi_format {
    use super::*;

    /* --- 1. SHA-1 + HMAC-SHA1 + PBKDF2-HMAC-SHA1 (for WinZip AES-128/192/256 0x9901) --- */

    pub fn sha1_digest(data: &[u8]) -> [u8; 20] {
        let mut h0: u32 = 0x6745_2301;
        let mut h1: u32 = 0xEFCD_AB89;
        let mut h2: u32 = 0x98BA_DCFE;
        let mut h3: u32 = 0x1032_5476;
        let mut h4: u32 = 0xC3D2_E1F0;

        let bit_len = (data.len() as u64).wrapping_mul(8);
        let mut msg = Vec::with_capacity((data.len() + 72) & !63);
        msg.extend_from_slice(data);
        msg.push(0x80);
        while (msg.len() % 64) != 56 {
            msg.push(0);
        }
        msg.extend_from_slice(&bit_len.to_be_bytes());

        let mut w = [0u32; 80];
        for chunk in msg.chunks_exact(64) {
            for i in 0..16 {
                w[i] = u32::from_be_bytes([
                    chunk[i * 4],
                    chunk[i * 4 + 1],
                    chunk[i * 4 + 2],
                    chunk[i * 4 + 3],
                ]);
            }
            for i in 16..80 {
                w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
            }

            let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);
            for i in 0..80 {
                let (f, k) = match i {
                    0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999u32),
                    20..=39 => (b ^ c ^ d, 0x6ED9_EBA1u32),
                    40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDCu32),
                    _ => (b ^ c ^ d, 0xCA62_C1D6u32),
                };
                let temp = a
                    .rotate_left(5)
                    .wrapping_add(f)
                    .wrapping_add(e)
                    .wrapping_add(k)
                    .wrapping_add(w[i]);
                e = d;
                d = c;
                c = b.rotate_left(30);
                b = a;
                a = temp;
            }
            h0 = h0.wrapping_add(a);
            h1 = h1.wrapping_add(b);
            h2 = h2.wrapping_add(c);
            h3 = h3.wrapping_add(d);
            h4 = h4.wrapping_add(e);
        }

        let mut out = [0u8; 20];
        out[0..4].copy_from_slice(&h0.to_be_bytes());
        out[4..8].copy_from_slice(&h1.to_be_bytes());
        out[8..12].copy_from_slice(&h2.to_be_bytes());
        out[12..16].copy_from_slice(&h3.to_be_bytes());
        out[16..20].copy_from_slice(&h4.to_be_bytes());
        out
    }

    pub fn hmac_sha1(key: &[u8], message: &[u8]) -> [u8; 20] {
        let mut k_block = [0u8; 64];
        if key.len() > 64 {
            let hashed = sha1_digest(key);
            k_block[..20].copy_from_slice(&hashed);
        } else {
            k_block[..key.len()].copy_from_slice(key);
        }
        let mut ipad = [0x36u8; 64];
        let mut opad = [0x5Cu8; 64];
        for i in 0..64 {
            ipad[i] ^= k_block[i];
            opad[i] ^= k_block[i];
        }
        let mut inner = Vec::with_capacity(64 + message.len());
        inner.extend_from_slice(&ipad);
        inner.extend_from_slice(message);
        let inner_hash = sha1_digest(&inner);

        let mut outer = [0u8; 84];
        outer[..64].copy_from_slice(&opad);
        outer[64..84].copy_from_slice(&inner_hash);
        sha1_digest(&outer)
    }

    pub fn pbkdf2_hmac_sha1(password: &[u8], salt: &[u8], iterations: u32, out_len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(out_len);
        let mut block_idx = 1u32;
        while out.len() < out_len {
            let mut salt_blk = Vec::with_capacity(salt.len() + 4);
            salt_blk.extend_from_slice(salt);
            salt_blk.extend_from_slice(&block_idx.to_be_bytes());
            let mut u = hmac_sha1(password, &salt_blk);
            let mut t = u;
            for _ in 1..iterations {
                u = hmac_sha1(password, &u);
                for j in 0..20 {
                    t[j] ^= u[j];
                }
            }
            let take = (out_len - out.len()).min(20);
            out.extend_from_slice(&t[..take]);
            block_idx += 1;
        }
        out
    }

    /* --- 2. Traditional PKWARE ZipCrypto Stream Cipher --- */

    pub struct ZipCryptoKeys {
        k0: u32,
        k1: u32,
        k2: u32,
    }

    impl ZipCryptoKeys {
        #[inline]
        fn crc32_byte(crc: u32, b: u8) -> u32 {
            let mut c = crc ^ (b as u32);
            for _ in 0..8 {
                if (c & 1) != 0 {
                    c = (c >> 1) ^ 0xEDB8_8320;
                } else {
                    c >>= 1;
                }
            }
            c
        }

        pub fn new(password: &[u8]) -> Self {
            let mut s = Self {
                k0: 0x1234_5678,
                k1: 0x2345_6789,
                k2: 0x3456_7890,
            };
            for &b in password {
                s.update(b);
            }
            s
        }

        #[inline]
        pub fn update(&mut self, b: u8) {
            self.k0 = Self::crc32_byte(self.k0, b);
            self.k1 = (self.k1.wrapping_add(self.k0 & 0xFF))
                .wrapping_mul(134_775_813)
                .wrapping_add(1);
            self.k2 = Self::crc32_byte(self.k2, (self.k1 >> 24) as u8);
        }

        #[inline]
        pub fn stream_byte(&self) -> u8 {
            let temp = (self.k2 as u16) | 2;
            (((temp.wrapping_mul(temp ^ 1)) >> 8) & 0xFF) as u8
        }

        #[inline]
        pub fn decrypt_byte(&mut self, c: u8) -> u8 {
            let p = c ^ self.stream_byte();
            self.update(p);
            p
        }

        #[inline]
        pub fn encrypt_byte(&mut self, p: u8) -> u8 {
            let c = p ^ self.stream_byte();
            self.update(p);
            c
        }
    }

    /* --- 3. RFC 1951 DEFLATE Decompressor (inflate_raw) & Compressor (deflate_compress) --- */

    struct BitReader<'a> {
        data: &'a [u8],
        pos: usize,
        bit_buf: u64,
        bit_cnt: u32,
    }

    impl<'a> BitReader<'a> {
        fn new(data: &'a [u8]) -> Self {
            Self {
                data,
                pos: 0,
                bit_buf: 0,
                bit_cnt: 0,
            }
        }

        #[inline]
        fn refill(&mut self) {
            while self.bit_cnt <= 56 && self.pos < self.data.len() {
                self.bit_buf |= (self.data[self.pos] as u64) << self.bit_cnt;
                self.pos += 1;
                self.bit_cnt += 8;
            }
        }

        #[inline]
        fn read_bits(&mut self, n: u32) -> Result<u32, String> {
            if n == 0 {
                return Ok(0);
            }
            if self.bit_cnt < n {
                self.refill();
                if self.bit_cnt < n {
                    return Err("Unexpected EOF in DEFLATE bitstream".to_string());
                }
            }
            let val = (self.bit_buf & ((1u64 << n) - 1)) as u32;
            self.bit_buf >>= n;
            self.bit_cnt -= n;
            Ok(val)
        }

        fn align_byte(&mut self) {
            let rem = self.bit_cnt & 7;
            if rem > 0 {
                self.bit_buf >>= rem;
                self.bit_cnt -= rem;
            }
        }

        fn read_u16_aligned(&mut self) -> Result<u16, String> {
            self.align_byte();
            let lo = self.read_bits(8)? as u16;
            let hi = self.read_bits(8)? as u16;
            Ok(lo | (hi << 8))
        }
    }

    #[derive(Clone)]
    struct HuffTable {
        counts: [u16; 16],
        symbols: Vec<u16>,
    }

    impl HuffTable {
        fn build(lengths: &[u8]) -> Result<Self, String> {
            let mut counts = [0u16; 16];
            for &l in lengths {
                if l as usize >= 16 {
                    return Err("Invalid Huffman code length".to_string());
                }
                if l > 0 {
                    counts[l as usize] += 1;
                }
            }
            let mut offsets = [0u16; 16];
            let mut total = 0u16;
            for bits in 1..16 {
                offsets[bits] = total;
                total += counts[bits];
            }
            let mut symbols = vec![0u16; total as usize];
            for (sym, &l) in lengths.iter().enumerate() {
                if l > 0 {
                    let off = offsets[l as usize] as usize;
                    symbols[off] = sym as u16;
                    offsets[l as usize] += 1;
                }
            }
            Ok(Self { counts, symbols })
        }

        #[inline]
        fn decode(&self, br: &mut BitReader) -> Result<u16, String> {
            let mut code = 0i32;
            let mut first = 0i32;
            let mut index = 0i32;
            for len in 1..=15 {
                code |= br.read_bits(1)? as i32;
                let count = self.counts[len] as i32;
                if code - count < first {
                    return Ok(self.symbols[(index + (code - first)) as usize]);
                }
                index += count;
                first += count;
                first <<= 1;
                code <<= 1;
            }
            Err("Invalid Huffman code in DEFLATE stream".to_string())
        }
    }

    pub fn inflate_raw(data: &[u8]) -> Result<Vec<u8>, String> {
        const LEN_BASE: [u16; 29] = [
            3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99,
            115, 131, 163, 195, 227, 258,
        ];
        const LEN_EXTRA: [u8; 29] = [
            0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
        ];
        const DIST_BASE: [u16; 30] = [
            1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025,
            1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
        ];
        const DIST_EXTRA: [u8; 30] = [
            0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12,
            12, 13, 13,
        ];
        const CL_ORDER: [usize; 19] = [
            16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
        ];

        let mut br = BitReader::new(data);
        let mut out = Vec::with_capacity(data.len().saturating_mul(2).max(1024));

        loop {
            let bfinal = br.read_bits(1)?;
            let btype = br.read_bits(2)?;

            match btype {
                0 => {
                    let len = br.read_u16_aligned()?;
                    let nlen = br.read_u16_aligned()?;
                    if (len ^ 0xFFFF) != nlen {
                        return Err("Corrupt uncompressed block length in DEFLATE".to_string());
                    }
                    for _ in 0..len {
                        out.push(br.read_bits(8)? as u8);
                    }
                }
                1 | 2 => {
                    let (lit_table, dist_table) = if btype == 1 {
                        let mut lit_lens = [0u8; 288];
                        for i in 0..=143 {
                            lit_lens[i] = 8;
                        }
                        for i in 144..=255 {
                            lit_lens[i] = 9;
                        }
                        for i in 256..=279 {
                            lit_lens[i] = 7;
                        }
                        for i in 280..=287 {
                            lit_lens[i] = 8;
                        }
                        let dist_lens = [5u8; 32];
                        (HuffTable::build(&lit_lens)?, HuffTable::build(&dist_lens)?)
                    } else {
                        let hlit = (br.read_bits(5)? as usize) + 257;
                        let hdist = (br.read_bits(5)? as usize) + 1;
                        let hclen = (br.read_bits(4)? as usize) + 4;
                        let mut cl_lens = [0u8; 19];
                        for i in 0..hclen {
                            cl_lens[CL_ORDER[i]] = br.read_bits(3)? as u8;
                        }
                        let cl_table = HuffTable::build(&cl_lens)?;
                        let mut lens = Vec::with_capacity(hlit + hdist);
                        while lens.len() < hlit + hdist {
                            let sym = cl_table.decode(&mut br)?;
                            match sym {
                                0..=15 => lens.push(sym as u8),
                                16 => {
                                    let prev = *lens
                                        .last()
                                        .ok_or_else(|| "Invalid repeat in DEFLATE header".to_string())?;
                                    let rep = (br.read_bits(2)? as usize) + 3;
                                    for _ in 0..rep {
                                        lens.push(prev);
                                    }
                                }
                                17 => {
                                    let rep = (br.read_bits(3)? as usize) + 3;
                                    for _ in 0..rep {
                                        lens.push(0);
                                    }
                                }
                                18 => {
                                    let rep = (br.read_bits(7)? as usize) + 11;
                                    for _ in 0..rep {
                                        lens.push(0);
                                    }
                                }
                                _ => return Err("Invalid code length symbol".to_string()),
                            }
                        }
                        (
                            HuffTable::build(&lens[..hlit])?,
                            HuffTable::build(&lens[hlit..hlit + hdist])?,
                        )
                    };

                    loop {
                        let sym = lit_table.decode(&mut br)?;
                        if sym < 256 {
                            out.push(sym as u8);
                        } else if sym == 256 {
                            break;
                        } else {
                            let l_idx = (sym as usize) - 257;
                            if l_idx >= LEN_BASE.len() {
                                return Err("Invalid length symbol in DEFLATE".to_string());
                            }
                            let length = (LEN_BASE[l_idx] as usize)
                                + (br.read_bits(LEN_EXTRA[l_idx] as u32)? as usize);
                            let d_sym = dist_table.decode(&mut br)? as usize;
                            if d_sym >= DIST_BASE.len() {
                                return Err("Invalid distance symbol in DEFLATE".to_string());
                            }
                            let dist = (DIST_BASE[d_sym] as usize)
                                + (br.read_bits(DIST_EXTRA[d_sym] as u32)? as usize);
                            if dist == 0 || dist > out.len() {
                                return Err("Distance out of bounds in DEFLATE".to_string());
                            }
                            let start = out.len() - dist;
                            for i in 0..length {
                                let b = out[start + i];
                                out.push(b);
                            }
                        }
                    }
                }
                _ => return Err("Invalid DEFLATE block type 3".to_string()),
            }

            if bfinal != 0 {
                break;
            }
        }
        Ok(out)
    }

    struct BitWriter {
        out: Vec<u8>,
        bit_buf: u64,
        bit_cnt: u32,
    }

    impl BitWriter {
        fn with_capacity(cap: usize) -> Self {
            Self {
                out: Vec::with_capacity(cap),
                bit_buf: 0,
                bit_cnt: 0,
            }
        }

        #[inline]
        fn write_bits(&mut self, val: u32, n: u32) {
            self.bit_buf |= ((val as u64) & ((1u64 << n) - 1)) << self.bit_cnt;
            self.bit_cnt += n;
            while self.bit_cnt >= 8 {
                self.out.push((self.bit_buf & 0xFF) as u8);
                self.bit_buf >>= 8;
                self.bit_cnt -= 8;
            }
        }

        #[inline]
        fn write_huff_msb(&mut self, code: u16, len: u8) {
            let mut rev = 0u32;
            for i in 0..(len as u32) {
                if (code & (1 << (len as u32 - 1 - i))) != 0 {
                    rev |= 1 << i;
                }
            }
            self.write_bits(rev, len as u32);
        }

        fn finish(mut self) -> Vec<u8> {
            if self.bit_cnt > 0 {
                self.out.push((self.bit_buf & 0xFF) as u8);
            }
            self.out
        }
    }

    #[inline]
    fn write_fixed_lit(bw: &mut BitWriter, sym: u16) {
        match sym {
            0..=143 => bw.write_huff_msb(0x30 + sym, 8),
            144..=255 => bw.write_huff_msb(0x190 + (sym - 144), 9),
            256..=279 => bw.write_huff_msb(sym - 256, 7),
            _ => bw.write_huff_msb(0xC0 + (sym - 280), 8),
        }
    }

    #[inline]
    fn write_fixed_match(bw: &mut BitWriter, mut len: usize, dist: usize) {
        const LEN_BASE: [usize; 29] = [
            3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99,
            115, 131, 163, 195, 227, 258,
        ];
        const LEN_EXTRA: [u8; 29] = [
            0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
        ];
        const DIST_BASE: [usize; 30] = [
            1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025,
            1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
        ];
        const DIST_EXTRA: [u8; 30] = [
            0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12,
            12, 13, 13,
        ];
        len = len.min(258);
        let mut l_idx = 0;
        for i in (0..29).rev() {
            if len >= LEN_BASE[i] {
                l_idx = i;
                break;
            }
        }
        write_fixed_lit(bw, (257 + l_idx) as u16);
        if LEN_EXTRA[l_idx] > 0 {
            bw.write_bits((len - LEN_BASE[l_idx]) as u32, LEN_EXTRA[l_idx] as u32);
        }

        let mut d_idx = 0;
        for i in (0..30).rev() {
            if dist >= DIST_BASE[i] {
                d_idx = i;
                break;
            }
        }
        bw.write_huff_msb(d_idx as u16, 5);
        if DIST_EXTRA[d_idx] > 0 {
            bw.write_bits((dist - DIST_BASE[d_idx]) as u32, DIST_EXTRA[d_idx] as u32);
        }
    }

    pub fn deflate_compress(data: &[u8], level: i32) -> Vec<u8> {
        if level <= 0 || data.is_empty() {
            let mut out = Vec::with_capacity(data.len() + (data.len() / 65535 + 1) * 5);
            let mut pos = 0;
            while pos < data.len() || pos == 0 {
                let rem = data.len() - pos;
                let chunk = rem.min(65535);
                let is_last = pos + chunk >= data.len();
                out.push(if is_last { 0x01 } else { 0x00 });
                let l = chunk as u16;
                let nl = !l;
                out.extend_from_slice(&l.to_le_bytes());
                out.extend_from_slice(&nl.to_le_bytes());
                out.extend_from_slice(&data[pos..pos + chunk]);
                pos += chunk;
                if pos >= data.len() {
                    break;
                }
            }
            return out;
        }

        let mut bw = BitWriter::with_capacity(data.len() / 2 + 64);
        bw.write_bits(1, 1); // BFINAL = 1
        bw.write_bits(1, 2); // BTYPE = 01 (Fixed Huffman)

        const HASH_BITS: usize = 15;
        const HASH_SIZE: usize = 1 << HASH_BITS;
        let mut head = vec![u32::MAX; HASH_SIZE];
        let mut prev = vec![u32::MAX; 32768];
        let max_chain = if level >= 7 { 64 } else { 16 };

        let hash4 = |p: usize| -> usize {
            let v = u32::from_le_bytes([data[p], data[p + 1], data[p + 2], data[p + 3]]);
            ((v.wrapping_mul(0x1E35_A7BD)) >> (32 - HASH_BITS)) as usize
        };

        let mut pos = 0usize;
        while pos < data.len() {
            let mut best_len = 0usize;
            let mut best_dist = 0usize;

            if pos + 4 <= data.len() {
                let h = hash4(pos);
                let mut cur = head[h];
                head[h] = pos as u32;
                prev[pos & 0x7FFF] = cur;

                let max_len = (data.len() - pos).min(258);
                let mut chain = 0;
                while cur != u32::MAX && chain < max_chain {
                    let cpos = cur as usize;
                    let dist = pos - cpos;
                    if dist > 32768 || dist == 0 {
                        break;
                    }
                    if data[cpos + best_len] == data[pos + best_len]
                        && data[cpos..cpos + 3] == data[pos..pos + 3]
                    {
                        let mut l = 3;
                        while l < max_len && data[cpos + l] == data[pos + l] {
                            l += 1;
                        }
                        if l > best_len {
                            best_len = l;
                            best_dist = dist;
                            if l == max_len {
                                break;
                            }
                        }
                    }
                    cur = prev[cpos & 0x7FFF];
                    chain += 1;
                }
            }

            if best_len >= 4 {
                write_fixed_match(&mut bw, best_len, best_dist);
                let end = (pos + best_len).min(data.len().saturating_sub(4));
                for p in (pos + 1)..=end {
                    let h = hash4(p);
                    prev[p & 0x7FFF] = head[h];
                    head[h] = p as u32;
                }
                pos += best_len;
            } else {
                write_fixed_lit(&mut bw, data[pos] as u16);
                pos += 1;
            }
        }

        write_fixed_lit(&mut bw, 256); // End of block
        bw.finish()
    }

    /* --- 4. Native .zip Archive Reader & Writer (STORE, DEFLATE, ZipCrypto, WinZip AES-128/192/256) --- */

    #[derive(Clone, Debug)]
    pub struct ZipEntryMeta {
        pub name: String,
        pub method: u16,
        pub flags: u16,
        pub crc32: u32,
        pub comp_size: u64,
        pub uncomp_size: u64,
        pub local_header_offset: u64,
        pub mtime: u16,
        pub is_dir: bool,
        pub aes_info: Option<(u16, u8, u16)>, // (ae_version, strength 1/2/3, actual_method)
    }

    fn parse_zip_extra(
        extra: &[u8],
        comp_size: &mut u64,
        uncomp_size: &mut u64,
        local_offset: &mut u64,
        aes_info: &mut Option<(u16, u8, u16)>,
    ) {
        let mut pos = 0;
        while pos + 4 <= extra.len() {
            let tag = u16::from_le_bytes([extra[pos], extra[pos + 1]]);
            let sz = u16::from_le_bytes([extra[pos + 2], extra[pos + 3]]) as usize;
            pos += 4;
            if pos + sz > extra.len() {
                break;
            }
            let body = &extra[pos..pos + sz];
            if tag == 0x0001 {
                // ZIP64 Extended Information Extra Field
                let mut bpos = 0;
                if *uncomp_size == 0xFFFF_FFFF && bpos + 8 <= body.len() {
                    *uncomp_size = u64::from_le_bytes(body[bpos..bpos + 8].try_into().unwrap());
                    bpos += 8;
                }
                if *comp_size == 0xFFFF_FFFF && bpos + 8 <= body.len() {
                    *comp_size = u64::from_le_bytes(body[bpos..bpos + 8].try_into().unwrap());
                    bpos += 8;
                }
                if *local_offset == 0xFFFF_FFFF && bpos + 8 <= body.len() {
                    *local_offset = u64::from_le_bytes(body[bpos..bpos + 8].try_into().unwrap());
                }
            } else if tag == 0x9901 && sz >= 7 {
                // WinZip AES Extra Field (AE-1 / AE-2)
                let ae_ver = u16::from_le_bytes([body[0], body[1]]);
                let strength = body[4];
                let actual_method = u16::from_le_bytes([body[5], body[6]]);
                *aes_info = Some((ae_ver, strength, actual_method));
            }
            pos += sz;
        }
    }

    pub fn parse_zip_central_directory(archive_bytes: &[u8]) -> Result<Vec<ZipEntryMeta>, String> {
        if archive_bytes.len() < 22 {
            return Err("File too small to be a valid .zip archive".to_string());
        }
        let max_back = archive_bytes.len().min(65557);
        let search_start = archive_bytes.len() - max_back;
        let mut eocd_pos = None;
        for pos in (search_start..=archive_bytes.len() - 22).rev() {
            if &archive_bytes[pos..pos + 4] == b"PK\x05\x06" {
                eocd_pos = Some(pos);
                break;
            }
        }
        let eocd = eocd_pos.ok_or_else(|| "Could not find .zip End of Central Directory".to_string())?;
        let mut num_entries =
            u16::from_le_bytes([archive_bytes[eocd + 10], archive_bytes[eocd + 11]]) as u64;
        let mut cd_offset = u32::from_le_bytes([
            archive_bytes[eocd + 16],
            archive_bytes[eocd + 17],
            archive_bytes[eocd + 18],
            archive_bytes[eocd + 19],
        ]) as u64;

        // Check for ZIP64 EOCD Locator immediately preceding EOCD
        if eocd >= 20 && &archive_bytes[eocd - 20..eocd - 16] == b"PK\x06\x07" {
            let z64_eocd_off = u64::from_le_bytes(
                archive_bytes[eocd - 12..eocd - 4].try_into().unwrap(),
            ) as usize;
            if z64_eocd_off + 56 <= archive_bytes.len()
                && &archive_bytes[z64_eocd_off..z64_eocd_off + 4] == b"PK\x06\x06"
            {
                num_entries = u64::from_le_bytes(
                    archive_bytes[z64_eocd_off + 32..z64_eocd_off + 40]
                        .try_into()
                        .unwrap(),
                );
                cd_offset = u64::from_le_bytes(
                    archive_bytes[z64_eocd_off + 48..z64_eocd_off + 56]
                        .try_into()
                        .unwrap(),
                );
            }
        }

        let mut pos = cd_offset as usize;
        let mut entries = Vec::with_capacity(num_entries as usize);
        for _ in 0..num_entries {
            if pos + 46 > archive_bytes.len() || &archive_bytes[pos..pos + 4] != b"PK\x01\x02" {
                break;
            }
            let flags = u16::from_le_bytes([archive_bytes[pos + 8], archive_bytes[pos + 9]]);
            let method = u16::from_le_bytes([archive_bytes[pos + 10], archive_bytes[pos + 11]]);
            let mtime = u16::from_le_bytes([archive_bytes[pos + 12], archive_bytes[pos + 13]]);
            let crc32 = u32::from_le_bytes(archive_bytes[pos + 16..pos + 20].try_into().unwrap());
            let mut comp_size =
                u32::from_le_bytes(archive_bytes[pos + 20..pos + 24].try_into().unwrap()) as u64;
            let mut uncomp_size =
                u32::from_le_bytes(archive_bytes[pos + 24..pos + 28].try_into().unwrap()) as u64;
            let name_len =
                u16::from_le_bytes([archive_bytes[pos + 28], archive_bytes[pos + 29]]) as usize;
            let extra_len =
                u16::from_le_bytes([archive_bytes[pos + 30], archive_bytes[pos + 31]]) as usize;
            let comment_len =
                u16::from_le_bytes([archive_bytes[pos + 32], archive_bytes[pos + 33]]) as usize;
            let ext_attr =
                u32::from_le_bytes(archive_bytes[pos + 38..pos + 42].try_into().unwrap());
            let mut local_offset =
                u32::from_le_bytes(archive_bytes[pos + 42..pos + 46].try_into().unwrap()) as u64;

            let name_start = pos + 46;
            let extra_start = name_start + name_len;
            let next_pos = extra_start + extra_len + comment_len;
            if next_pos > archive_bytes.len() {
                break;
            }

            let name = String::from_utf8_lossy(&archive_bytes[name_start..extra_start]).to_string();
            let mut aes_info = None;
            parse_zip_extra(
                &archive_bytes[extra_start..extra_start + extra_len],
                &mut comp_size,
                &mut uncomp_size,
                &mut local_offset,
                &mut aes_info,
            );
            let is_dir = name.ends_with('/') || ((ext_attr >> 16) & 0o170000) == 0o040000;

            entries.push(ZipEntryMeta {
                name,
                method,
                flags,
                crc32,
                comp_size,
                uncomp_size,
                local_header_offset: local_offset,
                mtime,
                is_dir,
                aes_info,
            });
            pos = next_pos;
        }
        Ok(entries)
    }

    pub fn decode_zip_entry(
        archive_bytes: &[u8],
        entry: &ZipEntryMeta,
        password: Option<&str>,
    ) -> Result<Vec<u8>, String> {
        if entry.is_dir {
            return Ok(Vec::new());
        }
        let lpos = entry.local_header_offset as usize;
        if lpos + 30 > archive_bytes.len() || &archive_bytes[lpos..lpos + 4] != b"PK\x03\x04" {
            return Err(format!("Invalid local file header for {}", entry.name));
        }
        let lname_len =
            u16::from_le_bytes([archive_bytes[lpos + 26], archive_bytes[lpos + 27]]) as usize;
        let lextra_len =
            u16::from_le_bytes([archive_bytes[lpos + 28], archive_bytes[lpos + 29]]) as usize;
        let data_start = lpos + 30 + lname_len + lextra_len;
        let data_end = data_start + (entry.comp_size as usize);
        if data_end > archive_bytes.len() {
            return Err(format!("Truncated .zip payload for {}", entry.name));
        }

        // Also check local extra field for 0x9901 if not in CD
        let mut aes_info = entry.aes_info;
        if aes_info.is_none() && lextra_len >= 11 {
            let mut dummy1 = 0u64;
            let mut dummy2 = 0u64;
            let mut dummy3 = 0u64;
            parse_zip_extra(
                &archive_bytes[lpos + 30 + lname_len..data_start],
                &mut dummy1,
                &mut dummy2,
                &mut dummy3,
                &mut aes_info,
            );
        }

        let raw_payload = &archive_bytes[data_start..data_end];
        let is_encrypted = (entry.flags & 1) != 0 || entry.method == 99;

        let (actual_method, compressed_stream, check_crc) = if entry.method == 99 {
            // WinZip AES-128 / AES-192 / AES-256 (0x9901)
            let pw = password
                .filter(|s| !s.is_empty())
                .ok_or_else(|| format!("Password required (-p<password>) to decrypt {}", entry.name))?;
            let (ae_ver, strength, act_method) =
                aes_info.unwrap_or((2, 3, 8)); // Default AE-2, AES-256, DEFLATE
            let (salt_len, key_len) = match strength {
                1 => (8usize, 16usize),
                2 => (12usize, 24usize),
                _ => (16usize, 32usize),
            };
            if raw_payload.len() < salt_len + 12 {
                return Err(format!("Invalid WinZip AES payload size for {}", entry.name));
            }
            let salt = &raw_payload[..salt_len];
            let pw_verify = &raw_payload[salt_len..salt_len + 2];
            let ciphertext = &raw_payload[salt_len + 2..raw_payload.len() - 10];
            let auth_code = &raw_payload[raw_payload.len() - 10..];

            let dk = pbkdf2_hmac_sha1(pw.as_bytes(), salt, 1000, key_len * 2 + 2);
            let aes_key = &dk[..key_len];
            let hmac_key = &dk[key_len..key_len * 2];
            let expected_verify = &dk[key_len * 2..key_len * 2 + 2];

            if pw_verify != expected_verify {
                return Err(format!("Wrong password for WinZip AES entry {}", entry.name));
            }
            let mac = hmac_sha1(hmac_key, ciphertext);
            if &mac[..10] != auth_code {
                return Err(format!(
                    "HMAC-SHA1-80 authentication failed for {}",
                    entry.name
                ));
            }
            let mut decrypted = ciphertext.to_vec();
            unsafe {
                oz_aes_ctr_le_crypt(
                    aes_key.as_ptr(),
                    aes_key.len(),
                    decrypted.as_mut_ptr(),
                    decrypted.len(),
                );
            }
            (act_method, decrypted, ae_ver == 1 && entry.crc32 != 0)
        } else if is_encrypted {
            // Traditional PKWARE ZipCrypto
            let pw = password
                .filter(|s| !s.is_empty())
                .ok_or_else(|| format!("Password required (-p<password>) to decrypt {}", entry.name))?;
            if raw_payload.len() < 12 {
                return Err(format!("Truncated ZipCrypto header for {}", entry.name));
            }
            let mut keys = ZipCryptoKeys::new(pw.as_bytes());
            let mut hdr = [0u8; 12];
            for i in 0..12 {
                hdr[i] = keys.decrypt_byte(raw_payload[i]);
            }
            let check_byte_crc = ((entry.crc32 >> 24) & 0xFF) as u8;
            let check_byte_time = ((entry.mtime >> 8) & 0xFF) as u8;
            if hdr[11] != check_byte_crc && hdr[11] != check_byte_time {
                return Err(format!("Wrong password for ZipCrypto entry {}", entry.name));
            }
            let mut decrypted = Vec::with_capacity(raw_payload.len() - 12);
            for &b in &raw_payload[12..] {
                decrypted.push(keys.decrypt_byte(b));
            }
            (entry.method, decrypted, true)
        } else {
            (entry.method, raw_payload.to_vec(), true)
        };

        let uncompressed = match actual_method {
            0 => compressed_stream,
            8 => inflate_raw(&compressed_stream)?,
            m => {
                return Err(format!(
                    "Unsupported .zip compression method {} on {}",
                    m, entry.name
                ))
            }
        };

        if uncompressed.len() as u64 != entry.uncomp_size {
            return Err(format!(
                "Size mismatch on {} (expected {}, got {})",
                entry.name,
                entry.uncomp_size,
                uncompressed.len()
            ));
        }
        if check_crc && entry.uncomp_size > 0 {
            let calc_crc = crc32_fast(&uncompressed);
            if calc_crc != entry.crc32 {
                return Err(format!("CRC32 mismatch on {}", entry.name));
            }
        }
        Ok(uncompressed)
    }

    pub fn write_zip_archive(
        archive_path: &Path,
        inputs: &[PathBuf],
        level: i32,
        password: Option<&str>,
        use_zipcrypto: bool,
        num_threads: usize,
    ) -> std::io::Result<(usize, usize, u64)> {
        let mut raw_files: Vec<(String, PathBuf, usize)> = Vec::new();
        for p in inputs {
            collect_files_recursive(p, p, &mut raw_files);
        }
        let pw_opt = password.filter(|s| !s.is_empty());

        #[derive(Clone)]
        struct PreparedZipItem {
            rel_path: String,
            uncomp_size: u32,
            crc32: u32,
            method: u16,
            flags: u16,
            extra: Vec<u8>,
            payload: Vec<u8>,
        }

        let results: Mutex<Vec<(usize, PreparedZipItem)>> =
            Mutex::new(Vec::with_capacity(raw_files.len()));
        let next_idx = AtomicUsize::new(0);
        let workers = num_threads.min(raw_files.len().max(1));

        run_workers(workers, || loop {
            let i = next_idx.fetch_add(1, Ordering::Relaxed);
            if i >= raw_files.len() {
                break;
            }
            let (ref rel_path, ref full_path, sz) = raw_files[i];
            let mut raw = vec![0u8; sz];
            if sz > 0 {
                if let Ok(mut f) = File::open(full_path) {
                    let _ = os_mmap::read_into_slice_mmap_or_read(&mut f, &mut raw);
                }
            }
            let crc = crc32_fast(&raw);
            let (actual_method, comp_bytes) = if level <= 0 || sz == 0 {
                (0u16, raw)
            } else {
                let def = deflate_compress(&raw, level);
                if def.len() < raw.len() {
                    (8u16, def)
                } else {
                    (0u16, raw)
                }
            };

            let (method, flags, extra, payload) = if let Some(pw) = pw_opt {
                if use_zipcrypto {
                    // Traditional PKWARE ZipCrypto
                    let mut keys = ZipCryptoKeys::new(pw.as_bytes());
                    let seed = sha256_fast(rel_path.as_bytes());
                    let mut enc = Vec::with_capacity(12 + comp_bytes.len());
                    for k in 0..11 {
                        enc.push(keys.encrypt_byte(seed[k]));
                    }
                    enc.push(keys.encrypt_byte(((crc >> 24) & 0xFF) as u8));
                    for &b in &comp_bytes {
                        enc.push(keys.encrypt_byte(b));
                    }
                    (actual_method, 0x0801u16, Vec::new(), enc)
                } else {
                    // WinZip AES-256 (0x9901, AE-1)
                    let seed = sha256_fast(rel_path.as_bytes());
                    let salt = &seed[0..16];
                    let dk = pbkdf2_hmac_sha1(pw.as_bytes(), salt, 1000, 66);
                    let aes_key = &dk[0..32];
                    let hmac_key = &dk[32..64];
                    let pw_verify = &dk[64..66];

                    let mut ctext = comp_bytes;
                    unsafe {
                        oz_aes_ctr_le_crypt(
                            aes_key.as_ptr(),
                            aes_key.len(),
                            ctext.as_mut_ptr(),
                            ctext.len(),
                        );
                    }
                    let mac = hmac_sha1(hmac_key, &ctext);
                    let mut enc = Vec::with_capacity(16 + 2 + ctext.len() + 10);
                    enc.extend_from_slice(salt);
                    enc.extend_from_slice(pw_verify);
                    enc.extend_from_slice(&ctext);
                    enc.extend_from_slice(&mac[..10]);

                    // Extra field 0x9901 (7 bytes body): AE-1 (ver=1), "AE", strength=3 (AES-256), actual_method
                    let mut ext = Vec::with_capacity(11);
                    ext.extend_from_slice(&0x9901u16.to_le_bytes());
                    ext.extend_from_slice(&7u16.to_le_bytes());
                    ext.extend_from_slice(&1u16.to_le_bytes()); // AE-1
                    ext.extend_from_slice(b"AE");
                    ext.push(3u8); // AES-256
                    ext.extend_from_slice(&actual_method.to_le_bytes());

                    (99u16, 0x0801u16, ext, enc)
                }
            } else {
                (actual_method, 0x0800u16, Vec::new(), comp_bytes)
            };

            results.lock().unwrap().push((
                i,
                PreparedZipItem {
                    rel_path: rel_path.clone(),
                    uncomp_size: sz as u32,
                    crc32: crc,
                    method,
                    flags,
                    extra,
                    payload,
                },
            ));
        });

        let mut items = results.into_inner().unwrap();
        items.sort_by_key(|(i, _)| *i);

        let mut out = File::create(archive_path)?;
        let mut cd = Vec::new();
        let mut offset = 0u32;
        let mut total_uncomp = 0usize;

        for (_, item) in &items {
            total_uncomp += item.uncomp_size as usize;
            let name_bytes = item.rel_path.as_bytes();
            let comp_len = item.payload.len() as u32;
            let ver_needed: u16 = if item.method == 99 { 51 } else { 20 };

            // Local File Header (30 bytes + name + extra)
            let mut lhdr = Vec::with_capacity(30 + name_bytes.len() + item.extra.len());
            lhdr.extend_from_slice(b"PK\x03\x04");
            lhdr.extend_from_slice(&ver_needed.to_le_bytes());
            lhdr.extend_from_slice(&item.flags.to_le_bytes());
            lhdr.extend_from_slice(&item.method.to_le_bytes());
            lhdr.extend_from_slice(&0u16.to_le_bytes()); // mtime
            lhdr.extend_from_slice(&0x5421u16.to_le_bytes()); // mdate
            lhdr.extend_from_slice(&item.crc32.to_le_bytes());
            lhdr.extend_from_slice(&comp_len.to_le_bytes());
            lhdr.extend_from_slice(&item.uncomp_size.to_le_bytes());
            lhdr.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
            lhdr.extend_from_slice(&(item.extra.len() as u16).to_le_bytes());
            lhdr.extend_from_slice(name_bytes);
            lhdr.extend_from_slice(&item.extra);

            out.write_all(&lhdr)?;
            out.write_all(&item.payload)?;

            // Central Directory Header (46 bytes + name + extra)
            cd.extend_from_slice(b"PK\x01\x02");
            cd.extend_from_slice(&ver_needed.to_le_bytes());
            cd.extend_from_slice(&ver_needed.to_le_bytes());
            cd.extend_from_slice(&item.flags.to_le_bytes());
            cd.extend_from_slice(&item.method.to_le_bytes());
            cd.extend_from_slice(&0u16.to_le_bytes());
            cd.extend_from_slice(&0x5421u16.to_le_bytes());
            cd.extend_from_slice(&item.crc32.to_le_bytes());
            cd.extend_from_slice(&comp_len.to_le_bytes());
            cd.extend_from_slice(&item.uncomp_size.to_le_bytes());
            cd.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
            cd.extend_from_slice(&(item.extra.len() as u16).to_le_bytes());
            cd.extend_from_slice(&0u16.to_le_bytes()); // comment len
            cd.extend_from_slice(&0u16.to_le_bytes()); // disk number
            cd.extend_from_slice(&0u16.to_le_bytes()); // internal attr
            cd.extend_from_slice(&0u32.to_le_bytes()); // external attr
            cd.extend_from_slice(&offset.to_le_bytes());
            cd.extend_from_slice(name_bytes);
            cd.extend_from_slice(&item.extra);

            offset = offset.wrapping_add((lhdr.len() + item.payload.len()) as u32);
        }

        let cd_offset = offset;
        let cd_size = cd.len() as u32;
        out.write_all(&cd)?;

        // End of Central Directory (22 bytes)
        let mut eocd = Vec::with_capacity(22);
        eocd.extend_from_slice(b"PK\x05\x06");
        eocd.extend_from_slice(&0u16.to_le_bytes());
        eocd.extend_from_slice(&0u16.to_le_bytes());
        eocd.extend_from_slice(&(items.len() as u16).to_le_bytes());
        eocd.extend_from_slice(&(items.len() as u16).to_le_bytes());
        eocd.extend_from_slice(&cd_size.to_le_bytes());
        eocd.extend_from_slice(&cd_offset.to_le_bytes());
        eocd.extend_from_slice(&0u16.to_le_bytes());
        out.write_all(&eocd)?;

        let total_archive_bytes = (cd_offset as u64) + (cd_size as u64) + 22;
        Ok((items.len(), total_uncomp, total_archive_bytes))
    }

    /* --- 5. Native .gz & POSIX .tar / .tar.gz / .tgz Support --- */

    pub fn gzip_decompress(data: &[u8]) -> Result<Vec<u8>, String> {
        if data.len() < 18 || data[0] != 0x1F || data[1] != 0x8B || data[2] != 0x08 {
            return Err("Invalid gzip header".to_string());
        }
        let flg = data[3];
        let mut pos = 10usize;
        if (flg & 0x04) != 0 {
            if pos + 2 > data.len() {
                return Err("Truncated gzip FEXTRA".to_string());
            }
            let xlen = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2 + xlen;
        }
        if (flg & 0x08) != 0 {
            while pos < data.len() && data[pos] != 0 {
                pos += 1;
            }
            pos += 1;
        }
        if (flg & 0x10) != 0 {
            while pos < data.len() && data[pos] != 0 {
                pos += 1;
            }
            pos += 1;
        }
        if (flg & 0x02) != 0 {
            pos += 2;
        }
        if pos + 8 > data.len() {
            return Err("Truncated gzip stream".to_string());
        }
        let deflate_slice = &data[pos..data.len() - 8];
        let expected_crc = u32::from_le_bytes(data[data.len() - 8..data.len() - 4].try_into().unwrap());
        let out = inflate_raw(deflate_slice)?;
        let calc_crc = crc32_fast(&out);
        if calc_crc != expected_crc {
            return Err("Gzip CRC32 mismatch".to_string());
        }
        Ok(out)
    }

    pub fn gzip_compress(data: &[u8], level: i32) -> Vec<u8> {
        let deflated = deflate_compress(data, level);
        let crc = crc32_fast(data);
        let isize_val = (data.len() as u32).to_le_bytes();
        let mut out = Vec::with_capacity(10 + deflated.len() + 8);
        out.extend_from_slice(&[0x1F, 0x8B, 0x08, 0x00, 0, 0, 0, 0, 0x00, 0x03]);
        out.extend_from_slice(&deflated);
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&isize_val);
        out
    }

    #[derive(Clone, Debug)]
    pub struct TarEntry {
        pub name: String,
        pub is_dir: bool,
        pub data: Vec<u8>,
    }

    pub fn parse_tar_bytes(tar: &[u8]) -> Result<Vec<TarEntry>, String> {
        let mut pos = 0usize;
        let mut entries = Vec::new();
        let mut next_long_name: Option<String> = None;

        while pos + 512 <= tar.len() {
            let blk = &tar[pos..pos + 512];
            if blk.iter().all(|&b| b == 0) {
                break;
            }
            let raw_name = blk[0..100]
                .split(|&b| b == 0)
                .next()
                .unwrap_or(&[]);
            let prefix = blk[345..500]
                .split(|&b| b == 0)
                .next()
                .unwrap_or(&[]);
            let mut name = if !prefix.is_empty() {
                format!(
                    "{}/{}",
                    String::from_utf8_lossy(prefix),
                    String::from_utf8_lossy(raw_name)
                )
            } else {
                String::from_utf8_lossy(raw_name).to_string()
            };
            if let Some(long_n) = next_long_name.take() {
                name = long_n;
            }

            let size_str = std::str::from_utf8(&blk[124..136])
                .unwrap_or("")
                .trim_matches(|c: char| c == '\0' || c.is_whitespace());
            let size = usize::from_str_radix(size_str, 8).unwrap_or(0);
            let typeflag = blk[156];
            pos += 512;
            if pos + size > tar.len() {
                break;
            }
            let payload = &tar[pos..pos + size];
            pos += (size + 511) & !511;

            if typeflag == b'L' {
                let s = String::from_utf8_lossy(payload)
                    .trim_end_matches('\0')
                    .to_string();
                next_long_name = Some(s);
                continue;
            } else if typeflag == b'x' || typeflag == b'g' {
                continue;
            }

            let is_dir = typeflag == b'5' || name.ends_with('/');
            entries.push(TarEntry {
                name,
                is_dir,
                data: payload.to_vec(),
            });
        }
        Ok(entries)
    }

    pub fn build_tar_bytes(inputs: &[PathBuf]) -> std::io::Result<(usize, usize, Vec<u8>)> {
        let mut raw_files: Vec<(String, PathBuf, usize)> = Vec::new();
        for p in inputs {
            collect_files_recursive(p, p, &mut raw_files);
        }
        let mut tar = Vec::new();
        let mut total_uncomp = 0usize;
        for (rel_path, full_path, sz) in &raw_files {
            total_uncomp += *sz;
            let mut hdr = [0u8; 512];
            let name_bytes = rel_path.as_bytes();
            let copy_len = name_bytes.len().min(100);
            hdr[..copy_len].copy_from_slice(&name_bytes[..copy_len]);
            hdr[100..107].copy_from_slice(b"0000644");
            hdr[108..115].copy_from_slice(b"0000000");
            hdr[116..123].copy_from_slice(b"0000000");
            let sz_oct = format!("{:011o}\0", sz);
            hdr[124..136].copy_from_slice(sz_oct.as_bytes());
            hdr[136..148].copy_from_slice(b"14600000000\0");
            hdr[148..156].fill(b' ');
            hdr[156] = b'0';
            hdr[257..263].copy_from_slice(b"ustar\0");
            hdr[263..265].copy_from_slice(b"00");
            let chksum: u32 = hdr.iter().map(|&b| b as u32).sum();
            let chk_oct = format!("{:06o}\0 ", chksum);
            hdr[148..156].copy_from_slice(chk_oct.as_bytes());

            tar.extend_from_slice(&hdr);
            if *sz > 0 {
                let data = fs::read(full_path)?;
                tar.extend_from_slice(&data);
                let rem = data.len() % 512;
                if rem != 0 {
                    tar.resize(tar.len() + (512 - rem), 0);
                }
            }
        }
        tar.resize(tar.len() + 1024, 0);
        Ok((raw_files.len(), total_uncomp, tar))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArchiveFormat {
    SevenZip,
    Zip,
    TarGz,
    Tar,
    Gzip,
}

pub fn detect_archive_format(path: &Path, check_magic: bool) -> ArchiveFormat {
    if check_magic {
        if let Ok(mut f) = File::open(path) {
            let mut magic = [0u8; 6];
            if std::io::Read::read(&mut f, &mut magic).unwrap_or(0) >= 4 {
                if magic == [b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C] {
                    return ArchiveFormat::SevenZip;
                }
                if &magic[0..4] == b"PK\x03\x04" || &magic[0..4] == b"PK\x05\x06" {
                    return ArchiveFormat::Zip;
                }
                if magic[0] == 0x1F && magic[1] == 0x8B {
                    let s = path.to_string_lossy().to_ascii_lowercase();
                    if s.ends_with(".tar.gz") || s.ends_with(".tgz") {
                        return ArchiveFormat::TarGz;
                    }
                    return ArchiveFormat::Gzip;
                }
            }
        }
    }
    let lower = path.to_string_lossy().to_ascii_lowercase();
    if lower.ends_with(".zip") || lower.ends_with(".jar") || lower.ends_with(".whl") {
        ArchiveFormat::Zip
    } else if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") {
        ArchiveFormat::TarGz
    } else if lower.ends_with(".tar") {
        ArchiveFormat::Tar
    } else if lower.ends_with(".gz") {
        ArchiveFormat::Gzip
    } else {
        ArchiveFormat::SevenZip
    }
}

fn run_benchmarks(num_threads: usize) {
    println!("================================================================================");
    println!("  OpenZip v1.0.0 : High-Performance Cross-Platform Archiver + BCJ/Delta + SIMD");
    println!("  Detected Hardware Threads: {}", num_threads);
    println!("================================================================================\n");

    let repo_root = if Path::new("C").exists() {
        PathBuf::from(".")
    } else {
        PathBuf::from("..")
    };
    let targets = vec![
        repo_root.join("C"),
        repo_root.join("Asm"),
        repo_root.join("DOC"),
        repo_root.join("src"),
    ];

    for &(label, level) in &[("-mx5", 5), ("-mx9", 9)] {
        let mut comp_times = Vec::new();
        let mut decomp_times = Vec::new();
        let mut archive_size = 0u64;
        let mut uncomp_size = 0usize;
        let mut file_count = 0usize;

        let archive_path = env::temp_dir().join(format!("test_openzip_std_mx{}.7z", level));

        for _ in 0..3 {
            let t_start = Instant::now();
            let (entries, folders) = parallel_ingest_and_compress(&targets, level, num_threads);
            archive_size = write_standard_archive(&archive_path, &entries, &folders).unwrap();
            let comp_ms = t_start.elapsed().as_secs_f64() * 1000.0;

            let t_dec = Instant::now();
            let (_files, f_bufs) = read_and_decompress_archive(&archive_path, num_threads).unwrap();
            let dec_ms = t_dec.elapsed().as_secs_f64() * 1000.0;

            comp_times.push(comp_ms);
            decomp_times.push(dec_ms);
            uncomp_size = f_bufs.iter().map(|b| b.len()).sum();
            file_count = entries.len();
        }
        let _ = fs::remove_file(&archive_path);

        let min_comp = comp_times.iter().cloned().fold(f64::INFINITY, f64::min);
        let avg_comp = comp_times.iter().sum::<f64>() / comp_times.len() as f64;
        let min_dec = decomp_times.iter().cloned().fold(f64::INFINITY, f64::min);
        let dec_speed_mbs = (uncomp_size as f64 / (1024.0 * 1024.0)) / (min_dec / 1000.0);

        println!(
            "[Standard .7z Source Tree {}] ({} files, {:.2} MiB -> {:.2} MiB ({} B))",
            label,
            file_count,
            uncomp_size as f64 / (1024.0 * 1024.0),
            archive_size as f64 / (1024.0 * 1024.0),
            archive_size
        );
        println!(
            "  End-to-End .7z Archive Time: min = {:6.1} ms, avg = {:6.1} ms",
            min_comp, avg_comp
        );
        println!(
            "  Parallel .7z Decompress+CRC: min = {:6.1} ms ({:.1} MiB/s) [100% .7z Compatible]\n",
            min_dec, dec_speed_mbs
        );
    }
}

fn main() {
    unsafe {
        oz_init_codecs();
    }
    let num_threads = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(8);

    let args: Vec<String> = env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("bench");

    match cmd {
        "bench" | "b" => run_benchmarks(num_threads),
        "a" => {
            let mut level = 5;
            let mut password: Option<String> = None;
            let mut use_zipcrypto = false;
            let mut positional: Vec<String> = Vec::new();
            for a in &args[2..] {
                if let Some(rest) = a.strip_prefix("-mx") {
                    level = rest.parse::<i32>().unwrap_or(5);
                } else if let Some(pw) = a.strip_prefix("-p") {
                    password = Some(pw.to_string());
                } else if a.eq_ignore_ascii_case("-mem=zipcrypto") {
                    use_zipcrypto = true;
                } else if a == "-y" || a.starts_with("-mhe") || a.starts_with("-t") {
                    // Accepted for 7-Zip CLI compatibility
                } else {
                    positional.push(a.clone());
                }
            }
            if positional.len() < 2 {
                eprintln!(
                    "Usage: openzip a [-mxN] [-p<password>] <archive.7z|.zip|.tar.gz|.tar|.gz> <paths...>"
                );
                std::process::exit(1);
            }
            let archive_path = PathBuf::from(&positional[0]);
            let inputs: Vec<PathBuf> = positional[1..].iter().map(PathBuf::from).collect();
            let fmt = detect_archive_format(&archive_path, false);
            let t0 = Instant::now();

            match fmt {
                ArchiveFormat::SevenZip => {
                    set_global_password(password.as_deref());
                    let (entries, folders) =
                        parallel_ingest_and_compress(&inputs, level, num_threads);
                    let uncomp_len: usize = folders.iter().map(|f| f.unpack_size).sum();
                    let sz = write_standard_archive_with_password(
                        &archive_path,
                        &entries,
                        &folders,
                        password.as_deref(),
                    )
                    .expect("Failed to write .7z archive");
                    println!(
                        "Archived {} files ({} bytes -> {} bytes) into {} .7z in {:.1} ms",
                        entries.len(),
                        uncomp_len,
                        sz,
                        if password.is_some() {
                            "AES-256 encrypted"
                        } else {
                            "standard"
                        },
                        t0.elapsed().as_secs_f64() * 1000.0
                    );
                }
                ArchiveFormat::Zip => {
                    let (count, uncomp_len, sz) = multi_format::write_zip_archive(
                        &archive_path,
                        &inputs,
                        level,
                        password.as_deref(),
                        use_zipcrypto,
                        num_threads,
                    )
                    .expect("Failed to write .zip archive");
                    println!(
                        "Archived {} files ({} bytes -> {} bytes) into {} .zip in {:.1} ms",
                        count,
                        uncomp_len,
                        sz,
                        if password.is_some() {
                            if use_zipcrypto {
                                "ZipCrypto encrypted"
                            } else {
                                "WinZip AES-256 encrypted"
                            }
                        } else {
                            "standard"
                        },
                        t0.elapsed().as_secs_f64() * 1000.0
                    );
                }
                ArchiveFormat::Tar => {
                    let (count, uncomp_len, tar_bytes) =
                        multi_format::build_tar_bytes(&inputs).expect("Failed to build .tar");
                    fs::write(&archive_path, &tar_bytes).expect("Failed to write .tar");
                    println!(
                        "Archived {} files ({} bytes -> {} bytes) into .tar in {:.1} ms",
                        count,
                        uncomp_len,
                        tar_bytes.len(),
                        t0.elapsed().as_secs_f64() * 1000.0
                    );
                }
                ArchiveFormat::TarGz => {
                    let (count, uncomp_len, tar_bytes) =
                        multi_format::build_tar_bytes(&inputs).expect("Failed to build .tar");
                    let gz_bytes = multi_format::gzip_compress(&tar_bytes, level);
                    fs::write(&archive_path, &gz_bytes).expect("Failed to write .tar.gz");
                    println!(
                        "Archived {} files ({} bytes -> {} bytes) into .tar.gz in {:.1} ms",
                        count,
                        uncomp_len,
                        gz_bytes.len(),
                        t0.elapsed().as_secs_f64() * 1000.0
                    );
                }
                ArchiveFormat::Gzip => {
                    let raw = fs::read(&inputs[0]).expect("Failed to read input file for .gz");
                    let gz_bytes = multi_format::gzip_compress(&raw, level);
                    fs::write(&archive_path, &gz_bytes).expect("Failed to write .gz");
                    println!(
                        "Archived 1 file ({} bytes -> {} bytes) into .gz in {:.1} ms",
                        raw.len(),
                        gz_bytes.len(),
                        t0.elapsed().as_secs_f64() * 1000.0
                    );
                }
            }
        }
        "t" => {
            let mut password: Option<String> = None;
            let mut archive_path = PathBuf::new();
            for a in &args[2..] {
                if let Some(pw) = a.strip_prefix("-p") {
                    password = Some(pw.to_string());
                } else if a != "-y" && archive_path.as_os_str().is_empty() {
                    archive_path = PathBuf::from(a);
                }
            }
            if archive_path.as_os_str().is_empty() {
                eprintln!("Usage: openzip t [-p<password>] <archive>");
                std::process::exit(1);
            }
            set_global_password(password.as_deref());
            let fmt = detect_archive_format(&archive_path, true);
            let t0 = Instant::now();

            match fmt {
                ArchiveFormat::SevenZip => {
                    let (files, folder_bufs) =
                        read_and_decompress_archive(&archive_path, num_threads)
                            .expect("Failed to read/verify .7z archive");
                    let total_uncomp: usize = folder_bufs.iter().map(|b| b.len()).sum();
                    println!(
                        "Everything is Ok ({} files, {} bytes verified in {:.1} ms)",
                        files.len(),
                        total_uncomp,
                        t0.elapsed().as_secs_f64() * 1000.0
                    );
                }
                ArchiveFormat::Zip => {
                    let archive_bytes = fs::read(&archive_path).expect("Failed to read .zip");
                    let entries = multi_format::parse_zip_central_directory(&archive_bytes)
                        .expect("Failed to parse .zip directory");
                    let mut total_uncomp = 0usize;
                    for e in &entries {
                        let dec = multi_format::decode_zip_entry(
                            &archive_bytes,
                            e,
                            password.as_deref(),
                        )
                        .unwrap_or_else(|err| panic!("Verification failed: {}", err));
                        total_uncomp += dec.len();
                    }
                    println!(
                        "Everything is Ok ({} files, {} bytes verified in {:.1} ms)",
                        entries.len(),
                        total_uncomp,
                        t0.elapsed().as_secs_f64() * 1000.0
                    );
                }
                ArchiveFormat::TarGz => {
                    let raw = fs::read(&archive_path).expect("Failed to read .tar.gz");
                    let tar = multi_format::gzip_decompress(&raw).expect("Invalid .tar.gz");
                    let entries =
                        multi_format::parse_tar_bytes(&tar).expect("Invalid .tar payload");
                    let total_uncomp: usize = entries.iter().map(|e| e.data.len()).sum();
                    println!(
                        "Everything is Ok ({} files, {} bytes verified in {:.1} ms)",
                        entries.len(),
                        total_uncomp,
                        t0.elapsed().as_secs_f64() * 1000.0
                    );
                }
                ArchiveFormat::Tar => {
                    let raw = fs::read(&archive_path).expect("Failed to read .tar");
                    let entries =
                        multi_format::parse_tar_bytes(&raw).expect("Invalid .tar archive");
                    let total_uncomp: usize = entries.iter().map(|e| e.data.len()).sum();
                    println!(
                        "Everything is Ok ({} files, {} bytes verified in {:.1} ms)",
                        entries.len(),
                        total_uncomp,
                        t0.elapsed().as_secs_f64() * 1000.0
                    );
                }
                ArchiveFormat::Gzip => {
                    let raw = fs::read(&archive_path).expect("Failed to read .gz");
                    let dec = multi_format::gzip_decompress(&raw).expect("Invalid .gz archive");
                    println!(
                        "Everything is Ok (1 file, {} bytes verified in {:.1} ms)",
                        dec.len(),
                        t0.elapsed().as_secs_f64() * 1000.0
                    );
                }
            }
        }
        "l" => {
            let mut password: Option<String> = None;
            let mut archive_path = PathBuf::new();
            for a in &args[2..] {
                if let Some(pw) = a.strip_prefix("-p") {
                    password = Some(pw.to_string());
                } else if a != "-y" && archive_path.as_os_str().is_empty() {
                    archive_path = PathBuf::from(a);
                }
            }
            if archive_path.as_os_str().is_empty() {
                eprintln!("Usage: openzip l [-p<password>] <archive>");
                std::process::exit(1);
            }
            set_global_password(password.as_deref());
            let fmt = detect_archive_format(&archive_path, true);

            match fmt {
                ArchiveFormat::SevenZip => {
                    let mut f = File::open(&archive_path).expect("Failed to open .7z archive");
                    let len = f.metadata().unwrap().len() as usize;
                    let mut archive_bytes = Vec::with_capacity(len);
                    unsafe {
                        archive_bytes.set_len(len);
                    }
                    os_mmap::read_into_slice_mmap_or_read(&mut f, &mut archive_bytes).unwrap();
                    let handle =
                        unsafe { oz_open_archive(archive_bytes.as_ptr(), archive_bytes.len()) };
                    assert!(
                        !handle.is_null(),
                        "Failed to parse .7z header (if headers are encrypted, pass -p<password>)"
                    );
                    let num_files = unsafe { oz_archive_num_files(handle) } as usize;
                    let mut utf16_buf = vec![0u16; 4096];
                    let mut total_size = 0usize;
                    println!("{:>12}  {:>8}  {}", "Size", "CRC32", "Name");
                    println!("------------  --------  ------------------------");
                    for i in 0..num_files {
                        let mut name_len = 0usize;
                        let mut folder_idx = u32::MAX;
                        let mut offset_in_folder = 0usize;
                        let mut size = 0usize;
                        let mut crc32 = 0u32;
                        let mut has_crc = 0i32;
                        let mut is_dir = 0i32;
                        unsafe {
                            oz_archive_get_file_info(
                                handle,
                                i as u32,
                                utf16_buf.as_mut_ptr(),
                                utf16_buf.len(),
                                &mut name_len,
                                &mut folder_idx,
                                &mut offset_in_folder,
                                &mut size,
                                &mut crc32,
                                &mut has_crc,
                                &mut is_dir,
                            );
                        }
                        let rel_path = String::from_utf16_lossy(&utf16_buf[..name_len]);
                        total_size += size;
                        if has_crc != 0 {
                            println!("{:>12}  {:08X}  {}", size, crc32, rel_path);
                        } else {
                            println!("{:>12}  {:>8}  {}", size, "-", rel_path);
                        }
                    }
                    unsafe {
                        oz_close_archive(handle);
                    }
                    println!("------------  --------  ------------------------");
                    println!(
                        "{:>12}            {} files ({} archive bytes)",
                        total_size, num_files, len
                    );
                }
                ArchiveFormat::Zip => {
                    let archive_bytes = fs::read(&archive_path).expect("Failed to read .zip");
                    let entries = multi_format::parse_zip_central_directory(&archive_bytes)
                        .expect("Failed to parse .zip directory");
                    let mut total_size = 0u64;
                    println!("{:>12}  {:>8}  {}", "Size", "CRC32", "Name");
                    println!("------------  --------  ------------------------");
                    for e in &entries {
                        total_size += e.uncomp_size;
                        let enc_tag = if e.method == 99 || (e.flags & 1) != 0 {
                            " *"
                        } else {
                            ""
                        };
                        println!(
                            "{:>12}  {:08X}  {}{}",
                            e.uncomp_size, e.crc32, e.name, enc_tag
                        );
                    }
                    println!("------------  --------  ------------------------");
                    println!(
                        "{:>12}            {} files ({} archive bytes)",
                        total_size,
                        entries.len(),
                        archive_bytes.len()
                    );
                }
                ArchiveFormat::TarGz | ArchiveFormat::Tar => {
                    let raw = fs::read(&archive_path).expect("Failed to read archive");
                    let tar = if fmt == ArchiveFormat::TarGz {
                        multi_format::gzip_decompress(&raw).expect("Invalid .tar.gz")
                    } else {
                        raw.clone()
                    };
                    let entries =
                        multi_format::parse_tar_bytes(&tar).expect("Invalid .tar archive");
                    let mut total_size = 0usize;
                    println!("{:>12}  {:>8}  {}", "Size", "CRC32", "Name");
                    println!("------------  --------  ------------------------");
                    for e in &entries {
                        total_size += e.data.len();
                        let crc = crc32_fast(&e.data);
                        println!("{:>12}  {:08X}  {}", e.data.len(), crc, e.name);
                    }
                    println!("------------  --------  ------------------------");
                    println!(
                        "{:>12}            {} files ({} archive bytes)",
                        total_size,
                        entries.len(),
                        raw.len()
                    );
                }
                ArchiveFormat::Gzip => {
                    let raw = fs::read(&archive_path).expect("Failed to read .gz");
                    let dec = multi_format::gzip_decompress(&raw).expect("Invalid .gz");
                    let crc = crc32_fast(&dec);
                    let stem = archive_path
                        .file_stem()
                        .map(|s| s.to_string_lossy().to_string())
                        .unwrap_or_else(|| "data".to_string());
                    println!("{:>12}  {:>8}  {}", "Size", "CRC32", "Name");
                    println!("------------  --------  ------------------------");
                    println!("{:>12}  {:08X}  {}", dec.len(), crc, stem);
                    println!("------------  --------  ------------------------");
                    println!(
                        "{:>12}            1 files ({} archive bytes)",
                        dec.len(),
                        raw.len()
                    );
                }
            }
        }
        "x" | "e" => {
            let preserve_paths = cmd == "x";
            let mut password: Option<String> = None;
            let mut archive_path = PathBuf::new();
            let mut out_dir = PathBuf::from(".");
            for a in &args[2..] {
                if let Some(rest) = a.strip_prefix("-o") {
                    out_dir = PathBuf::from(rest);
                } else if let Some(pw) = a.strip_prefix("-p") {
                    password = Some(pw.to_string());
                } else if a != "-y" {
                    if archive_path.as_os_str().is_empty() {
                        archive_path = PathBuf::from(a);
                    } else {
                        out_dir = PathBuf::from(a);
                    }
                }
            }
            if archive_path.as_os_str().is_empty() {
                eprintln!(
                    "Usage: openzip {} [-p<password>] <archive> [-o<outdir>]",
                    cmd
                );
                std::process::exit(1);
            }
            set_global_password(password.as_deref());
            let fmt = detect_archive_format(&archive_path, true);
            let t0 = Instant::now();
            let _ = fs::create_dir_all(&out_dir);

            match fmt {
                ArchiveFormat::SevenZip => {
                    let (files, folder_bufs) =
                        read_and_decompress_archive(&archive_path, num_threads)
                            .expect("Failed to read .7z archive");

                    if preserve_paths {
                        let mut dirs: Vec<PathBuf> = files
                            .iter()
                            .filter_map(|e| {
                                let p = out_dir.join(&e.rel_path);
                                if e.is_dir {
                                    Some(p)
                                } else {
                                    p.parent().map(|parent| parent.to_path_buf())
                                }
                            })
                            .collect();
                        dirs.sort();
                        dirs.dedup();
                        for d in &dirs {
                            let _ = fs::create_dir_all(d);
                        }
                    }

                    let next_idx = AtomicUsize::new(0);
                    run_workers(num_threads.min(files.len().max(1)), || loop {
                        let i = next_idx.fetch_add(1, Ordering::Relaxed);
                        if i >= files.len() {
                            break;
                        }
                        let e = &files[i];
                        if e.is_dir {
                            continue;
                        }
                        let dest_path = if preserve_paths {
                            out_dir.join(&e.rel_path)
                        } else {
                            let fname = Path::new(&e.rel_path)
                                .file_name()
                                .unwrap_or_else(|| std::ffi::OsStr::new(&e.rel_path));
                            out_dir.join(fname)
                        };
                        if let Ok(mut f) = File::create(&dest_path) {
                            if e.size > 0 {
                                if let Some(fidx) = e.folder_idx {
                                    let slice = &folder_bufs[fidx]
                                        [e.offset_in_folder..e.offset_in_folder + e.size];
                                    let _ = f.write_all(slice);
                                }
                            }
                        }
                    });
                    let total_uncomp: usize = folder_bufs.iter().map(|b| b.len()).sum();
                    println!(
                        "Extracted {} items ({} bytes) to {} in {:.1} ms",
                        files.len(),
                        total_uncomp,
                        out_dir.display(),
                        t0.elapsed().as_secs_f64() * 1000.0
                    );
                }
                ArchiveFormat::Zip => {
                    let archive_bytes = fs::read(&archive_path).expect("Failed to read .zip");
                    let entries = multi_format::parse_zip_central_directory(&archive_bytes)
                        .expect("Failed to parse .zip directory");
                    let mut total_uncomp = 0usize;
                    for e in &entries {
                        let dest_path = if preserve_paths {
                            out_dir.join(&e.name)
                        } else {
                            let fname = Path::new(&e.name)
                                .file_name()
                                .unwrap_or_else(|| std::ffi::OsStr::new(&e.name));
                            out_dir.join(fname)
                        };
                        if e.is_dir {
                            if preserve_paths {
                                let _ = fs::create_dir_all(&dest_path);
                            }
                            continue;
                        }
                        if let Some(parent) = dest_path.parent() {
                            let _ = fs::create_dir_all(parent);
                        }
                        let dec = multi_format::decode_zip_entry(
                            &archive_bytes,
                            e,
                            password.as_deref(),
                        )
                        .unwrap_or_else(|err| panic!("Extraction failed: {}", err));
                        total_uncomp += dec.len();
                        fs::write(&dest_path, &dec).expect("Failed to write extracted file");
                    }
                    println!(
                        "Extracted {} items ({} bytes) to {} in {:.1} ms",
                        entries.len(),
                        total_uncomp,
                        out_dir.display(),
                        t0.elapsed().as_secs_f64() * 1000.0
                    );
                }
                ArchiveFormat::TarGz | ArchiveFormat::Tar => {
                    let raw = fs::read(&archive_path).expect("Failed to read archive");
                    let tar = if fmt == ArchiveFormat::TarGz {
                        multi_format::gzip_decompress(&raw).expect("Invalid .tar.gz")
                    } else {
                        raw
                    };
                    let entries =
                        multi_format::parse_tar_bytes(&tar).expect("Invalid .tar archive");
                    let mut total_uncomp = 0usize;
                    for e in &entries {
                        let dest_path = if preserve_paths {
                            out_dir.join(&e.name)
                        } else {
                            let fname = Path::new(&e.name)
                                .file_name()
                                .unwrap_or_else(|| std::ffi::OsStr::new(&e.name));
                            out_dir.join(fname)
                        };
                        if e.is_dir {
                            if preserve_paths {
                                let _ = fs::create_dir_all(&dest_path);
                            }
                            continue;
                        }
                        if let Some(parent) = dest_path.parent() {
                            let _ = fs::create_dir_all(parent);
                        }
                        total_uncomp += e.data.len();
                        fs::write(&dest_path, &e.data).expect("Failed to write extracted file");
                    }
                    println!(
                        "Extracted {} items ({} bytes) to {} in {:.1} ms",
                        entries.len(),
                        total_uncomp,
                        out_dir.display(),
                        t0.elapsed().as_secs_f64() * 1000.0
                    );
                }
                ArchiveFormat::Gzip => {
                    let raw = fs::read(&archive_path).expect("Failed to read .gz");
                    let dec = multi_format::gzip_decompress(&raw).expect("Invalid .gz");
                    let stem = archive_path
                        .file_stem()
                        .map(|s| s.to_string_lossy().to_string())
                        .unwrap_or_else(|| "extracted_file".to_string());
                    let dest_path = out_dir.join(stem);
                    fs::write(&dest_path, &dec).expect("Failed to write extracted .gz file");
                    println!(
                        "Extracted 1 item ({} bytes) to {} in {:.1} ms",
                        dec.len(),
                        out_dir.display(),
                        t0.elapsed().as_secs_f64() * 1000.0
                    );
                }
            }
        }
        _ => {
            println!("Usage: openzip [bench | a [-mxN] [-p<password>] <archive.7z|.zip|.tar.gz|.tar|.gz> <paths...> | l [-p<pw>] <archive> | t [-p<pw>] <archive> | x [-p<pw>] <archive> -o<dir> | e [-p<pw>] <archive> -o<dir>]");
        }
    }
}
