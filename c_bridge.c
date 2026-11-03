/* c_bridge.c -- Cross-platform C ABI bridge between OpenZip (Rust) and C/ASM SIMD kernels */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "C/Precomp.h"
#include "C/CpuArch.h"
#include "C/OzCrc.h"
#include "C/XzCrc64.h"
#include "C/Sha256.h"
#include "C/Alloc.h"
#include "C/LzmaEnc.h"
#include "C/Lzma2Enc.h"
#include "C/Lzma2Dec.h"
#include "C/Bra.h"
#include "C/Delta.h"
#include "C/OzArc.h"

void oz_init_codecs(void)
{
  CrcGenerateTable();
  Crc64GenerateTable();
  Sha256Prepare();
}

uint32_t oz_crc32(uint32_t crc, const uint8_t *data, size_t size)
{
  return CrcUpdate(crc, data, size);
}

uint64_t oz_crc64(uint64_t crc, const uint8_t *data, size_t size)
{
  return Crc64Update(crc, data, size);
}

void oz_sha256(const uint8_t *data, size_t size, uint8_t out_digest[32])
{
  CSha256 sha;
  Sha256_Init(&sha);
  Sha256_Update(&sha, (const Byte *)data, size);
  Sha256_Final(&sha, (Byte *)out_digest);
}

/* Unaligned-safe ARM64 Branch-Call-Jump (BL + ADRP) filter matching C/Bra.c */
static void oz_arm64_conv(uint8_t *p, size_t size, uint32_t pc, int encoding)
{
  const uint32_t flag = (uint32_t)1 << (24 - 4);
  const uint32_t mask = ((uint32_t)1 << 24) - (flag << 1);
  size &= ~(size_t)3;
  const uint8_t *lim = p + size;
  pc -= (uint32_t)(uintptr_t)p;
  pc -= 4;

  while (p != lim)
  {
    uint32_t v = GetUi32(p);
    p += 4;
    if (((v - 0x94000000u) & 0xfc000000u) == 0)
    {
      uint32_t c = (pc + (uint32_t)(uintptr_t)p) >> 2;
      if (encoding)
        v += c;
      else
        v -= c;
      v &= 0x03ffffffu;
      v |= 0x94000000u;
      SetUi32(p - 4, v);
      continue;
    }
    v -= 0x90000000u;
    if ((v & 0x9f000000u) == 0)
    {
      uint32_t z, c;
      v += flag;
      if (v & mask)
        continue;
      z = (v & 0xffffffe0u) | (v >> 26);
      c = ((pc + (uint32_t)(uintptr_t)p) >> (12 - 3)) & ~(uint32_t)7;
      if (encoding)
        z += c;
      else
        z -= c;
      v &= 0x1fu;
      v |= 0x90000000u;
      v |= z << 26;
      v |= 0x00ffffe0u & ((z & ((flag << 1) - 1)) - flag);
      SetUi32(p - 4, v);
    }
  }
}

void oz_filter_arm64_enc(uint8_t *data, size_t size)
{
  oz_arm64_conv(data, size, 0, 1);
}

void oz_filter_arm64_dec(uint8_t *data, size_t size)
{
  oz_arm64_conv(data, size, 0, 0);
}

void oz_filter_x86_enc(uint8_t *data, size_t size)
{
  UInt32 state = Z7_BRANCH_CONV_ST_X86_STATE_INIT_VAL;
  z7_BranchConvSt_X86_Enc((Byte *)data, (SizeT)size, 0, &state);
}

void oz_filter_x86_dec(uint8_t *data, size_t size)
{
  UInt32 state = Z7_BRANCH_CONV_ST_X86_STATE_INIT_VAL;
  z7_BranchConvSt_X86_Dec((Byte *)data, (SizeT)size, 0, &state);
}

void oz_filter_delta_enc(uint8_t *data, size_t size, unsigned delta)
{
  Byte state[DELTA_STATE_SIZE];
  Delta_Init(state);
  Delta_Encode(state, delta, (Byte *)data, (SizeT)size);
}

void oz_filter_delta_dec(uint8_t *data, size_t size, unsigned delta)
{
  Byte state[DELTA_STATE_SIZE];
  Delta_Init(state);
  Delta_Decode(state, delta, (Byte *)data, (SizeT)size);
}

/* Fast-path check for cryptographic random / incompressible data:
   Tests 4x 1024-byte slices (4096 bytes) for uniform byte distribution AND zero 4-byte repeats. */
static int oz_is_incompressible_random(const uint8_t *src, size_t src_len)
{
  if (src_len < 65536)
    return 0;
  uint32_t counts[256];
  memset(counts, 0, sizeof(counts));
  uint16_t htab[512];
  memset(htab, 0xFF, sizeof(htab));
  unsigned collisions = 0;

  const size_t step = src_len / 4;
  for (unsigned s = 0; s < 4; s++)
  {
    const uint8_t *p = src + s * step;
    for (unsigned i = 0; i < 1024; i++)
      counts[p[i]]++;
    for (unsigned i = 0; i + 4 <= 1024; i += 4)
    {
      uint32_t v = GetUi32(p + i);
      uint32_t h = (v * 0x9E3779B1u) >> 23;
      uint16_t tag = (uint16_t)(v & 0xFFFFu);
      if (htab[h] == tag)
        collisions++;
      htab[h] = tag;
    }
  }
  if (collisions > 2)
    return 0;
  for (unsigned i = 0; i < 256; i++)
  {
    if (counts[i] < 2 || counts[i] > 38)
      return 0;
  }
  return 1;
}

int oz_lzma2_compress_block(
    const uint8_t *src,
    size_t src_len,
    uint8_t *dst,
    size_t *dst_len,
    int level,
    uint32_t dict_size,
    int num_threads,
    uint8_t *out_prop)
{
  if (oz_is_incompressible_random(src, src_len))
  {
    size_t pos = 0;
    size_t rem = src_len;
    size_t dpos = 0;
    const size_t max_out = *dst_len;
    *out_prop = 0;
    while (rem > 0)
    {
      uint32_t u = (rem < (1u << 16)) ? (uint32_t)rem : (1u << 16);
      if (dpos + u + 4 > max_out)
        return SZ_ERROR_OUTPUT_EOF;
      dst[dpos++] = (uint8_t)(pos == 0 ? 1 : 2);
      dst[dpos++] = (uint8_t)((u - 1) >> 8);
      dst[dpos++] = (uint8_t)(u - 1);
      memcpy(dst + dpos, src + pos, u);
      dpos += u;
      pos += u;
      rem -= u;
    }
    dst[dpos++] = 0;
    *dst_len = dpos;
    return SZ_OK;
  }

  CLzma2EncHandle enc = Lzma2Enc_Create(&g_AlignedAlloc, &g_BigAlloc);
  if (!enc)
    return SZ_ERROR_MEM;

  CLzma2EncProps props;
  Lzma2EncProps_Init(&props);
  props.lzmaProps.level = level;
  props.lzmaProps.dictSize = dict_size;
  props.lzmaProps.reduceSize = (UInt64)src_len;
  if (level <= 5)
  {
    props.lzmaProps.algo = 0;
    props.lzmaProps.btMode = 0;
    props.lzmaProps.numHashBytes = 4;
    props.lzmaProps.mc = 48;
    props.lzmaProps.fb = 64;
    props.lzmaProps.numThreads = 1;
    props.numTotalThreads = 1;
  }
  else
  {
    props.lzmaProps.numThreads = (num_threads > 1) ? 2 : 1;
    props.numTotalThreads = (num_threads > 1) ? 2 : 1;
  }
  props.blockSize = LZMA2_ENC_PROPS_BLOCK_SIZE_SOLID;
  props.numBlockThreads_Max = 1;

  SRes res = Lzma2Enc_SetProps(enc, &props);
  if (res != SZ_OK)
  {
    Lzma2Enc_Destroy(enc);
    return (int)res;
  }

  Lzma2Enc_SetDataSize(enc, (UInt64)src_len);
  *out_prop = (uint8_t)Lzma2Enc_WriteProperties(enc);

  res = Lzma2Enc_Encode2(
      enc,
      NULL,
      (Byte *)dst,
      dst_len,
      NULL,
      (const Byte *)src,
      src_len,
      NULL);

  Lzma2Enc_Destroy(enc);
  return (int)res;
}

int oz_lzma2_decompress_block(
    const uint8_t *src,
    size_t src_len,
    uint8_t *dst,
    size_t *dst_len,
    uint8_t prop,
    int finish_end)
{
  SizeT d_len = (SizeT)(*dst_len);
  SizeT s_len = (SizeT)src_len;
  ELzmaStatus status = LZMA_STATUS_NOT_SPECIFIED;

  SRes res = Lzma2Decode(
      (Byte *)dst,
      &d_len,
      (const Byte *)src,
      &s_len,
      (Byte)prop,
      finish_end ? LZMA_FINISH_END : LZMA_FINISH_ANY,
      &status,
      &g_AlignedAlloc);

  *dst_len = (size_t)d_len;
  return (int)res;
}

/* ---------- Official .7z Archive Reader Bridge (via C/OzArcIn.c & C/OzDec.c) ---------- */

typedef struct
{
  ILookInStream vt;
  const uint8_t *data;
  size_t size;
  size_t pos;
} CMemLookInStream;

static SRes MemLook_Look(ILookInStreamPtr pp, const void **buf, size_t *size)
{
  CMemLookInStream *p = Z7_CONTAINER_FROM_VTBL(pp, CMemLookInStream, vt);
  size_t rem = (p->pos <= p->size) ? (p->size - p->pos) : 0;
  if (*size > rem)
    *size = rem;
  *buf = p->data + p->pos;
  return SZ_OK;
}

static SRes MemLook_Skip(ILookInStreamPtr pp, size_t offset)
{
  CMemLookInStream *p = Z7_CONTAINER_FROM_VTBL(pp, CMemLookInStream, vt);
  p->pos += offset;
  return SZ_OK;
}

static SRes MemLook_Read(ILookInStreamPtr pp, void *buf, size_t *size)
{
  CMemLookInStream *p = Z7_CONTAINER_FROM_VTBL(pp, CMemLookInStream, vt);
  size_t rem = (p->pos <= p->size) ? (p->size - p->pos) : 0;
  if (*size > rem)
    *size = rem;
  if (*size != 0)
  {
    memcpy(buf, p->data + p->pos, *size);
    p->pos += *size;
  }
  return SZ_OK;
}

static SRes MemLook_Seek(ILookInStreamPtr pp, Int64 *pos, ESzSeek origin)
{
  CMemLookInStream *p = Z7_CONTAINER_FROM_VTBL(pp, CMemLookInStream, vt);
  Int64 new_pos = 0;
  switch (origin)
  {
    case SZ_SEEK_SET: new_pos = *pos; break;
    case SZ_SEEK_CUR: new_pos = (Int64)p->pos + *pos; break;
    case SZ_SEEK_END: new_pos = (Int64)p->size + *pos; break;
    default: return SZ_ERROR_PARAM;
  }
  if (new_pos < 0 || (size_t)new_pos > p->size)
    return SZ_ERROR_PARAM;
  p->pos = (size_t)new_pos;
  *pos = new_pos;
  return SZ_OK;
}

typedef struct
{
  CMemLookInStream stream;
  CSzArEx db;
} OzArchiveReader;

void *oz_open_archive(const uint8_t *archive_data, size_t archive_len)
{
  OzArchiveReader *r = (OzArchiveReader *)malloc(sizeof(OzArchiveReader));
  if (!r)
    return NULL;
  r->stream.vt.Look = MemLook_Look;
  r->stream.vt.Skip = MemLook_Skip;
  r->stream.vt.Read = MemLook_Read;
  r->stream.vt.Seek = MemLook_Seek;
  r->stream.data = archive_data;
  r->stream.size = archive_len;
  r->stream.pos = 0;

  SzArEx_Init(&r->db);
  if (SzArEx_Open(&r->db, &r->stream.vt, &g_AlignedAlloc, &g_AlignedAlloc) != SZ_OK)
  {
    SzArEx_Free(&r->db, &g_AlignedAlloc);
    free(r);
    return NULL;
  }
  return r;
}

void oz_close_archive(void *handle)
{
  if (!handle)
    return;
  OzArchiveReader *r = (OzArchiveReader *)handle;
  SzArEx_Free(&r->db, &g_AlignedAlloc);
  free(r);
}

uint32_t oz_archive_num_files(const void *handle)
{
  const OzArchiveReader *r = (const OzArchiveReader *)handle;
  return r->db.NumFiles;
}

uint32_t oz_archive_num_folders(const void *handle)
{
  const OzArchiveReader *r = (const OzArchiveReader *)handle;
  return r->db.db.NumFolders;
}

/* Filter IDs matching Rust:
   0 = NONE, 1 = BCJ_X86, 2 = BCJ_ARM64, 3 = DELTA_1, 4 = DELTA_2, 5 = DELTA_4 */
int oz_archive_get_folder_info(
    const void *handle,
    uint32_t folder_idx,
    const uint8_t **out_pack_ptr,
    size_t *out_pack_len,
    size_t *out_unpack_len,
    uint8_t *out_lzma2_prop,
    uint8_t *out_filter_id,
    int *out_can_parallel_lzma2)
{
  const OzArchiveReader *r = (const OzArchiveReader *)handle;
  const CSzAr *db = &r->db.db;
  if (folder_idx >= db->NumFolders)
    return -1;

  *out_unpack_len = (size_t)SzAr_GetFolderUnpackSize(db, folder_idx);
  *out_filter_id = 0;
  *out_lzma2_prop = 0;
  *out_can_parallel_lzma2 = 0;

  CSzFolder folder;
  CSzData sd;
  const Byte *props_data = db->CodersData + db->FoCodersOffsets[folder_idx];
  sd.Data = props_data;
  sd.Size = db->FoCodersOffsets[folder_idx + 1] - db->FoCodersOffsets[folder_idx];

  if (SzGetNextFolderItem(&folder, &sd) != SZ_OK)
    return -1;

  if (folder.NumPackStreams == 1 && folder.Coders[0].MethodID == 0x21 && folder.Coders[0].PropsSize == 1)
  {
    uint32_t pack_idx = db->FoStartPackStreamIndex[folder_idx];
    uint64_t pack_off = r->db.dataPos + db->PackPositions[pack_idx];
    uint64_t pack_sz = db->PackPositions[pack_idx + 1] - db->PackPositions[pack_idx];
    *out_pack_ptr = r->stream.data + (size_t)pack_off;
    *out_pack_len = (size_t)pack_sz;
    *out_lzma2_prop = props_data[folder.Coders[0].PropsOffset];

    if (folder.NumCoders == 1)
    {
      *out_can_parallel_lzma2 = 1;
      return 0;
    }
    else if (folder.NumCoders == 2 && folder.NumBonds == 1
        && folder.Bonds[0].InIndex == 1 && folder.Bonds[0].OutIndex == 0)
    {
      uint32_t m1 = folder.Coders[1].MethodID;
      if (m1 == 0x03030103u && folder.Coders[1].PropsSize == 0) /* k_BCJ x86 */
      {
        *out_filter_id = 1;
        *out_can_parallel_lzma2 = 1;
        return 0;
      }
      else if (m1 == 0x0Au && folder.Coders[1].PropsSize == 0) /* k_ARM64 */
      {
        *out_filter_id = 2;
        *out_can_parallel_lzma2 = 1;
        return 0;
      }
      else if (m1 == 0x03u && folder.Coders[1].PropsSize == 1) /* k_Delta */
      {
        unsigned d = (unsigned)props_data[folder.Coders[1].PropsOffset] + 1;
        if (d == 1) { *out_filter_id = 3; *out_can_parallel_lzma2 = 1; return 0; }
        if (d == 2) { *out_filter_id = 4; *out_can_parallel_lzma2 = 1; return 0; }
        if (d == 4) { *out_filter_id = 5; *out_can_parallel_lzma2 = 1; return 0; }
      }
    }
  }

  *out_pack_ptr = NULL;
  *out_pack_len = 0;
  return 0;
}

int oz_archive_decode_folder_fallback(
    void *handle,
    uint32_t folder_idx,
    uint8_t *dst,
    size_t unpack_len)
{
  OzArchiveReader *r = (OzArchiveReader *)handle;
  return (int)SzAr_DecodeFolder(
      &r->db.db,
      folder_idx,
      &r->stream.vt,
      r->db.dataPos,
      (Byte *)dst,
      unpack_len,
      &g_AlignedAlloc);
}

int oz_archive_get_file_info(
    const void *handle,
    uint32_t file_idx,
    uint16_t *name_utf16_buf,
    size_t name_utf16_cap,
    size_t *out_name_len,
    uint32_t *out_folder_idx,
    size_t *out_offset_in_folder,
    size_t *out_size,
    uint32_t *out_crc32,
    int *out_has_crc,
    int *out_is_dir)
{
  const OzArchiveReader *r = (const OzArchiveReader *)handle;
  const CSzArEx *db = &r->db;
  if (file_idx >= db->NumFiles)
    return -1;

  *out_is_dir = SzArEx_IsDir(db, file_idx) ? 1 : 0;
  *out_size = (size_t)SzArEx_GetFileSize(db, file_idx);
  *out_folder_idx = db->FileToFolder[file_idx];
  if (*out_folder_idx != (uint32_t)-1)
  {
    uint32_t first_file = db->FolderToFile[*out_folder_idx];
    *out_offset_in_folder = (size_t)(db->UnpackPositions[file_idx] - db->UnpackPositions[first_file]);
  }
  else
  {
    *out_offset_in_folder = 0;
  }

  if (SzBitWithVals_Check(&db->CRCs, file_idx))
  {
    *out_has_crc = 1;
    *out_crc32 = db->CRCs.Vals[file_idx];
  }
  else
  {
    *out_has_crc = 0;
    *out_crc32 = 0;
  }

  size_t req_len = SzArEx_GetFileNameUtf16(db, file_idx, NULL);
  if (req_len > 0 && req_len <= name_utf16_cap)
  {
    SzArEx_GetFileNameUtf16(db, file_idx, (UInt16 *)name_utf16_buf);
    *out_name_len = req_len - 1; /* exclude trailing NUL */
  }
  else
  {
    *out_name_len = 0;
  }
  return 0;
}
