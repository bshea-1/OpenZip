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

/* ---------- AES-128/192/256 (CBC & CTR) + .7z AES-256 + WinZip AES (PBKDF2-HMAC-SHA1) ---------- */

static const uint8_t OZ_AES_SBOX[256] = {
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t OZ_AES_INV_SBOX[256] = {
  0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
  0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
  0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
  0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
  0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
  0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
  0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
  0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
  0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
  0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
  0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
  0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
  0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
  0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
  0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
  0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

static const uint8_t OZ_AES_RCON[11] = {
  0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

typedef struct {
  uint8_t round_key[240];
  unsigned nr;
} OzAesCtx;

static void oz_aes_init(OzAesCtx *ctx, const uint8_t *key, unsigned key_bytes)
{
  unsigned nk = key_bytes >> 2;
  ctx->nr = nk + 6;
  unsigned total_words = 4 * (ctx->nr + 1);
  memcpy(ctx->round_key, key, key_bytes);
  uint8_t temp[4];
  for (unsigned i = nk; i < total_words; i++)
  {
    memcpy(temp, &ctx->round_key[(i - 1) * 4], 4);
    if (i % nk == 0)
    {
      uint8_t t = temp[0];
      temp[0] = OZ_AES_SBOX[temp[1]] ^ OZ_AES_RCON[i / nk];
      temp[1] = OZ_AES_SBOX[temp[2]];
      temp[2] = OZ_AES_SBOX[temp[3]];
      temp[3] = OZ_AES_SBOX[t];
    }
    else if (nk > 6 && (i % nk == 4))
    {
      temp[0] = OZ_AES_SBOX[temp[0]];
      temp[1] = OZ_AES_SBOX[temp[1]];
      temp[2] = OZ_AES_SBOX[temp[2]];
      temp[3] = OZ_AES_SBOX[temp[3]];
    }
    for (unsigned j = 0; j < 4; j++)
      ctx->round_key[i * 4 + j] = ctx->round_key[(i - nk) * 4 + j] ^ temp[j];
  }
}

static inline uint8_t oz_gf_xtime(uint8_t x)
{
  return (uint8_t)((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

static inline uint8_t oz_gf_mul(uint8_t x, uint8_t y)
{
  return (uint8_t)(((y & 1) * x) ^
         (((y >> 1) & 1) * oz_gf_xtime(x)) ^
         (((y >> 2) & 1) * oz_gf_xtime(oz_gf_xtime(x))) ^
         (((y >> 3) & 1) * oz_gf_xtime(oz_gf_xtime(oz_gf_xtime(x)))));
}

static void oz_aes_encrypt_block(const OzAesCtx *ctx, uint8_t s[16])
{
  for (unsigned i = 0; i < 16; i++) s[i] ^= ctx->round_key[i];
  for (unsigned r = 1; r <= ctx->nr; r++)
  {
    for (unsigned i = 0; i < 16; i++) s[i] = OZ_AES_SBOX[s[i]];
    uint8_t t;
    t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
    t = s[2]; s[2] = s[10]; s[10] = t; t = s[6]; s[6] = s[14]; s[14] = t;
    t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;
    if (r < ctx->nr)
    {
      for (unsigned c = 0; c < 4; c++)
      {
        uint8_t *col = s + c * 4;
        uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
        uint8_t all = a0 ^ a1 ^ a2 ^ a3;
        col[0] ^= all ^ oz_gf_xtime(a0 ^ a1);
        col[1] ^= all ^ oz_gf_xtime(a1 ^ a2);
        col[2] ^= all ^ oz_gf_xtime(a2 ^ a3);
        col[3] ^= all ^ oz_gf_xtime(a3 ^ a0);
      }
    }
    const uint8_t *rk = ctx->round_key + r * 16;
    for (unsigned i = 0; i < 16; i++) s[i] ^= rk[i];
  }
}

static void oz_aes_decrypt_block(const OzAesCtx *ctx, uint8_t s[16])
{
  const uint8_t *rk = ctx->round_key + ctx->nr * 16;
  for (unsigned i = 0; i < 16; i++) s[i] ^= rk[i];
  for (unsigned r = ctx->nr; r >= 1; r--)
  {
    uint8_t t;
    t = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = t;
    t = s[2]; s[2] = s[10]; s[10] = t; t = s[6]; s[6] = s[14]; s[14] = t;
    t = s[3]; s[3] = s[7]; s[7] = s[11]; s[11] = s[15]; s[15] = t;
    for (unsigned i = 0; i < 16; i++) s[i] = OZ_AES_INV_SBOX[s[i]];
    rk = ctx->round_key + (r - 1) * 16;
    for (unsigned i = 0; i < 16; i++) s[i] ^= rk[i];
    if (r > 1)
    {
      for (unsigned c = 0; c < 4; c++)
      {
        uint8_t *col = s + c * 4;
        uint8_t a = col[0], b = col[1], d = col[2], e = col[3];
        col[0] = oz_gf_mul(a, 0x0e) ^ oz_gf_mul(b, 0x0b) ^ oz_gf_mul(d, 0x0d) ^ oz_gf_mul(e, 0x09);
        col[1] = oz_gf_mul(a, 0x09) ^ oz_gf_mul(b, 0x0e) ^ oz_gf_mul(d, 0x0b) ^ oz_gf_mul(e, 0x0d);
        col[2] = oz_gf_mul(a, 0x0d) ^ oz_gf_mul(b, 0x09) ^ oz_gf_mul(d, 0x0e) ^ oz_gf_mul(e, 0x0b);
        col[3] = oz_gf_mul(a, 0x0b) ^ oz_gf_mul(b, 0x0d) ^ oz_gf_mul(d, 0x09) ^ oz_gf_mul(e, 0x0e);
      }
    }
  }
}

static uint8_t g_oz_pw_utf16le[512];
static size_t  g_oz_pw_len = 0;
static int     g_oz_cache_valid = 0;
static uint8_t g_oz_cache_cycles = 0;
static uint8_t g_oz_cache_salt[16];
static size_t  g_oz_cache_salt_len = 0;
static uint8_t g_oz_cache_key[32];

void oz_set_password(const uint8_t *pw_utf16le, size_t pw_byte_len)
{
  if (pw_byte_len > sizeof(g_oz_pw_utf16le))
    pw_byte_len = sizeof(g_oz_pw_utf16le);
  if (pw_byte_len > 0 && pw_utf16le)
    memcpy(g_oz_pw_utf16le, pw_utf16le, pw_byte_len);
  g_oz_pw_len = pw_byte_len;
  g_oz_cache_valid = 0;
}

void oz_7zaes_derive_key(
    unsigned num_cycles_power,
    const uint8_t *salt,
    size_t salt_len,
    const uint8_t *pw_utf16le,
    size_t pw_len,
    uint8_t out_key[32])
{
  if (num_cycles_power == 0x3F)
  {
    memset(out_key, 0, 32);
    size_t pos = 0;
    for (size_t i = 0; i < salt_len && pos < 32; i++) out_key[pos++] = salt[i];
    for (size_t i = 0; i < pw_len && pos < 32; i++) out_key[pos++] = pw_utf16le[i];
    return;
  }

  CSha256 sha;
  Sha256_Init(&sha);
  uint64_t num_rounds = 1ULL << num_cycles_power;
  uint8_t buf[560];
  size_t base_len = 0;
  if (salt_len > 0)
  {
    memcpy(buf, salt, salt_len);
    base_len += salt_len;
  }
  if (pw_len > 0)
  {
    memcpy(buf + base_len, pw_utf16le, pw_len);
    base_len += pw_len;
  }
  for (uint64_t r = 0; r < num_rounds; r++)
  {
    for (unsigned b = 0; b < 8; b++)
      buf[base_len + b] = (uint8_t)(r >> (b * 8));
    Sha256_Update(&sha, (const Byte *)buf, base_len + 8);
  }
  Sha256_Final(&sha, (Byte *)out_key);
}

int oz_7zaes_decrypt_inplace(const Byte *props, unsigned propsSize, Byte *data, size_t dataSize)
{
  if (propsSize < 1 || (dataSize & 15) != 0)
    return -1;
  uint8_t b0 = props[0];
  uint8_t b1 = (propsSize >= 2) ? props[1] : 0;
  unsigned num_cycles = b0 & 0x3Fu;
  size_t salt_len = (b0 & 0x80u) ? (size_t)(((b0 >> 7) & 1u) + (b1 >> 4)) : 0;
  size_t iv_len   = (b0 & 0x40u) ? (size_t)(((b0 >> 6) & 1u) + (b1 & 0x0Fu)) : 0;
  size_t hdr_bytes = ((b0 & 0xC0u) != 0) ? 2 : 1;
  if (hdr_bytes + salt_len + iv_len > propsSize)
    return -1;

  const uint8_t *salt = props + hdr_bytes;
  uint8_t iv[16];
  memset(iv, 0, 16);
  if (iv_len > 0)
    memcpy(iv, props + hdr_bytes + salt_len, iv_len < 16 ? iv_len : 16);

  uint8_t key[32];
  if (g_oz_cache_valid
      && g_oz_cache_cycles == num_cycles
      && g_oz_cache_salt_len == salt_len
      && (salt_len == 0 || memcmp(g_oz_cache_salt, salt, salt_len) == 0))
  {
    memcpy(key, g_oz_cache_key, 32);
  }
  else
  {
    oz_7zaes_derive_key(num_cycles, salt, salt_len, g_oz_pw_utf16le, g_oz_pw_len, key);
    g_oz_cache_valid = 1;
    g_oz_cache_cycles = (uint8_t)num_cycles;
    g_oz_cache_salt_len = salt_len;
    if (salt_len > 0)
      memcpy(g_oz_cache_salt, salt, salt_len);
    memcpy(g_oz_cache_key, key, 32);
  }

  OzAesCtx ctx;
  oz_aes_init(&ctx, key, 32);
  uint8_t prev[16];
  memcpy(prev, iv, 16);
  for (size_t off = 0; off < dataSize; off += 16)
  {
    uint8_t next_prev[16];
    memcpy(next_prev, data + off, 16);
    oz_aes_decrypt_block(&ctx, data + off);
    for (unsigned i = 0; i < 16; i++)
      data[off + i] ^= prev[i];
    memcpy(prev, next_prev, 16);
  }
  return 0;
}

void oz_7zaes_encrypt_cbc(
    unsigned num_cycles,
    const uint8_t *salt,
    size_t salt_len,
    const uint8_t iv[16],
    const uint8_t *pw_utf16le,
    size_t pw_len,
    uint8_t *data,
    size_t data_size)
{
  uint8_t key[32];
  oz_7zaes_derive_key(num_cycles, salt, salt_len, pw_utf16le, pw_len, key);
  OzAesCtx ctx;
  oz_aes_init(&ctx, key, 32);
  uint8_t prev[16];
  memcpy(prev, iv, 16);
  for (size_t off = 0; off < data_size; off += 16)
  {
    for (unsigned i = 0; i < 16; i++)
      data[off + i] ^= prev[i];
    oz_aes_encrypt_block(&ctx, data + off);
    memcpy(prev, data + off, 16);
  }
}

void oz_aes_ctr_le_crypt(const uint8_t *key, size_t key_len, uint8_t *data, size_t data_len)
{
  OzAesCtx ctx;
  oz_aes_init(&ctx, key, (unsigned)key_len);
  uint8_t ctr[16];
  memset(ctr, 0, 16);
  uint8_t ks[16];
  size_t off = 0;
  while (off < data_len)
  {
    /* WinZip AES uses 1-based little-endian counter in bytes 0..15 */
    for (unsigned i = 0; i < 16; i++)
    {
      if (++ctr[i] != 0)
        break;
    }
    memcpy(ks, ctr, 16);
    oz_aes_encrypt_block(&ctx, ks);
    size_t chunk = (data_len - off < 16) ? (data_len - off) : 16;
    for (size_t i = 0; i < chunk; i++)
      data[off + i] ^= ks[i];
    off += chunk;
  }
}

