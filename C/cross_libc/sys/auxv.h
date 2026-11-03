#ifndef CROSS_SYS_AUXV_H
#define CROSS_SYS_AUXV_H
#define AT_HWCAP 16
#define AT_HWCAP2 26
#define HWCAP_FP (1 << 0)
#define HWCAP_ASIMD (1 << 1)
#define HWCAP_AES (1 << 3)
#define HWCAP_PMULL (1 << 4)
#define HWCAP_SHA1 (1 << 5)
#define HWCAP_SHA2 (1 << 6)
#define HWCAP_CRC32 (1 << 7)
#define HWCAP_SHA3 (1 << 17)
#define HWCAP_SHA512 (1 << 21)
unsigned long getauxval(unsigned long type);
#endif
