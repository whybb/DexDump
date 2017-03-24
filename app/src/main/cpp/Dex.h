/*
 *
 * Header file for the definitions of Dexheader and DexOptHeader
 *
 * 
 */


#ifdef HAVE_STDINT_H
#include <stdint.h>    /* C99 */
typedef uint8_t             u1;
typedef uint16_t            u2;
typedef uint32_t            u4;
typedef uint64_t            u8;
typedef int8_t              s1;
typedef int16_t             s2;
typedef int32_t             s4;
typedef int64_t             s8;
#else
typedef unsigned char       u1;
typedef unsigned short      u2;
typedef unsigned int        u4;
typedef unsigned long long  u8;
typedef signed char         s1;
typedef signed short        s2;
typedef signed int          s4;
typedef signed long long    s8;
#endif

/*
 * define kSHA1DigestLen
 */
enum { kSHA1DigestLen = 20,
       kSHA1DigestOutputLen = kSHA1DigestLen*2 +1 };

/*
 * define DexHeader ---the real magic is just zhe  fileSize
 */
typedef struct DexHeader {
    u1  magic[8];           /* includes version number */
    u4  checksum;           /* adler32 checksum */
    u1  signature[kSHA1DigestLen]; /* SHA-1 hash */
    u4  fileSize;           /* length of entire file */
    u4  headerSize;         /* offset to start of next section */
    u4  endianTag;
    u4  linkSize;
    u4  linkOff;
    u4  mapOff;
    u4  stringIdsSize;
    u4  stringIdsOff;
    u4  typeIdsSize;
    u4  typeIdsOff;
    u4  protoIdsSize;
    u4  protoIdsOff;
    u4  fieldIdsSize;
    u4  fieldIdsOff;
    u4  methodIdsSize;
    u4  methodIdsOff;
    u4  classDefsSize;
    u4  classDefsOff;
    u4  dataSize;
    u4  dataOff;
} DexHeader;

/*
 * define DexOptHeader ---we can not use this head to fet really Odex length 
 */
typedef struct DexOptHeader {
    u1  magic[8];
    u4  dexOffset;
    u4  dexLength;
    u4  depsOffset;
    u4  depsLength;
    u4  optOffset;
    u4  optLength;
    u4  flags;
    u4  checksum;
}DexOptHeader;
