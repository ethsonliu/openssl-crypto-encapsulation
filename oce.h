#ifndef OCE_H
#define OCE_H

#ifdef __cplusplus
extern "C"
{
#endif

#define OCE_YES 1
#define OCE_NO  0

/**
 * To reduce compilation links, you can use the below macros to disable what
 * you don't use.
 *
 * Default all is enabled.
 */
#define OCE_WITH_MD5    OCE_YES
#define OCE_WITH_AES    OCE_YES
#define OCE_WITH_BASE64 OCE_YES

/**
 * Returns a hex encoded copy of the byte array. The hex encoding uses the
 * numbers 0-9 and the lowercase letters a-f.
 *
 * @param[in]  byte_array
 *             The byte array you want to encode.
 *
 * @param[in]  byte_array_len
 *             The length of param byte_array.
 *
 * @param[out] hex
 *             The hex output. The capacity should be large enough to contain
 *             the hex string, byte_array_len * 2 + 1 is advisable.
 */
void to_hex(unsigned char *byte_array, int byte_array_len, char *hex);

#if OCE_WITH_MD5
/**
 * Digest a string.
 *
 * @param[in]  str
 *             A valid string.
 *
 * @param[out] digest
 *             16 bytes digest output.
 */
void md5_string(const char *str, unsigned char digest[16]);

/**
 * Digest a file.
 *
 * @param[in]  filename
 *             A valid file.
 *
 * @param[out] digest
 *             16 bytes digest output.
 */
void md5_file(const char *filename, unsigned char digest[16]);
#endif

#ifdef __cplusplus
}
#endif

#endif
