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
 *             The length of byte_array.
 *
 * @param[out] hex
 *             The hex output. The capacity should be large enough to contain
 *             the hex string, byte_array_len * 2 + 1 is advisable.
 */
void to_hex(const unsigned char *byte_array, int byte_array_len, char *hex);

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

#if OCE_WITH_BASE64

#define BASE64_ENCODE_OUT_SIZE(n) ((((n) + 2) / 3) * 4 + 1)
#define BASE64_DECODE_OUT_SIZE(n) (((n) / 4) * 3)

/**
 * Base64 encode.
 *
 * @param[in]  plain_text
 *             The plain text byte array you want to encode.
 *
 * @param[in]  plain_text_len
 *             The length of plain_text.
 *
 * @param[out] base64_string
 *             The encoded base64 string output with a null character terminator. The capacity
 *             should be large enough to contain the encoded string, you can use
 *             BASE64_ENCODE_OUT_SIZE(byte_array_len) directly.
 *
 * @return     The length of base64_string.
 */
int base64_encode(const unsigned char *plain_text, int plain_text_len, char *base64_string);

/**
 * Base64 decode.
 *
 * @param[in]  base64_string
 *             The base64 encoded string.
 *
 * @param[in]  base64_string_len
 *             The length of base64_string.
 *
 * @param[out] plain_text
 *             The plain text byte array output. The capacity should be large enough
 *             to contain the byte array, you can use BASE64_DECODE_OUT_SIZE(byte_array_len)
 *             directly.
 *
 * @return     The length of plain_text.
 */
int base64_decode(const char *base64_string, int base64_string_len, unsigned char *plain_text);
#endif

#ifdef __cplusplus
}
#endif

#endif
