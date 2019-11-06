#ifndef OCE_H
#define OCE_H

#ifdef __cplusplus
extern "C"
{
#endif /** __cplusplus */

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
#endif /** OCE_WITH_MD5 */

#if OCE_WITH_AES
/**
 * AES 128/192/256 ECB encode with default PADDING_PKCS7.
 *
 * @param[in]  plain_text
 *             The plain text byte array you want to encode.
 *
 * @param[in]  plain_text_len
 *             The length of plain_text.
 *
 * @param[in]  key
 *             The 16/24/32 bytes key.
 *
 * @param[out] aes_cipher_text
 *             The encoded cipher text output. The capacity should be large
 *             enough to contain the cipher text.
 *
 * @return     The length of aes_cipher_text.
 */
int aes128_ecb_encode(const unsigned char *plain_text, int plain_text_len, const unsigned char key[16], unsigned char *aes_cipher_text);
int aes192_ecb_encode(const unsigned char *plain_text, int plain_text_len, const unsigned char key[24], unsigned char *aes_cipher_text);
int aes256_ecb_encode(const unsigned char *plain_text, int plain_text_len, const unsigned char key[32], unsigned char *aes_cipher_text);

/**
 * AES 128/192/256 ECB decode with default PADDING_PKCS7.
 *
 * @param[in]  aes_cipher_text
 *             The plain text byte array you want to encode.
 *
 * @param[in]  aes_cipher_text_len
 *             The length of aes_cipher_text.
 *
 * @param[in]  key
 *             The 16/24/32 bytes key.
 *
 * @param[out] plain_text
 *             The plain text byte array output. The capacity should be large
 *             enough to contain the plain text.
 *
 * @return     The length of plain_text.
 */
int aes128_ecb_decode(const unsigned char *aes_cipher_text, int aes_cipher_text_len, const unsigned char key[16], unsigned char *plain_text);
int aes192_ecb_decode(const unsigned char *aes_cipher_text, int aes_cipher_text_len, const unsigned char key[24], unsigned char *plain_text);
int aes256_ecb_decode(const unsigned char *aes_cipher_text, int aes_cipher_text_len, const unsigned char key[32], unsigned char *plain_text);

/**
 * AES 128/192/256 CBC encode with default PADDING_PKCS7.
 *
 * @param[in]  plain_text
 *             The plain text byte array you want to encode.
 *
 * @param[in]  plain_text_len
 *             The length of plain_text.
 *
 * @param[in]  key
 *             The 16/24/32 bytes key.
 *
 * @param[in]  iv
 *             The 16 bytes initialization vector.
 *
 * @param[out] aes_cipher_text
 *             The encoded cipher text output. The capacity should be large
 *             enough to contain the cipher text.
 *
 * @return     The length of aes_cipher_text.
 */
int aes128_cbc_encode(const unsigned char *plain_text, int plain_text_len, const unsigned char key[16], const unsigned char iv[16], unsigned char *aes_cipher_text);
int aes192_cbc_encode(const unsigned char *plain_text, int plain_text_len, const unsigned char key[16], const unsigned char iv[16], unsigned char *aes_cipher_text);
int aes256_cbc_encode(const unsigned char *plain_text, int plain_text_len, const unsigned char key[16], const unsigned char iv[16], unsigned char *aes_cipher_text);

/**
 * AES 128/192/256 CBC decode with default PADDING_PKCS7.
 *
 * @param[in]  aes_cipher_text
 *             The plain text byte array you want to encode.
 *
 * @param[in]  aes_cipher_text_len
 *             The length of aes_cipher_text.
 *
 * @param[in]  key
 *             The 16/24/32 bytes key.
 *
 * @param[in]  iv
 *             The 16 bytes initialization vector.
 *
 * @param[out] plain_text
 *             The plain text byte array output. The capacity should be large
 *             enough to contain the plain text.
 *
 * @return     The length of plain_text.
 */
int aes128_cbc_decode(const unsigned char *aes_cipher_text, int aes_cipher_text_len, const unsigned char key[16], const unsigned char iv[16], unsigned char *plain_text);
int aes192_cbc_decode(const unsigned char *aes_cipher_text, int aes_cipher_text_len, const unsigned char key[16], const unsigned char iv[16], unsigned char *plain_text);
int aes256_cbc_decode(const unsigned char *aes_cipher_text, int aes_cipher_text_len, const unsigned char key[16], const unsigned char iv[16], unsigned char *plain_text);
#endif /** OCE_WITH_AES */

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
#endif /** OCE_WITH_BASE64 */

#ifdef __cplusplus
}
#endif /** __cplusplus */

#endif /** OCE_H */
