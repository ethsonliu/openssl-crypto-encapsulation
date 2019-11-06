#include "oce.h"

#include <stdio.h>
#include <string.h>

#if OCE_WITH_MD5
#include <openssl/md5.h>
#endif

#if OCE_WITH_AES
#include <openssl/evp.h>
#endif

#if OCE_WITH_BASE64
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#endif

void to_hex(const unsigned char *byte_array, int byte_array_len, char *hex)
{
    for (int i = 0; i < byte_array_len; ++i)
        sprintf(hex + i * 2, "%02x", byte_array[i]);
}

#if OCE_WITH_MD5
void md5_string(const char *str, unsigned char digest[16])
{
    MD5((const unsigned char *)str, strlen(str), digest);
}

void md5_file(const char *filename, unsigned char digest[16])
{
    FILE *file = fopen(filename, "rb");
    if (file)
    {
        MD5_CTX context;
        MD5_Init(&context);

        int len = 0;
        unsigned char buffer[1024];

        while (len = fread(buffer, 1, 1024, file))
            MD5_Update(&context, buffer, len);

        MD5_Final(digest, &context);

        fclose(file);
    }
}
#endif /** OCE_WITH_MD5 */

#if OCE_WITH_AES
int aes128_ecb_encode(const unsigned char *plain_text, int plain_text_len, const unsigned char key[16], unsigned char *aes_cipher_text)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);

    int len = 0;
    int outlen = 0;

    EVP_EncryptUpdate(ctx, aes_cipher_text, &outlen, plain_text, plain_text_len);

    len += outlen;
    aes_cipher_text += outlen;

    EVP_EncryptFinal_ex(ctx, aes_cipher_text, &outlen);
    len += outlen;

    EVP_CIPHER_CTX_free(ctx);

    return len;
}

int aes128_ecb_decode(const unsigned char *aes_cipher_text, int aes_cipher_text_len, const unsigned char key[16], unsigned char *plain_text)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);

    int len = 0;
    int outlen = 0;

    EVP_DecryptUpdate(ctx, plain_text, &outlen, aes_cipher_text, aes_cipher_text_len);
    len += outlen;
    plain_text += outlen;

    EVP_DecryptFinal_ex(ctx, plain_text, &outlen);
    len += outlen;

    EVP_CIPHER_CTX_free(ctx);

    return len;
}

int aes192_ecb_encode(const unsigned char *plain_text, int plain_text_len, const unsigned char key[24], unsigned char *aes_cipher_text)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    EVP_EncryptInit_ex(ctx, EVP_aes_192_ecb(), NULL, key, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);

    int len = 0;
    int outlen = 0;

    EVP_EncryptUpdate(ctx, aes_cipher_text, &outlen, plain_text, plain_text_len);
    len += outlen;
    aes_cipher_text += outlen;

    EVP_EncryptFinal_ex(ctx, aes_cipher_text, &outlen);
    len += outlen;

    EVP_CIPHER_CTX_free(ctx);

    return len;
}

int aes192_ecb_decode(const unsigned char *aes_cipher_text, int aes_cipher_text_len, const unsigned char key[24], unsigned char *plain_text)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();;

    EVP_DecryptInit_ex(ctx, EVP_aes_192_ecb(), NULL, key, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);

    int len = 0;
    int outlen = 0;

    EVP_DecryptUpdate(ctx, plain_text, &outlen, aes_cipher_text, aes_cipher_text_len);
    len += outlen;
    plain_text += outlen;

    EVP_DecryptFinal_ex(ctx, plain_text, &outlen);
    len += outlen;

    EVP_CIPHER_CTX_free(ctx);

    return len;
}

int aes256_ecb_encode(const unsigned char *plain_text, int plain_text_len, const unsigned char key[32], unsigned char *aes_cipher_text)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);

    int len = 0;
    int outlen = 0;

    EVP_EncryptUpdate(ctx, aes_cipher_text, &outlen, plain_text, plain_text_len);
    len += outlen;
    aes_cipher_text += outlen;

    EVP_EncryptFinal_ex(ctx, aes_cipher_text, &outlen);
    len += outlen;

    EVP_CIPHER_CTX_free(ctx);

    return len;
}

int aes256_ecb_decode(const unsigned char *aes_cipher_text, int aes_cipher_text_len, const unsigned char key[32], unsigned char *plain_text)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);

    int len = 0;
    int outlen = 0;

    EVP_DecryptUpdate(ctx, plain_text, &outlen, aes_cipher_text, aes_cipher_text_len);
    len += outlen;
    plain_text += outlen;

    EVP_DecryptFinal_ex(ctx, plain_text, &outlen);
    len += outlen;

    EVP_CIPHER_CTX_free(ctx);

    return len;
}

int aes128_cbc_encode(const unsigned char *plain_text, int plain_text_len, const unsigned char key[16], const unsigned char iv[16], unsigned char *aes_cipher_text)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();;

    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);

    int len = 0;
    int outlen = 0;

    EVP_EncryptUpdate(ctx, aes_cipher_text, &outlen, plain_text, plain_text_len);
    len += outlen;
    aes_cipher_text += outlen;

    EVP_EncryptFinal_ex(ctx, aes_cipher_text, &outlen);
    len += outlen;

    EVP_CIPHER_CTX_free(ctx);

    return len;
}

int aes128_cbc_decode(const unsigned char *aes_cipher_text, int aes_cipher_text_len, const unsigned char key[16], const unsigned char iv[16], unsigned char *plain_text)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();;

    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);

    int len = 0;
    int outlen = 0;

    EVP_DecryptUpdate(ctx, plain_text, &outlen, aes_cipher_text, aes_cipher_text_len);
    len += outlen;
    plain_text += outlen;

    EVP_DecryptFinal_ex(ctx, plain_text, &outlen);
    len += outlen;

    EVP_CIPHER_CTX_free(ctx);

    return len;
}

int aes192_cbc_encode(const unsigned char *plain_text, int plain_text_len, const unsigned char key[16], const unsigned char iv[16], unsigned char *aes_cipher_text)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();;

    EVP_EncryptInit_ex(ctx, EVP_aes_192_cbc(), NULL, key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);

    int len = 0;
    int outlen = 0;

    EVP_EncryptUpdate(ctx, aes_cipher_text, &outlen, plain_text, plain_text_len);
    len += outlen;
    aes_cipher_text += outlen;

    EVP_EncryptFinal_ex(ctx, aes_cipher_text, &outlen);
    len += outlen;

    EVP_CIPHER_CTX_free(ctx);

    return len;
}

int aes192_cbc_decode(const unsigned char *aes_cipher_text, int aes_cipher_text_len, const unsigned char key[16], const unsigned char iv[16], unsigned char *plain_text)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();;

    EVP_DecryptInit_ex(ctx, EVP_aes_192_cbc(), NULL, key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);

    int len = 0;
    int outlen = 0;

    EVP_DecryptUpdate(ctx, plain_text, &outlen, aes_cipher_text, aes_cipher_text_len);
    len += outlen;
    plain_text += outlen;

    EVP_DecryptFinal_ex(ctx, plain_text, &outlen);
    len += outlen;

    EVP_CIPHER_CTX_free(ctx);

    return len;
}

int aes256_cbc_encode(const unsigned char *plain_text, int plain_text_len, const unsigned char key[16], const unsigned char iv[16], unsigned char *aes_cipher_text)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);

    int len = 0;
    int outlen = 0;

    EVP_EncryptUpdate(ctx, aes_cipher_text, &outlen, plain_text, plain_text_len);
    len += outlen;
    aes_cipher_text += outlen;

    EVP_EncryptFinal_ex(ctx, aes_cipher_text, &outlen);
    len += outlen;

    EVP_CIPHER_CTX_free(ctx);

    return len;
}

int aes256_cbc_decode(const unsigned char *aes_cipher_text, int aes_cipher_text_len, const unsigned char key[16], const unsigned char iv[16], unsigned char *plain_text)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();;

    EVP_DecryptInit_ex(ctx, EVP_aes_192_cbc(), NULL, key, iv);
    EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);

    int len = 0;
    int outlen = 0;

    EVP_DecryptUpdate(ctx, plain_text, &outlen, aes_cipher_text, aes_cipher_text_len);
    len += outlen;
    plain_text += outlen;

    EVP_DecryptFinal_ex(ctx, plain_text, &outlen);
    len += outlen;

    EVP_CIPHER_CTX_free(ctx);

    return len;
}
#endif /** OCE_WITH_AES */

#if OCE_WITH_BASE64
int base64_encode(const unsigned char *plain_text, int plain_text_len, char *base64_string)
{
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *mem = BIO_new(BIO_s_mem());

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, mem);
    BIO_write(b64, plain_text, plain_text_len);
    BIO_flush(b64);

    char *output = NULL;
    int len = 0;

    len = BIO_get_mem_data(mem, &output);
    memcpy(base64_string, output, len);
    base64_string[len] = '\0';

    BIO_free_all(b64);

    return len;
}

int base64_decode(const char *base64_string, int base64_string_len, unsigned char *plain_text)
{
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *mem = BIO_new_mem_buf(base64_string, -1);

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, mem);

    int len = 0;
    len = BIO_read(b64, plain_text, base64_string_len);

    BIO_free_all(b64);

    return len;
}
#endif /** OCE_WITH_BASE64 */
