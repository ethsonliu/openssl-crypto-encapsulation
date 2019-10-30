#include "oce.h"

#include <stdio.h>
#include <string.h>

#if OCE_WITH_MD5
#include <openssl/md5.h>
#endif

void to_hex(unsigned char *byte_array, int byte_array_len, char *hex)
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
#endif
