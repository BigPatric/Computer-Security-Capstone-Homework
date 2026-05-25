#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define BUFSIZE 4096

int encrypt_file(unsigned char *__key, unsigned char *__iv, char *input, char *output)
{
    int retval;

    FILE *infp = fopen(input, "rb");
    FILE *outfp = fopen(output, "wb");
    if (!infp || !outfp) {
        retval = -1;
        goto close_file;
    }
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        retval = -1;
        goto free_ctx;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, __key, __iv) != 1) {
        retval = -1;
        goto free_ctx;
    }

    unsigned char *inbuf = malloc(BUFSIZE);
    unsigned char *outbuf = malloc(BUFSIZE + EVP_MAX_BLOCK_LENGTH);
    if (!inbuf || !outbuf) {
        retval = -1;
        goto free_buf;
    }

    size_t total_len = 0;
    size_t read_bytes;
    int outlen = 0;

    while ((read_bytes = fread(inbuf, 1, BUFSIZE, infp)) > 0) {
        if (EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, read_bytes) != 1) {
            retval = -1;
            goto free_buf;
        }
        total_len += fwrite(outbuf, 1, outlen, outfp);
    }

    if (EVP_EncryptFinal_ex(ctx, outbuf, &outlen) != 1) {
        retval = -1;
        goto free_buf;
    }
    total_len += fwrite(outbuf, 1, outlen, outfp);

    retval = total_len;

free_buf:
    free(inbuf);
    free(outbuf);
free_ctx:
    EVP_CIPHER_CTX_free(ctx);
close_file:
    fclose(infp);
    fclose(outfp);

    return retval;
}

int decrypt_file(unsigned char *__key, unsigned char *__iv, char *input, char *output)
{
    int retval;

    FILE *infp = fopen(input, "rb");
    FILE *outfp = fopen(output, "wb");
    if (!infp || !outfp) {
        retval = -1;
        goto close_file;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        retval = -1;
        goto free_ctx;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, __key, __iv) != 1) {
        retval = -1;
        goto free_ctx;
    }

    char *inbuf = malloc(BUFSIZE);
    char *outbuf = malloc(BUFSIZE + EVP_MAX_BLOCK_LENGTH);
    if (!inbuf || !outbuf) {
        retval = -1;
        goto free_buf;
    }

    size_t total_len = 0;
    size_t read_bytes;
    int outlen = 0;

    while ((read_bytes = fread(inbuf, 1, BUFSIZE, infp)) > 0) {
        if (EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, read_bytes) != 1) {
            retval = -1;
            goto free_buf;
        }
        total_len += fwrite(outbuf, 1, outlen, outfp);
    }

    if (EVP_DecryptFinal_ex(ctx, outbuf, &outlen) != 1) {
        retval = -1;
        goto free_buf;
    }
    total_len += fwrite(outbuf, 1, outlen, outfp);

    retval = total_len;

free_buf:
    free(inbuf);
    free(outbuf);
free_ctx:
    EVP_CIPHER_CTX_free(ctx);
close_file:
    fclose(infp);
    fclose(outfp);

    return retval;
}

int main(int argc, char *argv[])
{
    if (argc != 6) {
        printf("Usage: %s [enc/dec] [key] [iv] [input] [output]\n", argv[0]);
        return -1;
    }

    unsigned char *key = (unsigned char *)argv[2];
    unsigned char *iv  = (unsigned char *)argv[3];

    if (strcasecmp(argv[1], "enc") == 0) {
        encrypt_file(key, iv, argv[4], argv[5]);
    } else if (strcasecmp(argv[1], "dec") == 0) {
        decrypt_file(key, iv, argv[4], argv[5]);
    } else {
        printf("Usage: %s [enc/dec] [key] [iv] [input] [output]\n", argv[0]);
        return -1;
    }
    return 0;
}
