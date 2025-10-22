#include "../include/antivirus.h"

void bytes_to_hex(const BYTE *b, DWORD len, char *out) {
    const char hex[] = "0123456789abcdef";
    for (DWORD i = 0; i < len; i++) {
        out[i*2] = hex[(b[i] >> 4) & 0xF];
        out[i*2+1] = hex[b[i] & 0xF];
    }
    out[len*2] = '\0';
}

int file_sha256(const char *path, char *out_hex) {
    HCRYPTPROV hProv = 0; HCRYPTHASH hHash = 0;
    BYTE buffer[BUF_SIZE];
    DWORD read;
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        fclose(f); return -2;
    }
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0); fclose(f); return -3;
    }

    while ((read = (DWORD)fread(buffer, 1, BUF_SIZE, f)) > 0)
        if (!CryptHashData(hHash, buffer, read, 0)) {
            fclose(f);
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return -4;
        }

    BYTE hash[32];
    DWORD hashLen = sizeof(hash);
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
        fclose(f);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return -5;
    }

    bytes_to_hex(hash, hashLen, out_hex);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    fclose(f);
    return 0;
}
