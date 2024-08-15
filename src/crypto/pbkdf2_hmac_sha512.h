#ifndef PBKDF2_HMAC_SHA512_H
#define PBKDF2_HMAC_SHA512_H

#include "crypto/hmac_sha512.h"
#include <vector>
#include <string>

void PBKDF2_HMAC_SHA512(const std::string& password, const std::string& salt, int iterations, int dkLen, std::vector<unsigned char>& output) {
    output.resize(dkLen);
    std::vector<unsigned char> U(64);  // SHA-512 produces 64-byte outputs
    std::vector<unsigned char> T(64);
    std::vector<unsigned char> F(64);

    int blockCount = (dkLen + 63) / 64; // 64 bytes for SHA512 output size

    for (int block = 1; block <= blockCount; ++block) {
        std::string blockStr = salt + std::string(reinterpret_cast<const char*>(&block), 4);

        CHMAC_SHA512(reinterpret_cast<const unsigned char*>(password.data()), password.size())
            .Write((const unsigned char*)blockStr.data(), blockStr.size())
            .Finalize(U.data());

        std::copy(U.begin(), U.end(), F.begin());

        for (int i = 1; i < iterations; ++i) {
            CHMAC_SHA512(reinterpret_cast<const unsigned char*>(password.data()), password.size())
                .Write(U.data(), U.size())
                .Finalize(U.data());

            for (int j = 0; j < F.size(); ++j) {
                F[j] ^= U[j];
            }
        }

        for (int i = 0; i < 64 && (i + (block - 1) * 64) < dkLen; ++i) {
            output[i + (block - 1) * 64] = F[i];
        }
    }
}
#endif // PBKDF2_HMAC_SHA512_H
