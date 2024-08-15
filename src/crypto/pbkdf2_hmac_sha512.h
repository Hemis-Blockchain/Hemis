#ifndef PBKDF2_HMAC_SHA512_H
#define PBKDF2_HMAC_SHA512_H

#include "crypto/hmac_sha512.h"
#include <vector>
#include <string>

void PBKDF2_HMAC_SHA512(const std::string& password, const std::string& salt, int iterations, int dkLen, std::vector<unsigned char>& output) {
    output.resize(dkLen);
    std::vector<unsigned char> U(dkLen);
    std::vector<unsigned char> T(dkLen);
    std::vector<unsigned char> F(dkLen);

    int blockCount = (dkLen + 63) / 64; // 64 bytes for SHA512 output size

    for (int block = 1; block <= blockCount; ++block) {
        std::string blockStr = salt + std::string(reinterpret_cast<const char*>(&block), 4);

        CHMAC_SHA512(password.data(), password.size()).Write((unsigned char*)blockStr.data(), blockStr.size()).Finalize(&U[0]);
        std::copy(U.begin(), U.end(), F.begin());

        for (int i = 1; i < iterations; ++i) {
            CHMAC_SHA512(password.data(), password.size()).Write(&U[0], U.size()).Finalize(&U[0]);

            for (int j = 0; j < F.size(); ++j) {
                F[j] ^= U[j];
            }
        }

        for (int i = 0; i < dkLen; ++i) {
            output[i] = F[i];
        }
    }
}

#endif // PBKDF2_HMAC_SHA512_H
