#include "crypto/hmac_sha512.h"
#include <vector>
#include <string>
#include <cstring>
#include <stdexcept>
#include "key.h"
#include "base58.h"

// BIP32 extended master private key structure
class CExtKey {
public:
    unsigned char vch[74];

    void SetMaster(const unsigned char* seed, unsigned int nSeedLen) {
        unsigned char I[64];
        // Use the custom CHMAC_SHA512 class instead of OpenSSL's HMAC
        CHMAC_SHA512((const unsigned char*)"Bitcoin seed", 12).Write(seed, nSeedLen).Finalize(I);

        memcpy(vch, I, 32); // Private key
        memcpy(vch + 32, I + 32, 32); // Chain code
    }

    std::string ToString() const {
        return EncodeBase58(vch, vch + sizeof(vch));
    }
};

// BIP32 extended master public key structure
class CExtPubKey {
public:
    CPubKey pubkey;
    unsigned char chaincode[32];

    void SetKey(const CExtKey& key) {
        pubkey = key.key.GetPubKey();
        memcpy(chaincode, key.chaincode, sizeof(chaincode));
    }

    std::string ToString() const {
        unsigned char vch[78];
        memcpy(vch, pubkey.begin(), pubkey.size());
        memcpy(vch + pubkey.size(), chaincode, sizeof(chaincode));
        return EncodeBase58(vch, vch + sizeof(vch));
    }
};
