#include "crypto/sha256.h"
#include "crypto/hmac_sha512.h"
#include "random.h"
#include "pbkdf2_hmac_sha512.h"
#include "bip39_wordlist.h"
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <iostream>

// Helper function to convert a binary string to a hexadecimal string
std::string binaryToHex(const std::string& binary) {
    std::ostringstream oss;
    for (unsigned char c : binary) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)c;
    }
    return oss.str();
}

// Helper function to compute SHA-256 hash using PIVX's built-in CSHA256
std::string sha256(const std::string& data) {
    CSHA256 sha256;
    unsigned char hash[CSHA256::OUTPUT_SIZE];
    sha256.Write((const unsigned char*)data.data(), data.size()).Finalize(hash);
    return std::string((char*)hash, CSHA256::OUTPUT_SIZE);
}

// Generate a BIP39 mnemonic
std::string generateMnemonic(int wordCount) {
    if (wordCount != 12 && wordCount != 15 && wordCount != 18 && wordCount != 21 && wordCount != 24) {
        throw std::runtime_error("Invalid number of words. Choose between 12, 15, 18, 21, or 24.");
    }

    int entropyBits = (wordCount / 3) * 32;
    int checksumBits = entropyBits / 32;
    int totalBits = entropyBits + checksumBits;

    std::vector<unsigned char> entropy(entropyBits / 8);
    GetStrongRandBytes(entropy.data(), entropy.size());  // Replaced RAND_bytes

    std::string hash = sha256(std::string(entropy.begin(), entropy.end()));
    unsigned char checksum = hash[0];

    for (int i = 0; i < checksumBits; ++i) {
        if (checksum & (1 << (7 - i))) {
            entropy[entropy.size() - 1] |= (1 << i);
        }
    }

    std::string binary;
    for (unsigned char c : entropy) {
        for (int i = 7; i >= 0; --i) {
            binary += (c & (1 << i)) ? '1' : '0';
        }
    }

    std::vector<std::string> words;
    for (size_t i = 0; i < binary.size(); i += 11) {
        int index = std::stoi(binary.substr(i, 11), nullptr, 2);
        words.push_back(bip39_wordlist[index]);
    }

    std::ostringstream oss;
    for (size_t i = 0; i < words.size(); ++i) {
        if (i != 0) oss << " ";
        oss << words[i];
    }

    return oss.str();
}

// Convert mnemonic to seed
std::vector<unsigned char> mnemonicToSeed(const std::string& mnemonic, const std::string& passphrase) {
    std::string salt = "mnemonic" + passphrase;
    std::vector<unsigned char> seed(64);

    // Replace PKCS5_PBKDF2_HMAC_SHA1 with PBKDF2_HMAC_SHA512
    PBKDF2_HMAC_SHA512(mnemonic, salt, 2048, seed.size(), seed);

    return seed;
}
