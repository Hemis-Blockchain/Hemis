#include "bip39_wordlist.h"
#include "crypto/sha256.h"
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <cstring>

// Helper function to convert a binary string to a hexadecimal string
std::string binaryToHex(const std::string& binary) {
    std::ostringstream oss;
    for (unsigned char c : binary) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)c;
    }
    return oss.str();
}

std::string sha256(const std::string& data) {
    CSHA256 sha256;
    unsigned char hash[CSHA256::OUTPUT_SIZE];
    sha256.Write((const unsigned char*)data.data(), data.size()).Finalize(hash);
    return std::string((char*)hash, CSHA256::OUTPUT_SIZE);
}

// Generate a BIP39 mnemonic
std::string generateMnemonic(int wordCount) {
    // Ensure wordCount is valid
    if (wordCount != 12 && wordCount != 15 && wordCount != 18 && wordCount != 21 && wordCount != 24) {
        throw std::runtime_error("Invalid number of words. Choose between 12, 15, 18, 21, or 24.");
    }

    int entropyBits = (wordCount / 3) * 32; // Number of entropy bits (128 for 12 words, 256 for 24 words)
    int checksumBits = entropyBits / 32;    // Number of checksum bits
    int totalBits = entropyBits + checksumBits;

    // Generate random entropy
    std::vector<unsigned char> entropy(entropyBits / 8);
    RAND_bytes(entropy.data(), entropy.size());

    // Compute checksum
    std::string hash = sha256(std::string(entropy.begin(), entropy.end()));
    unsigned char checksum = hash[0]; // Take the first byte of the hash

    // Append checksum to entropy
    for (int i = 0; i < checksumBits; ++i) {
        if (checksum & (1 << (7 - i))) {
            entropy[entropy.size() - 1] |= (1 << i);
        }
    }

    // Convert entropy+checksum to binary string
    std::string binary;
    for (unsigned char c : entropy) {
        for (int i = 7; i >= 0; --i) {
            binary += (c & (1 << i)) ? '1' : '0';
        }
    }

    // Split binary string into groups of 11 bits and map to words
    std::vector<std::string> words;
    for (size_t i = 0; i < binary.size(); i += 11) {
        int index = std::stoi(binary.substr(i, 11), nullptr, 2);
        words.push_back(bip39_wordlist[index]);
    }

    // Join words to form mnemonic
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

    PKCS5_PBKDF2_HMAC_SHA1(mnemonic.c_str(), mnemonic.size(),
                           (unsigned char*)salt.c_str(), salt.size(),
                           2048, seed.size(), seed.data());

    return seed;
}
