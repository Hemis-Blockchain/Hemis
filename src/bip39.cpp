#include "crypto/sha256.h"
#include "crypto/hmac_sha512.h"
#include "random.h"
#include "crypto/pbkdf2_hmac_sha512.h"
#include "bip39_wordlist.h"
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <bitset>
#include <algorithm>
#include "bip39.h"

// Helper function to compute SHA-256 hash using PIVX's built-in CSHA256
std::string sha256(const std::string& data) {
    CSHA256 sha256;
    unsigned char hash[CSHA256::OUTPUT_SIZE];
    sha256.Write((const unsigned char*)data.data(), data.size()).Finalize(hash);
    return std::string((char*)hash, CSHA256::OUTPUT_SIZE);
}

// Convert mnemonic to seed
std::vector<unsigned char> mnemonicToSeed(const std::string& mnemonic, const std::string& passphrase) {
    std::string salt = "mnemonic" + passphrase;
    std::vector<unsigned char> seed(64);

    // PBKDF2 with HMAC-SHA512
    PBKDF2_HMAC_SHA512(mnemonic, salt, 2048, seed.size(), seed);

    return seed;
}

// Generate a BIP39 mnemonic
std::string generateMnemonic(int wordCount) {
    if (wordCount != 12 && wordCount != 15 && wordCount != 18 && wordCount != 21 && wordCount != 24) {
        throw std::runtime_error("Invalid number of words. Choose between 12, 15, 18, 21, or 24.");
    }

    // Step 1: Calculate entropy size
    int entropyBits = (wordCount / 3) * 32;
    int checksumBits = entropyBits / 32;
    int totalBits = entropyBits + checksumBits;

    // Step 2: Generate random entropy
    std::vector<unsigned char> entropy(entropyBits / 8);
    GetStrongRandBytes(entropy.data(), entropy.size());

    // Step 3: Compute checksum
    std::string hash = sha256(std::string(entropy.begin(), entropy.end()));
    unsigned char checksum = hash[0];  // Take the first byte of the SHA256 hash

    // Step 4: Append checksum to entropy
    int lastByteIndex = entropy.size() - 1;
    entropy[lastByteIndex] &= (0xFF << checksumBits);  // Clear last bits
    entropy[lastByteIndex] |= (checksum >> (8 - checksumBits));  // Add checksum bits

    // Step 5: Convert entropy + checksum to a binary string
    std::string binary;
    for (unsigned char c : entropy) {
        binary += std::bitset<8>(c).to_string();  // Convert each byte to binary
    }

    // Step 6: Split binary string into 11-bit chunks and map to words
    std::vector<std::string> words;
    for (size_t i = 0; i < totalBits; i += 11) {
        int index = std::bitset<11>(binary.substr(i, 11)).to_ulong();  // Convert to index
        words.push_back(bip39_wordlist[index]);  // Map to word in BIP39 wordlist
    }

    // Step 7: Join words into a mnemonic string
    std::ostringstream oss;
    for (size_t i = 0; i < words.size(); ++i) {
        if (i != 0) oss << " ";
        oss << words[i];
    }

    return oss.str();
}

// Helper function to validate the checksum of a BIP39 mnemonic
bool validateMnemonicChecksum(const std::string& mnemonic) {
    // Step 1: Split mnemonic into words
    std::vector<std::string> words;
    std::istringstream iss(mnemonic);
    for (std::string word; iss >> word;) {
        words.push_back(word);
    }

    // Step 2: Ensure valid word count
    if (words.size() != 12 && words.size() != 15 && words.size() != 18 && words.size() != 21 && words.size() != 24) {
        return false;
    }

    // Step 3: Convert words to binary
    std::string binary;
    for (const std::string& word : words) {
        auto it = std::find(bip39_wordlist.begin(), bip39_wordlist.end(), word);
        if (it == bip39_wordlist.end()) {
            return false;  // Invalid word not found in BIP39 wordlist
        }
        int index = std::distance(bip39_wordlist.begin(), it);
        binary += std::bitset<11>(index).to_string();  // Convert to 11-bit binary
    }

    // Step 4: Extract entropy and checksum from the binary string
    int totalBits = words.size() * 11;
    int checksumBits = totalBits / 33;
    int entropyBits = totalBits - checksumBits;

    std::string entropyBinary = binary.substr(0, entropyBits);
    std::string checksumBinary = binary.substr(entropyBits, checksumBits);

    // Step 5: Convert entropy binary back to bytes
    std::vector<unsigned char> entropy(entropyBits / 8);
    for (size_t i = 0; i < entropy.size(); ++i) {
        entropy[i] = std::bitset<8>(entropyBinary.substr(i * 8, 8)).to_ulong();
    }

    // Step 6: Compute checksum of the entropy
    std::string hash = sha256(std::string(entropy.begin(), entropy.end()));
    std::string calculatedChecksumBinary = std::bitset<8>(hash[0]).to_string().substr(0, checksumBits);

    // Step 7: Compare checksums
    return checksumBinary == calculatedChecksumBinary;
}
