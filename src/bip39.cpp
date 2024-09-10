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

    // Step 1: Generate entropy
    std::vector<unsigned char> entropy(entropyBits / 8);
    GetStrongRandBytes(entropy.data(), entropy.size());

    // Step 2: Compute checksum
    std::string hash = sha256(std::string(entropy.begin(), entropy.end()));
    unsigned char checksum = hash[0];  // Use the first byte of the hash

    // Step 3: Append checksum to entropy (modify the last byte of entropy)
    int lastByteIndex = entropy.size() - 1;
    entropy[lastByteIndex] &= (0xFF << checksumBits);  // Clear the last checksumBits
    entropy[lastByteIndex] |= (checksum >> (8 - checksumBits));  // Append checksum bits

    // Step 4: Convert entropy + checksum to binary
    std::string binary;
    for (unsigned char c : entropy) {
        for (int i = 7; i >= 0; --i) {
            binary += (c & (1 << i)) ? '1' : '0';
        }
    }

    // Step 5: Split binary into 11-bit chunks and map to words
    std::vector<std::string> words;
    for (size_t i = 0; i < totalBits; i += 11) {
        int index = std::bitset<11>(binary.substr(i, 11)).to_ulong();  // Convert binary to index
        words.push_back(bip39_wordlist[index]);  // Map to BIP39 wordlist
    }

    // Step 6: Join words to create the mnemonic
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

// Helper function to validate the checksum of a BIP39 mnemonic
// Helper function to validate the checksum of a BIP39 mnemonic
bool validateMnemonicChecksum(const std::string& mnemonic) {
    // Split mnemonic into words
    std::vector<std::string> words;
    std::istringstream iss(mnemonic);
    for (std::string word; iss >> word;) {
        words.push_back(word);
    }

    // Convert words back to entropy + checksum binary string
    std::string binary;
    for (const std::string& word : words) {
        auto it = std::find(bip39_wordlist.begin(), bip39_wordlist.end(), word);
        if (it == bip39_wordlist.end()) {
            return false;  // Invalid word not found in BIP39 wordlist
        }
        int index = std::distance(bip39_wordlist.begin(), it);
        binary += std::bitset<11>(index).to_string();  // Convert index to 11-bit binary
    }

    // Calculate original entropy length
    int wordCount = words.size();
    int entropyBits = (wordCount / 3) * 32;  // Entropy bits based on word count
    int checksumBits = wordCount / 3;  // Checksum bits

    // Separate the entropy and checksum from the binary string
    std::string entropyBinary = binary.substr(0, entropyBits);
    std::string checksumBinary = binary.substr(entropyBits, checksumBits);

    // Convert the entropy binary back to bytes
    std::vector<unsigned char> entropy(entropyBits / 8);
    for (size_t i = 0; i < entropy.size(); ++i) {
        entropy[i] = std::bitset<8>(entropyBinary.substr(i * 8, 8)).to_ulong();
    }

    // Calculate the SHA256 checksum of the entropy
    std::string hash = sha256(std::string(entropy.begin(), entropy.end()));
    std::string calculatedChecksumBinary = std::bitset<8>(hash[0]).to_string().substr(0, checksumBits);

    // Compare the calculated checksum with the checksum from the mnemonic
    return checksumBinary == calculatedChecksumBinary;
}
