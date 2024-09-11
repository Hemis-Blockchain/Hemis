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
#include <codecvt>
#include <locale>

// Helper function to compute SHA-256 hash using PIVX's built-in CSHA256
std::string sha256(const std::string& data) {
    CSHA256 sha256;
    unsigned char hash[CSHA256::OUTPUT_SIZE];
    sha256.Write((const unsigned char*)data.data(), data.size()).Finalize(hash);
    return std::string((char*)hash, CSHA256::OUTPUT_SIZE);
}

std::string normalizeString(const std::string& input) {
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    std::wstring wideStr = converter.from_bytes(input);
    std::wstring normalizedStr = std::wstring(wideStr);  // Add NFKD normalization here
    return converter.to_bytes(normalizedStr);
}

std::vector<unsigned char> mnemonicToSeed(const std::string& mnemonic, const std::string& passphrase) {
    // Normalize both the mnemonic and passphrase
    std::string normalizedMnemonic = normalizeString(mnemonic);
    std::string normalizedPassphrase = normalizeString(passphrase);

    std::string salt = "mnemonic" + normalizedPassphrase;
    std::vector<unsigned char> seed(64);

    PBKDF2_HMAC_SHA512(normalizedMnemonic, salt, 2048, seed.size(), seed);

    return seed;
}

// Generate a BIP39 mnemonic
std::string generateMnemonic(int wordCount) {
    if (wordCount != 12 && wordCount != 15 && wordCount != 18 && wordCount != 21 && wordCount != 24) {
        throw std::runtime_error("Invalid number of words. Choose between 12, 15, 18, 21, or 24.");
    }

    // Step 1: Calculate entropy size based on the word count
    int entropyBits = (wordCount / 3) * 32;  // entropy bits = (wordCount / 3) * 32
    int checksumBits = entropyBits / 32;  // checksum bits = entropyBits / 32

    // Step 2: Generate random entropy
    std::vector<unsigned char> entropy(entropyBits / 8);
    GetStrongRandBytes(entropy.data(), entropy.size());

    // Step 3: Compute checksum as first (checksumBits) bits of SHA256(entropy)
    std::string hash = sha256(std::string(entropy.begin(), entropy.end()));
    unsigned char checksum = hash[0];  // Take the first byte of the SHA256 hash

    // Step 4: Convert entropy + checksum to binary
    std::string binary;
    for (unsigned char c : entropy) {
        binary += std::bitset<8>(c).to_string();  // Convert each byte to 8-bit binary
    }

    // Append checksum bits (first `checksumBits` of the SHA256 hash)
    binary += std::bitset<8>(checksum).to_string().substr(0, checksumBits);

    // Step 5: Split the binary string into 11-bit chunks and map to words
    std::vector<std::string> words;
    for (size_t i = 0; i < binary.size(); i += 11) {
        int index = std::bitset<11>(binary.substr(i, 11)).to_ulong();  // Convert 11 bits to an integer
        words.push_back(bip39_wordlist[index]);  // Map to word from the BIP39 wordlist
    }

    // Step 6: Join words into a mnemonic string
    std::ostringstream oss;
    for (size_t i = 0; i < words.size(); ++i) {
        if (i != 0) oss << " ";
        oss << words[i];
    }

    return oss.str();
}

// Validate BIP39 mnemonic
bool validateMnemonicChecksum(const std::string& mnemonic) {
    // Step 1: Split the mnemonic into words
    std::vector<std::string> words;
    std::istringstream iss(mnemonic);
    for (std::string word; iss >> word;) {
        words.push_back(word);
    }

    // Step 2: Ensure that the word count is valid
    if (words.size() != 12 && words.size() != 15 && words.size() != 18 && words.size() != 21 && words.size() != 24) {
        return false;
    }

    // Step 3: Convert words to binary
    std::string binary;
    for (const std::string& word : words) {
        auto it = std::find(bip39_wordlist.begin(), bip39_wordlist.end(), word);
        if (it == bip39_wordlist.end()) {
            return false;  // Word not found in BIP39 wordlist
        }
        int index = std::distance(bip39_wordlist.begin(), it);
        binary += std::bitset<11>(index).to_string();  // Convert index to 11-bit binary
    }

    // Step 4: Separate the entropy and checksum from the binary string
    int totalBits = words.size() * 11;
    int checksumBits = totalBits / 33;
    int entropyBits = totalBits - checksumBits;

    std::string entropyBinary = binary.substr(0, entropyBits);
    std::string checksumBinary = binary.substr(entropyBits, checksumBits);

    // Step 5: Convert the entropy binary back to bytes
    std::vector<unsigned char> entropy(entropyBits / 8);
    for (size_t i = 0; i < entropy.size(); ++i) {
        entropy[i] = std::bitset<8>(entropyBinary.substr(i * 8, 8)).to_ulong();
    }

    // Step 6: Compute the checksum from the entropy's SHA256 hash
    std::string hash = sha256(std::string(entropy.begin(), entropy.end()));
    std::string calculatedChecksumBinary = std::bitset<8>(hash[0]).to_string().substr(0, checksumBits);

    // Step 7: Compare calculated checksum with the extracted checksum
    return checksumBinary == calculatedChecksumBinary;
}
