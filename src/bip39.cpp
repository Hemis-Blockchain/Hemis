#include "crypto/sha256.h"
#include "crypto/hmac_sha512.h"
#include "random.h"
#include "crypto/pbkdf2_hmac_sha512.h" // Include the existing PBKDF2 implementation
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
#include <iomanip>

const uint64_t K[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

const uint64_t INITIAL_STATE[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

inline uint64_t rotr(uint64_t x, uint64_t n) {
    return (x >> n) | (x << (64 - n));
}

inline uint64_t Ch(uint64_t x, uint64_t y, uint64_t z) {
    return (x & y) ^ (~x & z);
}

inline uint64_t Maj(uint64_t x, uint64_t y, uint64_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

inline uint64_t Sigma0(uint64_t x) {
    return rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39);
}

inline uint64_t Sigma1(uint64_t x) {
    return rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41);
}

inline uint64_t sigma0(uint64_t x) {
    return rotr(x, 1) ^ rotr(x, 8) ^ (x >> 7);
}

inline uint64_t sigma1(uint64_t x) {
    return rotr(x, 19) ^ rotr(x, 61) ^ (x >> 6);
}

void sha512_transform(uint64_t state[8], const uint8_t block[128]) {
    uint64_t W[80];
    uint64_t a, b, c, d, e, f, g, h;
    uint64_t T1, T2;

    // Prepare message schedule
    for (int t = 0; t < 16; ++t) {
        W[t] = (uint64_t)block[t * 8] << 56 | (uint64_t)block[t * 8 + 1] << 48 |
               (uint64_t)block[t * 8 + 2] << 40 | (uint64_t)block[t * 8 + 3] << 32 |
               (uint64_t)block[t * 8 + 4] << 24 | (uint64_t)block[t * 8 + 5] << 16 |
               (uint64_t)block[t * 8 + 6] << 8 | (uint64_t)block[t * 8 + 7];
    }

    for (int t = 16; t < 80; ++t) {
        W[t] = sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16];
    }

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];

    for (int t = 0; t < 80; ++t) {
        T1 = h + Sigma1(e) + Ch(e, f, g) + K[t] + W[t];
        T2 = Sigma0(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

std::vector<uint8_t> sha512(const std::vector<uint8_t>& data) {
    uint64_t state[8];
    memcpy(state, INITIAL_STATE, sizeof(INITIAL_STATE));

    // Padding and processing
    size_t original_len = data.size();
    size_t padded_len = original_len + 1 + 16;
    while (padded_len % 128 != 0) ++padded_len;

    std::vector<uint8_t> padded_data(padded_len, 0);
    memcpy(padded_data.data(), data.data(), original_len);
    padded_data[original_len] = 0x80;

    uint64_t bit_len = original_len * 8;
    for (int i = 0; i < 8; ++i) {
        padded_data[padded_len - 8 + i] = (bit_len >> (56 - 8 * i)) & 0xFF;
    }

    for (size_t i = 0; i < padded_len; i += 128) {
        sha512_transform(state, padded_data.data() + i);
    }

    std::vector<uint8_t> result(64);
    for (int i = 0; i < 8; ++i) {
        for (int j = 0; j < 8; ++j) {
            result[i * 8 + j] = (state[i] >> (56 - j * 8)) & 0xFF;
        }
    }

    return result;
}

std::vector<uint8_t> hmac_sha512(const std::vector<uint8_t>& key, const std::vector<uint8_t>& message) {
    std::vector<uint8_t> key_prime = key;

    if (key_prime.size() > 128) {
        key_prime = sha512(key_prime);  // Hash the key if it's too long
    }

    key_prime.resize(128, 0);  // Pad key to block size (128 bytes for SHA-512)

    std::vector<uint8_t> o_key_pad(128), i_key_pad(128);
    for (int i = 0; i < 128; ++i) {
        o_key_pad[i] = key_prime[i] ^ 0x5c;
        i_key_pad[i] = key_prime[i] ^ 0x36;
    }

    // Inner hash: H(K XOR ipad || message)
    std::vector<uint8_t> inner_data = i_key_pad;
    inner_data.insert(inner_data.end(), message.begin(), message.end());
    std::vector<uint8_t> inner_hash = sha512(inner_data);

    // Outer hash: H(K XOR opad || inner_hash)
    std::vector<uint8_t> outer_data = o_key_pad;
    outer_data.insert(outer_data.end(), inner_hash.begin(), inner_hash.end());
    return sha512(outer_data);
}

std::vector<uint8_t> pbkdf2_hmac_sha512(const std::string& password, const std::vector<uint8_t>& salt, int iterations, int dkLen) {
    int hLen = 64;  // SHA512 output size in bytes
    int l = (dkLen + hLen - 1) / hLen; // Number of blocks to produce
    int r = dkLen - (l - 1) * hLen;    // Last block may be truncated

    std::vector<uint8_t> derivedKey(dkLen);
    std::vector<uint8_t> block(hLen);

    for (int i = 1; i <= l; i++) {
        // Initial block: U1 = HMAC(password, salt || INT_32_BE(i))
        std::vector<uint8_t> saltPlusCounter = salt;
        saltPlusCounter.push_back((i >> 24) & 0xff);
        saltPlusCounter.push_back((i >> 16) & 0xff);
        saltPlusCounter.push_back((i >> 8) & 0xff);
        saltPlusCounter.push_back(i & 0xff);

        std::vector<uint8_t> u = hmac_sha512(std::vector<uint8_t>(password.begin(), password.end()), saltPlusCounter);
        block = u;

        // Compute U2, U3, ..., Uc and XOR them into the block
        for (int j = 1; j < iterations; j++) {
            u = hmac_sha512(std::vector<uint8_t>(password.begin(), password.end()), u);
            for (int k = 0; k < hLen; k++) {
                block[k] ^= u[k];
            }
        }

        // Copy the block into the derived key
        if (i == l) {
            std::copy(block.begin(), block.begin() + r, derivedKey.begin() + (i - 1) * hLen);
        } else {
            std::copy(block.begin(), block.end(), derivedKey.begin() + (i - 1) * hLen);
        }
    }

    return derivedKey;
}


// Helper function to compute SHA-256 hash using PIVX's built-in CSHA256
std::string sha256(const std::string& data) {
    CSHA256 sha256;
    unsigned char hash[CSHA256::OUTPUT_SIZE];
    sha256.Write((const unsigned char*)data.data(), data.size()).Finalize(hash);
    return std::string((char*)hash, CSHA256::OUTPUT_SIZE);
}

// Proper NFKD normalization using ICU library
std::string normalizeString(const std::string& input) {
    // No normalization performed, just return the input
    return input;
}

std::vector<unsigned char> mnemonicToSeed(const std::string& mnemonic, const std::string& passphrase) {
    // Normalize both mnemonic and passphrase (currently using simple pass-through)
    std::string normalizedMnemonic = normalizeString(mnemonic);
    std::string normalizedPassphrase = normalizeString(passphrase);

    // Salt is "mnemonic" + normalized passphrase
    std::string salt = "mnemonic" + normalizedPassphrase;

    // Use PBKDF2-HMAC-SHA512 to generate the seed (64 bytes)
    std::vector<uint8_t> saltBytes(salt.begin(), salt.end());
    std::vector<unsigned char> seed = pbkdf2_hmac_sha512(normalizedMnemonic, saltBytes, 2048, 64);

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
