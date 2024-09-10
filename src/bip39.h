#ifndef BIP39_H
#define BIP39_H

#include <vector>
#include <string>

// Function declarations
std::vector<unsigned char> mnemonicToSeed(const std::string& mnemonic, const std::string& passphrase);
std::string generateMnemonic(int wordCount);
bool validateMnemonicChecksum(const std::string& mnemonic);
std::string sha256(const std::string& data);

#endif // BIP39_H
