#pragma once
#include <vector>
#include <string>
#include <cryptopp/rsa.h>

class CryptoUtils {
public:
    CryptoUtils();
    ~CryptoUtils();

    // Load keys from DER files
    bool LoadPrivateKeyDER(const std::string& filename);
    bool LoadPublicKeyDER(const std::string& filename);
    bool LoadPeerPublicKeyDER(const std::string& filename); // NEW: For peer's key

    // RSA encrypt/decrypt (OAEP-SHA)
    std::vector<unsigned char> RSAEncryptWithPeerPublic(const std::vector<unsigned char>& data); // CHANGED
    std::vector<unsigned char> RSADecryptWithPrivate(const std::vector<unsigned char>& cipher);

    // AES-CBC encrypt/decrypt (PKCS padding)
    std::vector<unsigned char> AESEncrypt(const std::vector<unsigned char>& key,
                                          const std::vector<unsigned char>& iv,
                                          const std::string& plaintext);
    std::string AESDecrypt(const std::vector<unsigned char>& key,
                           const std::vector<unsigned char>& iv,
                           const std::vector<unsigned char>& cipher);

    // Random
    std::vector<unsigned char> GenerateRandomBytes(size_t n);

private:
    CryptoPP::RSA::PrivateKey rsaPriv;
    CryptoPP::RSA::PublicKey rsaPub;        // Own public key (if needed)
    CryptoPP::RSA::PublicKey peerRsaPub;    // Peer's public key
    bool hasPriv = false;
    bool hasPub = false;
    bool hasPeerPub = false;                // NEW: Track peer public key
};