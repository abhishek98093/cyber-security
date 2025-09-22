#include "CryptoUtils.h"
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/filters.h>
#include <cryptopp/rsa.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/secblock.h>
#include <cryptopp/hex.h>
#include <iostream>

using namespace CryptoPP;

CryptoUtils::CryptoUtils() {}

CryptoUtils::~CryptoUtils() {}

bool CryptoUtils::LoadPrivateKeyDER(const std::string& filename) {
    try {
        FileSource fs(filename.c_str(), true);
        rsaPriv.Load(fs);
        hasPriv = true;
        return true;
    } catch (const Exception& e) {
        std::cerr << "LoadPrivateKeyDER error: " << e.what() << std::endl;
        return false;
    }
}

bool CryptoUtils::LoadPublicKeyDER(const std::string& filename) {
    try {
        FileSource fs(filename.c_str(), true);
        rsaPub.Load(fs);
        hasPub = true;
        return true;
    } catch (const Exception& e) {
        std::cerr << "LoadPublicKeyDER error: " << e.what() << std::endl;
        return false;
    }
}

// NEW: Load peer's public key
bool CryptoUtils::LoadPeerPublicKeyDER(const std::string& filename) {
    try {
        FileSource fs(filename.c_str(), true);
        peerRsaPub.Load(fs);
        hasPeerPub = true;
        return true;
    } catch (const Exception& e) {
        std::cerr << "LoadPeerPublicKeyDER error: " << e.what() << std::endl;
        return false;
    }
}

// CHANGED: Use peer's public key for encryption
std::vector<unsigned char> CryptoUtils::RSAEncryptWithPeerPublic(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> out;
    if (!hasPeerPub) return out;
    AutoSeededRandomPool rng;
    RSAES_OAEP_SHA_Encryptor e(peerRsaPub);
    try {
        StringSource ss(data.data(), data.size(), true,
            new PK_EncryptorFilter(rng, e, new VectorSink(out))
        );
    } catch (const Exception& ex) {
        std::cerr << "RSA encrypt error: " << ex.what() << std::endl;
    }
    return out;
}

std::vector<unsigned char> CryptoUtils::RSADecryptWithPrivate(const std::vector<unsigned char>& cipher) {
    std::vector<unsigned char> out;
    if (!hasPriv) return out;
    AutoSeededRandomPool rng;
    RSAES_OAEP_SHA_Decryptor d(rsaPriv);
    try {
        ArraySource a(cipher.data(), cipher.size(), true,
            new PK_DecryptorFilter(rng, d, new VectorSink(out))
        );
    } catch (const Exception& ex) {
        std::cerr << "RSA decrypt error: " << ex.what() << std::endl;
    }
    return out;
}

std::vector<unsigned char> CryptoUtils::AESEncrypt(const std::vector<unsigned char>& key,
                                                   const std::vector<unsigned char>& iv,
                                                   const std::string& plaintext) {
    std::vector<unsigned char> cipher;
    try {
        CBC_Mode<AES>::Encryption enc;
        SecByteBlock keyb(key.data(), key.size());
        SecByteBlock ivb(iv.data(), iv.size());
        enc.SetKeyWithIV(keyb, keyb.size(), ivb);
        StringSource ss(plaintext, true,
            new StreamTransformationFilter(enc, new VectorSink(cipher),
                                           StreamTransformationFilter::PKCS_PADDING)
        );
    } catch (const Exception& ex) {
        std::cerr << "AES encrypt error: " << ex.what() << std::endl;
    }
    return cipher;
}

std::string CryptoUtils::AESDecrypt(const std::vector<unsigned char>& key,
                                    const std::vector<unsigned char>& iv,
                                    const std::vector<unsigned char>& cipher) {
    std::string recovered;
    try {
        CBC_Mode<AES>::Decryption dec;
        SecByteBlock keyb(key.data(), key.size());
        SecByteBlock ivb(iv.data(), iv.size());
        dec.SetKeyWithIV(keyb, keyb.size(), ivb);
        ArraySource a(cipher.data(), cipher.size(), true,
            new StreamTransformationFilter(dec, new StringSink(recovered),
                                           StreamTransformationFilter::PKCS_PADDING)
        );
    } catch (const Exception& ex) {
        std::cerr << "AES decrypt error: " << ex.what() << std::endl;
    }
    return recovered;
}

std::vector<unsigned char> CryptoUtils::GenerateRandomBytes(size_t n) {
    std::vector<unsigned char> v(n);
    AutoSeededRandomPool rng;
    rng.GenerateBlock(v.data(), v.size());
    return v;
}