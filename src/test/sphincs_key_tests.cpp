// Copyright (c) 2012-2022 The Quranium Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include <common/system.h>
#include <fstream>
#include <key.h>
#include <key_io.h>
#include <span.h>
#include <streams.h>
#include <string>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <vector>

#include <boost/test/unit_test.hpp>

#include "../sphincsplus/include/params.h"

using util::ToString;

// static const std::string strSecret1 = "L3wod261x1ui842sPDH4E4MQpCfFz6P2TcxNWtiPeaFQM4TUYqJT";
// static const std::string strSecretC1 = "5Jdu9WKCg8bQSGc2GG2hCUmDLE2tQ2iFGHmGBriUJfWwwFVZmtQ";

BOOST_FIXTURE_TEST_SUITE(sphincs_key_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(sphincs_key_test1)
{
    std::cout << "---------------------Testing the Key Generation function---------------------------\n";
    CKey key;
    key.MakeNewKey(false);
    CPubKey pubKey = key.GetPubKey();

    BOOST_CHECK(key.size() == CKey::SIZE);
    BOOST_CHECK(pubKey.size() == CPubKey::SIZE);
    BOOST_CHECK(key.IsValid() && !key.IsCompressed());
    BOOST_CHECK(key.VerifyPubKey(pubKey));

    CKey key1;
    key1.MakeNewKey(false);
    BOOST_CHECK(key1.IsValid() && !key1.IsCompressed());
    CKey key2;
    key2.MakeNewKey(false);
    BOOST_CHECK(key2.IsValid() && !key2.IsCompressed());
    CKey key3;
    key3.MakeNewKey(false);
    BOOST_CHECK(key3.IsValid() && !key3.IsCompressed());
    CKey key4;
    key4.MakeNewKey(false);
    BOOST_CHECK(key4.IsValid() && !key4.IsCompressed());
    CKey key5;
    key5.MakeNewKey(false);
    BOOST_CHECK(key5.IsValid() && !key5.IsCompressed());

    BOOST_CHECK(key1.size() == CKey::SIZE);
    BOOST_CHECK(key2.size() == CKey::SIZE);
    BOOST_CHECK(key3.size() == CKey::SIZE);
    BOOST_CHECK(key4.size() == CKey::SIZE);
    BOOST_CHECK(key5.size() == CKey::SIZE);

    CPubKey pubKey1 = key1.GetPubKey();
    CPubKey pubKey2 = key2.GetPubKey();
    CPubKey pubKey3 = key3.GetPubKey();
    CPubKey pubKey4 = key4.GetPubKey();
    CPubKey pubKey5 = key5.GetPubKey();

    std::string strPubKey1 = HexStr(pubKey1);
    std::cout << "\nGenerated Public Key 1: " << strPubKey1 << std::endl;
    std::cout << "pubkey size: " << pubKey1.size() << std::endl;

    std::string strPubKey2 = HexStr(pubKey2);
    std::cout << "\nGenerated Public Key 2: " << strPubKey2 << std::endl;
    std::cout << "pubkey size: " << pubKey1.size() << std::endl;

    std::string strPubKey3 = HexStr(pubKey3);
    std::cout << "\nGenerated Public Key 3: " << strPubKey3 << std::endl;
    std::cout << "pubkey size: " << pubKey1.size() << std::endl;

    std::string strPubKey4 = HexStr(pubKey4);
    std::cout << "\nGenerated Public Key 4: " << strPubKey4 << std::endl;
    std::cout << "pubkey size: " << pubKey1.size() << std::endl;

    std::string strPubKey5 = HexStr(pubKey5);
    std::cout << "\nGenerated Public Key 5: " << strPubKey5 << std::endl;
    std::cout << "pubkey size: " << pubKey1.size() << "\n\n";

    BOOST_CHECK(pubKey1.size() == CPubKey::SIZE);
    BOOST_CHECK(pubKey2.size() == CPubKey::SIZE);
    BOOST_CHECK(pubKey3.size() == CPubKey::SIZE);
    BOOST_CHECK(pubKey4.size() == CPubKey::SIZE);
    BOOST_CHECK(pubKey5.size() == CPubKey::SIZE);

    BOOST_CHECK(key1.VerifyPubKey(pubKey1));
    BOOST_CHECK(key2.VerifyPubKey(pubKey2));
    BOOST_CHECK(key3.VerifyPubKey(pubKey3));
    BOOST_CHECK(key4.VerifyPubKey(pubKey4));
    BOOST_CHECK(key5.VerifyPubKey(pubKey5));
}

BOOST_AUTO_TEST_CASE(sphincs_key_test_signing)
{
    std::cout << "---------------------Testing the Signing function---------------------------\n";
    CKey key;
    key.MakeNewKey(false);

    // Log the public key for reference
    CPubKey pubKey = key.GetPubKey();
    std::string strPubKey = HexStr(pubKey);
    std::cout << "\nGenerated Public Key: " << strPubKey << std::endl;
    BOOST_CHECK(key.IsValid() && !key.IsCompressed());

    for (int n = 0; n < 16; n++) {
        std::string strMsg = strprintf("Very secret message %i: 11", n);
        uint256 hashMsg = Hash(strMsg);

        // SPHINCS+ signatures
        std::vector<unsigned char> sign;
        BOOST_CHECK(key.Sign(hashMsg, sign));
        BOOST_CHECK(sign.size() == SPX_BYTES);
        // outputing the signature to a file
        std::ofstream sigFile("key-signature.txt", std::ios_base::app);
        if (!sigFile.is_open()) {
            std::cerr << "Error opening file for writing" << std::endl;
            continue;
        }
        sigFile << "Signature: \n================ SIGBEGIN ========================\n\n";
        for (int i = 0; i < CPubKey::SIGNATURE_SIZE; i++) {
            // std::cout << static_cast<int>(vchSig.data()[i]);
            sigFile << static_cast<int>(sign.data()[i]);
        }

        // Output the signature as a hex string
        // for (unsigned char byte : sign) {
        //     sigFile << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        // }
        sigFile << "\n================ SIGEND ========================\nSignature Size: " << sign.size() << " (" << sign.size() / 1024.0 << "kb)\n\n\n\n";
        sigFile.close();
    }
}

BOOST_AUTO_TEST_CASE(sphincs_key_test3)
{
    std::cout << "---------------------Testing CKey VerifyPubKey function ---------------------------\n";
    CKey key;
    key.MakeNewKey(false);

    // Log the public key for reference
    CPubKey pubKey = key.GetPubKey();
    std::string strPubKey = HexStr(pubKey);
    BOOST_CHECK(key.IsValid() && !key.IsCompressed());

    // Verifying the generated pubKey function With sample signing and verifying it against Sphincs+
    BOOST_CHECK(key.VerifyPubKey(pubKey));
}

BOOST_AUTO_TEST_CASE(sphincs_key_test4)
{
    std::cout << "---------------------Testing CPubKey verify function ---------------------------\n";
    CKey key;
    key.MakeNewKey(false);
    BOOST_CHECK(key.IsValid() && !key.IsCompressed());

    std::string strMsg = strprintf("Very secret message %i: 11", 0);
    uint256 hashMsg = Hash(strMsg);

    // SPHINCS+ signing the signatures with secret key
    std::vector<unsigned char> sign;
    BOOST_CHECK(key.Sign(hashMsg, sign));

    // Extracting the pubkey key pair with which secret key is signed
    CPubKey pubKey = key.GetPubKey();

    // Verifying the Authenticity of signature by calling verify with signed message
    BOOST_CHECK(pubKey.Verify(hashMsg, sign));

    // Failure case
    CKey tamperedKey;
    tamperedKey.MakeNewKey(false);

    CPubKey tamperedPublicKey = tamperedKey.GetPubKey();

    // Trying to verify message with tampered key
    BOOST_CHECK_EQUAL(tamperedPublicKey.Verify(hashMsg, sign), false);
}


BOOST_AUTO_TEST_SUITE_END()