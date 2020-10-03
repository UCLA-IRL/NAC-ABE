/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017-2019, Regents of the University of California.
 *
 * This file is part of NAC-ABE.
 *
 * NAC-ABE is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation, either
 * version 3 of the License, or (at your option) any later version.
 *
 * NAC-ABE is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received copies of the GNU General Public License along with
 * NAC-ABE, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of NAC-ABE authors and contributors.
 */

#include "algo/abe-support.hpp"
#include "test-common.hpp"

namespace ndn {
namespace nacabe {
namespace tests {

const uint8_t PLAIN_TEXT[] = {
  0x41, 0x45, 0x53, 0x2d, 0x45, 0x6e, 0x63, 0x72,
  0x79, 0x70, 0x74, 0x2d, 0x54, 0x65, 0x73, 0x74,
  0x41, 0x45, 0x53, 0x2d, 0x45, 0x6e, 0x63, 0x72,
  0x79, 0x70, 0x74, 0x2d, 0x54, 0x65, 0x73, 0x74,
  0x41, 0x45, 0x53, 0x2d, 0x45, 0x6e, 0x63, 0x72,
  0x79, 0x70, 0x74, 0x2d, 0x54, 0x65, 0x73, 0x74,
  0x41, 0x45, 0x53, 0x2d, 0x45, 0x6e, 0x63, 0x72,
  0x79, 0x70, 0x74, 0x2d, 0x54, 0x65, 0x73, 0x74
};

NDN_LOG_INIT(Test.ABESupport);

BOOST_AUTO_TEST_SUITE(TestAbeSupport)

BOOST_AUTO_TEST_CASE(Setup)
{
  algo::PublicParams pubParams;
  algo::MasterKey masterKey;

  algo::ABESupport::setup(pubParams, masterKey);

  BOOST_CHECK(pubParams.m_pub != "");
  BOOST_CHECK(masterKey.m_msk != "");
}

BOOST_AUTO_TEST_CASE(GenPrivateKey)
{
  algo::PublicParams pubParams;
  algo::MasterKey masterKey;

  algo::ABESupport::setup(pubParams, masterKey);

  std::vector<std::string> attrList = {"(attr1 or attr2) and attr3"};
  algo::PrivateKey prvKey = algo::ABESupport::prvKeyGen(pubParams, masterKey, attrList);

  BOOST_CHECK(prvKey.m_prv != "");
}

BOOST_AUTO_TEST_CASE(Encryption)
{
  algo::PublicParams pubParams;
  algo::MasterKey masterKey;

  algo::ABESupport::setup(pubParams, masterKey);
  algo::CipherText cipherText = algo::ABESupport::encrypt(pubParams, "attr1",
                                                          Buffer(PLAIN_TEXT, sizeof(PLAIN_TEXT)));

  BOOST_CHECK(cipherText.m_aesKey.size() != 0);
  BOOST_CHECK(cipherText.m_content.size() > sizeof(PLAIN_TEXT));
}

BOOST_AUTO_TEST_CASE(Decryption)
{
  algo::PublicParams pubParams;
  algo::MasterKey masterKey;

  // setup
  algo::ABESupport::setup(pubParams, masterKey);

  // generate prv key
  std::vector<std::string> attrList = {"(attr1 or attr2) and attr3"};
  algo::PrivateKey prvKey = algo::ABESupport::prvKeyGen(pubParams, masterKey, attrList);

  // encrypt
  algo::CipherText cipherText = algo::ABESupport::encrypt(pubParams, "|attr1|attr3",
                                                          Buffer(PLAIN_TEXT, sizeof(PLAIN_TEXT)));

  // decrypt
  Buffer result = algo::ABESupport::decrypt(pubParams, prvKey, cipherText);

  BOOST_CHECK_EQUAL_COLLECTIONS(result.begin(), result.end(),
                                PLAIN_TEXT, PLAIN_TEXT + sizeof(PLAIN_TEXT));

  // 32 bytes random plaintext encryption and decryption
  uint8_t randomBytes1[32];
  random::generateSecureBytes(randomBytes1, sizeof(randomBytes1));

  algo::CipherText cipherTextRandomBytes1 = algo::ABESupport::encrypt(pubParams, "|attr1|attr3",
                                                          Buffer(randomBytes1, sizeof(randomBytes1)));
                                  
  Buffer decryptedRandomBytes1 = algo::ABESupport::decrypt(pubParams, prvKey, cipherTextRandomBytes1);      
  BOOST_CHECK_EQUAL_COLLECTIONS(decryptedRandomBytes1.begin(), decryptedRandomBytes1.end(),
                                randomBytes1, randomBytes1 + sizeof(randomBytes1));

  // 64 bytes random plaintext encryption and decryption
  uint8_t randomBytes2[64];
  random::generateSecureBytes(randomBytes2, sizeof(randomBytes2));

  algo::CipherText cipherTextRandomBytes2 = algo::ABESupport::encrypt(pubParams, "|attr1|attr3",
                                                          Buffer(randomBytes2, sizeof(randomBytes2)));
                                  
  Buffer decryptedRandomBytes2 = algo::ABESupport::decrypt(pubParams, prvKey, cipherTextRandomBytes2);      
  BOOST_CHECK_EQUAL_COLLECTIONS(decryptedRandomBytes2.begin(), decryptedRandomBytes2.end(),
                                randomBytes2, randomBytes2 + sizeof(randomBytes2));

  // 1024 bytes random plaintext encryption and decryption
  uint8_t randomBytes3[1024];
  random::generateSecureBytes(randomBytes3, sizeof(randomBytes3));

  algo::CipherText cipherTextRandomBytes3 = algo::ABESupport::encrypt(pubParams, "|attr1|attr3",
                                                          Buffer(randomBytes3, sizeof(randomBytes3)));
                                  
  Buffer decryptedRandomBytes3 = algo::ABESupport::decrypt(pubParams, prvKey, cipherTextRandomBytes3);      
  BOOST_CHECK_EQUAL_COLLECTIONS(decryptedRandomBytes3.begin(), decryptedRandomBytes3.end(),
                                randomBytes3, randomBytes3 + sizeof(randomBytes3));

  // the following case tests decryption using wrong key; expects decryption failure
  // generate prv key
  std::vector<std::string> wrongKeyAttrList = {"(attr4 or attr6) and attr7"};
  algo::PrivateKey wrongPrvKey = algo::ABESupport::prvKeyGen(pubParams, masterKey, wrongKeyAttrList);
  bool decryptedSuccess = false;
  try {
      Buffer decryptedRandomBytes3 = algo::ABESupport::decrypt(pubParams, wrongPrvKey, cipherTextRandomBytes3); 
      decryptedSuccess = true;
  } catch (const std::runtime_error& e) {

  }
  BOOST_CHECK(!decryptedSuccess);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace nacabe
} // namespace ndn