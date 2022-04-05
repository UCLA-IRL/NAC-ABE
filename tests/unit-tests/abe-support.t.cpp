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

BOOST_AUTO_TEST_SUITE(TestAbeSupport)

BOOST_AUTO_TEST_CASE(CpSetup)
{
  algo::PublicParams pubParams;
  algo::MasterKey masterKey;
  algo::ABESupport::getInstance().cpInit(pubParams, masterKey);
  BOOST_CHECK(pubParams.m_pub != "");
  BOOST_CHECK(masterKey.m_msk != "");
}

BOOST_AUTO_TEST_CASE(KpSetup)
{
  algo::PublicParams pubParams;
  algo::MasterKey masterKey;
  algo::ABESupport::getInstance().kpInit(pubParams, masterKey);
  BOOST_CHECK(pubParams.m_pub != "");
  BOOST_CHECK(masterKey.m_msk != "");
}

BOOST_AUTO_TEST_CASE(CpGenPrivateKey)
{
  algo::PublicParams pubParams;
  algo::MasterKey masterKey;
  algo::ABESupport::getInstance().cpInit(pubParams, masterKey);
  std::vector<std::string> attrList = { "attr1", "attr2" };
  algo::PrivateKey prvKey = algo::ABESupport::getInstance().cpPrvKeyGen(pubParams, masterKey, attrList);
  BOOST_CHECK(prvKey.m_prv != "");
}

BOOST_AUTO_TEST_CASE(KpGenPrivateKey)
{
  algo::PublicParams pubParams;
  algo::MasterKey masterKey;
  algo::ABESupport::getInstance().kpInit(pubParams, masterKey);
  std::string policy = "(attr1 or attr2) and attr3";
  algo::PrivateKey prvKey = algo::ABESupport::getInstance().kpPrvKeyGen(pubParams, masterKey, policy);
  BOOST_CHECK(prvKey.m_prv != "");
}

BOOST_AUTO_TEST_CASE(CpEncryptionDecryption)
{
  // key cpInit
  algo::PublicParams pubParams;
  algo::MasterKey masterKey;
  algo::ABESupport::getInstance().cpInit(pubParams, masterKey);

  // encryption/decryption test case 1
  std::vector<std::string> attrList = { "ucla", "professor" };
  auto prvKey = algo::ABESupport::getInstance().cpPrvKeyGen(pubParams, masterKey, attrList);
  auto cipherText1 = algo::ABESupport::getInstance().cpEncrypt(pubParams, "(ucla or mit) and professor",
                                                               Buffer(PLAIN_TEXT, sizeof(PLAIN_TEXT)));
  auto result1 = algo::ABESupport::getInstance().cpDecrypt(pubParams, prvKey, cipherText1);
  BOOST_CHECK_EQUAL_COLLECTIONS(result1.begin(), result1.end(), PLAIN_TEXT, PLAIN_TEXT + sizeof(PLAIN_TEXT));

  // encryption/decryption test case 2
  uint8_t random32[32];
  random::generateSecureBytes({random32, sizeof(random32)});
  auto cipherText2 = algo::ABESupport::getInstance().cpEncrypt(pubParams, "ucla and professor",
                                                               Buffer(random32, sizeof(random32)));
  auto result2 = algo::ABESupport::getInstance().cpDecrypt(pubParams, prvKey, cipherText2);
  BOOST_CHECK_EQUAL_COLLECTIONS(result2.begin(), result2.end(), random32, random32 + sizeof(random32));

  // encryption/decryption test case 3
  uint8_t random64[64];
  random::generateSecureBytes({random64, sizeof(random64)});
  auto cipherText3 = algo::ABESupport::getInstance().cpEncrypt(pubParams, "ucla or mit",
                                                               Buffer(random64, sizeof(random64)));
  auto result3 = algo::ABESupport::getInstance().cpDecrypt(pubParams, prvKey, cipherText3);
  BOOST_CHECK_EQUAL_COLLECTIONS(result3.begin(), result3.end(), random64, random64 + sizeof(random64));

  // encryption/decryption test case 4
  uint8_t random1024[1024];
  random::generateSecureBytes({random1024, sizeof(random1024)});
  auto cipherText4 = algo::ABESupport::getInstance().cpEncrypt(pubParams, "ucla or professor",
                                                               Buffer(random1024, sizeof(random1024)));
  auto result4 = algo::ABESupport::getInstance().cpDecrypt(pubParams, prvKey, cipherText4);
  BOOST_CHECK_EQUAL_COLLECTIONS(result4.begin(), result4.end(), random1024, random1024 + sizeof(random1024));

  // encryption/decryption test case 5: access forbidden
  std::vector<std::string> wrongKeyAttrList = { "mit", "professor" };
  auto anotherPrvKey = algo::ABESupport::getInstance().cpPrvKeyGen(pubParams, masterKey, wrongKeyAttrList);
  try {
    auto result5 = algo::ABESupport::getInstance().cpDecrypt(pubParams, anotherPrvKey, cipherText2);
    BOOST_CHECK_EQUAL_COLLECTIONS(result5.begin(), result5.end(), random32, random32 + sizeof(random32));
    BOOST_CHECK(false);
  }
  catch (const std::runtime_error& e) {
    std::cout << "CP - Cannot decrypt because of the wrong decryption key attribute set" << std::endl;
    BOOST_CHECK(true);
  }

  // encryption/decryption test case 6: access forbidden
  algo::CipherText cipherText6 = algo::ABESupport::getInstance().cpEncrypt(pubParams, "mit and professor",
                                                                           Buffer(PLAIN_TEXT, sizeof(PLAIN_TEXT)));
  try{
    auto result6 = algo::ABESupport::getInstance().cpDecrypt(pubParams, prvKey, cipherText6);
    BOOST_CHECK(false);
  }
  catch (const std::runtime_error& e) {
    std::cout << "CP - Cannot decrypt because of the wrong encryption attribute policy" << std::endl;
    BOOST_CHECK(true);
  }
}

BOOST_AUTO_TEST_CASE(KpEncryptionDecryption)
{
  // key cpInit
  algo::PublicParams pubParams;
  algo::MasterKey masterKey;
  algo::ABESupport::getInstance().kpInit(pubParams, masterKey);

  uint8_t random32[32];
  auto prvKey = algo::ABESupport::getInstance().kpPrvKeyGen(pubParams, masterKey, "(cs or math) and homework");

  // encryption/decryption test case 1
  random::generateSecureBytes({random32, sizeof(random32)});
  std::vector<std::string> attrList = { "cs", "homework" };
  auto cipherText1 = algo::ABESupport::getInstance().kpEncrypt(pubParams, attrList,
                                                               Buffer(random32, sizeof(random32)));
  auto result1 = algo::ABESupport::getInstance().kpDecrypt(pubParams, prvKey, cipherText1);
  BOOST_CHECK_EQUAL_COLLECTIONS(result1.begin(), result1.end(), random32, random32 + sizeof(random32));

  // encryption/decryption test case 2
  random::generateSecureBytes({random32, sizeof(random32)});
  attrList = { "math", "homework" };
  auto cipherText2 = algo::ABESupport::getInstance().kpEncrypt(pubParams, attrList,
                                                               Buffer(random32, sizeof(random32)));
  auto result2 = algo::ABESupport::getInstance().kpDecrypt(pubParams, prvKey, cipherText2);
  BOOST_CHECK_EQUAL_COLLECTIONS(result2.begin(), result2.end(), random32, random32 + sizeof(random32));

  // encryption/decryption test case 3
  random::generateSecureBytes({random32, sizeof(random32)});
  attrList = { "math", "cs", "homework" };
  auto cipherText3 = algo::ABESupport::getInstance().kpEncrypt(pubParams, attrList,
                                                               Buffer(random32, sizeof(random32)));
  auto result3 = algo::ABESupport::getInstance().kpDecrypt(pubParams, prvKey, cipherText3);
  BOOST_CHECK_EQUAL_COLLECTIONS(result3.begin(), result3.end(), random32, random32 + sizeof(random32));

  // encryption/decryption test case 4
  random::generateSecureBytes({random32, sizeof(random32)});
  attrList = { "cs", "cs118", "homework" };
  auto cipherText4 = algo::ABESupport::getInstance().kpEncrypt(pubParams, attrList,
                                                               Buffer(random32, sizeof(random32)));
  auto result4 = algo::ABESupport::getInstance().kpDecrypt(pubParams, prvKey, cipherText4);
  BOOST_CHECK_EQUAL_COLLECTIONS(result4.begin(), result4.end(), random32, random32 + sizeof(random32));

  // encryption/decryption test case 5: access forbidden
  auto anotherPrvKey = algo::ABESupport::getInstance().kpPrvKeyGen(pubParams, masterKey, "cs and homework");
  try {
    attrList = { "math", "homework" };
    auto cipherText5 = algo::ABESupport::getInstance().kpEncrypt(pubParams, attrList,
                                                                 Buffer(random32, sizeof(random32)));
    auto result5 = algo::ABESupport::getInstance().kpDecrypt(pubParams, anotherPrvKey, cipherText5);
    BOOST_CHECK_EQUAL_COLLECTIONS(result5.begin(), result5.end(), random32, random32 + sizeof(random32));
    BOOST_CHECK(false);
  }
  catch (const std::runtime_error& e) {
    std::cout << "KP - Cannot decrypt because of the wrong decryption key attribute set" << std::endl;
    BOOST_CHECK(true);
  }

  // encryption/decryption test case 6: access forbidden
  attrList = {"homework"};
  algo::CipherText cipherText6 = algo::ABESupport::getInstance().kpEncrypt(pubParams, attrList,
                                                                           Buffer(PLAIN_TEXT, sizeof(PLAIN_TEXT)));
  try{
    auto result6 = algo::ABESupport::getInstance().cpDecrypt(pubParams, prvKey, cipherText6);
    BOOST_CHECK(false);
  }
  catch (const std::runtime_error& e) {
    std::cout << "CP - Cannot decrypt because of the wrong encryption attribute policy" << std::endl;
    BOOST_CHECK(true);
  }
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace nacabe
} // namespace ndn