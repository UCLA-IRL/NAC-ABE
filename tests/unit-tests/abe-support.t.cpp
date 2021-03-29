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

BOOST_AUTO_TEST_CASE(Setup)
{
  algo::PublicParams pubParams;
  algo::MasterKey masterKey;

  algo::ABESupport::getInstance().init(pubParams, masterKey);

  BOOST_CHECK(pubParams.m_pub != "");
  BOOST_CHECK(masterKey.m_msk != "");
}

BOOST_AUTO_TEST_CASE(GenPrivateKey)
{
  algo::PublicParams pubParams;
  algo::MasterKey masterKey;

  algo::ABESupport::getInstance().init(pubParams, masterKey);

  std::vector<std::string> attrList = { "attr1", "attr2" };
  algo::PrivateKey prvKey = algo::ABESupport::getInstance().prvKeyGen(pubParams, masterKey, attrList);

  BOOST_CHECK(prvKey.m_prv != "");
}

BOOST_AUTO_TEST_CASE(Encryption)
{
  algo::PublicParams pubParams;
  algo::MasterKey masterKey;

  algo::ABESupport::getInstance().init(pubParams, masterKey);
  algo::CipherText cipherText = algo::ABESupport::getInstance().encrypt(pubParams, "attr1 and attr2",
                                                                        Buffer(PLAIN_TEXT, sizeof(PLAIN_TEXT)));

  BOOST_CHECK(cipherText.m_aesKey.size() != 0);
  BOOST_CHECK(cipherText.m_content.size() > sizeof(PLAIN_TEXT));
}

BOOST_AUTO_TEST_CASE(EncryptionDecryption)
{
  // key init
  algo::PublicParams pubParams;
  algo::MasterKey masterKey;
  algo::ABESupport::getInstance().init(pubParams, masterKey);

  // encryption/decryption test case 1
  std::vector<std::string> attrList = { "ucla", "professor" };
  auto prvKey = algo::ABESupport::getInstance().prvKeyGen(pubParams, masterKey, attrList);
  auto cipherText1 = algo::ABESupport::getInstance().encrypt(pubParams, "(ucla or mit) and professor", Buffer(PLAIN_TEXT, sizeof(PLAIN_TEXT)));
  auto result1 = algo::ABESupport::getInstance().decrypt(pubParams, prvKey, cipherText1);
  BOOST_CHECK_EQUAL_COLLECTIONS(result1.begin(), result1.end(), PLAIN_TEXT, PLAIN_TEXT + sizeof(PLAIN_TEXT));

  // encryption/decryption test case 2
  uint8_t random32[32];
  random::generateSecureBytes(random32, sizeof(random32));
  auto cipherText2 = algo::ABESupport::getInstance().encrypt(pubParams, "ucla and professor", Buffer(random32, sizeof(random32)));
  auto result2 = algo::ABESupport::getInstance().decrypt(pubParams, prvKey, cipherText2);
  BOOST_CHECK_EQUAL_COLLECTIONS(result2.begin(), result2.end(), random32, random32 + sizeof(random32));

  // encryption/decryption test case 3
  uint8_t random64[64];
  random::generateSecureBytes(random64, sizeof(random64));
  auto cipherText3 = algo::ABESupport::getInstance().encrypt(pubParams, "ucla or mit", Buffer(random64, sizeof(random64)));
  auto result3 = algo::ABESupport::getInstance().decrypt(pubParams, prvKey, cipherText3);
  BOOST_CHECK_EQUAL_COLLECTIONS(result3.begin(), result3.end(), random64, random64 + sizeof(random64));

  // encryption/decryption test case 4
  uint8_t random1024[1024];
  random::generateSecureBytes(random1024, sizeof(random1024));
  auto cipherText4 = algo::ABESupport::getInstance().encrypt(pubParams, "ucla or professor", Buffer(random1024, sizeof(random1024)));
  auto result4 = algo::ABESupport::getInstance().decrypt(pubParams, prvKey, cipherText4);
  BOOST_CHECK_EQUAL_COLLECTIONS(result4.begin(), result4.end(), random1024, random1024 + sizeof(random1024));

  // encryption/decryption test case 5: access forbidden
  std::vector<std::string> wrongKeyAttrList = { "mit", "professor" };
  auto anotherPrvKey = algo::ABESupport::getInstance().prvKeyGen(pubParams, masterKey, wrongKeyAttrList);
  try {
    auto result5 = algo::ABESupport::getInstance().decrypt(pubParams, anotherPrvKey, cipherText2);
    BOOST_CHECK_EQUAL_COLLECTIONS(result5.begin(), result5.end(), random32, random32 + sizeof(random32));
    BOOST_CHECK(false);
  }
  catch (const std::runtime_error& e) {
    std::cout << "Cannot decrypt because of the wrong decryption key attribute set" << std::endl;
    BOOST_CHECK(true);
  }

  // encryption/decryption test case 6: access forbidden
  algo::CipherText cipherText6 = algo::ABESupport::getInstance().encrypt(pubParams, "mit and professor", Buffer(PLAIN_TEXT, sizeof(PLAIN_TEXT)));
  try{
    auto result6 = algo::ABESupport::getInstance().decrypt(pubParams, prvKey, cipherText6);
    BOOST_CHECK(false);
  }
  catch (const std::runtime_error& e) {
    std::cout << "Cannot decrypt because of the wrong encryption attribute policy" << std::endl;
    BOOST_CHECK(true);
  }
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace nacabe
} // namespace ndn