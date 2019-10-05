/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2013-2017, Regents of the University of California.
 *
 * This file is part of ChronoShare, a decentralized file sharing application over NDN.
 *
 * ChronoShare is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation, either
 * version 3 of the License, or (at your option) any later version.
 *
 * ChronoShare is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received copies of the GNU General Public License along with
 * ChronoShare, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of ChronoShare authors and contributors.
 */

#include "algo/abe-support.hpp"
#include "test-common.hpp"

namespace ndn {
namespace ndnabac {
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

  BOOST_CHECK(pubParams.m_pub != nullptr);
  BOOST_CHECK(masterKey.m_msk != nullptr);
}

BOOST_AUTO_TEST_CASE(GenPrivateKey)
{
  algo::PublicParams pubParams;
  algo::MasterKey masterKey;

  algo::ABESupport::setup(pubParams, masterKey);

  std::vector<std::string> attrList = {"attr1", "attr2", "attr3", "attr4"};
  algo::PrivateKey prvKey = algo::ABESupport::prvKeyGen(pubParams, masterKey, attrList);

  BOOST_CHECK(prvKey.m_prv != nullptr);
}

BOOST_AUTO_TEST_CASE(Encryption)
{
  algo::PublicParams pubParams;
  algo::MasterKey masterKey;

  algo::ABESupport::setup(pubParams, masterKey);
  algo::CipherText cipherText = algo::ABESupport::encrypt(pubParams, "attr1 attr2 1of2",
                                                          Buffer(PLAIN_TEXT, sizeof(PLAIN_TEXT)));

  BOOST_CHECK(cipherText.m_cph != nullptr);
  BOOST_CHECK(cipherText.m_content.size() > sizeof(PLAIN_TEXT));
}

BOOST_AUTO_TEST_CASE(Decryption)
{
  algo::PublicParams pubParams;
  algo::MasterKey masterKey;

  // setup
  algo::ABESupport::setup(pubParams, masterKey);

  // generate prv key
  std::vector<std::string> attrList = {"attr1", "attr2", "attr3", "attr4"};
  algo::PrivateKey prvKey = algo::ABESupport::prvKeyGen(pubParams, masterKey, attrList);

  // encrypt
  algo::CipherText cipherText = algo::ABESupport::encrypt(pubParams, "attr1 attr2 1of2",
                                                          Buffer(PLAIN_TEXT, sizeof(PLAIN_TEXT)));

  // decrypt
  Buffer result = algo::ABESupport::decrypt(pubParams, prvKey, cipherText);

  BOOST_CHECK_EQUAL_COLLECTIONS(result.begin(), result.end(),
                                PLAIN_TEXT, PLAIN_TEXT + sizeof(PLAIN_TEXT));
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace ndnabac
} // namespace ndn
