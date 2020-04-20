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

#include "token-issuer.hpp"
#include "test-common.hpp"
#include <ndn-cxx/util/dummy-client-face.hpp>

namespace ndn {
namespace nacabe {
namespace tests {

namespace fs = boost::filesystem;

NDN_LOG_INIT(Test.TokenIssuer);

class TestTokenIssuerFixture : public IdentityManagementTimeFixture
{
public:
  TestTokenIssuerFixture()
    : c1(io, m_keyChain, util::DummyClientFace::Options{true, true})
    , c2(io, m_keyChain, util::DummyClientFace::Options{true, true})
  {
    c1.linkTo(c2);
  }

public:
  util::DummyClientFace c1;
  util::DummyClientFace c2;
};

BOOST_FIXTURE_TEST_SUITE(TestTokenIssuer, TestTokenIssuerFixture)

BOOST_AUTO_TEST_CASE(onTokenRequestTest)
{
  security::Identity id = addIdentity("/tokenissuer1");
  security::Identity consumerId = addIdentity("/consumer1");
  security::Key key = id.getDefaultKey();
  security::v2::Certificate cert = key.getDefaultCertificate();

  TokenIssuer tokenissuer(cert, c1, m_keyChain);

  advanceClocks(time::milliseconds(20), 60);

  BOOST_CHECK_EQUAL(tokenissuer.m_interestFilterIds.size(), 1);

  Name tokenIssuerPrefix = cert.getIdentity();

  Interest interest(
    tokenIssuerPrefix.append(TokenIssuer::TOKEN_REQUEST).append(consumerId.getName()));

  //******* how to handle token Issuer
  c2.expressInterest(interest,
                     [=](const Interest&, const Data&){},
                     [=](const Interest&, const lp::Nack&){},
                     [=](const Interest&){});
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace nacabe
} // namespace ndn
