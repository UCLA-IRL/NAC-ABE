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

#include "token-issuer.hpp"

#include "test-common.hpp"
#include "dummy-forwarder.hpp"

namespace ndn {
namespace ndnabac {
namespace tests {

namespace fs = boost::filesystem;

_LOG_INIT(Test.TokenIssuer);

class TestTokenIssuerFixture : public IdentityManagementTimeFixture
{
public:
  TestTokenIssuerFixture()
    : forwarder(m_io, m_keyChain)
  {
  }

public:
  DummyForwarder forwarder;
};

BOOST_FIXTURE_TEST_SUITE(TestTokenIssuer, TestTokenIssuerFixture)

BOOST_AUTO_TEST_CASE(onTokenRequestTest)
{
  Face& c1 = forwarder.addFace();
  Face& c2 = forwarder.addFace();
  security::Identity id = addIdentity("/tokenissuer1");
  security::Identity consumerId = addIdentity("/consumer1");
  security::Key key = id.getDefaultKey();
  security::v2::Certificate cert = key.getDefaultCertificate();

  TokenIssuer tokenissuer(cert, c1, m_keyChain);

  Name tokenIssuerPrefix = Name("/tokenissuer1");

  Interest interest(
    Name("/tokenissuer1").append(TokenIssuer::TOKEN_REQUEST).append(consumerId.getName()));

  c2.expressInterest(interest,
                     [=](const Interest&, const Data&){},
                     [=](const Interest&, const lp::Nack&){},
                     [=](const Interest&){});
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace ndnabac
} // namespace ndn
