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

#include "attribute-authority.hpp"

#include "test-common.hpp"
#include "dummy-forwarder.hpp"

namespace ndn {
namespace ndnabac {
namespace tests {

namespace fs = boost::filesystem;

_LOG_INIT(Test.AttributeAuthority);

class TestAttributeAuthorityFixture : public IdentityManagementTimeFixture
{
public:
  TestAttributeAuthorityFixture()
    : forwarder(m_io, m_keyChain)
    , c1(forwarder.addFace())
    , c2(forwarder.addFace())
  {
    id = addIdentity("/ndn/test/abac");
    key = id.getDefaultKey();
    cert = key.getDefaultCertificate();

    aa = make_shared<AttributeAuthority>(AttributeAuthority(cert, c1, m_keyChain));
  }

public:
  DummyForwarder forwarder;
  Face& c1;
  Face& c2;
  security::Identity id;
  security::Key key;
  security::v2::Certificate cert;
  shared_ptr<AttributeAuthority> aa;
};

BOOST_FIXTURE_TEST_SUITE(TestAttributeAuthority, TestAttributeAuthorityFixture)

BOOST_AUTO_TEST_CASE(onDecryptionKeyRequest)
{
  Interest interest(
    Name("/ndn/test/abac").append("DKEY"));
}

BOOST_AUTO_TEST_CASE(onPublicParamsRequest)
{
  Interest interest(
    Name("/ndn/test/abac").append(AttributeAuthority::PUBLIC_PARAMS));
  c2.expressInterest(interest,
                     [=](const Interest&, const Data&){},
                     [=](const Interest&, const lp::Nack&){},
                     [=](const Interest&){});
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace ndnabac
} // namespace ndn
