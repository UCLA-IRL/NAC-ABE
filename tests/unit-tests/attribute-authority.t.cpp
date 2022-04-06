/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2017-2022, Regents of the University of California.
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

#include "attribute-authority.hpp"

#include "test-common.hpp"

#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>
#include <ndn-cxx/util/dummy-client-face.hpp>

namespace ndn {
namespace nacabe {
namespace tests {

class TestAttributeAuthorityFixture : public IdentityManagementTimeFixture
{
public:
  TestAttributeAuthorityFixture()
    : attrAuthorityPrefix("/authority")
  {
    consumerCert = addIdentity("/consumer", RsaKeyParams()).getDefaultKey().getDefaultCertificate();
    authorityCert = addIdentity("/authority").getDefaultKey().getDefaultCertificate();
  }

protected:
  Name attrAuthorityPrefix;
  security::Certificate consumerCert;
  security::Certificate authorityCert;
};

BOOST_FIXTURE_TEST_SUITE(TestAttributeAuthority, TestAttributeAuthorityFixture)

BOOST_AUTO_TEST_CASE(Constructor)
{
  util::DummyClientFace face(io, {true, true});
  CpAttributeAuthority aa(authorityCert, face, m_keyChain);
  BOOST_CHECK(!aa.m_pubParams.m_pub.empty());
  BOOST_CHECK(!aa.m_masterKey.m_msk.empty());
}

BOOST_AUTO_TEST_CASE(OnPublicParams)
{
  util::DummyClientFace face(io, {true, true});
  CpAttributeAuthority aa(authorityCert, face, m_keyChain);
  Name interestName = attrAuthorityPrefix;
  Interest request(interestName.append(PUBLIC_PARAMS));
  request.setCanBePrefix(true);
  auto requiredBuffer = aa.m_pubParams.toBuffer();

  advanceClocks(time::milliseconds(20), 60);

  int count = 0;
  face.onSendData.connect([&] (const Data& response) {
      count++;
      BOOST_CHECK(security::verifySignature(response, authorityCert));

      auto block = response.getContent();
      Buffer contentBuffer(block.value(), block.value_size());
      algo::PublicParams pubParams;
      pubParams.fromBuffer(contentBuffer);
      auto buffer = pubParams.toBuffer();

      BOOST_CHECK_EQUAL_COLLECTIONS(buffer.begin(), buffer.end(),
                                    requiredBuffer.begin(), requiredBuffer.end());
    });
  face.receive(request);

  advanceClocks(time::milliseconds(20), 60);

  BOOST_CHECK_EQUAL(count, 1);
}

BOOST_AUTO_TEST_CASE(OnPrvKey)
{
  Name consumerName("/consumer");
  std::list<std::string> attrList = {"attr1", "attr2", "attr3", "attr4", "attr5",
                                     "attr6", "attr7", "attr8", "attr9", "attr10"};

  util::DummyClientFace face(io, {true, true});
  CpAttributeAuthority aa(authorityCert, face, m_keyChain);
  aa.addNewPolicy(consumerCert, attrList);

  Name interestName = attrAuthorityPrefix;
  interestName.append("DKEY")
              .append(consumerName.wireEncode().begin(), consumerName.wireEncode().end());
  Interest interest(interestName);
  interest.setCanBePrefix(true);
  m_keyChain.sign(interest, security::signingByCertificate(consumerCert));

  advanceClocks(time::milliseconds(20), 60);

  int count = 0;
  face.onSendData.connect([&] (const Data& response) {
    count++;
    BOOST_CHECK(security::verifySignature(response, authorityCert));
  });
  face.receive(interest);

  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK_EQUAL(count, 1);
}

BOOST_AUTO_TEST_CASE(OnKpPrvKey)
{
  Name consumerName("/consumer");
  Policy policy = "(a or b) and (c or d)";

  util::DummyClientFace face(io, {true, true});
  KpAttributeAuthority aa(authorityCert, face, m_keyChain);
  aa.addNewPolicy(consumerCert, policy);

  Name interestName = attrAuthorityPrefix;
  interestName.append("DKEY")
              .append(consumerName.wireEncode().begin(), consumerName.wireEncode().end());
  Interest interest(interestName);
  interest.setCanBePrefix(true);
  m_keyChain.sign(interest, security::signingByCertificate(consumerCert));

  advanceClocks(time::milliseconds(20), 60);

  int count = 0;
  face.onSendData.connect([&] (const Data& response) {
    count++;
    BOOST_CHECK(security::verifySignature(response, authorityCert));
  });
  face.receive(interest);

  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK_EQUAL(count, 1);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace nacabe
} // namespace ndn
