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
#include "consumer.hpp"
#include "data-owner.hpp"
#include "producer.hpp"
#include "token-issuer.hpp"

#include "test-common.hpp"
#include "dummy-forwarder.hpp"

namespace ndn {
namespace ndnabac {
namespace tests {

namespace fs = boost::filesystem;

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

_LOG_INIT(Test.IntegratedTest);

class TestIntegratedFixture : public IdentityManagementTimeFixture
{
public:
  TestIntegratedFixture()
    : forwarder(m_io, m_keyChain)
    , aaFace(forwarder.addFace())
    , tokenIssuerFace(forwarder.addFace())
    , consumerFace(forwarder.addFace())
    , producerFace(forwarder.addFace())
    , dataOwnerFace(forwarder.addFace())
  {
  }

public:
  DummyForwarder forwarder;

  Face& aaFace;
  Face& tokenIssuerFace;
  Face& consumerFace;
  Face& producerFace;
  Face& dataOwnerFace;

  security::v2::Certificate aaCert;
  security::v2::Certificate tokenIssuerCert;
  security::v2::Certificate consumerCert;
  security::v2::Certificate producerCert;
  security::v2::Certificate dataOwnerCert;

  shared_ptr<AttributeAuthority> aa;
  shared_ptr<TokenIssuer> tokenIssuer;
  shared_ptr<Consumer> consumer;
  shared_ptr<Producer> producer;
  shared_ptr<DataOwner> dataOwner;
};

BOOST_FIXTURE_TEST_SUITE(TestIntegrated, TestIntegratedFixture)

BOOST_AUTO_TEST_CASE(IntegratedTest)
{
  security::Identity aaId = addIdentity("/aaPrefix");
  security::Key aaKey = aaId.getDefaultKey();
  aaCert = aaKey.getDefaultCertificate();
  aa = make_shared<AttributeAuthority>(AttributeAuthority(aaCert, aaFace, m_keyChain));
  advanceClocks(time::milliseconds(20), 60);

  BOOST_CHECK(aa->m_pubParams.m_pub != nullptr);
  BOOST_CHECK(aa->m_masterKey.m_msk != nullptr);

  security::Identity tokenIssuerId = addIdentity("/tokenIssuerPrefix");
  security::Key tokenIssuerKey = tokenIssuerId.getDefaultKey();
  tokenIssuerCert = tokenIssuerKey.getDefaultCertificate();
  tokenIssuer = make_shared<TokenIssuer>(TokenIssuer(tokenIssuerCert, tokenIssuerFace, m_keyChain));
  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK_EQUAL(tokenIssuer->m_interestFilterIds.size(), 1);

  std::list<std::string> attrList = {"attr1, attr3"};
  tokenIssuer->m_tokens.insert(std::pair<Name, std::list<std::string> >(consumerCert.getIdentity(), attrList));

  BOOST_CHECK_EQUAL(tokenIssuer->m_tokens.size(), 1);

  security::Identity consumerId = addIdentity("/consumerPrefix");
  security::Key consumerKey = consumerId.getDefaultKey();
  consumerCert = consumerKey.getDefaultCertificate();
  consumer = make_shared<Consumer>(Consumer(aaCert, consumerFace, m_keyChain, aaCert.getIdentity()));
  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK(consumer->m_pubParamsCache.m_pub != nullptr);
  //***** need to compare pointer content *****
  BOOST_CHECK(consumer->m_pubParamsCache.m_pub == aa->m_pubParams.m_pub);

  security::Identity producerId = addIdentity("/producerPrefix");
  security::Key producerKey = producerId.getDefaultKey();
  producerCert = producerKey.getDefaultCertificate();
  producer = make_shared<Producer>(Producer(aaCert, producerFace, m_keyChain, aaCert.getIdentity()));
  advanceClocks(time::milliseconds(20), 60);

  BOOST_CHECK(producer->m_pubParamsCache.m_pub != nullptr);
  //***** need to compare pointer content *****
  BOOST_CHECK(producer->m_pubParamsCache.m_pub == aa->m_pubParams.m_pub);
  BOOST_CHECK_EQUAL(producer->m_interestFilterIds.size(), 1);

  security::Identity dataOwnerId = addIdentity("/dataOwnerPrefix");
  security::Key dataOwnerKey = dataOwnerId.getDefaultKey();
  dataOwnerCert = dataOwnerKey.getDefaultCertificate();
  dataOwner = make_shared<DataOwner>(DataOwner(dataOwnerCert, dataOwnerFace, m_keyChain));

  //==============================================

  Name dataName = "/dataName";
  Name interestName = producerCert.getIdentity();
  std::string policy = "attr1 attr2 1of2 attr3 2of2";
  interestName.append(DataOwner::SET_POLICY);
  interestName.append(policy);

  dataOwner->commandProducerPolicy(producerCert.getIdentity(), dataName, policy,
                                   [&] (const Data& response) {
                                     BOOST_CHECK_EQUAL(readString(response.getContent()), "success");
                                     auto it = producer->m_policyCache.find(dataName);
                                     BOOST_CHECK(it != producer->m_policyCache.end());
                                     BOOST_CHECK(it->second == policy);
                                   },
                                   [=] (const std::string& err) {
                                     BOOST_CHECK(false);
                                   });

  producerFace.setInterestFilter(dataName,
    [&] (const ndn::InterestFilter&, const ndn::Interest& interest) {
      auto it = producer->m_policyCache.find(dataName);
      BOOST_CHECK(it != producer->m_policyCache.end());
      BOOST_CHECK(it->second == policy);
      producer->produce(dataName, it->second, PLAIN_TEXT, sizeof(PLAIN_TEXT),
        [&] (const Data& data) {
          producerFace.put(data);
        },
        [&] (const std::string& err) {
          BOOST_CHECK(false);
        });
    }
  );

  consumer->consume(dataName, tokenIssuerCert.getIdentity(),
    [&] (const Buffer& result) {
      BOOST_CHECK_EQUAL_COLLECTIONS(result.begin(), result.end(),
                                    PLAIN_TEXT, PLAIN_TEXT + sizeof(PLAIN_TEXT));
    },
    [&] (const std::string& err) {
      BOOST_CHECK(false);
    }
  );
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace ndnabac
} // namespace ndn
