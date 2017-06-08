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
    : forwarder(m_io)
    , producerFace(forwarder.addFace())
    , aaFace(forwarder.addFace())
    , tokenIssuerFace(forwarder.addFace())
    , consumerFace(forwarder.addFace())
    , dataOwnerFace(forwarder.addFace())
  {
  }

public:
  DummyForwarder forwarder;

  Face& producerFace;
  Face& aaFace;
  Face& tokenIssuerFace;
  Face& consumerFace;

  Face& dataOwnerFace;

  //shared_ptr<AttributeAuthority> aa;
  //shared_ptr<TokenIssuer> tokenIssuer;
  //shared_ptr<Consumer> consumer;
  //shared_ptr<Producer> producer;
  //shared_ptr<DataOwner> dataOwner;
};

BOOST_FIXTURE_TEST_SUITE(TestIntegrated, TestIntegratedFixture)

BOOST_AUTO_TEST_CASE(IntegratedTest)
{
  // set up AA
  security::Identity aaId = addIdentity("/aaPrefix");
  security::Key aaKey = aaId.getDefaultKey();
  security::v2::Certificate aaCert = aaKey.getDefaultCertificate();

  NDN_LOG_INFO("Create Attribute Authority. AA prefix:"<<aaCert.getIdentity());
  AttributeAuthority aa = AttributeAuthority(aaCert, aaFace, m_keyChain);
  advanceClocks(time::milliseconds(20), 60);

  BOOST_CHECK(aa.m_pubParams.m_pub != nullptr);
  BOOST_CHECK(aa.m_masterKey.m_msk != nullptr);

  // set up token issuer
  security::Identity tokenIssuerId = addIdentity("/tokenIssuerPrefix");
  security::Key tokenIssuerKey = tokenIssuerId.getDefaultKey();
  security::v2::Certificate tokenIssuerCert = tokenIssuerKey.getDefaultCertificate();

  NDN_LOG_INFO("Create Token Issuer. Token Issuer prefix:"<<tokenIssuerCert.getIdentity());
  TokenIssuer tokenIssuer = TokenIssuer(tokenIssuerCert, tokenIssuerFace, m_keyChain);
  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK_EQUAL(tokenIssuer.m_interestFilterIds.size(), 1);

  // define attr list for consumer rights
  security::Identity consumerId = addIdentity("/consumerPrefix");
  // m_keyChain.createKey(consumerId, RsaKeyParamsInfo());
  security::Key consumerKey = m_keyChain.createKey(consumerId, RsaKeyParams());
  security::v2::Certificate consumerCert = consumerKey.getDefaultCertificate();

  std::list<std::string> attrList = {"attr1, attr3"};
  NDN_LOG_INFO("Add comsumer "<<consumerCert.getIdentity()<<" with attributes: attr1, attr3");
  tokenIssuer.m_tokens.insert(std::pair<Name, std::list<std::string>>(consumerCert.getIdentity(),
                                                                      attrList));
  BOOST_CHECK_EQUAL(tokenIssuer.m_tokens.size(), 1);
  _LOG_DEBUG("after token issuer");

  // set up consumer
  NDN_LOG_INFO("Create Consumer. Consumer prefix:"<<consumerCert.getIdentity());
  Consumer consumer = Consumer(consumerCert, consumerFace, m_keyChain, aaCert.getIdentity());
  tokenIssuer.m_trustConfig.m_trustAnchors.push_back(consumerCert);
  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK(consumer.m_pubParamsCache.m_pub != nullptr);
  //***** need to compare pointer content *****
  //BOOST_CHECK(consumer->m_pubParamsCache.m_pub == aa->m_pubParams.m_pub);

  //NDN_LOG_INFO("after consumer");

  // set up producer
  security::Identity producerId = addIdentity("/producerPrefix");
  security::Key producerKey = producerId.getDefaultKey();
  security::v2::Certificate producerCert = producerKey.getDefaultCertificate();
  NDN_LOG_INFO("Create Producer. Producer prefix:"<<producerCert.getIdentity());
  Producer producer = Producer(producerCert, producerFace, m_keyChain, aaCert.getIdentity());
  advanceClocks(time::milliseconds(20), 60);

  BOOST_CHECK(producer.m_pubParamsCache.m_pub != nullptr);
  //***** need to compare pointer content *****
  //BOOST_CHECK(producer->m_pubParamsCache.m_pub == aa->m_pubParams.m_pub);
  BOOST_CHECK_EQUAL(producer.m_interestFilterIds.size(), 1);

  // set up data owner
  security::Identity dataOwnerId = addIdentity("/dataOwnerPrefix");
  security::Key dataOwnerKey = dataOwnerId.getDefaultKey();
  security::v2::Certificate dataOwnerCert = dataOwnerKey.getDefaultCertificate();
  NDN_LOG_INFO("Create Data Owner. Data Owner prefix:"<<dataOwnerCert.getIdentity());
  DataOwner dataOwner = DataOwner(dataOwnerCert, dataOwnerFace, m_keyChain);
  advanceClocks(time::milliseconds(20), 60);

  //==============================================

  Name dataName = "/dataName";
  std::string policy = "attr1 attr2 1of2 attr3 2of2";

  bool isPolicySet = false;
  dataOwner.commandProducerPolicy(producerCert.getIdentity(), dataName, policy,
                                   [&] (const Data& response) {
                                    _LOG_DEBUG("on policy set data callback");
                                     isPolicySet = true;
                                     BOOST_CHECK_EQUAL(readString(response.getContent()), "success");
                                     auto it = producer.m_policyCache.find(dataName);
                                     BOOST_CHECK(it != producer.m_policyCache.end());
                                     //std::cout << it->second << std::endl;
                                     //std::cout << policy << std::endl;
                                     BOOST_CHECK(it->second == policy);
                                   },
                                   [=] (const std::string& err) {
                                     BOOST_CHECK(false);
                                   });

  _LOG_DEBUG("before policy set");
  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK(isPolicySet);

  bool isProdCbCalled = false;
  producerFace.setInterestFilter(producerCert.getIdentity().append(dataName),
    [&] (const ndn::InterestFilter&, const ndn::Interest& interest) {

      NDN_LOG_INFO("consumer request for"<<interest.toUri());
      auto it = producer.m_policyCache.find(dataName);
      BOOST_CHECK(it != producer.m_policyCache.end());
      BOOST_CHECK(it->second == policy);
      producer.produce(dataName, it->second, PLAIN_TEXT, sizeof(PLAIN_TEXT),
        [&] (const Data& data) {
          isProdCbCalled = true;

          NDN_LOG_INFO("data successfully encrypted");
          producerFace.put(data);
        },
        [&] (const std::string& err) {
          BOOST_CHECK(false);
        });
    }
  );

  bool isConsumeCbCalled = false;
  consumer.consume(producerCert.getIdentity().append(dataName), tokenIssuerCert.getIdentity(),
    [&] (const Buffer& result) {
      isConsumeCbCalled = true;
      BOOST_CHECK_EQUAL_COLLECTIONS(result.begin(), result.end(),
                                    PLAIN_TEXT, PLAIN_TEXT + sizeof(PLAIN_TEXT));
    },
    [&] (const std::string& err) {
      BOOST_CHECK(false);
    }
  );
  advanceClocks(time::milliseconds(20), 60);

  BOOST_CHECK(isProdCbCalled);
  BOOST_CHECK(isConsumeCbCalled);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace ndnabac
} // namespace ndn
