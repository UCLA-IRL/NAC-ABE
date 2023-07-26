/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2017-2023, Regents of the University of California.
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
#include "consumer.hpp"
#include "data-owner.hpp"
#include "producer.hpp"
#include "cache-producer.hpp"

#include "test-common.hpp"

#include <ndn-cxx/util/dummy-client-face.hpp>

namespace ndn {
namespace nacabe {
namespace tests {

const uint8_t PLAIN_TEXT[1024] = {1};

NDN_LOG_INIT(Test.IntegratedTest);

class TestIntegratedFixture : public IdentityManagementTimeFixture
{
public:
  TestIntegratedFixture()
    : producerFace(io, m_keyChain, {false, true})
    , aaFace(io, m_keyChain, {false, true})
    , tokenIssuerFace(io, m_keyChain, {false, true})
    , consumerFace1(io, m_keyChain, {false, true})
    , consumerFace2(io, m_keyChain, {false, true})
    , dataOwnerFace(io, m_keyChain, {false, true})
  {
    producerFace.linkTo(aaFace);
    producerFace.linkTo(tokenIssuerFace);
    producerFace.linkTo(consumerFace1);
    producerFace.linkTo(consumerFace2);
    producerFace.linkTo(dataOwnerFace);

    security::pib::Identity anchorId = addIdentity("/example");
    anchorCert = anchorId.getDefaultKey().getDefaultCertificate();
    saveCertToFile(anchorCert, "example-trust-anchor.cert");
    security::pib::Identity consumerId1 = addIdentity("/example/consumer1", RsaKeyParams());
    addSubCertificate("/example/consumer1", anchorId);
    consumerCert1 = consumerId1.getDefaultKey().getDefaultCertificate();

    security::pib::Identity consumerId2 = addIdentity("/example/consumer2", RsaKeyParams());
    addSubCertificate("/example/consumer1", anchorId);
    consumerCert2 = consumerId2.getDefaultKey().getDefaultCertificate();

    security::pib::Identity producerId = addIdentity("/example/producer");
    addSubCertificate("/example/producer", anchorId);
    producerCert = producerId.getDefaultKey().getDefaultCertificate();

    security::pib::Identity dataOwnerId = addIdentity("/example/dataOwner");
    addSubCertificate("/example/dataOwner", anchorId);
    dataOwnerCert = dataOwnerId.getDefaultKey().getDefaultCertificate();

    security::pib::Identity tokenIssuerId = addIdentity("/example/tokenIssuer");
    addSubCertificate("/example/tokenIssuer", anchorId);
    tokenIssuerCert = tokenIssuerId.getDefaultKey().getDefaultCertificate();

    security::pib::Identity authorityId = addIdentity("/example/authority");
    addSubCertificate("/example/authority", anchorId);
    aaCert = authorityId.getDefaultKey().getDefaultCertificate();

    signingInfo = signingByCertificate(producerCert);
  }

protected:
  util::DummyClientFace producerFace;
  util::DummyClientFace aaFace;
  util::DummyClientFace tokenIssuerFace;
  util::DummyClientFace consumerFace1;
  util::DummyClientFace consumerFace2;
  util::DummyClientFace dataOwnerFace;

  security::Certificate aaCert;
  security::Certificate anchorCert;
  security::Certificate tokenIssuerCert;
  security::Certificate consumerCert1;
  security::Certificate consumerCert2;
  security::Certificate producerCert;
  security::Certificate dataOwnerCert;
  security::SigningInfo signingInfo;
};

BOOST_FIXTURE_TEST_SUITE(TestIntegrated, TestIntegratedFixture)

BOOST_AUTO_TEST_CASE(Cp)
{
  // set up AA
  NDN_LOG_INFO("Create Attribute Authority. AA prefix: " << aaCert.getIdentity());
  CpAttributeAuthority aa(aaCert, aaFace, m_keyChain);
  advanceClocks(time::milliseconds(20), 60);

  // define attr list for consumer rights
  std::list<std::string> attrList = {"attr1", "attr3"};
  NDN_LOG_INFO("Add comsumer 1 "<<consumerCert1.getIdentity()<<" with attributes: attr1, attr3");
  aa.addNewPolicy(consumerCert1, attrList);
  BOOST_CHECK_EQUAL(aa.m_tokens.size(), 1);

  std::list<std::string> attrList1 = {"attr1"};
  NDN_LOG_INFO("Add comsumer 2 "<<consumerCert2.getIdentity()<<" with attributes: attr1");
  aa.addNewPolicy(consumerCert2, attrList1);
  BOOST_CHECK_EQUAL(aa.m_tokens.size(), 2);

  // set up consumer
  NDN_LOG_INFO("Create Consumer 1. Consumer 1 prefix:"<<consumerCert1.getIdentity());
  security::ValidatorConfig validator1(consumerFace1);
  validator1.load("trust-schema.conf");
  Consumer consumer1(consumerFace1, m_keyChain, validator1, consumerCert1, aaCert);
  advanceClocks(time::milliseconds(20), 60);
  consumerFace1.receive(aaCert);
  advanceClocks(time::milliseconds(20), 60);
  consumerFace1.receive(anchorCert);
  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK(consumer1.m_paramFetcher.getPublicParams().m_pub != "");

  // set up consumer
  NDN_LOG_INFO("Create Consumer 2. Consumer 2 prefix:"<<consumerCert2.getIdentity());
  security::ValidatorConfig validator2(consumerFace2);
  validator2.load("trust-schema.conf");
  Consumer consumer2(consumerFace2, m_keyChain, validator2, consumerCert2, aaCert);
  advanceClocks(time::milliseconds(20), 60);
  consumerFace2.receive(aaCert);
  advanceClocks(time::milliseconds(20), 60);
  consumerFace2.receive(anchorCert);
  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK(consumer2.m_paramFetcher.getPublicParams().m_pub != "");

  // set up producer
  NDN_LOG_INFO("Create Producer. Producer prefix:"<<producerCert.getIdentity());
  security::ValidatorConfig validator3(producerFace);
  validator3.load("trust-schema.conf");
  Producer producer(producerFace, m_keyChain, validator3, producerCert, aaCert, dataOwnerCert);
  advanceClocks(time::milliseconds(20), 60);
  producerFace.receive(aaCert);
  advanceClocks(time::milliseconds(20), 60);
  producerFace.receive(anchorCert);
  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK(producer.m_paramFetcher.getPublicParams().m_pub != "");

  // set up data owner
  NDN_LOG_INFO("Create Data Owner. Data Owner prefix:"<<dataOwnerCert.getIdentity());
  DataOwner dataOwner(dataOwnerCert, dataOwnerFace, m_keyChain);
  advanceClocks(time::milliseconds(20), 60);

  NDN_LOG_INFO("\n=================== start work flow ==================\n");

  Name dataName = "/dataName";
  std::string policy = "(attr1 or attr2) and attr3";

  bool isPolicySet = false;
  dataOwner.commandProducerPolicy(producerCert.getIdentity(), dataName, policy,
                                   [&] (const Data& response) {
                                     NDN_LOG_DEBUG("on policy set data callback");
                                     isPolicySet = true;
                                     BOOST_CHECK_EQUAL(readString(response.getContent()), "success");
                                     auto policyFound = producer.findMatchedPolicy(dataName);
                                     BOOST_CHECK(policyFound == policy);
                                   },
                                   [] (const std::string&) {
                                     BOOST_CHECK(false);
                                   });

  NDN_LOG_DEBUG("Before policy set");
  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK(isPolicySet);

  std::vector<std::shared_ptr<Data>> contentData, ckData;
  auto policyFound = producer.findMatchedPolicy(dataName);

  std::tie(contentData, ckData) = producer.produce(dataName, policyFound, PLAIN_TEXT, signingInfo);
  BOOST_CHECK(contentData.size() > 0);
  BOOST_CHECK(ckData.size() > 0);
  NDN_LOG_DEBUG("Content data name: " << contentData.at(0)->getName());
  producerFace.setInterestFilter(producerCert.getIdentity(),
    [&] (const ndn::InterestFilter&, const ndn::Interest& interest) {
      NDN_LOG_INFO("Consumer request for " << interest.toUri());
      for (auto seg : contentData) {
        bool exactSeg = interest.getName() == seg->getName();
        bool probeSeg = (interest.getName() == seg->getName().getPrefix(-1)) &&
                         interest.getCanBePrefix();
        if (exactSeg || probeSeg) {
          producerFace.put(*seg);
          break;
        }
      }
      if (interest.getName().isPrefixOf(ckData.at(0)->getName())) {
        producerFace.put(*ckData.at(0));
      }
    }
  );

  bool isConsumeCbCalled = false;
  consumer1.obtainDecryptionKey();
  advanceClocks(time::milliseconds(20), 60);
  consumer1.consume(producerCert.getIdentity().append(dataName),
    [&] (const Buffer& result) {
      isConsumeCbCalled = true;
      BOOST_CHECK_EQUAL_COLLECTIONS(result.begin(), result.end(),
                                    PLAIN_TEXT, PLAIN_TEXT + sizeof(PLAIN_TEXT));
    },
    [] (const std::string&) {
      BOOST_CHECK(false);
    }
  );
  advanceClocks(time::milliseconds(20), 60);
  consumerFace1.receive(producerCert);
  advanceClocks(time::milliseconds(20), 60);
  consumerFace1.receive(anchorCert);
  advanceClocks(time::milliseconds(20), 60);
  consumerFace1.receive(aaCert);
  advanceClocks(time::milliseconds(20), 60);
  consumerFace1.receive(anchorCert);
  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK(isConsumeCbCalled);

  isConsumeCbCalled = false;
  consumer2.obtainDecryptionKey();
  advanceClocks(time::milliseconds(20), 60);
  consumer2.consume(producerCert.getIdentity().append(dataName),
    [] (const Buffer&) {
      BOOST_CHECK(false);
    },
    [&] (const std::string&) {
      isConsumeCbCalled = true;
    }
  );
  advanceClocks(time::milliseconds(20), 60);
  consumerFace2.receive(producerCert);
  advanceClocks(time::milliseconds(20), 60);
  consumerFace2.receive(anchorCert);
  advanceClocks(time::milliseconds(20), 60);
  consumerFace2.receive(aaCert);
  advanceClocks(time::milliseconds(20), 60);
  consumerFace2.receive(anchorCert);
  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK(isConsumeCbCalled);
}

BOOST_AUTO_TEST_CASE(Kp)
{
  // set up AA
  NDN_LOG_INFO("Create Attribute Authority. AA prefix: " << aaCert.getIdentity());
  KpAttributeAuthority aa(aaCert, aaFace, m_keyChain);
  advanceClocks(time::milliseconds(20), 60);

  // define attr list for consumer rights
  Policy policy1 = "cs";
  NDN_LOG_INFO("Add comsumer 1 "<< consumerCert1.getIdentity() <<" with policy: " << policy1);
  aa.addNewPolicy(consumerCert1, policy1);
  BOOST_CHECK_EQUAL(aa.m_tokens.size(), 1);

  Policy policy2 = "cs and homework";
  NDN_LOG_INFO("Add comsumer 2 "<<consumerCert2.getIdentity()<<" with policy: " << policy2);
  aa.addNewPolicy(consumerCert2, policy2);
  BOOST_CHECK_EQUAL(aa.m_tokens.size(), 2);

  // set up consumer
  NDN_LOG_INFO("Create Consumer 1. Consumer 1 prefix:"<<consumerCert1.getIdentity());
  security::ValidatorConfig validator1(consumerFace1);
  validator1.load("trust-schema.conf");
  Consumer consumer1(consumerFace1, m_keyChain, validator1, consumerCert1, aaCert);
  advanceClocks(time::milliseconds(20), 60);
  consumerFace1.receive(aaCert);
  advanceClocks(time::milliseconds(20), 60);
  consumerFace1.receive(anchorCert);
  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK(consumer1.m_paramFetcher.getPublicParams().m_pub != "");

  // set up consumer
  NDN_LOG_INFO("Create Consumer 2. Consumer 2 prefix:"<<consumerCert2.getIdentity());
  security::ValidatorConfig validator2(consumerFace2);
  validator2.load("trust-schema.conf");
  Consumer consumer2(consumerFace2, m_keyChain, validator2, consumerCert2, aaCert);
  advanceClocks(time::milliseconds(20), 60);
  consumerFace2.receive(aaCert);
  advanceClocks(time::milliseconds(20), 60);
  consumerFace2.receive(anchorCert);
  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK(consumer2.m_paramFetcher.getPublicParams().m_pub != "");

  // set up producer
  NDN_LOG_INFO("Create Producer. Producer prefix:"<<producerCert.getIdentity());
  security::ValidatorConfig validator3(producerFace);
  validator3.load("trust-schema.conf");
  Producer producer(producerFace, m_keyChain, validator3, producerCert, aaCert, dataOwnerCert);
  advanceClocks(time::milliseconds(20), 60);
  producerFace.receive(aaCert);
  advanceClocks(time::milliseconds(20), 60);
  producerFace.receive(anchorCert);
  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK(producer.m_paramFetcher.getPublicParams().m_pub != "");

  // set up data owner
  NDN_LOG_INFO("Create Data Owner. Data Owner prefix:"<<dataOwnerCert.getIdentity());
  DataOwner dataOwner(dataOwnerCert, dataOwnerFace, m_keyChain);
  advanceClocks(time::milliseconds(20), 60);

  NDN_LOG_INFO("\n=================== start work flow ==================\n");

  Name dataName = "/dataName";
  std::vector<std::string> attr = {"cs", "exam"};

  bool isPolicySet = false;
  dataOwner.commandProducerPolicy(producerCert.getIdentity(), dataName, attr,
    [&] (const Data& response) {
      NDN_LOG_DEBUG("on policy set data callback");
      isPolicySet = true;
      BOOST_CHECK_EQUAL(readString(response.getContent()), "success");
      auto attrFound = producer.findMatchedAttributes(dataName);
      BOOST_CHECK_EQUAL_COLLECTIONS(attrFound.begin(), attrFound.end(), attr.begin(), attr.end());
    },
    [] (const std::string&) {
      BOOST_CHECK(false);
    }
  );

  NDN_LOG_DEBUG("Before policy set");
  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK(isPolicySet);

  std::vector<std::shared_ptr<Data>> contentData, ckData;
  auto attributeFound = producer.findMatchedAttributes(dataName);
  std::tie(contentData, ckData) = producer.produce(dataName, attributeFound, PLAIN_TEXT, signingInfo);
  BOOST_CHECK(contentData.size() > 0);
  BOOST_CHECK(ckData.size() > 0);
  NDN_LOG_DEBUG("Content data name: " << contentData.at(0)->getName());

  producerFace.setInterestFilter(producerCert.getIdentity(),
    [&] (const ndn::InterestFilter&, const ndn::Interest& interest) {
      NDN_LOG_INFO("consumer request for" << interest.toUri());
      if (interest.getName().isPrefixOf(contentData.at(0)->getName())) {
        producerFace.put(*contentData.at(0));
      }
      if (interest.getName().isPrefixOf(ckData.at(0)->getName())) {
        producerFace.put(*ckData.at(0));
      }
    }
  );

  bool isConsumeCbCalled = false;
  consumer1.obtainDecryptionKey();
  advanceClocks(time::milliseconds(20), 60);
  consumer1.consume(producerCert.getIdentity().append(dataName),
    [&] (const Buffer& result) {
      isConsumeCbCalled = true;
      BOOST_CHECK_EQUAL_COLLECTIONS(result.begin(), result.end(),
                                    PLAIN_TEXT, PLAIN_TEXT + sizeof(PLAIN_TEXT));
    },
    [] (const std::string&) {
      BOOST_CHECK(false);
    }
  );
  advanceClocks(time::milliseconds(20), 60);
  consumerFace1.receive(producerCert);
  advanceClocks(time::milliseconds(20), 60);
  consumerFace1.receive(anchorCert);
  advanceClocks(time::milliseconds(20), 60);
  consumerFace1.receive(aaCert);
  advanceClocks(time::milliseconds(20), 60);
  consumerFace1.receive(anchorCert);
  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK(isConsumeCbCalled);

  isConsumeCbCalled = false;
  consumer2.obtainDecryptionKey();
  advanceClocks(time::milliseconds(20), 60);
  consumer2.consume(producerCert.getIdentity().append(dataName),
    [] (const Buffer&) {
      BOOST_CHECK(false);
    },
    [&] (const std::string&) {
      isConsumeCbCalled = true;
    }
  );
  advanceClocks(time::milliseconds(20), 60);
  consumerFace2.receive(producerCert);
  advanceClocks(time::milliseconds(20), 60);
  consumerFace2.receive(anchorCert);
  advanceClocks(time::milliseconds(20), 60);
  consumerFace2.receive(aaCert);
  advanceClocks(time::milliseconds(20), 60);
  consumerFace2.receive(anchorCert);
  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK(isConsumeCbCalled);
}

BOOST_AUTO_TEST_CASE(KpCache)
{
  // set up AA
  NDN_LOG_INFO("Create Attribute Authority. AA prefix: " << aaCert.getIdentity());
  KpAttributeAuthority aa(aaCert, aaFace, m_keyChain);
  advanceClocks(time::milliseconds(20), 60);

  // define attr list for consumer rights
  Policy policy1 = "cs";
  NDN_LOG_INFO("Add comsumer 1 "<< consumerCert1.getIdentity() <<" with policy: " << policy1);
  aa.addNewPolicy(consumerCert1, policy1);
  BOOST_CHECK_EQUAL(aa.m_tokens.size(), 1);

  Policy policy2 = "cs and homework";
  NDN_LOG_INFO("Add comsumer 2 "<<consumerCert2.getIdentity()<<" with policy: " << policy2);
  aa.addNewPolicy(consumerCert2, policy2);
  BOOST_CHECK_EQUAL(aa.m_tokens.size(), 2);

  // set up consumer
  NDN_LOG_INFO("Create Consumer 1. Consumer 1 prefix:"<<consumerCert1.getIdentity());
  security::ValidatorConfig validator1(consumerFace1);
  validator1.load("trust-schema.conf");
  Consumer consumer1(consumerFace1, m_keyChain, validator1, consumerCert1, aaCert);
  advanceClocks(time::milliseconds(20), 60);
  consumerFace1.receive(aaCert);
  advanceClocks(time::milliseconds(20), 60);
  consumerFace1.receive(anchorCert);
  BOOST_CHECK(consumer1.m_paramFetcher.getPublicParams().m_pub != "");

  // set up consumer
  NDN_LOG_INFO("Create Consumer 2. Consumer 2 prefix:"<<consumerCert2.getIdentity());
  security::ValidatorConfig validator2(consumerFace2);
  validator2.load("trust-schema.conf");
  Consumer consumer2(consumerFace2, m_keyChain, validator2, consumerCert2, aaCert);
  advanceClocks(time::milliseconds(20), 60);
  consumerFace2.receive(aaCert);
  advanceClocks(time::milliseconds(20), 60);
  consumerFace2.receive(anchorCert);
  BOOST_CHECK(consumer2.m_paramFetcher.getPublicParams().m_pub != "");

  // set up producer
  NDN_LOG_INFO("Create Producer. Producer prefix:"<<producerCert.getIdentity());
  security::ValidatorConfig validator3(producerFace);
  validator3.load("trust-schema.conf");
  CacheProducer producer(producerFace, m_keyChain, validator3, producerCert, aaCert, dataOwnerCert);
  advanceClocks(time::milliseconds(20), 60);
  producerFace.receive(aaCert);
  advanceClocks(time::milliseconds(20), 60);
  producerFace.receive(anchorCert);
  BOOST_CHECK(producer.m_paramFetcher.getPublicParams().m_pub != "");

  // set up data owner
  NDN_LOG_INFO("Create Data Owner. Data Owner prefix:"<<dataOwnerCert.getIdentity());
  DataOwner dataOwner(dataOwnerCert, dataOwnerFace, m_keyChain);
  advanceClocks(time::milliseconds(20), 60);

  NDN_LOG_INFO("\n=================== start work flow ==================\n");

  Name dataName = "/dataName";
  std::vector<std::string> attr = {"cs", "exam"};

  bool isPolicySet = false;
  dataOwner.commandProducerPolicy(producerCert.getIdentity(), dataName, attr,
    [&] (const Data& response) {
      NDN_LOG_DEBUG("on policy set data callback");
      isPolicySet = true;
      BOOST_CHECK_EQUAL(readString(response.getContent()), "success");
      auto attrFound = producer.findMatchedAttributes(dataName);
      BOOST_CHECK_EQUAL_COLLECTIONS(attrFound.begin(), attrFound.end(), attr.begin(), attr.end());
    },
    [] (const std::string&) {
      BOOST_CHECK(false);
    }
  );

  NDN_LOG_DEBUG("Before policy set");
  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK(isPolicySet);
  std::vector<std::shared_ptr<Data>>  contentData, ckData;
  auto attributeFound = producer.findMatchedAttributes(dataName);
  BOOST_CHECK(producer.m_kpKeyCache.size() == 0);
  std::tie(contentData, ckData) = producer.produce(dataName, attributeFound, PLAIN_TEXT, signingInfo);
  BOOST_CHECK(producer.m_kpKeyCache.size() == 1);
  std::tie(contentData, ckData) = producer.produce(dataName, attributeFound, PLAIN_TEXT, signingInfo);
  BOOST_CHECK(producer.m_kpKeyCache.size() == 1);
  BOOST_CHECK(contentData.size() > 0);
  BOOST_CHECK(ckData.size() > 0);
  NDN_LOG_DEBUG("Content data name: " << contentData.at(0)->getName());

  producerFace.setInterestFilter(producerCert.getIdentity(),
    [&] (const ndn::InterestFilter&, const ndn::Interest& interest) {
      NDN_LOG_INFO("consumer request for" << interest.toUri());
      if (interest.getName().isPrefixOf(contentData.at(0)->getName())) {
        producerFace.put(*contentData.at(0));
      }
      if (interest.getName().isPrefixOf(ckData.at(0)->getName())) {
        producerFace.put(*ckData.at(0));
      }
    }
  );

  bool isConsumeCbCalled = false;
  consumer1.obtainDecryptionKey();
  advanceClocks(time::milliseconds(20), 60);
  consumer1.consume(producerCert.getIdentity().append(dataName),
    [&] (const Buffer& result) {
      isConsumeCbCalled = true;
      BOOST_CHECK_EQUAL_COLLECTIONS(result.begin(), result.end(),
                                    PLAIN_TEXT, PLAIN_TEXT + sizeof(PLAIN_TEXT));
    },
    [] (const std::string&) {
      BOOST_CHECK(false);
    }
  );
  advanceClocks(time::milliseconds(20), 60);
  consumerFace1.receive(producerCert);
  advanceClocks(time::milliseconds(20), 60);
  consumerFace1.receive(anchorCert);
  advanceClocks(time::milliseconds(20), 60);
  consumerFace1.receive(aaCert);
  advanceClocks(time::milliseconds(20), 60);
  consumerFace1.receive(anchorCert);
  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK(isConsumeCbCalled);

  isConsumeCbCalled = false;
  consumer2.obtainDecryptionKey();
  advanceClocks(time::milliseconds(20), 60);
  consumer2.consume(producerCert.getIdentity().append(dataName),
    [] (const Buffer&) {
      BOOST_CHECK(false);
    },
    [&] (const std::string&) {
      isConsumeCbCalled = true;
    }
  );
  advanceClocks(time::milliseconds(20), 60);
  consumerFace2.receive(producerCert);
  advanceClocks(time::milliseconds(20), 60);
  consumerFace2.receive(anchorCert);
  advanceClocks(time::milliseconds(20), 60);
  consumerFace2.receive(aaCert);
  advanceClocks(time::milliseconds(20), 60);
  consumerFace2.receive(anchorCert);
  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK(isConsumeCbCalled);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace nacabe
} // namespace ndn
