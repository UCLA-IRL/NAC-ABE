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
#include "consumer.hpp"
#include "data-owner.hpp"
#include "producer.hpp"

#include "test-common.hpp"

#include <ndn-cxx/util/dummy-client-face.hpp>

namespace ndn {
namespace nacabe {
namespace tests {

const uint8_t PLAIN_TEXT[1024] = {1};

NDN_LOG_INIT(Test.IntegratedUpdateTest);

class TestIntegratedUpdateFixture : public IdentityManagementTimeFixture
{
public:
  TestIntegratedUpdateFixture()
    : producerFace(io, m_keyChain, {false, true})
    , aaFace(io, m_keyChain, {false, true})
    , tokenIssuerFace(io, m_keyChain, {false, true})
    , consumerFace1(io, m_keyChain, {false, true})
    , consumerFace2(io, m_keyChain, {false, true})
  {
    producerFace.linkTo(aaFace);
    producerFace.linkTo(tokenIssuerFace);
    producerFace.linkTo(consumerFace1);
    producerFace.linkTo(consumerFace2);

    aaCert = addIdentity("/aaPrefix").getDefaultKey().getDefaultCertificate();
    tokenIssuerCert = addIdentity("/tokenIssuerPrefix").getDefaultKey().getDefaultCertificate();
    consumerCert1 = addIdentity("/consumerPrefix1", RsaKeyParams()).getDefaultKey().getDefaultCertificate();
    consumerCert2 = addIdentity("/consumerPrefix2", RsaKeyParams()).getDefaultKey().getDefaultCertificate();
    producerCert = addIdentity("/producerPrefix").getDefaultKey().getDefaultCertificate();
  }

protected:
  util::DummyClientFace producerFace;
  util::DummyClientFace aaFace;
  util::DummyClientFace tokenIssuerFace;
  util::DummyClientFace consumerFace1;
  util::DummyClientFace consumerFace2;

  security::Certificate aaCert;
  security::Certificate tokenIssuerCert;
  security::Certificate consumerCert1;
  security::Certificate consumerCert2;
  security::Certificate producerCert;
};

BOOST_FIXTURE_TEST_SUITE(TestIntegratedUpdate, TestIntegratedUpdateFixture)

BOOST_AUTO_TEST_CASE(KpdecKeyUpdate)
{
  // set up AA
  NDN_LOG_INFO("Create Attribute Authority. AA prefix: " << aaCert.getIdentity());
  KpAttributeAuthority aa(aaCert, aaFace, m_keyChain);
  advanceClocks(time::milliseconds(20), 60);

  // define attr list for consumer rights
  Policy policy1 = "cs";
  NDN_LOG_INFO("Add comsumer 1 " << consumerCert1.getIdentity() << " with policy: " << policy1);
  aa.addNewPolicy(consumerCert1, policy1);
  BOOST_CHECK_EQUAL(aa.m_tokens.size(), 1);

  Policy policy2 = "cs and homework";
  NDN_LOG_INFO("Add comsumer 2 " << consumerCert2.getIdentity() << " with policy: " << policy2);
  aa.addNewPolicy(consumerCert2, policy2);
  BOOST_CHECK_EQUAL(aa.m_tokens.size(), 2);

  // set up consumer
  NDN_LOG_INFO("Create Consumer 1. Consumer 1 prefix:" << consumerCert1.getIdentity());
  Consumer consumer1(consumerFace1, m_keyChain, consumerCert1, aaCert);
  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK(consumer1.m_paramFetcher.getPublicParams().m_pub != "");

  // set up consumer
  NDN_LOG_INFO("Create Consumer 2. Consumer 2 prefix:" << consumerCert2.getIdentity());
  Consumer consumer2(consumerFace2, m_keyChain, consumerCert2, aaCert);
  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK(consumer2.m_paramFetcher.getPublicParams().m_pub != "");

  // set up producer
  NDN_LOG_INFO("Create Producer. Producer prefix:" << producerCert.getIdentity());
  Producer producer(producerFace, m_keyChain, producerCert, aaCert);
  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK(producer.m_paramFetcher.getPublicParams().m_pub != "");

  NDN_LOG_INFO("\n=================== start work flow ==================\n");

  Name dataName = "/dataName";
  std::vector<std::string> attr = {"cs", "exam"};

  std::shared_ptr<Data> contentData, ckData;
  std::tie(contentData, ckData) = producer.produce(dataName, attr, PLAIN_TEXT);
  BOOST_CHECK(contentData != nullptr);
  BOOST_CHECK(ckData != nullptr);
  NDN_LOG_DEBUG("content data name: " << contentData->getName());

  auto f = producerFace.setInterestFilter(producerCert.getIdentity(),
                                          [&](const ndn::InterestFilter &, const ndn::Interest &interest) {
                                            NDN_LOG_INFO("consumer request for" << interest.toUri());
                                            if (interest.getName().isPrefixOf(contentData->getName())) {
                                              producerFace.put(*contentData);
                                            }
                                            if (interest.getName().isPrefixOf(ckData->getName())) {
                                              producerFace.put(*ckData);
                                            }
                                          }
  );

  bool isConsumeCbCalled = false;
  consumer1.obtainDecryptionKey();
  BOOST_CHECK(!consumer1.readyForDecryption());
  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK(consumer1.readyForDecryption());
  consumer1.obtainDecryptionKey();
  BOOST_CHECK(!consumer1.readyForDecryption());
  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK(consumer1.readyForDecryption());
  consumer1.consume(producerCert.getIdentity().append(dataName),
                    [&](const Buffer &result) {
                      isConsumeCbCalled = true;
                      BOOST_CHECK_EQUAL_COLLECTIONS(result.begin(), result.end(),
                                                    PLAIN_TEXT, PLAIN_TEXT + sizeof(PLAIN_TEXT));
                    },
                    [](const std::string &) {
                      BOOST_CHECK(false);
                    }
  );
  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK(isConsumeCbCalled);

  isConsumeCbCalled = false;
  consumer2.obtainDecryptionKey();
  advanceClocks(time::milliseconds(20), 60);
  consumer2.consume(producerCert.getIdentity().append(dataName),
                    [](const Buffer &) {
                      BOOST_CHECK(false);
                    },
                    [&](const std::string &) {
                      isConsumeCbCalled = true;
                    }
  );
  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK(isConsumeCbCalled);

  f.cancel();

  NDN_LOG_INFO("\n=================== Attempt Key Change ==================\n");

  policy1 = "cs and class <= 2";
  NDN_LOG_INFO("Change comsumer 1 " << consumerCert1.getIdentity() << " to policy: " << policy1);
  aa.addNewPolicy(consumerCert1, policy1);

  policy2 = "(cs and class > 2) or (type > 84029849 and date = Mar 16, 2023)";
  NDN_LOG_INFO("Change comsumer 2 " << consumerCert2.getIdentity() << " to policy: " << policy2);
  aa.addNewPolicy(consumerCert2, policy2);
  BOOST_CHECK_EQUAL(aa.m_tokens.size(), 2);

  dataName = "/dataName";
  attr = {"cs", "class = 3"};

  std::tie(contentData, ckData) = producer.produce(dataName, attr, PLAIN_TEXT);
  BOOST_CHECK(contentData != nullptr);
  BOOST_CHECK(ckData != nullptr);
  NDN_LOG_DEBUG("content data name: " << contentData->getName());

  f = producerFace.setInterestFilter(producerCert.getIdentity(),
                                     [&](const ndn::InterestFilter &, const ndn::Interest &interest) {
                                       NDN_LOG_INFO("consumer request for" << interest.toUri());
                                       if (interest.getName().isPrefixOf(contentData->getName())) {
                                         producerFace.put(*contentData);
                                       }
                                       if (interest.getName().isPrefixOf(ckData->getName())) {
                                         producerFace.put(*ckData);
                                       }
                                     }
  );

  isConsumeCbCalled = false;
  consumer1.obtainDecryptionKey();
  advanceClocks(time::milliseconds(20), 60);
  consumer1.consume(producerCert.getIdentity().append(dataName),
                    [&](const Buffer &) {
                      BOOST_CHECK(false);
                    },
                    [&](const std::string &) {
                      isConsumeCbCalled = true;
                    }
  );
  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK(isConsumeCbCalled);

  isConsumeCbCalled = false;
  consumer2.obtainDecryptionKey();
  advanceClocks(time::milliseconds(20), 60);
  consumer2.consume(producerCert.getIdentity().append(dataName),
                    [&](const Buffer &result) {
                      isConsumeCbCalled = true;
                      BOOST_CHECK_EQUAL_COLLECTIONS(result.begin(), result.end(),
                                                    PLAIN_TEXT, PLAIN_TEXT + sizeof(PLAIN_TEXT));
                    },
                    [](const std::string &) {
                      BOOST_CHECK(false);
                    }
  );
  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK(isConsumeCbCalled);

  f.cancel();

  NDN_LOG_INFO("\n=================== Attempt Key Removal ==================\n");

  policy2 = "cs and class > 2";
  NDN_LOG_INFO("Change comsumer 2 " << consumerCert2.getIdentity() << " to policy: " << policy2);
  aa.removePolicy(consumerCert2.getIdentity());
  BOOST_CHECK_EQUAL(aa.m_tokens.size(), 1);

  consumer2.obtainDecryptionKey();
  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK(!consumer2.readyForDecryption());
}

BOOST_AUTO_TEST_CASE(KpParamUpdate)
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
  Consumer consumer1(consumerFace1, m_keyChain, consumerCert1, aaCert);
  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK(consumer1.m_paramFetcher.getPublicParams().m_pub != "");

  // set up consumer
  NDN_LOG_INFO("Create Consumer 2. Consumer 2 prefix:"<<consumerCert2.getIdentity());
  Consumer consumer2(consumerFace2, m_keyChain, consumerCert2, aaCert);
  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK(consumer2.m_paramFetcher.getPublicParams().m_pub != "");

  // set up producer
  NDN_LOG_INFO("Create Producer. Producer prefix:"<<producerCert.getIdentity());
  Producer producer(producerFace, m_keyChain, producerCert, aaCert);
  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK(producer.m_paramFetcher.getPublicParams().m_pub != "");

  NDN_LOG_INFO("\n=================== start work flow ==================\n");

  Name dataName = "/dataName";
  std::vector<std::string> attr = {"cs", "exam"};

  std::shared_ptr<Data> contentData, ckData;
  std::tie(contentData, ckData) = producer.produce(dataName, attr, PLAIN_TEXT);
  BOOST_CHECK(contentData != nullptr);
  BOOST_CHECK(ckData != nullptr);
  NDN_LOG_DEBUG("content data name: " << contentData->getName());

  producerFace.setInterestFilter(producerCert.getIdentity(),
                                 [&] (const ndn::InterestFilter&, const ndn::Interest& interest) {
                                   NDN_LOG_INFO("consumer request for"<<interest.toUri());
                                   if (interest.getName().isPrefixOf(contentData->getName())) {
                                     producerFace.put(*contentData);
                                   }
                                   if (interest.getName().isPrefixOf(ckData->getName())) {
                                     producerFace.put(*ckData);
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
  BOOST_CHECK(isConsumeCbCalled);

  NDN_LOG_INFO("\n=================== Attempt Param Change ==================\n");

  aa.updatePublicParam();
  producer.obtainPublicParam();
  BOOST_CHECK(!producer.readyForEncryption());
  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK(producer.readyForEncryption());


  std::tie(contentData, ckData) = producer.produce(dataName, attr, PLAIN_TEXT);
  BOOST_CHECK(contentData != nullptr);
  BOOST_CHECK(ckData != nullptr);
  NDN_LOG_DEBUG("content data name: " << contentData->getName());

  producerFace.setInterestFilter(producerCert.getIdentity(),
                                 [&] (const ndn::InterestFilter&, const ndn::Interest& interest) {
                                   NDN_LOG_INFO("consumer request for"<<interest.toUri());
                                   if (interest.getName().isPrefixOf(contentData->getName())) {
                                     producerFace.put(*contentData);
                                   }
                                   if (interest.getName().isPrefixOf(ckData->getName())) {
                                     producerFace.put(*ckData);
                                   }
                                 }
  );

  isConsumeCbCalled = false;
  consumer1.obtainDecryptionKey();
  BOOST_CHECK(!consumer1.readyForDecryption());
  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK(consumer1.readyForDecryption());
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
  BOOST_CHECK(isConsumeCbCalled);

  isConsumeCbCalled = false;
  consumer2.obtainDecryptionKey();
  BOOST_CHECK(!consumer2.readyForDecryption());
  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK(consumer2.readyForDecryption());
  consumer2.consume(producerCert.getIdentity().append(dataName),
                    [] (const Buffer&) {
                      BOOST_CHECK(false);
                    },
                    [&] (const std::string&) {
                      isConsumeCbCalled = true;
                    }
  );
  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK(isConsumeCbCalled);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace nacabe
} // namespace ndn
