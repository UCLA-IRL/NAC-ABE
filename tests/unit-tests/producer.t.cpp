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

#include "producer.hpp"
#include "algo/abe-support.hpp"

#include "test-common.hpp"

#include <ndn-cxx/security/verification-helpers.hpp>
#include <ndn-cxx/util/dummy-client-face.hpp>

namespace ndn {
namespace nacabe {
namespace tests {

const uint8_t PLAIN_TEXT[1024] = {1};

NDN_LOG_INIT(Test.Producer);

class TestProducerFixture : public IdentityManagementTimeFixture
{
public:
  TestProducerFixture()
    : c1(io, m_keyChain, util::DummyClientFace::Options{true, true})
    , c2(io, m_keyChain, util::DummyClientFace::Options{true, true})
    , attrAuthorityPrefix("/authority")
  {
    c1.linkTo(c2);
    producerCert = addIdentity("/producer").getDefaultKey().getDefaultCertificate();
    authorityCert = addIdentity("/authority").getDefaultKey().getDefaultCertificate();
    ownerCert = addIdentity("/owner").getDefaultKey().getDefaultCertificate();
  }

protected:
  util::DummyClientFace c1;
  util::DummyClientFace c2;
  Name attrAuthorityPrefix;
  security::Certificate producerCert;
  security::Certificate authorityCert;
  security::Certificate ownerCert;
};

BOOST_FIXTURE_TEST_SUITE(TestProducer, TestProducerFixture)

BOOST_AUTO_TEST_CASE(Constructor)
{
  bool commandReceived = false;
  c2.setInterestFilter(Name(attrAuthorityPrefix).append("PUBPARAMS"),
                       [&] (const ndn::InterestFilter&, const ndn::Interest&) {
                         commandReceived = true;
                       });

  advanceClocks(time::milliseconds(20), 60);

  Producer producer(c1, m_keyChain, producerCert, authorityCert);
  advanceClocks(time::milliseconds(10), 60);

  BOOST_CHECK(commandReceived);
}

BOOST_AUTO_TEST_CASE(OnPolicyInterest)
{
  Producer producer(c1, m_keyChain, producerCert, authorityCert, ownerCert);
  producer.m_paramFetcher.m_abeType = ABE_TYPE_CP_ABE;
  advanceClocks(time::milliseconds(20), 60);

  Name dataPrefix("dataPrefix");
  Name setPolicyInterestName = producerCert.getIdentity();
  setPolicyInterestName.append(SET_POLICY)
                       .append(dataPrefix.wireEncode().begin(), dataPrefix.wireEncode().end())
                       .append(Name("policy"));

  NDN_LOG_DEBUG("set policy Interest name:" << setPolicyInterestName);
  Interest setPolicyInterest = Interest(setPolicyInterestName);
  setPolicyInterest.setCanBePrefix(true);
  setPolicyInterest.setMustBeFresh(true);
  m_keyChain.sign(setPolicyInterest, signingByCertificate(ownerCert));

  NDN_LOG_DEBUG("before receive, interest name:" << setPolicyInterest.getName());
  //dynamic_cast<util::DummyClientFace*>(&c1)->receive(setPolicyInterest);
  c2.expressInterest(setPolicyInterest,
      [&](const Interest&, const Data& response) {
        BOOST_CHECK(security::verifySignature(response, producerCert));
        BOOST_CHECK(readString(response.getContent()) == "success");
      },
      [](const Interest&, const lp::Nack&) {},
      [](const Interest&) {});

  NDN_LOG_DEBUG("set policy Interest:" << setPolicyInterest.getName());
  // /producer/SET_POLICY/dataPrefix/policy
  NDN_LOG_DEBUG("data prefix:" << setPolicyInterest.getName().getSubName(2, 1));
  NDN_LOG_DEBUG(setPolicyInterest.getName().getSubName(3, 1));

  advanceClocks(time::milliseconds(20), 60);

  auto policyFound = producer.findMatchedPolicy(dataPrefix);
  BOOST_CHECK_EQUAL(producer.m_policies.size(), 1);
  BOOST_CHECK_EQUAL(policyFound, "policy");

  advanceClocks(time::milliseconds(20), 60);

  c2.expressInterest(setPolicyInterest,
      [&](const Interest&, const Data& response) {
        BOOST_CHECK(security::verifySignature(response, producerCert));
        BOOST_CHECK_EQUAL(readString(response.getContent()), "success");
      },
      [](const Interest&, const lp::Nack&) {},
      [](const Interest&) {});

  advanceClocks(time::milliseconds(20), 60);

  policyFound = producer.findMatchedPolicy(dataPrefix);
  BOOST_CHECK_EQUAL(producer.m_policies.size(), 1);
  BOOST_CHECK_EQUAL(policyFound, "policy");
}

BOOST_AUTO_TEST_CASE(OnKpPolicyInterest)
{
  Producer producer(c1, m_keyChain, producerCert, authorityCert, ownerCert);
  producer.m_paramFetcher.m_abeType = ABE_TYPE_KP_ABE;
  advanceClocks(time::milliseconds(20), 60);

  Name dataPrefix("dataPrefix");
  auto attr1 = ndn::makeStringBlock(TLV_Attribute, "attr1");
  Name setPolicyInterestName = producerCert.getIdentity();
  setPolicyInterestName.append(SET_POLICY)
                       .append(dataPrefix.wireEncode().begin(), dataPrefix.wireEncode().end())
                       .append(attr1.begin(), attr1.end());

  NDN_LOG_DEBUG("set policy Interest name:" << setPolicyInterestName);
  Interest setPolicyInterest = Interest(setPolicyInterestName);
  setPolicyInterest.setCanBePrefix(true);
  setPolicyInterest.setMustBeFresh(true);
  m_keyChain.sign(setPolicyInterest, signingByCertificate(ownerCert));

  NDN_LOG_DEBUG("before receive, interest name:" << setPolicyInterest.getName());
  //dynamic_cast<util::DummyClientFace*>(&c1)->receive(setPolicyInterest);
  c2.expressInterest(setPolicyInterest,
      [&](const Interest&, const Data& response) {
        BOOST_CHECK(security::verifySignature(response, producerCert));
        BOOST_CHECK(readString(response.getContent()) == "success");
      },
      [](const Interest&, const lp::Nack&) {},
      [](const Interest&) {});

  NDN_LOG_DEBUG("set policy Interest:" << setPolicyInterest.getName());
  // /producer/SET_POLICY/dataPrefix/policy
  NDN_LOG_DEBUG("data prefix:" << setPolicyInterest.getName().getSubName(2, 1));
  NDN_LOG_DEBUG(setPolicyInterest.getName().getSubName(3, 1));

  advanceClocks(time::milliseconds(20), 60);

  auto attributesFound = producer.findMatchedAttributes(dataPrefix);
  BOOST_CHECK_EQUAL(producer.m_attributes.size(), 1);
  BOOST_CHECK_EQUAL(attributesFound.size(), 1);
  BOOST_CHECK_EQUAL(attributesFound[0], "attr1");

  advanceClocks(time::milliseconds(20), 60);

  c2.expressInterest(setPolicyInterest,
      [&](const Interest&, const Data& response) {
        BOOST_CHECK(security::verifySignature(response, producerCert));
        BOOST_CHECK_EQUAL(readString(response.getContent()), "success");
      },
      [](const Interest&, const lp::Nack&) {},
      [](const Interest&) {});

  advanceClocks(time::milliseconds(20), 60);

  attributesFound = producer.findMatchedAttributes(dataPrefix);
  BOOST_CHECK_EQUAL(producer.m_attributes.size(), 1);
  BOOST_CHECK_EQUAL(attributesFound.size(), 1);
  BOOST_CHECK_EQUAL(attributesFound[0], "attr1");
}

BOOST_AUTO_TEST_CASE(EncryptContent)
{
  algo::PublicParams pubParams;
  algo::MasterKey masterKey;
  Producer producer(c1, m_keyChain, producerCert, authorityCert);
  advanceClocks(time::milliseconds(20), 60);
  algo::ABESupport::getInstance().cpInit(pubParams, masterKey);

  BOOST_CHECK(pubParams.m_pub != "");
  BOOST_CHECK(masterKey.m_msk != "");

  producer.m_paramFetcher.m_pubParamsCache = pubParams;
  producer.m_paramFetcher.m_abeType = ABE_TYPE_CP_ABE;
  // generate prv key
  std::vector<std::string> attrList = {"attr1", "attr2", "attr3", "attr4", "attr5",
                                       "attr6", "attr7", "attr8", "attr9", "attr10"};
  algo::PrivateKey prvKey = algo::ABESupport::getInstance().cpPrvKeyGen(pubParams, masterKey, attrList);

  std::shared_ptr<Data> data, ckData;
  std::tie(data, ckData) = producer.produce(Name("/dataset1/example/data1"), "attr1 or attr2", PLAIN_TEXT);
  BOOST_CHECK(data != nullptr);
  BOOST_CHECK(ckData != nullptr);
}

BOOST_AUTO_TEST_CASE(KpEncryptContent)
{
  algo::PublicParams pubParams;
  algo::MasterKey masterKey;
  Producer producer(c1, m_keyChain, producerCert, authorityCert);
  advanceClocks(time::milliseconds(20), 60);
  algo::ABESupport::getInstance().kpInit(pubParams, masterKey);

  BOOST_CHECK(pubParams.m_pub != "");
  BOOST_CHECK(masterKey.m_msk != "");

  producer.m_paramFetcher.m_pubParamsCache = pubParams;
  producer.m_paramFetcher.m_abeType = ABE_TYPE_KP_ABE;
  // generate prv key
  std::vector<std::string> attrList = {"attr1", "attr2", "attr3", "attr4", "attr5",
                                       "attr6", "attr7", "attr8", "attr9", "attr10"};
  algo::PrivateKey prvKey = algo::ABESupport::getInstance().kpPrvKeyGen(pubParams, masterKey, "attr1 or attr2");

  std::shared_ptr<Data> data, ckData;
  std::tie(data, ckData) = producer.produce(Name("/dataset1/example/data1"), attrList, PLAIN_TEXT);
  BOOST_CHECK(data != nullptr);
  BOOST_CHECK(ckData != nullptr);
}

BOOST_AUTO_TEST_SUITE_END()

}  // namespace tests
}  // namespace nacabe
}  // namespace ndn
