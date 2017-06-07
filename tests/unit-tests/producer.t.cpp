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

#include "producer.hpp"

#include "test-common.hpp"
#include "dummy-forwarder.hpp"
#include "algo/abe-support.hpp"

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

_LOG_INIT(Test.Producer);

class TestProducerFixture : public IdentityManagementTimeFixture
{
public:
  TestProducerFixture()
    : forwarder(m_io, m_keyChain)
    , c1(forwarder.addFace())
    , c2(forwarder.addFace())
    , attrAuthorityPrefix("/authority")
  {
    auto id = addIdentity("/producer");
    auto key = id.getDefaultKey();
    cert = key.getDefaultCertificate();
  }

public:
  DummyForwarder forwarder;
  Face& c1;
  Face& c2;
  Name attrAuthorityPrefix;
  security::v2::Certificate cert;
};

BOOST_FIXTURE_TEST_SUITE(TestProducer, TestProducerFixture)

BOOST_AUTO_TEST_CASE(Constructor)
{
  algo::PublicParams m_pubParams;
  c2.setInterestFilter((attrAuthorityPrefix),
                     [&] (const ndn::InterestFilter&, const ndn::Interest& interest) {
                        algo::MasterKey m_masterKey;
                        algo::ABESupport::setup(m_pubParams, m_masterKey);
                        Data result;
                        Name dataName = interest.getName();
                        dataName.appendTimestamp();
                        result.setName(dataName);
                        const auto& contentBuf = m_pubParams.toBuffer();
                        result.setContent(makeBinaryBlock(ndn::tlv::Content,
                                                          contentBuf.buf(), contentBuf.size()));
                        m_keyChain.sign(result, signingByCertificate(cert));

                        _LOG_TRACE("Reply public params request.");
                        _LOG_TRACE("Pub params size: " << contentBuf.size());

                        c2.put(result);
                     });

  advanceClocks(time::milliseconds(20), 60);

  Producer producer(cert, c1, m_keyChain, attrAuthorityPrefix);
  advanceClocks(time::milliseconds(20), 60);

  BOOST_CHECK(producer.m_pubParamsCache.m_pub != nullptr);
  //***** need to compare pointer content *****
  //BOOST_CHECK(producer.m_pubParamsCache.m_pub == m_pubParams.m_pub);
}

BOOST_AUTO_TEST_CASE(onPolicyInterest)
{
  _LOG_DEBUG("on policy interest unit test");
  Producer producer(cert, c1, m_keyChain, attrAuthorityPrefix);
  advanceClocks(time::milliseconds(20), 60);

  Name dataPrefix("dataPrefix");
  Name setPolicyInterestName = cert.getIdentity();
  setPolicyInterestName.append(Producer::SET_POLICY);
  setPolicyInterestName.append(dataPrefix);
  setPolicyInterestName.append(Name("policy"));

  _LOG_DEBUG("set policy Interest name:"<<setPolicyInterestName);
  Interest setPolicyInterest = Interest(setPolicyInterestName);

  _LOG_DEBUG(setPolicyInterest.getName().getSubName(2,1));

  int count = 0;
  auto onSend = [&] (const Data& response, std::string isSuccess) {
    count++;
    BOOST_CHECK(security::verifySignature(response, cert));

    BOOST_CHECK(readString(response.getContent()) == isSuccess);
    _LOG_DEBUG("content is:"<<readString(response.getContent()));
  };

  dynamic_cast<util::DummyClientFace*>(&c1)->onSendData.connect(
    [&](const Data& dt) {
      _LOG_DEBUG("on send data");
      onSend(dt, "success");
    }
  );

  _LOG_DEBUG("before receive, interest name:"<<setPolicyInterest.getName());
  //dynamic_cast<util::DummyClientFace*>(&c1)->receive(setPolicyInterest);
  c2.expressInterest(setPolicyInterest,
                     [=](const Interest&, const Data&){},
                     [=](const Interest&, const lp::Nack&){},
                     [=](const Interest&){});

  _LOG_DEBUG("set policy Interest:"<<setPolicyInterest.getName());
  ///producer/SET_POLICY/dataPrefix/policy
  _LOG_DEBUG("data prefix:"<<setPolicyInterest.getName().getSubName(2,1));
  _LOG_DEBUG(setPolicyInterest.getName().getSubName(3,1));
  //_LOG_DEBUG("policy:"<<setPolicyInterest.getName().at(3).toUri());

  advanceClocks(time::milliseconds(20), 60);

  auto it = producer.m_policyCache.find(dataPrefix);
  BOOST_CHECK_EQUAL(producer.m_policyCache.size(), 1);
  BOOST_CHECK(it != producer.m_policyCache.end());
  BOOST_CHECK_EQUAL(it->second, "policy");
  BOOST_CHECK_EQUAL(count, 1);

  dynamic_cast<util::DummyClientFace*>(&c1)->onSendData.connect(
    [&](const Data& dt) {
      onSend(dt, "exist");
    }
  );
  dynamic_cast<util::DummyClientFace*>(&c1)->receive(setPolicyInterest);

  advanceClocks(time::milliseconds(20), 60);

  it = producer.m_policyCache.find(dataPrefix);
  BOOST_CHECK_EQUAL(producer.m_policyCache.size(), 1);
  BOOST_CHECK(it != producer.m_policyCache.end());
  BOOST_CHECK_EQUAL(it->second, "policy");
  BOOST_CHECK_EQUAL(count, 2);
}

BOOST_AUTO_TEST_CASE(encryptContent)
{
  algo::PublicParams pubParams;
  algo::MasterKey masterKey;
  Producer producer(cert, c1, m_keyChain, attrAuthorityPrefix);
  advanceClocks(time::milliseconds(20), 60);
  algo::ABESupport::setup(pubParams, masterKey);

  BOOST_CHECK(pubParams.m_pub != nullptr);
  BOOST_CHECK(masterKey.m_msk != nullptr);

  producer.m_pubParamsCache = pubParams;
  // generate prv key
  std::vector<std::string> attrList = {"attr1", "attr2", "attr3", "attr4"};
  algo::PrivateKey prvKey = algo::ABESupport::prvKeyGen(pubParams, masterKey, attrList);

  producer.produce(Name("/dataPrefix"), "attr1 attr2 1of2", PLAIN_TEXT, sizeof(PLAIN_TEXT),
                   [&] (const Data& data) {
                     BOOST_CHECK_EQUAL(data.getName(), producer.m_cert.getIdentity().append(Name("/dataPrefix")));
                     algo::CipherText cipherText;
                     cipherText.wireDecode(data.getContent());
                     Buffer result = algo::ABESupport::decrypt(pubParams, prvKey, cipherText);

                     BOOST_CHECK_EQUAL_COLLECTIONS(result.begin(), result.end(),
                                                   PLAIN_TEXT, PLAIN_TEXT + sizeof(PLAIN_TEXT));
                   },
                   [&] (const std::string& err) {
                     BOOST_CHECK(false);
                   });
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace ndnabac
} // namespace ndn
