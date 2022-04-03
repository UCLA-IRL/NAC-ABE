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

#include "data-owner.hpp"
#include "test-common.hpp"
#include "producer.hpp"
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/util/dummy-client-face.hpp>

namespace ndn {
namespace nacabe {
namespace tests {

namespace fs = boost::filesystem;

NDN_LOG_INIT(Test.DataOwner);

class TestDataOwnerFixture : public IdentityManagementTimeFixture
{
public:
  TestDataOwnerFixture()
    : c1(io, m_keyChain, util::DummyClientFace::Options{true, true})
    , c2(io, m_keyChain, util::DummyClientFace::Options{true, true})
  {
    c1.linkTo(c2);
  }

public:
  util::DummyClientFace c1;
  util::DummyClientFace c2;
};

BOOST_FIXTURE_TEST_SUITE(TestDataOwner, TestDataOwnerFixture)

BOOST_AUTO_TEST_CASE(CpSetPolicy)
{
  security::Identity id = addIdentity("/nacabe/test/dataowner");
  security::Key key = id.getDefaultKey();
  security::Certificate cert = key.getDefaultCertificate();

  DataOwner dataowner(cert, c1, m_keyChain);

  Name producerPrefix = Name("/producer1");
  Name dataPrefix = Name("/data");
  std::string policy = "attr1 and attr2 or attr3";
  Name interestName = producerPrefix;
  interestName.append(SET_POLICY)
              .append(dataPrefix.wireEncode().begin(), dataPrefix.wireEncode().end())
              .append(policy);

  advanceClocks(time::milliseconds(1), 10);

  auto f1 = c2.setInterestFilter(Name("/producer1"),
                                 [&] (const ndn::InterestFilter&, const ndn::Interest& interest) {
                                   BOOST_CHECK_EQUAL(interest.getName().getSubName(0, 1), producerPrefix);
                                   BOOST_CHECK_EQUAL(interest.getName().get(1).toUri(), SET_POLICY);
                                   BOOST_CHECK_EQUAL(Name(interest.getName().get(2).blockFromValue()), dataPrefix);
                                   BOOST_CHECK_EQUAL(readString(interest.getName().get(3)), policy);

                                   BOOST_CHECK(security::verifySignature(interest, cert));

                                   Data reply;
                                   reply.setName(interest.getName());
                                   reply.setContent(makeStringBlock(tlv::Content, "success"));
                                   reply.setFreshnessPeriod(time::seconds(1));
                                   m_keyChain.sign(reply, signingByCertificate(cert));
                                   c2.put(reply);
                                 });

  advanceClocks(time::milliseconds(1), 100);

  bool getItem = false;
  dataowner.commandProducerPolicy(producerPrefix, dataPrefix, policy,
                                  [&] (const Data& data) {
                                    BOOST_CHECK(interestName.isPrefixOf(data.getName()));
                                    getItem = true;
                                  },
                                  [=] (const std::string&) {
                                    BOOST_CHECK(false);
                                  });

  advanceClocks(time::milliseconds(1), 10);
  BOOST_CHECK(getItem);
  f1.cancel();

  // bad reply check
  auto f2 = c2.setInterestFilter(Name("/producer1"),
                                 [&] (const ndn::InterestFilter&, const ndn::Interest& interest) {
                                   BOOST_CHECK_EQUAL(interest.getName().getSubName(0, 1), producerPrefix);
                                   BOOST_CHECK_EQUAL(interest.getName().get(1).toUri(), SET_POLICY);
                                   BOOST_CHECK_EQUAL(Name(interest.getName().get(2).blockFromValue()), dataPrefix);
                                   BOOST_CHECK_EQUAL(readString(interest.getName().get(3)), policy);

                                   BOOST_CHECK(security::verifySignature(interest, cert));

                                   Data reply;
                                   reply.setName(interest.getName());
                                   reply.setContent(makeStringBlock(tlv::Content, "failure"));
                                   reply.setFreshnessPeriod(time::seconds(1));
                                   m_keyChain.sign(reply, signingByCertificate(cert));
                                   c2.put(reply);
                                 });

  advanceClocks(time::milliseconds(1), 100);

  getItem = false;
  dataowner.commandProducerPolicy(producerPrefix, dataPrefix, policy,
                                  [=] (const Data& data) {
                                    BOOST_CHECK(false);
                                  },
                                  [&] (const std::string& s) {
                                    BOOST_CHECK_EQUAL(s, "register failed");
                                    getItem = true;
                                  });

  advanceClocks(time::milliseconds(1), 10);
  BOOST_CHECK(getItem);
  f2.cancel();

  // timeout check
  auto f3 = c2.setInterestFilter(Name("/producer1"),
                                 [&] (const ndn::InterestFilter&, const ndn::Interest& interest) {
                                   BOOST_CHECK_EQUAL(interest.getName().getSubName(0, 1), producerPrefix);
                                   BOOST_CHECK_EQUAL(interest.getName().get(1).toUri(), SET_POLICY);
                                   BOOST_CHECK_EQUAL(Name(interest.getName().get(2).blockFromValue()), dataPrefix);
                                   BOOST_CHECK_EQUAL(readString(interest.getName().get(3)), policy);

                                   BOOST_CHECK(security::verifySignature(interest, cert));
                                 });

  advanceClocks(time::milliseconds(1), 100);

  getItem = false;
  dataowner.commandProducerPolicy(producerPrefix, dataPrefix, policy,
                                  [=] (const Data& data) {
                                    BOOST_CHECK(false);
                                  },
                                  [&] (const std::string& s) {
                                    BOOST_CHECK_EQUAL(s, "time out");
                                    getItem = true;
                                  });

  advanceClocks(time::milliseconds(100), 20);
  BOOST_CHECK(getItem);
  f3.cancel();

  // nack check
  auto f4 = c2.setInterestFilter(Name("/producer1"),
                                 [&] (const ndn::InterestFilter&, const ndn::Interest& interest) {
                                   BOOST_CHECK_EQUAL(interest.getName().getSubName(0, 1), producerPrefix);
                                   BOOST_CHECK_EQUAL(interest.getName().get(1).toUri(), SET_POLICY);
                                   BOOST_CHECK_EQUAL(Name(interest.getName().get(2).blockFromValue()), dataPrefix);
                                   BOOST_CHECK_EQUAL(readString(interest.getName().get(3)), policy);

                                   BOOST_CHECK(security::verifySignature(interest, cert));

                                   lp::Nack nack(interest);
                                   nack.setReason(lp::NackReason::NO_ROUTE);
                                   c2.put(nack);
                                 });

  advanceClocks(time::milliseconds(1), 100);

  getItem = false;
  dataowner.commandProducerPolicy(producerPrefix, dataPrefix, policy,
                                  [=] (const Data& data) {
                                    BOOST_CHECK(false);
                                  },
                                  [&] (const std::string& s) {
                                    BOOST_CHECK_EQUAL(s, "nack");
                                    getItem = true;
                                  });

  advanceClocks(time::milliseconds(1), 20);
  BOOST_CHECK(getItem);
  f4.cancel();
}

BOOST_AUTO_TEST_CASE(KpSetPolicy)
{
  security::Identity id = addIdentity("/nacabe/test/dataowner");
  security::Key key = id.getDefaultKey();
  security::Certificate cert = key.getDefaultCertificate();

  DataOwner dataowner(cert, c1, m_keyChain);

  Name producerPrefix("/producer1");
  Name dataPrefix("/data");
  const std::vector<std::string> attributes{"attr1", "attr2", "attr3"};
  name::Component attrComp;
  for (const auto& i : attributes)
    attrComp.push_back(makeStringBlock(TLV_Attribute, i));
  attrComp.encode();
  Name interestName = producerPrefix;
  interestName.append(SET_POLICY)
              .append(dataPrefix.wireEncode().begin(), dataPrefix.wireEncode().end())
              .append(attrComp);

  advanceClocks(time::milliseconds(1), 10);

  auto f1 = c2.setInterestFilter(Name("/producer1"),
                       [&] (const ndn::InterestFilter&, const ndn::Interest& interest) {
                         BOOST_CHECK_EQUAL(interest.getName().getSubName(0, 1), producerPrefix);
                         BOOST_CHECK_EQUAL(interest.getName().get(1).toUri(), SET_POLICY);
                         BOOST_CHECK_EQUAL(Name(interest.getName().get(2).blockFromValue()), dataPrefix);
                         BOOST_CHECK_EQUAL(interest.getName().get(3), attrComp);

                         BOOST_CHECK(security::verifySignature(interest, cert));

                         Data reply;
                         reply.setName(interest.getName());
                         reply.setContent(makeStringBlock(tlv::Content, "success"));
                         reply.setFreshnessPeriod(time::seconds(1));
                         m_keyChain.sign(reply, signingByCertificate(cert));
                         c2.put(reply);
                       });

  advanceClocks(time::milliseconds(1), 100);

  bool getItem = false;
  dataowner.commandProducerPolicy(producerPrefix, dataPrefix, attributes,
                                  [&] (const Data& data) {
                                    BOOST_CHECK(interestName.isPrefixOf(data.getName()));
                                    getItem = true;
                                  },
                                  [=] (const std::string&) {
                                    BOOST_CHECK(false);
                                  });

  advanceClocks(time::milliseconds(1), 10);
  BOOST_CHECK(getItem);
  f1.cancel();

  // bad reply check
  auto f2 = c2.setInterestFilter(Name("/producer1"),
                       [&] (const ndn::InterestFilter&, const ndn::Interest& interest) {
                         BOOST_CHECK_EQUAL(interest.getName().getSubName(0, 1), producerPrefix);
                         BOOST_CHECK_EQUAL(interest.getName().get(1).toUri(), SET_POLICY);
                         BOOST_CHECK_EQUAL(Name(interest.getName().get(2).blockFromValue()), dataPrefix);
                         BOOST_CHECK_EQUAL(interest.getName().get(3), attrComp);

                         BOOST_CHECK(security::verifySignature(interest, cert));

                         Data reply;
                         reply.setName(interest.getName());
                         reply.setContent(makeStringBlock(tlv::Content, "failure"));
                         reply.setFreshnessPeriod(time::seconds(1));
                         m_keyChain.sign(reply, signingByCertificate(cert));
                         c2.put(reply);
                       });

  advanceClocks(time::milliseconds(1), 100);

  getItem = false;
  dataowner.commandProducerPolicy(producerPrefix, dataPrefix, attributes,
                                  [=] (const Data& data) {
                                    BOOST_CHECK(false);
                                  },
                                  [&] (const std::string& s) {
                                    BOOST_CHECK_EQUAL(s, "register failed");
                                    getItem = true;
                                  });

  advanceClocks(time::milliseconds(1), 10);
  BOOST_CHECK(getItem);
  f2.cancel();

  // timeout check
  auto f3 = c2.setInterestFilter(Name("/producer1"),
                                 [&] (const ndn::InterestFilter&, const ndn::Interest& interest) {
                                   BOOST_CHECK_EQUAL(interest.getName().getSubName(0, 1), producerPrefix);
                                   BOOST_CHECK_EQUAL(interest.getName().get(1).toUri(), SET_POLICY);
                                   BOOST_CHECK_EQUAL(Name(interest.getName().get(2).blockFromValue()), dataPrefix);
                                   BOOST_CHECK_EQUAL(interest.getName().get(3), attrComp);

                                   BOOST_CHECK(security::verifySignature(interest, cert));
                                 });

  advanceClocks(time::milliseconds(1), 100);

  getItem = false;
  dataowner.commandProducerPolicy(producerPrefix, dataPrefix, attributes,
                                  [=] (const Data& data) {
                                    BOOST_CHECK(false);
                                  },
                                  [&] (const std::string& s) {
                                    BOOST_CHECK_EQUAL(s, "time out");
                                    getItem = true;
                                  });

  advanceClocks(time::milliseconds(100), 20);
  BOOST_CHECK(getItem);
  f3.cancel();

  // nack check
  auto f4 = c2.setInterestFilter(Name("/producer1"),
                                 [&] (const ndn::InterestFilter&, const ndn::Interest& interest) {
                                   BOOST_CHECK_EQUAL(interest.getName().getSubName(0, 1), producerPrefix);
                                   BOOST_CHECK_EQUAL(interest.getName().get(1).toUri(), SET_POLICY);
                                   BOOST_CHECK_EQUAL(Name(interest.getName().get(2).blockFromValue()), dataPrefix);
                                   BOOST_CHECK_EQUAL(interest.getName().get(3), attrComp);

                                   BOOST_CHECK(security::verifySignature(interest, cert));

                                   lp::Nack nack(interest);
                                   nack.setReason(lp::NackReason::NO_ROUTE);
                                   c2.put(nack);
                                 });

  advanceClocks(time::milliseconds(1), 100);

  getItem = false;
  dataowner.commandProducerPolicy(producerPrefix, dataPrefix, attributes,
                                  [=] (const Data& data) {
                                    BOOST_CHECK(false);
                                  },
                                  [&] (const std::string& s) {
                                    BOOST_CHECK_EQUAL(s, "nack");
                                    getItem = true;
                                  });

  advanceClocks(time::milliseconds(1), 20);
  BOOST_CHECK(getItem);
  f4.cancel();
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace nacabe
} // namespace ndn
