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

#include "data-owner.hpp"

#include "test-common.hpp"
#include "dummy-forwarder.hpp"
#include "producer.hpp"

#include <ndn-cxx/security/signing-helpers.hpp>

namespace ndn {
namespace ndnabac {
namespace tests {

namespace fs = boost::filesystem;

_LOG_INIT(Test.DataOwner);

class TestDataOwnerFixture : public IdentityManagementTimeFixture
{
public:
  TestDataOwnerFixture()
    : forwarder(m_io, m_keyChain)
  {
  }

public:
  DummyForwarder forwarder;
};

BOOST_FIXTURE_TEST_SUITE(TestDataOwner, TestDataOwnerFixture)

BOOST_AUTO_TEST_CASE(setPolicy)
{
  Face& c1 = forwarder.addFace();
  Face& c2 = forwarder.addFace();
  security::Identity id = addIdentity("/ndnabac/test/dataowner");
  security::Key key = id.getDefaultKey();
  security::v2::Certificate cert = key.getDefaultCertificate();

  DataOwner dataowner(cert, c1, m_keyChain);

  Name producerPrefix = Name("/producer1");
  Name dataPrefix = Name("/data");
  std::string policy = "attr1 and attr2 or attr3";
  Name interestName = producerPrefix;
  interestName.append(dataPrefix)
              .append(DataOwner::SET_POLICY)
              .append(policy);

  c2.setInterestFilter(Name("/producer1"),
                       [&] (const ndn::InterestFilter&, const ndn::Interest& interest) {
                         BOOST_CHECK_EQUAL(interest.getName().get(0).toUri(), "/producer1");
                         BOOST_CHECK_EQUAL(interest.getName().get(1).toUri(), DataOwner::SET_POLICY.toUri());
                         BOOST_CHECK_EQUAL(interest.getName().get(2).toUri(), "/data");
                         BOOST_CHECK_EQUAL(interest.getName().get(3).toUri(), policy);
                         BOOST_CHECK_EQUAL(interest.getName().get(4).toUri(), "addSig");

                         Data reply;
                         reply.setName(interest.getName());
                         reply.setContent(makeStringBlock(tlv::Content, "success"));
                         m_keyChain.sign(reply, signingByCertificate(cert));
                         c2.put(reply);
                       });

  dataowner.commandProducerPolicy(producerPrefix, dataPrefix, policy,
                                 [=] (const Data& data) {
                                   BOOST_CHECK_EQUAL(data.getName().toUri(), interestName.toUri());
                                 },
                                 [=] (const std::string&) {
                                   BOOST_CHECK(false);
                                 });

  c2.setInterestFilter(Name("/producer2").append(Producer::SET_POLICY),
                       [&] (const ndn::InterestFilter&, const ndn::Interest& interest) {
                         BOOST_CHECK_EQUAL(interest.getName().get(0).toUri(), "/producer2");
                         BOOST_CHECK_EQUAL(interest.getName().get(1).toUri(), DataOwner::SET_POLICY.toUri());
                         BOOST_CHECK_EQUAL(interest.getName().get(2).toUri(), "/data");
                         BOOST_CHECK_EQUAL(interest.getName().get(3).toUri(), policy);
                         BOOST_CHECK_EQUAL(interest.getName().get(4).toUri(), "addSig");

                         Data reply;
                         reply.setName(interest.getName());
                         reply.setContent(makeStringBlock(tlv::Content, "exist"));
                         m_keyChain.sign(reply, signingByCertificate(cert));
                         c2.put(reply);
                       });

  dataowner.commandProducerPolicy(producerPrefix, dataPrefix, policy,
                                 [=] (const Data&) {
                                   BOOST_CHECK(false);
                                 },
                                 [=] (const std::string& err) {
                                   BOOST_CHECK_EQUAL(err, "register failed");
                                 });
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace ndnabac
} // namespace ndn
