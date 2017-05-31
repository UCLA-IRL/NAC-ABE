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

void
successCallBack(const Data& data, const std::string& info)
{

}

void
errorCallBack(const std::string& errorInfo)
{

}

BOOST_FIXTURE_TEST_SUITE(TestDataOwner, TestDataOwnerFixture)

BOOST_AUTO_TEST_CASE(setPolicy)
{
  Face& c1 = forwarder.addFace();
  security::Identity id = addIdentity("/ndnabac/test/dataowner");
  security::Key key = id.getDefaultKey();
  security::v2::Certificate cert = key.getDefaultCertificate();

  DataOwner dataowner(cert, c1, m_keyChain);

  Name producerPrefix = Name("/producer1");
  std::string policy = "attr1 and attr2 or attr3"
  dataowner.commandProducerPolicy(producerPrefix, policy, std::bind(successCallBack, _1, "success"), errorCallBack); 
  Name interestName = producerPrefix.append(DataOwner::SET_POLICY).append(policy);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace ndnabac
} // namespace ndn
