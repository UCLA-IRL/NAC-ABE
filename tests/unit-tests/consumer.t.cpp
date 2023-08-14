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

#include "consumer.hpp"

#include "test-common.hpp"

#include <ndn-cxx/util/dummy-client-face.hpp>

namespace ndn {
namespace nacabe {
namespace tests {

class TestConsumerFixture : public IdentityManagementTimeFixture
{
public:
  TestConsumerFixture()
    : c1(io, m_keyChain, util::DummyClientFace::Options{true, true})
    , c2(io, m_keyChain, util::DummyClientFace::Options{true, true})
    , attrAuthorityPrefix("/authority")
  {
    c1.linkTo(c2);
    security::pib::Identity anchorId = addIdentity("/example");
    saveCertToFile(anchorCert, "example-trust-anchor.cert");
    security::pib::Identity consumerId = addIdentity("/example/consumer", RsaKeyParams());
    addSubCertificate("/example/consumer", anchorId);
    consumerCert = consumerId.getDefaultKey().getDefaultCertificate();

    security::pib::Identity authorityId = addIdentity(attrAuthorityPrefix);
    addSubCertificate("/example/authority", anchorId);
    authorityCert = authorityId.getDefaultKey().getDefaultCertificate();
  }

protected:
  util::DummyClientFace c1;
  util::DummyClientFace c2;
  Name attrAuthorityPrefix;
  security::Certificate anchorCert;
  security::Certificate consumerCert;
  security::Certificate authorityCert;
};

BOOST_FIXTURE_TEST_SUITE(TestConsumer, TestConsumerFixture)

BOOST_AUTO_TEST_CASE(Constructor)
{
  bool commandReceived = false;
  c2.setInterestFilter(Name(attrAuthorityPrefix).append("PUBPARAMS"),
    [&] (auto&&...) { commandReceived = true; }
  );

  advanceClocks(time::milliseconds(20), 60);

  security::ValidatorConfig validator(c1);
  validator.load("trust-schema.conf");
  Consumer consumer(c1, m_keyChain, validator, consumerCert, authorityCert);
  advanceClocks(time::milliseconds(20), 60);

  BOOST_CHECK(commandReceived);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace nacabe
} // namespace ndn
