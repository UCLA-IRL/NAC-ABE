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

#include "param-fetcher.hpp"
#include "algo/abe-support.hpp"

#include "test-common.hpp"

#include <ndn-cxx/util/dummy-client-face.hpp>

namespace ndn {
namespace nacabe {
namespace tests {

const uint8_t PLAIN_TEXT[1024] = {1};

NDN_LOG_INIT(Test.ParamFetcher);

class TestParamFetcherFixture : public IdentityManagementTimeFixture
{
public:
  TestParamFetcherFixture()
    : c1(io, m_keyChain, {true, true})
    , c2(io, m_keyChain, {true, true})
    , attrAuthorityPrefix("/example/authority")
  {
    c1.linkTo(c2);

    security::pib::Identity anchorId = addIdentity("/example");
    anchorCert = anchorId.getDefaultKey().getDefaultCertificate();
    saveCertToFile(anchorCert, "example-trust-anchor.cert");
    security::pib::Identity authorityId = addIdentity(attrAuthorityPrefix);
    addSubCertificate(attrAuthorityPrefix, anchorId);
    authorityCert = authorityId.getDefaultKey().getDefaultCertificate();
    
    trustConfig.addOrUpdateCertificate(security::Certificate(authorityCert));
  }

protected:
  DummyClientFace c1;
  DummyClientFace c2;
  Name attrAuthorityPrefix;
  security::Certificate authorityCert;
  security::Certificate anchorCert;
  TrustConfig trustConfig;
};

BOOST_FIXTURE_TEST_SUITE(TestParamFetcher, TestParamFetcherFixture)

BOOST_AUTO_TEST_CASE(Constructor)
{
  algo::PublicParams m_pubParams;
  c2.setInterestFilter(Name(attrAuthorityPrefix).append("PUBPARAMS"),
    [&](const ndn::InterestFilter&, const ndn::Interest& interest) {
      algo::MasterKey m_masterKey;
      algo::ABESupport::getInstance().cpInit(m_pubParams, m_masterKey);
      Data result;
      Name dataName = interest.getName();
      dataName.append(ABE_TYPE_CP_ABE);
      dataName.appendTimestamp();
      result.setName(dataName);
      result.setFreshnessPeriod(10_s);
      const auto& contentBuf = m_pubParams.toBuffer();
      result.setContent(contentBuf);
      m_keyChain.sign(result, signingByCertificate(authorityCert));

      NDN_LOG_TRACE("Reply public params request.");
      NDN_LOG_TRACE("Pub params size: " << contentBuf.size());

      c2.put(result);
    }
  );

  security::ValidatorConfig validator(c1);
  validator.load("trust-schema.conf");
  ParamFetcher paramFetcher(c1, validator, attrAuthorityPrefix, trustConfig);
  paramFetcher.fetchPublicParams();
  advanceClocks(time::milliseconds(20), 60);
  c1.receive(authorityCert);
  advanceClocks(time::milliseconds(20), 60);
  c1.receive(anchorCert);
  advanceClocks(time::milliseconds(20), 60);

  BOOST_CHECK(paramFetcher.getPublicParams().m_pub != "");
  BOOST_CHECK(paramFetcher.getAbeType() == ABE_TYPE_CP_ABE);
}

BOOST_AUTO_TEST_CASE(FetchPublicParamsSuccessWithinRetryLimit)
{
  algo::PublicParams m_pubParams;
  int attemptCount = 0;

  c2.setInterestFilter(Name(attrAuthorityPrefix).append("PUBPARAMS"),
    [&](const ndn::InterestFilter&, const ndn::Interest& interest) {
      ++attemptCount;

      algo::MasterKey m_masterKey;
      algo::ABESupport::getInstance().cpInit(m_pubParams, m_masterKey);

      Data result;
      Name dataName = interest.getName();
      dataName.append(ABE_TYPE_CP_ABE);
      dataName.appendTimestamp();
      result.setName(dataName);
      result.setFreshnessPeriod(10_s);

      const auto& contentBuf = m_pubParams.toBuffer();
      result.setContent(contentBuf);


      m_keyChain.sign(result, signingByCertificate(authorityCert));
      c2.put(result);
    });


  security::ValidatorConfig validator(c1);
  validator.load("trust-schema.conf");


  ParamFetcher paramFetcher(c1, validator, attrAuthorityPrefix, trustConfig);

  paramFetcher.fetchPublicParams();

  advanceClocks(time::milliseconds(20), 60);
  c1.receive(authorityCert);
  advanceClocks(time::milliseconds(20), 60);
  c1.receive(anchorCert);
  advanceClocks(time::milliseconds(20), 60);



  for (int i = 0; i < 10; ++i) {
    advanceClocks(time::seconds(1), 20);
  }

  BOOST_CHECK(paramFetcher.getPublicParams().m_pub != "");
  BOOST_CHECK(paramFetcher.getAbeType() == ABE_TYPE_CP_ABE);
  BOOST_CHECK_EQUAL(attemptCount, 1);
}


BOOST_AUTO_TEST_CASE(FetchPublicParamsFailsAfterMaxRetries)
{
  int attemptCount = 0;

  c2.setInterestFilter(Name(attrAuthorityPrefix).append("PUBPARAMS"),
    [&](const ndn::InterestFilter&, const ndn::Interest& interest) {
      ++attemptCount;
    });

  security::ValidatorConfig validator(c1);
  validator.load("trust-schema.conf");

  ParamFetcher paramFetcher(c1, validator, attrAuthorityPrefix, trustConfig);

  advanceClocks(time::milliseconds(20), 60);
  c1.receive(authorityCert);
  advanceClocks(time::milliseconds(20), 60);
  c1.receive(anchorCert);
  advanceClocks(time::milliseconds(20), 60);

  BOOST_CHECK_THROW(
    [&] {
      paramFetcher.fetchPublicParams();
      for (int i = 0; i < 20; ++i) {
        advanceClocks(time::seconds(1), 60);
      }
    }(),
    std::runtime_error
  );

  BOOST_CHECK_GE(attemptCount, 10);
}




BOOST_AUTO_TEST_SUITE_END()

}  // namespace tests
}  // namespace nacabe
}  // namespace ndn
