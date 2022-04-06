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
    , attrAuthorityPrefix("/authority")
  {
    c1.linkTo(c2);
    authorityCert = addIdentity("/authority").getDefaultKey().getDefaultCertificate();
    trustConfig.addOrUpdateCertificate(authorityCert);
  }

protected:
  util::DummyClientFace c1;
  util::DummyClientFace c2;
  Name attrAuthorityPrefix;
  security::Certificate authorityCert;
  TrustConfig trustConfig;
};

BOOST_FIXTURE_TEST_SUITE(TestParamFetcher, TestParamFetcherFixture)

BOOST_AUTO_TEST_CASE(Constructor)
{
  algo::PublicParams m_pubParams;
  c2.setInterestFilter(InterestFilter(attrAuthorityPrefix),
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
                       });

  ParamFetcher paramFetcher(c1, attrAuthorityPrefix, trustConfig);
  paramFetcher.fetchPublicParams();
  advanceClocks(time::milliseconds(10), 100);

  BOOST_CHECK(paramFetcher.getPublicParams().m_pub != "");
  BOOST_CHECK(paramFetcher.getAbeType() == ABE_TYPE_CP_ABE);
}

BOOST_AUTO_TEST_SUITE_END()

}  // namespace tests
}  // namespace nacabe
}  // namespace ndn
