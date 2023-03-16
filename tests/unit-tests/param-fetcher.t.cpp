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
#include "rdr-producer.hpp"

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
    authorityCert = addIdentity(attrAuthorityPrefix).getDefaultKey().getDefaultCertificate();
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
  algo::MasterKey m_masterKey;
  algo::ABESupport::getInstance().cpInit(m_pubParams, m_masterKey);
  Buffer b = m_pubParams.toBuffer();
  RdrProducer producer(c2, Name(attrAuthorityPrefix).append(PUBLIC_PARAMS));
  producer.setInterestFilter([t = time::system_clock::now()]{return t;},
                             [b](time::system_clock::time_point i) {
                               NDN_LOG_TRACE("Reply public params request.");
                               NDN_LOG_TRACE("Pub params size: " << b.size());
                               return b;
                             }, [this](auto& data) {
        MetaInfo info = data.getMetaInfo();
        info.addAppMetaInfo(makeStringBlock(TLV_AbeType, ABE_TYPE_CP_ABE));
        data.setMetaInfo(info);
        m_keyChain.sign(data, signingByCertificate(authorityCert));
      });
  advanceClocks(time::milliseconds(20), 60);

  ParamFetcher paramFetcher(c1, attrAuthorityPrefix, trustConfig);
  paramFetcher.fetchPublicParams();
  advanceClocks(time::milliseconds(20), 60);

  auto interestName = c1.sentInterests.at(0).getName();
  auto dataName = c2.sentData.at(0).getName();

  BOOST_CHECK(!paramFetcher.getPublicParams().m_pub.empty());
  BOOST_CHECK_EQUAL(paramFetcher.getAbeType(), ABE_TYPE_CP_ABE);
}

BOOST_AUTO_TEST_SUITE_END()

}  // namespace tests
}  // namespace nacabe
}  // namespace ndn
