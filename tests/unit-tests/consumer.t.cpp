// /* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
// /**
//  * Copyright (c) 2017-2019, Regents of the University of California.
//  *
//  * This file is part of NAC-ABE.
//  *
//  * NAC-ABE is free software: you can redistribute it and/or modify it under the terms
//  * of the GNU General Public License as published by the Free Software Foundation, either
//  * version 3 of the License, or (at your option) any later version.
//  *
//  * NAC-ABE is distributed in the hope that it will be useful, but WITHOUT ANY
//  * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
//  * PARTICULAR PURPOSE.  See the GNU General Public License for more details.
//  *
//  * You should have received copies of the GNU General Public License along with
//  * NAC-ABE, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
//  *
//  * See AUTHORS.md for complete list of NAC-ABE authors and contributors.
//  */

// #include "consumer.hpp"
// #include "test-common.hpp"
// #include "algo/abe-support.hpp"
// #include <ndn-cxx/util/dummy-client-face.hpp>

// namespace ndn {
// namespace nacabe {
// namespace tests {

// namespace fs = boost::filesystem;

// NDN_LOG_INIT(Test.Consumer);

// class TestConsumerFixture : public IdentityManagementTimeFixture
// {
// public:
//   TestConsumerFixture()
//     : c1(io, m_keyChain, util::DummyClientFace::Options{true, true})
//     , c2(io, m_keyChain, util::DummyClientFace::Options{true, true})
//     , attrAuthorityPrefix("/authority")
//     , tokenIssuerPrefix("/token/issuer")
//   {
//     c1.linkTo(c2);
//     auto id = addIdentity("/consumer");
//     auto key = id.getDefaultKey();
//     cert = key.getDefaultCertificate();
//   }

// public:
//   util::DummyClientFace c1;
//   util::DummyClientFace c2;
//   Name attrAuthorityPrefix;
//   Name tokenIssuerPrefix;
//   security::v2::Certificate cert;
// };

// BOOST_FIXTURE_TEST_SUITE(TestConsumer, TestConsumerFixture)

// BOOST_AUTO_TEST_CASE(Constructor)
// {
//   algo::PublicParams m_pubParams;
//   c2.setInterestFilter((attrAuthorityPrefix),
//                      [&] (const ndn::InterestFilter&, const ndn::Interest& interest) {
//                         algo::MasterKey m_masterKey;
//                         algo::ABESupport::setup(m_pubParams, m_masterKey);
//                         Data result;
//                         Name dataName = interest.getName();
//                         dataName.appendTimestamp();
//                         result.setName(dataName);
//                         const auto& contentBuf = m_pubParams.toBuffer();
//                         result.setContent(makeBinaryBlock(ndn::tlv::Content,
//                                                           contentBuf.data(), contentBuf.size()));
//                         m_keyChain.sign(result, signingByCertificate(cert));

//                         NDN_LOG_TRACE("Reply public params request.");
//                         NDN_LOG_TRACE("Pub params size: " << contentBuf.size());

//                         c2.put(result);
//                      });

//   advanceClocks(time::milliseconds(20), 60);

//   Consumer consumer(cert, c1, m_keyChain, attrAuthorityPrefix);
//   advanceClocks(time::milliseconds(20), 60);

//   BOOST_CHECK(consumer.m_pubParamsCache.m_pub != "");
//   //***** need to compare pointer content *****
//   //BOOST_CHECK(consumer.m_pubParamsCache.m_pub == m_pubParams.m_pub);
// }


// BOOST_AUTO_TEST_CASE(comsumeData)
// {
//   // Maybe we can put this to integrated test?
// }


// BOOST_AUTO_TEST_SUITE_END()

// } // namespace tests
// } // namespace nacabe
// } // namespace ndn
