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

#include "rdr-producer.hpp"
#include "rdr-fetcher.hpp"

#include "test-common.hpp"

#include <ndn-cxx/util/dummy-client-face.hpp>

namespace ndn {
namespace nacabe {
namespace tests {

const uint8_t PLAIN_TEXT1[39999] = {1};
const uint8_t PLAIN_TEXT2[8000] = {2};

NDN_LOG_INIT(Test.RdrTest);

class TestRdrFixture : public IdentityManagementTimeFixture
{
public:
  TestRdrFixture()
    : producerFace(io, m_keyChain, {false, true})
    , fetcherFace(io, m_keyChain, {false, true})
  {
    producerFace.linkTo(fetcherFace);
    advanceClocks(42_us, 1);
  }

protected:
  util::DummyClientFace producerFace;
  util::DummyClientFace fetcherFace;
  std::map<time::system_clock::TimePoint, Buffer> buffer_map;
};

BOOST_FIXTURE_TEST_SUITE(TestRdr, TestRdrFixture)

BOOST_AUTO_TEST_CASE(Rdr)
{
  //set up interface counter
  uint32_t producerSent = 0, fetcherSent = 0;
  producerFace.onSendData.connect([&](auto&&...){producerSent ++;});
  fetcherFace.onSendInterest.connect([&](auto&&...){fetcherSent ++;});
  
  // set up RDR Producer
  Name objectName = "/a/b";
  NDN_LOG_INFO("Create RDR Producer. Data Object prefix: " << objectName);
  RdrProducer producer(producerFace, objectName);
  advanceClocks(time::milliseconds(20), 60);
  time::system_clock::TimePoint timeS = systemClock->getNow();
  buffer_map.emplace(timeS, Buffer({PLAIN_TEXT2, 8000}));

  uint8_t tsCheck = 0, getBufferExecuted = 0, signingExecuted = 0;
  producer.setInterestFilter([&](){tsCheck ++; return timeS;},
                             [&](auto timePoint){getBufferExecuted ++; return buffer_map.at(timePoint);},
                             [&](Data &data) {
                               signingExecuted++;
                               m_keyChain.sign(data, signingWithSha256());
                             });

  // set up RDR Fetcher
  NDN_LOG_INFO("Create RDR Fetcher. ");
  RdrFetcher fetcher(fetcherFace, objectName);
  uint8_t verificationExecuted = 0;
  fetcher.setMetaDataVerificationCallback([&](const auto& data, bool isRecent){ BOOST_CHECK(isRecent); verificationExecuted ++; return true; });

  advanceClocks(time::milliseconds(20), 10);
  BOOST_CHECK(tsCheck == 0);
  BOOST_CHECK(getBufferExecuted == 0);
  BOOST_CHECK(signingExecuted == 0);
  BOOST_CHECK(verificationExecuted == 0);

  //fetch first
  bool done = false;
  fetcher.fetchRDRSegments([&](bool error){
    BOOST_CHECK(!error);
    done = true;
    auto b = fetcher.getSegmentDataBuffers();
    BOOST_CHECK_EQUAL_COLLECTIONS(b.begin(), b.end(), PLAIN_TEXT2, PLAIN_TEXT2 + 8000);
  });
  BOOST_CHECK(fetcher.isPending());
  BOOST_CHECK_THROW(fetcher.fetchRDRSegments([&](bool error){}), std::exception);
  BOOST_CHECK_THROW(fetcher.getSegmentDataBuffers(), std::exception);
  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK(done);
  BOOST_CHECK(!fetcher.isPending());
  BOOST_CHECK_EQUAL(tsCheck, 1);
  BOOST_CHECK_EQUAL(getBufferExecuted, 1);
  BOOST_CHECK_EQUAL(signingExecuted, 1);
  BOOST_CHECK_EQUAL(verificationExecuted, 1);
  BOOST_CHECK_EQUAL(producerSent, 2);
  BOOST_CHECK_EQUAL(fetcherSent, 2);
  auto b = fetcher.getSegmentDataBuffers();
  BOOST_CHECK_EQUAL_COLLECTIONS(b.begin(), b.end(), PLAIN_TEXT2, PLAIN_TEXT2 + 8000);

  //another fetch
  done = false;
  fetcher.fetchRDRSegments([&](bool error){
    BOOST_CHECK(!error);
    done = true;
    auto b = fetcher.getSegmentDataBuffers();
    BOOST_CHECK_EQUAL_COLLECTIONS(b.begin(), b.end(), PLAIN_TEXT2, PLAIN_TEXT2 + 8000);
  });
  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK(done);
  BOOST_CHECK(!fetcher.isPending());
  BOOST_CHECK_EQUAL(tsCheck, 2);
  BOOST_CHECK_EQUAL(getBufferExecuted, 1);
  BOOST_CHECK_EQUAL(signingExecuted, 1);
  BOOST_CHECK_EQUAL(verificationExecuted, 2);
  BOOST_CHECK_EQUAL(producerSent, 3);
  BOOST_CHECK_EQUAL(fetcherSent, 3);
  b = fetcher.getSegmentDataBuffers();
  BOOST_CHECK_EQUAL_COLLECTIONS(b.begin(), b.end(), PLAIN_TEXT2, PLAIN_TEXT2 + 8000);

  //update data
  timeS = systemClock->getNow();
  buffer_map.emplace(timeS, Buffer({PLAIN_TEXT1, 39999}));
  done = false;
  fetcher.fetchRDRSegments([&](bool error){
    BOOST_CHECK(!error);
    done = true;
    auto b = fetcher.getSegmentDataBuffers();
    BOOST_CHECK_EQUAL_COLLECTIONS(b.begin(), b.end(), PLAIN_TEXT1, PLAIN_TEXT1 + 39999);
  });
  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK(done);
  BOOST_CHECK(!fetcher.isPending());
  BOOST_CHECK_EQUAL(tsCheck, 3);
  BOOST_CHECK_EQUAL(getBufferExecuted, 2);
  BOOST_CHECK_EQUAL(signingExecuted, 2);
  BOOST_CHECK_EQUAL(verificationExecuted, 3);

  BOOST_CHECK_EQUAL(producerSent, 9);
  BOOST_CHECK_EQUAL(fetcherSent, 9);

  b = fetcher.getSegmentDataBuffers();
  BOOST_CHECK_EQUAL_COLLECTIONS(b.begin(), b.end(), PLAIN_TEXT1, PLAIN_TEXT1 + 39999);

  //another fetch
  advanceClocks(150_s, 1);
  done = false;
  fetcher.fetchRDRSegments([&](bool error){
    BOOST_CHECK(!error);
    done = true;
    auto b = fetcher.getSegmentDataBuffers();
    BOOST_CHECK_EQUAL_COLLECTIONS(b.begin(), b.end(), PLAIN_TEXT1, PLAIN_TEXT1 + 39999);
  });
  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK(done);
  BOOST_CHECK(!fetcher.isPending());
  BOOST_CHECK_EQUAL(tsCheck, 4);
  BOOST_CHECK_EQUAL(getBufferExecuted, 2);
  BOOST_CHECK_EQUAL(signingExecuted, 3);
  BOOST_CHECK_EQUAL(verificationExecuted, 4);

  BOOST_CHECK_EQUAL(producerSent, 10);
  BOOST_CHECK_EQUAL(fetcherSent, 10);

  b = fetcher.getSegmentDataBuffers();
  BOOST_CHECK_EQUAL_COLLECTIONS(b.begin(), b.end(), PLAIN_TEXT1, PLAIN_TEXT1 + 39999);

  //update data
  timeS = systemClock->getNow();
  buffer_map.emplace(timeS, Buffer({PLAIN_TEXT1, 0}));
  done = false;
  fetcher.fetchRDRSegments([&](bool error){
    BOOST_CHECK(!error);
    done = true;
    auto b = fetcher.getSegmentDataBuffers();
    BOOST_CHECK(b.empty());
  });
  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK(done);
  BOOST_CHECK(!fetcher.isPending());
  BOOST_CHECK_EQUAL(tsCheck, 5);
  BOOST_CHECK_EQUAL(getBufferExecuted, 3);
  BOOST_CHECK_EQUAL(signingExecuted, 4);
  BOOST_CHECK_EQUAL(verificationExecuted, 5);
  BOOST_CHECK_EQUAL(producerSent, 11);
  BOOST_CHECK_EQUAL(fetcherSent, 11);

  b = fetcher.getSegmentDataBuffers();
  BOOST_CHECK(b.empty());

  BOOST_CHECK(!producer.checkCancel());
  advanceClocks(time::minutes(5), 5);
  BOOST_CHECK(producer.checkCancel());
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace nacabe
} // namespace ndn
