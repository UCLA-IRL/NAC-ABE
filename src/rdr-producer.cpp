//
// Created by Tyler on 3/5/23.
//

#include "rdr-producer.hpp"

#include <utility>
#include <ndn-cxx/util/logger.hpp>
#include <ndn-cxx/util/logging.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>

NDN_LOG_INIT(nacabe.RdrProducer);

using namespace ndn;


KeyChain ndn::nacabe::RdrProducer::KEYCHAIN("pib-memory:", "tpm-memory:");
const size_t ndn::nacabe::RdrProducer::MAX_DATA_SIZE = 8000;

ndn::nacabe::RdrProducer::RdrProducer(Face &face, Name objectName, time::milliseconds metaDataTtl,
                                      time::milliseconds segmentTtl) :
                                      m_face(face),
                                      m_metaDataTtl(metaDataTtl),
                                      m_segmentTtl(segmentTtl),
                                      m_objectName(std::move(objectName))
{
}

void ndn::nacabe::RdrProducer::setInterestFilter(std::function<time::system_clock::time_point()> getLastTimestamp,
                                                 std::function<Buffer(
                                                     time::system_clock::time_point)> getContent,
                                                 std::function<void(Data &)> decorateMetaData) {
  m_handle.cancel();
  m_getLastTimestamp = std::move(getLastTimestamp);
  m_getContent = std::move(getContent);
  m_decorateMetaData = std::move(decorateMetaData);
  m_handle = m_face.setInterestFilter(m_objectName,
                           std::bind(&RdrProducer::onInterest, this, _2));
}

void ndn::nacabe::RdrProducer::onInterest(const Interest &interest) {
  const auto &name = interest.getName();
  if (!interest.getName().get(m_objectName.size()).isKeyword()) {
    // put segments
    bool hasDigest = name.get(-1).isImplicitSha256Digest();
    if (name.size() != m_objectName.size() + 2 + (hasDigest) ||
        !name.get(m_objectName.size() + 1).isSegment() || !name.get(m_objectName.size()).isTimestamp()) {
      NDN_LOG_WARN("Received interest with bad name: " << name);
      return;
    }
    auto ts = name.get(m_objectName.size()).toTimestamp();
    auto seg = name.get(m_objectName.size() + 1).toSegment();
    if (m_segments.count(ts) == 0 || seg >= m_segments.at(ts).size()) {
      NDN_LOG_WARN("Item not found: " << name);
      return;
    }
    m_face.put(m_segments.at(ts).at(seg));
    return;
  }

  if (readString(name.get(m_objectName.size())) != METADATA_KEYWORD) {
    NDN_LOG_WARN("Received metadata interest with bad name: " << name);
    return;
  }
  auto currentTime = time::system_clock::now();
  auto new_time = m_getLastTimestamp();
  if (new_time != m_lastGenerationTime) {
    m_expireTime[m_lastGenerationTime] = currentTime + m_metaDataTtl * 2;
    m_lastGenerationTime = new_time;
    m_metaData = nullptr;
  }
  if (m_metaData != nullptr) {
    m_face.put(*m_metaData);
    return;
  }

  //generate new item
  auto content = m_getContent(new_time);
  size_t nSegments = content.empty() ? 0 : ((content.size() - 1) / MAX_DATA_SIZE) + 1;
  Block digestBlock(tlv::Content);

  for (size_t i = 0; i < nSegments; i++) {
    // Create encapsulated segment
    auto segmentName = Name(m_objectName).appendTimestamp(new_time).appendSegment(i);
    Data segment(segmentName);
    segment.setFreshnessPeriod(time::duration_cast<time::milliseconds>(m_segmentTtl));

    const uint8_t* segVal = content.data() + i * MAX_DATA_SIZE;
    const size_t segValSize = std::min(content.size() - i * MAX_DATA_SIZE, MAX_DATA_SIZE);
    segment.setContent(make_span(segVal, segValSize));

    KEYCHAIN.sign(segment, signingWithSha256());
    digestBlock.push_back(segment.getFullName().get(-1));

    // Insert outer segment
    new_time = time::duration_cast<time::milliseconds>(new_time - time::getUnixEpoch()) + time::getUnixEpoch();
    m_segments[new_time].push_back(std::move(segment));
  }

  // make metadata
  auto metadataName = Name(m_objectName).appendKeyword(METADATA_KEYWORD.c_str()).appendTimestamp(new_time);
  m_metaData = std::make_unique<Data>(metadataName);
  m_metaData->setFreshnessPeriod(time::duration_cast<time::milliseconds>(m_metaDataTtl));

  m_metaData->setContent(digestBlock);
  m_decorateMetaData(*m_metaData);

  m_face.put(*m_metaData);

  // remove expired data
  while (!m_expireTime.empty()) {
    if (m_expireTime.begin()->second < currentTime) {
      m_segments.erase(m_expireTime.begin()->first);
      m_expireTime.erase(m_expireTime.begin());
    } else break;
  }
}

bool nacabe::RdrProducer::checkCancel() {
  auto currentTime = time::system_clock::now();
  while (!m_expireTime.empty()) {
    if (m_expireTime.begin()->second < currentTime) {
      m_segments.erase(m_expireTime.begin()->first);
      m_expireTime.erase(m_expireTime.begin());
    } else break;
  }
  if (m_segments.empty()) {
    m_handle.cancel();
    return true;
  }
  return false;
}
