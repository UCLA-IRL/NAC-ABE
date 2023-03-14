#include "rdr-fetcher.hpp"
#include <ndn-cxx/util/logger.hpp>
#include <ndn-cxx/util/logging.hpp>

namespace ndn {
namespace nacabe {

NDN_LOG_INIT(nacabe.RdrFetcher);

const std::string METADATA_KEYWORD = "metadata";

RdrFetcher::RdrFetcher(Face& face, const Name& objectName, const TrustConfig& trustConfig, std::function<Interest()> baseInterestTemplate)
  : m_face(face),
    m_objectName(objectName),
    m_trustConfig(trustConfig),
    m_baseInterestCallback(std::move(baseInterestTemplate)),
    m_pendingSegments(0)
{
}

void RdrFetcher::fetchRDRSegments(std::function<void(bool)> updateDoneCallback)
{
  if (m_pendingSegments) {
    NDN_THROW(std::runtime_error("RDR fetcher: not ready for consecutive fetch"));
  }
  m_pendingSegments = 1;
  m_updateDoneCallback = updateDoneCallback;
  // fetch meta data
  Name interestName = m_objectName;
  interestName.appendKeyword(METADATA_KEYWORD.c_str());
  auto interest = m_baseInterestCallback();
  interest.setName(interestName);

  NDN_LOG_INFO("Request metaData: " << interest.getName());
  m_face.expressInterest(interest,
                         [this](const Interest &, const Data &data) { onMetaData(data); },
                         [this](auto&&...) { NDN_LOG_INFO("NACK"); m_updateDoneCallback(true);m_pendingSegments = 0;},
                         [this](auto&&...) { NDN_LOG_INFO("Timeout"); m_updateDoneCallback(true);m_pendingSegments = 0;});
}

Buffer RdrFetcher::getSegmentDataBuffers() {
  if (m_pendingSegments) {
    NDN_THROW(std::runtime_error("RDR fetcher: segments not ready"));
  }
  Buffer buf;
  for (const auto& i: m_segmentBuffers) {
    buf.reserve(buf.size() + i.size());
    buf.insert(buf.end(), i.begin(), i.end());
  }
  return buf;
}

void
RdrFetcher::onMetaData(const Data& fetchedMetaData)
{
  // when receive metadata, unpack it
  NDN_LOG_INFO("[onMetaData()] Get Meta data");
  
  // code to verify the data?
  if (m_metaDataVerificationCallback) {
    if (!m_metaDataVerificationCallback(fetchedMetaData)) {
      NDN_LOG_WARN("Metadata Verification failed");
      m_updateDoneCallback(true);
      m_pendingSegments = 0;
      return;
    }
  }
  
  // code to fetch metadata name and get segment names
  auto timeStampComponent = fetchedMetaData.getName().get(m_objectName.size() + 1);
  if (!timeStampComponent.isTimestamp()) {
    NDN_LOG_WARN("Metadata have a bad timestamp component");
    m_updateDoneCallback(true);
    m_pendingSegments = 0;
    return;
  }
  auto fetchedTimestamp = timeStampComponent.toTimestamp();
  NDN_LOG_INFO("timestamp component is : " << timeStampComponent);
  if (fetchedTimestamp == m_lastFetchedTime) {
    //no update
    NDN_LOG_INFO("update done with no new version");
    m_updateDoneCallback(false);
    m_pendingSegments = 0;
    return;
  }
  m_lastFetchedTime = fetchedTimestamp;
  m_segmentBuffers.clear();

  // code to fetch metadata content to know how many segments
  auto& metaContent = fetchedMetaData.getContent();
  metaContent.parse();
  // send interest based on this current version name
  size_t i = 0;
  for (auto element : metaContent.elements()) {
    Name interestName = Name(m_objectName).appendTimestamp(fetchedTimestamp);
    // append segment number
    try {
      name::Component digestComponent(element);
      interestName.appendSegment(i).append(digestComponent);
      Interest interest = m_baseInterestCallback();
      interest.setMustBeFresh(false);
      interest.setCanBePrefix(false);
      interest.setName(interestName);

      NDN_LOG_INFO("Request Segment Data: " << interest.getName());
      m_face.expressInterest(interest,
                            [this](const Interest &, const Data &data) { onSegmentData(data); },
                            [this](auto&&...) { NDN_LOG_INFO("NACK"); m_updateDoneCallback(true);m_pendingSegments = 0;},
                            [this](auto&&...) { NDN_LOG_INFO("Timeout"); m_updateDoneCallback(true);m_pendingSegments = 0;}
                            );
    } catch(const std::exception& e) {
      NDN_LOG_WARN("Error in metadata decoding: " << e.what());
      m_updateDoneCallback(true);
      m_pendingSegments = 0;
      return;
    }
    i++;  
  }
  m_pendingSegments = i;
  m_segmentBuffers.resize(i);
  if (i == 0) {
    NDN_LOG_INFO("New Metadata has no segments; ");
    m_updateDoneCallback(false);
  }
}
void
RdrFetcher::onSegmentData(const Data& fetchedSegmentData)
{
  // when receive metadata, unpack it
  NDN_LOG_INFO("[onSegmentData()] Get Segment data");

  if (m_pendingSegments == 0) {
    NDN_LOG_INFO("[onSegmentData()] Other segments failed...");
    return;
  }

  // code to fetch segname to find out sequence number
  auto segmentNumberComponent = fetchedSegmentData.getName().get(-1);
  NDN_LOG_INFO("Current segment number:  " << segmentNumberComponent);
  
  // code to fetch segdata content
  const auto& segContent = fetchedSegmentData.getContent();
  
  // put content buffer into index i = segmentNumber
  uint64_t segmentNumber = segmentNumberComponent.toSegment();
  m_segmentBuffers[segmentNumber] = Buffer(segContent.value(), segContent.value_size());
  m_pendingSegments --;
  if (m_pendingSegments == 0) {
    NDN_LOG_INFO("All segment fetched. ");
    m_updateDoneCallback(false);
  }
}

} // namespace nacabe
} // namespace ndn