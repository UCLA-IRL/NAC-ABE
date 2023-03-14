#include "rdr-fetcher.hpp"
#include <ndn-cxx/util/logger.hpp>
#include <ndn-cxx/util/logging.hpp>

namespace ndn {
namespace nacabe {

NDN_LOG_INIT(nacabe.RdrFetcher);

const std::string METADATAKEYWORD = "metadata";

RdrFetcher::RdrFetcher(Face& face, const Name& metaDataName, Interest baseInterest)
  : m_face(face),
    m_metaDataName(metaDataName),
    m_baseInterest(std::move(baseInterest))
{
}

void RdrFetcher::fetchRDRSegments()
{
  // fetch meta data
  Name interestName = m_metaDataName;
  interestName.appendKeyword("metadata");
  Interest interest(m_baseInterest);
  interest.setName(interestName);

  NDN_LOG_INFO("Request metaData: " << interest.getName());
  m_face.expressInterest(interest,
                         [this](const Interest &, const Data &data) { onMetaData(data); },
                         [](auto&&...) { NDN_LOG_INFO("NACK"); },
                         [](auto&&...) { NDN_LOG_INFO("Timeout"); });  
  
}
void
RdrFetcher::onMetaData(const Data& fetchedMetaData)
{
  // when receive metadata, unpack it
  NDN_LOG_INFO("[onMetaData()] Get Meta data");
  
  // code to verify the data?

  
  // code to fetch metadata name and get segment names
  
  // std::string segmentName = ndn::encoding::readString(fetchedMetaData.getName().get(0));
  // // discard the segment number
  // int pos = segmentName.find_last_of("\\");
  // if (pos != std::string::npos) {
  //   segmentName = segmentName.substr(0, pos);
  // }
  
  PartialName segmentName = fetchedMetaData.getName().getSubName(0, fetchedMetaData.getName().size() - 1);
  NDN_LOG_INFO("segment name is : " << segmentName);
  
  // code to fetch metadata content to know how many segments
  Block metaContent = fetchedMetaData.getContent();
  metaContent.parse();
  // send interest based on this current version name
  size_t i = 0;
  for (auto element : metaContent.elements()) {
    Name interestName = Name(segmentName);
    // append segment number
    interestName.appendSegment(i);
    Interest interest(m_baseInterest);
    interest.setName(interestName);

    NDN_LOG_INFO("Request Segment Data: " << interest.getName());
    m_face.expressInterest(interest,
                          [this](const Interest &, const Data &data) { onSegmentData(data); },
                          [](auto&&...) { NDN_LOG_INFO("NACK"); },
                          [](auto&&...) { NDN_LOG_INFO("Timeout"); });
    i++;  
  }
}
void
RdrFetcher::onSegmentData(const Data& fetchedSegmentData)
{
  // when receive metadata, unpack it
  NDN_LOG_INFO("[onSegmentData()] Get Segment data");

  // code to fetch segname to find out sequence number
  // std::string segmentNumber = ndn::encoding::readString(fetchedSegmentData.getName().get(0));
  // size_t pos = segmentNumber.find_last_of("\\");
  // if (pos != string::npos) {
  //   segmentNumber = segmentNumber.substr(pos + 1);
  // }
  PartialName segmentNumberName = fetchedSegmentData.getName().getSubName(-1, 1);
  NDN_LOG_INFO("Current segment number:  " << segmentNumberName);
  
  // code to fetch segdata content
  Block segContent = fetchedSegmentData.getContent();
  
  // put content buffer into index i = segmentNumber
  uint64_t segmentNumber = segmentNumberName.get(0).toSegment();
  m_segmentBuffers[segmentNumber] = Buffer(segContent.value(), segContent.size());
}

} // namespace nacabe
} // namespace ndn