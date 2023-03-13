#include "rdr-fetcher.hpp"
#include <ndn-cxx/util/logger.hpp>
#include <ndn-cxx/util/logging.hpp>

namespace ndn {
namespace nacabe {

NDN_LOG_INIT(nacabe.RdrFetcher);

const std::string METADATAKEYWORD = "32=metadata";

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
  interestName.appendKeyword("32=metadata");
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

  // code to fetch metadata content
  Block metaContent = fetchedMetaData.getContent();
  metaContent.parse();
  // get the name block
  std::string segmentName = ndn::encoding::readString(metaContent.get(tlv::Name)); 
  NDN_LOG_INFO("segment name is : " << segmentName);

  // // discard the segment number
  // int pos = segmentName.find_last_of("\\");
  // if (pos != std::string::npos) {
  //   segmentName = segmentName.substr(0, pos);
  // }
  
  // send interest based on this current version name
  // how many segment interest to send?
  for (size_t i = 0; i < 10, i++;) {
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
  }
}
void
RdrFetcher::onSegmentData(const Data& fetchedSegmentData)
{
  // when receive metadata, unpack it
  NDN_LOG_INFO("[onSegmentData()] Get Segment data");

  // code to fetch metadata content
  Block segContent = fetchedSegmentData.getContent();
  m_segmentBuffers.push_back(Buffer(segContent.value(), segContent.size()));

}

} // namespace nacabe
} // namespace ndn