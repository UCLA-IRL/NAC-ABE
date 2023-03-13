#ifndef NAC_ABE_RDR_FETCHER_HPP
#define NAC_ABE_RDR_FETCHER_HPP

#include <map>
#include <vector>
#include <ndn-cxx/data.hpp>
#include <ndn-cxx/util/time.hpp>
#include <ndn-cxx/face.hpp>
#include <vector>

using namespace std;

namespace ndn {
namespace nacabe {

class RdrFetcher {
public:
  RdrFetcher(ndn::Face& face, const Name& metaDataName, Interest baseInterest = getDefaultInterestTemplate());

  void fetchRDRSegments();

  std::vector<Buffer> getSegmentDataBuffers()
  {
    return m_segmentBuffers;
  }


public:
  static inline Interest getDefaultInterestTemplate() {
    Interest interest;
    interest.setCanBePrefix(true);
    interest.setMustBeFresh(true);
    return interest;
  }

private:
  void
  onMetaData(const Data& MetaData);
  void
  onSegmentData(const Data& SegmentData);

private:
  ndn::Face& m_face;
  // this is name prefix before 32=metadata
  const Name& m_metaDataName;
  Interest m_baseInterest;
  std::vector<Buffer> m_segmentBuffers;
};

}
}

#endif //NAC_ABE_RDR_FETCHER_HPP
