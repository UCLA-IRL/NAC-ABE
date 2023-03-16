#ifndef NAC_ABE_RDR_FETCHER_HPP
#define NAC_ABE_RDR_FETCHER_HPP

#include "common.hpp"

#include <map>
#include <utility>
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
  RdrFetcher(ndn::Face& face, Name objectName,
             std::function<Interest()> baseInterestTemplate = getDefaultInterestTemplate);

  inline void setMetaDataVerificationCallback(std::function<bool(const Data&, bool)> callback) {
    m_metaDataVerificationCallback = std::move(callback);
  }

  /**
   * @param updateDoneCallback callback will be called when fetching is done. The argument represent if there is an error.
   */
  void fetchRDRSegments(std::function<void(bool)> updateDoneCallback);

  Buffer getSegmentDataBuffers();

  inline bool isPending() const {
    return m_pendingSegments != 0;
  }

  inline time::system_clock::time_point lastFetchedTimestamp() const {
    return m_lastFetchedTime;
  }

public:
  static inline Interest getDefaultInterestTemplate() {
    Interest interest;
    interest.setCanBePrefix(true);
    interest.setMustBeFresh(true);
    interest.setInterestLifetime(time::seconds(4));
    return interest;
  }

private:
  void
  onMetaData(const Data& MetaData);
  void
  onSegmentData(const Data& SegmentData);

  void onDone(bool haveError);

private:
  ndn::Face& m_face;
  // this is name prefix before metadata
  Name m_objectName;
  uint32_t m_pendingSegments;
  time::system_clock::time_point m_lastFetchedTime;
  std::function<Interest()> m_baseInterestCallback;
  std::function<bool(const Data&, bool)> m_metaDataVerificationCallback;
  std::function<void(bool)> m_updateDoneCallback;
  std::vector<Buffer> m_segmentBuffers;
};

}
}

#endif //NAC_ABE_RDR_FETCHER_HPP