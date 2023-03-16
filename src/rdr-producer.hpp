//
// Created by Tyler on 3/5/23.
//

#ifndef NAC_ABE_RDR_PRODUCER_HPP
#define NAC_ABE_RDR_PRODUCER_HPP

#include "common.hpp"
#include <map>
#include <vector>
#include <ndn-cxx/data.hpp>
#include <ndn-cxx/util/time.hpp>
#include <ndn-cxx/face.hpp>

namespace ndn {
namespace nacabe {

class RdrProducer {
public:
  RdrProducer(ndn::Face& face, ndn::Name objectName, time::milliseconds metaDataTtl = time::minutes(5),
              time::milliseconds segmentTtl = time::days(1), time::milliseconds metaDataRefreshTime = 150_s);

  void setInterestFilter(std::function<time::system_clock::time_point()> getLastTimestamp,
                         std::function<Buffer(time::system_clock::time_point)> getContent,
                         std::function<void(ndn::Data&)> decorateMetaData
                         );

  bool checkCancel();
private:
  void onInterest(const ndn::Interest& interest);

private:
  //config
  time::milliseconds m_metaDataTtl;
  time::milliseconds m_segmentTtl;
  time::milliseconds m_metaDataRefreshTime;

  //callbacks
  ndn::Face& m_face;
  ndn::Name m_objectName;
  ndn::InterestFilterHandle m_handle;
  std::function<time::system_clock::time_point()> m_getLastTimestamp;
  std::function<Buffer(time::system_clock::time_point)> m_getContent;
  std::function<void(ndn::Data&)> m_decorateMetaData;

  std::map<time::system_clock::time_point, std::vector<ndn::Data>> m_segments;
  std::map<time::system_clock::time_point, time::system_clock::time_point> m_expireTime;
  std::unique_ptr<ndn::Data> m_metaData;
  time::system_clock::time_point m_lastGenerationTime;

  static const size_t MAX_DATA_SIZE;

  static KeyChain KEYCHAIN;
};

}
}

#endif //NAC_ABE_RDR_PRODUCER_HPP
