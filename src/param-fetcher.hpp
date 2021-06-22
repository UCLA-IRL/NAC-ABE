//
// Created by Tyler on 6/22/21.
//

#ifndef NAC_ABE_PARAM_FETCHER_H
#define NAC_ABE_PARAM_FETCHER_H

#include <algo/public-params.hpp>
#include "common.hpp"
#include "trust-config.hpp"

namespace ndn {
namespace nacabe {

/**
 * Internal class for fetching parameters
 */
class ParamFetcher {
public:

  ParamFetcher(Face& face, const Name &attrAuthorityPrefix, const TrustConfig &trustConfig);

  void onAttributePubParams(const Data &pubParamData);

  void fetchPublicParams();

  algo::PublicParams getPublicParams();
PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  algo::PublicParams m_pubParamsCache;
  Face &m_face;
  const Name &m_attrAuthorityPrefix;
  const TrustConfig &m_trustConfig;
};

}
}

#endif //NAC_ABE_PARAM_FETCHER_H
