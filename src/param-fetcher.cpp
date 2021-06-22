//
// Created by Tyler on 6/22/21.
//

#include "param-fetcher.hpp"
#include <ndn-cxx/security/verification-helpers.hpp>

namespace ndn {
namespace nacabe {

NDN_LOG_INIT(nacabe.paramFetcher);

ParamFetcher::ParamFetcher(Face& face, const Name &attrAuthorityPrefix, const TrustConfig &trustConfig)
    : m_face(face),
      m_attrAuthorityPrefix(attrAuthorityPrefix),
      m_trustConfig(trustConfig) {
}

void
ParamFetcher::fetchPublicParams() {
  // fetch pub parameters
  Name interestName = m_attrAuthorityPrefix;
  interestName.append(PUBLIC_PARAMS);
  Interest interest(interestName);
  interest.setMustBeFresh(true);
  interest.setCanBePrefix(true);

  NDN_LOG_INFO("Request public parameters:" << interest.getName());
  m_face.expressInterest(interest,
                         [this](const Interest &, const Data &data) { onAttributePubParams(data); },
                         [=](const Interest &, const lp::Nack &) { NDN_LOG_INFO("NACK"); },
                         [=](const Interest &) { NDN_LOG_INFO("Timeout"); });
}

void
ParamFetcher::onAttributePubParams(const Data &pubParamData) {
  NDN_LOG_INFO("[onAttributePubParams()] Get public parameters");
  auto optionalAAKey = m_trustConfig.findCertificate(m_attrAuthorityPrefix);

  if (optionalAAKey) {
    if (!security::verifySignature(pubParamData, *optionalAAKey)) {
      NDN_THROW(std::runtime_error("Fetched public parameters cannot be authenticated: bad signature"));
    }
  } else {
    NDN_THROW(std::runtime_error("Fetched public parameters cannot be authenticated: no certificate"));
  }

  m_abeType = readString(pubParamData.getName().get((ssize_t) m_attrAuthorityPrefix.size() + 1));
  if (m_abeType != ABE_TYPE_CP_ABE && m_abeType != ABE_TYPE_KP_ABE) {
    NDN_THROW(std::runtime_error("Fetched public parameters with unsupported ABE type"));
  }
  auto block = pubParamData.getContent();
  m_pubParamsCache.fromBuffer(Buffer(block.value(), block.value_size()));
}

algo::PublicParams
ParamFetcher::getPublicParams() {
  return m_pubParamsCache;
}

AbeType
ParamFetcher::getAbeType() {
  return m_abeType;
}

}
}