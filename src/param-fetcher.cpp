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

#include "param-fetcher.hpp"

#include <utility>
#include <ndn-cxx/security/verification-helpers.hpp>

namespace ndn {
namespace nacabe {

NDN_LOG_INIT(nacabe.ParamFetcher);

ParamFetcher::ParamFetcher(Face& face, const Name& attrAuthorityPrefix, const TrustConfig& trustConfig)
  : m_attrAuthorityPrefix(attrAuthorityPrefix),
    m_trustConfig(trustConfig),
    m_rdrFetcher(face, Name(attrAuthorityPrefix).append(PUBLIC_PARAMS))
{
  m_rdrFetcher.setMetaDataVerificationCallback([this](const Data& pubParamData, bool isRecent) {
    if (!isRecent) {
      NDN_LOG_WARN("The metainfo for public param is not recent");
      return false;
    }
    auto optionalAAKey = m_trustConfig.findCertificate(m_attrAuthorityPrefix);
    if (optionalAAKey) {
      if (!security::verifySignature(pubParamData, *optionalAAKey)) {
        NDN_LOG_WARN("Fetched public parameters cannot be authenticated: bad signature");
        return false;
      }
    } else {
      NDN_LOG_WARN("Fetched public parameters cannot be authenticated: no certificate");
      return false;
    }

    auto abeTypeBlock = pubParamData.getMetaInfo().findAppMetaInfo(TLV_AbeType);
    if (abeTypeBlock != nullptr) {
      m_abeType = readString(*abeTypeBlock);
      if (m_abeType == ABE_TYPE_CP_ABE || m_abeType == ABE_TYPE_KP_ABE) {
        return true;
      }
    }
    NDN_LOG_WARN("Fetched public parameters with unsupported ABE type");
    return false;
  });
}

void
ParamFetcher::fetchPublicParams()
{  
  // set metadata checking call back
  NDN_LOG_INFO("[onAttributePubParams()] Get public parameters");
  // call fetch on rdr fetcher, set call back to be onAttributePubParams
  m_rdrFetcher.fetchRDRSegments([this](bool haveError) {
    if (haveError) {
      NDN_LOG_INFO("[onAttributePubParams()] error on getting public parameters");
      return;
    }
    m_pubParamsCache.fromBuffer(m_rdrFetcher.getSegmentDataBuffers());
  });
}

} // namespace nacabe
} // namespace ndn
