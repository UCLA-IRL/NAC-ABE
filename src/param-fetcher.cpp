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

ParamFetcher::ParamFetcher(Face& face, security::Validator& validator, 
                           const Name& attrAuthorityPrefix, const TrustConfig& trustConfig, Interest interestTemplate)
  : m_face(face),
    m_validator(validator),
    m_attrAuthorityPrefix(attrAuthorityPrefix),
    m_trustConfig(trustConfig),
    m_interestTemplate(std::move(interestTemplate))
{
}

void
ParamFetcher::fetchPublicParams()
{
  if (m_retryCount >= MAX_RETRIES) {
    throw std::runtime_error("Failed to fetch public parameters after multiple attempts.");
  }

  ++m_retryCount;

  Name interestName = m_attrAuthorityPrefix;
  interestName.append(PUBLIC_PARAMS);
  Interest interest(m_interestTemplate);
  interest.setName(interestName);
  interest.refreshNonce();

  NDN_LOG_INFO("Request public parameters (attempt " << m_retryCount << "): " << interest.getName());

  m_face.expressInterest(
    interest,
    [this](const Interest&, const Data& data) {
      m_retryCount = 0;
      onAttributePubParams(data);
    },
    [this](const Interest&, const lp::Nack&) {
      NDN_LOG_WARN("Received NACK, retrying...");
      fetchPublicParams(); // Retry
    },
    [this](const Interest&) {
      NDN_LOG_WARN("Timeout, retrying...");
      fetchPublicParams(); // Retry
    });
}



void
ParamFetcher::onAttributePubParams(const Data& pubParamData)
{
  NDN_LOG_INFO("[onAttributePubParams()] Get public parameters");

  m_validator.validate(pubParamData,
    [this, pubParamData] (const Data& data) {
      NDN_LOG_INFO("Public parameters conforms to trust schema");
      m_abeType = readString(pubParamData.getName().get(m_attrAuthorityPrefix.size() + 1));
      if (m_abeType != ABE_TYPE_CP_ABE && m_abeType != ABE_TYPE_KP_ABE) {
        NDN_THROW(std::runtime_error("Fetched public parameters with unsupported ABE type"));
      }
      auto block = pubParamData.getContent();
      m_pubParamsCache.fromBuffer(Buffer(block.value(), block.value_size()));
    },
    [] (auto&&, const ndn::security::ValidationError& error) {
      NDN_THROW(std::runtime_error("Fetched public parameters cannot be authenticated: " + error.getInfo()));
    }    
  );
}

} // namespace nacabe
} // namespace ndn
