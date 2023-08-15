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

#include "trust-config.hpp"
#include <boost/property_tree/json_parser.hpp>
#include <ndn-cxx/util/io.hpp>

namespace ndn {
namespace nacabe {

void
TrustConfig::load(const std::string& fileName)
{
  JsonSection jsonConfig;
  try {
    boost::property_tree::read_json(fileName, jsonConfig);
  }
  catch (const boost::property_tree::file_parser_error& error) {
    NDN_THROW(std::runtime_error("Failed to parse configuration file " + fileName +
                                 " " + error.message() + " line " + std::to_string(error.line())));
  }
  if (jsonConfig.begin() == jsonConfig.end()) {
    NDN_THROW(std::runtime_error("Error processing configuration file: " + fileName + " no data"));
  }
  parse(jsonConfig);
}

void
TrustConfig::parse(const JsonSection& jsonConfig)
{
  m_knownKeys.clear();
  auto caList = jsonConfig.get_child("certificate-list");
  auto it = caList.begin();
  for (; it != caList.end(); it++) {
    std::istringstream ss(it->second.get<std::string>("certificate"));
    auto certItem = *io::load<security::Certificate>(ss);
    m_knownKeys.insert(std::make_pair(certItem.getKeyName(), certItem));
  }
}

void
TrustConfig::addOrUpdateCertificate(const security::Certificate& certificate)
{
  auto search = m_knownKeys.find(certificate.getKeyName());
  if (search != m_knownKeys.end()) {
    search->second = certificate;
  }
  else {
    m_knownKeys.insert(std::make_pair(certificate.getKeyName(), certificate));
  }
}

std::optional<security::Certificate>
TrustConfig::findCertificateFromLocal(const Name& KeyName) const
{
  auto search = m_knownKeys.find(KeyName);
  if (search != m_knownKeys.end()) {
    return search->second;
  }
  else {
    return std::nullopt;
  }
}

void
TrustConfig::findCertificateFromNetwork(Face& face, security::Validator& validator,
                                        const Name& KeyName,
                                        const FetchCertSuccessCb& onSuccess,
                                        const FetchCertFailureCb& onFailure)
{
  Interest interest(KeyName);
  interest.setCanBePrefix(true);
  face.expressInterest(interest,
    [=, &validator](const Interest&, const Data& data) {
      validator.validate(data,
        [onSuccess] (const Data& data) {onSuccess(security::Certificate(data));},
        [onFailure] (auto&&, const ndn::security::ValidationError& error) {onFailure(error.getInfo());}
      );
    },
    [onFailure](auto&&...) {onFailure("nack");}, 
    [onFailure](auto&&...) {onFailure("timeout");}
  );
}

} // namespace nacabe
} // namespace ndn
