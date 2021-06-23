/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017-2019, Regents of the University of California.
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
  catch (const boost::property_tree::info_parser_error& error) {
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
  m_knownIdentities.clear();
  auto caList = jsonConfig.get_child("certificate-list");
  auto it = caList.begin();
  for (; it != caList.end(); it++) {
    std::istringstream ss(it->second.get<std::string>("certificate"));
    auto certItem = *(io::load<security::Certificate>(ss));
    m_knownIdentities.insert(std::make_pair(certItem.getIdentity(), certItem));
  }
}

void
TrustConfig::addOrUpdateCertificate(const security::Certificate& certificate)
{
  auto search = m_knownIdentities.find(certificate.getIdentity());
  if (search != m_knownIdentities.end()) {
    search->second = certificate;
  }
  else {
    m_knownIdentities.insert(std::make_pair(certificate.getIdentity(), certificate));
  }
}

optional<security::Certificate>
TrustConfig::findCertificate(const Name& identityName) const
{
  auto search = m_knownIdentities.find(identityName);
  if (search != m_knownIdentities.end()) {
    return make_optional(search->second);
  }
  else {
    return nullopt;
  }
}

} // namespace nacabe
} // namespace ndn
