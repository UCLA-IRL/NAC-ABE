/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2017-2023, Regents of the University of California.
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

#include "cache-producer.hpp"

namespace ndn {
namespace nacabe {

void
CacheProducer::clearCache()
{
  m_cpKeyCache.clear();
  m_kpKeyCache.clear();
}

std::tuple<std::shared_ptr<Data>, std::shared_ptr<Data>>
CacheProducer::produce(const Name& dataName, const Policy& accessPolicy,
                       span<const uint8_t> content, const security::SigningInfo& info,
                       std::shared_ptr<Data> ckTemplate, shared_ptr<Data> dataTemplate)
{
  if (m_cpKeyCache.count(accessPolicy) == 0) {
    auto k = ckDataGen(accessPolicy, info, ckTemplate);
    if (k.first == nullptr || k.second == nullptr) {
      return std::make_tuple(nullptr, nullptr);
    }
    m_cpKeyCache.emplace(accessPolicy, k);
  }

  auto& key = m_cpKeyCache.at(accessPolicy);
  auto data = Producer::produce(key.first, key.second->getName(), dataName, content, info, dataTemplate);
  return std::make_tuple(data, key.second);
}

std::tuple<std::shared_ptr<Data>, std::shared_ptr<Data>>
CacheProducer::produce(const Name& dataName, const std::vector<std::string>& attributes,
                       span<const uint8_t> content, const security::SigningInfo& info,
                       std::shared_ptr<Data> ckTemplate, shared_ptr<Data> dataTemplate)
{
  std::stringstream ss;
  for (auto& i : attributes) ss << i << "|";
  auto attStr = ss.str();
  if (m_kpKeyCache.count(attStr) == 0) {
    auto k = ckDataGen(attributes, info, ckTemplate);
    if (k.first == nullptr || k.second == nullptr) {
      return std::make_tuple(nullptr, nullptr);
    }
    m_kpKeyCache.emplace(attStr, k);
  }
  auto& key = m_kpKeyCache.at(attStr);
  auto data = Producer::produce(key.first, key.second->getName(), dataName, content, info, dataTemplate);
  return std::make_tuple(data, key.second);
}

} // namespace nacabe
} // namespace ndn