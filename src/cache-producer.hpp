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

#ifndef NAC_ABE_CACHE_PRODUCER_HPP
#define NAC_ABE_CACHE_PRODUCER_HPP

#include "producer.hpp"

#include <map>

namespace ndn {
namespace nacabe {

/**
 * @brief A producer that automatically reuses the same key for the same attributes.
 */
class CacheProducer : public Producer
{
public:
  using Producer::Producer;

  void
  clearCache();

  /**
   * @brief Produce CP-encrypted Data and corresponding encrypted CK Data
   *
   * Used when data owner is not used.
   *
   * @param dataName The name of data, not including producer's prefix
   * @param dataSuffix The suffix of data.
   * @param accessPolicy The encryption policy, e.g., (ucla or mit) and professor
   * @param content The payload
   * @return The encrypted data and the encrypted CK data
   */
  std::tuple<std::shared_ptr<Data>, std::shared_ptr<Data>>
  produce(const Name& dataName, const Policy& accessPolicy, span<const uint8_t> content,
          std::shared_ptr<Data> ckTemplate = getDefaultCkTemplate(), shared_ptr<Data> dataTemplate = getDefaultEncryptedDataTemplate()) override;

  /**
   * @brief Produce KP-encrypted Data and corresponding encrypted CK Data
   *
   * Used when data owner is not used.
   *
   * @param dataName The name of data, not including producer's prefix
   * @param dataSuffix The suffix of data.
   * @param accessPolicy The encryption policy, e.g., (ucla or mit) and professor
   * @param content The payload
   * @return The encrypted data and the encrypted CK data
   */
  std::tuple<std::shared_ptr<Data>, std::shared_ptr<Data>>
  produce(const Name& dataName, const std::vector<std::string>& attributes,
          span<const uint8_t> content, std::shared_ptr<Data> ckTemplate = getDefaultCkTemplate(),
          shared_ptr<Data> dataTemplate = getDefaultEncryptedDataTemplate()) override;

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  std::map<std::string, std::pair<std::shared_ptr<algo::ContentKey>, std::shared_ptr<Data>>> m_cpKeyCache;
  std::map<std::string, std::pair<std::shared_ptr<algo::ContentKey>, std::shared_ptr<Data>>> m_kpKeyCache;
};

} // namespace nacabe
} // namespace ndn

#endif // NAC_ABE_CACHE_PRODUCER_HPP
