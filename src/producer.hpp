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

#ifndef NAC_ABE_PRODUCER_HPP
#define NAC_ABE_PRODUCER_HPP

#include "trust-config.hpp"
#include "algo/public-params.hpp"
#include "param-fetcher.hpp"

#include <ndn-cxx/security/verification-helpers.hpp>

namespace ndn {
namespace nacabe {

class Producer
{
public:
  using ErrorCallback = function<void (const std::string&)>;
  using SuccessCallback = function<void (const Data&, const Data&)>;
  using PolicyTuple = std::tuple<Name, std::string>;

public:
  Producer(Face& face,
           security::v2::KeyChain& keyChain,
           const security::v2::Certificate& identityCert,
           const security::v2::Certificate& attrAuthorityCertificate,
           const security::v2::Certificate& dataOwnerCertificate,
           uint8_t repeatAttempts = 3);

  Producer(Face& face,
           security::v2::KeyChain& keyChain,
           const security::v2::Certificate& identityCert,
           const security::v2::Certificate& attrAuthorityCertificate,
           uint8_t repeatAttempts = 3);

  ~Producer();

  /**
   * @brief Produce encrypted Data and corresponding encrypted CK Data
   *
   * Used when data owner is not used.
   *
   * @param dataName The name of data, not including producer's prefix
   * @param dataSuffix The suffix of data.
   * @param accessPolicy The encryption policy, e.g., (ucla or mit) and professor
   * @param content The payload
   * @param contentLen The payload length
   * @return The encrypted data and the encrypted CK data
   */
  std::tuple<std::shared_ptr<Data>, std::shared_ptr<Data>>
  produce(const Name& dataName, const std::string& accessPolicy,
          const uint8_t* content, size_t contentLen);

  /**
   * @brief Produce encrypted Data and corresponding encrypted CK Data
   *
   * Used when the data owner is used and data owner has command the policy for the @p dataPrefix
   *
   * @param dataName The name of data, not including producer's prefix
   * @param content The payload
   * @param contentLen The payload length
   * @return The encrypted data and the encrypted CK data
   */
  std::tuple<std::shared_ptr<Data>, std::shared_ptr<Data>>
  produce(const Name& dataName, const uint8_t* content, size_t contentLen);

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  void
  onPolicyInterest(const Interest& interest);

  void
  addNewPolicy(const Name& dataPrefix, const std::string& policy);

  std::string
  findMatchedPolicy(const Name& dataName);

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  security::v2::Certificate m_cert;
  Face& m_face;
  security::v2::KeyChain& m_keyChain;
  Name m_attrAuthorityPrefix;
  Name m_dataOwnerPrefix;
  uint8_t m_repeatAttempts;

  std::vector<PolicyTuple> m_policies;
  RegisteredPrefixHandle m_registeredPrefixHandle;
  TrustConfig m_trustConfig;
  ParamFetcher m_paramFetcher;
};

} // namespace nacabe
} // namespace ndn

#endif // NAC_ABE_PRODUCER_HPP
