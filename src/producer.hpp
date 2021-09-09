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
#include "algo/abe-support.hpp"

namespace ndn {
namespace nacabe {

class Producer
{
public:
  using ErrorCallback = function<void (const std::string&)>;
  using SuccessCallback = function<void (const Data&, const Data&)>;
  using PolicyTuple = std::pair<Name, std::string>;
  using AttributeTuple = std::pair<Name, std::vector<std::string>>;

public:
  /**
   * Initialize a producer. Use when no data owner defined.
   * @param face
   * @param keyChain
   * @param identityCert
   * @param attrAuthorityCertificate
   * @param repeatAttempts
   */
  Producer(Face& face,
           security::KeyChain& keyChain,
           const security::Certificate& identityCert,
           const security::Certificate& attrAuthorityCertificate);

  /**
   * Initialize a producer. Use when a data owner defined.
   * @param face
   * @param keyChain
   * @param identityCert
   * @param attrAuthorityCertificate
   */
  Producer(Face& face,
           security::KeyChain& keyChain,
           const security::Certificate& identityCert,
           const security::Certificate& attrAuthorityCertificate,
           const security::Certificate& dataOwnerCertificate);

  virtual ~Producer();

  virtual /**
   * @brief Produce CP-encrypted Data and corresponding encrypted CK Data
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
  produce(const Name& dataName, const Policy& accessPolicy,
          const uint8_t* content, size_t contentLen);

  /**
   * @brief Produce CP-encrypted CK Data
   *
   * Used when data owner is not used.
   *
   * @param dataName The name of data, not including producer's prefix
   * @param dataSuffix The suffix of data.
   * @param accessPolicy The encryption policy, e.g., (ucla or mit) and professor
   * @param content The payload
   * @param contentLen The payload length
   * @return The content key and the encrypted CK data
   */
  std::pair<std::shared_ptr<algo::ContentKey>, std::shared_ptr<Data>>
  ckDataGen(const Policy& accessPolicy);

  virtual /**
   * @brief Produce KP-encrypted Data and corresponding encrypted CK Data
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
  produce(const Name& dataName, const std::vector<std::string>& attributes,
          const uint8_t* content, size_t contentLen);

  /**
   * @brief Produce KP-encrypted CK Data
   *
   * Used when data owner is not used.
   *
   * @param dataName The name of data, not including producer's prefix
   * @param dataSuffix The suffix of data.
   * @param accessPolicy The encryption policy, e.g., (ucla or mit) and professor
   * @param content The payload
   * @param contentLen The payload length
   * @return The content key and the encrypted CK data
   */
  std::pair<std::shared_ptr<algo::ContentKey>, std::shared_ptr<Data>>
  ckDataGen(const std::vector<std::string>& attributes);

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

  /**
   * @brief Produce encrypted Data and from CK Data
   *
   * Used when the CK is known
   *
   * @param dataName The name of data, not including producer's prefix
   * @param content The payload
   * @param contentLen The payload length
   * @return The encrypted data and the encrypted CK data
   */
  std::shared_ptr<Data>
  produce(std::shared_ptr<algo::ContentKey> key, const Name& keyName,
          const Name& dataName, const uint8_t* content, size_t contentLen);

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  void
  onPolicyInterest(const Interest& interest);

  void
  addNewPolicy(const Name& dataPrefix, const Policy& policy);

  void
  addNewAttributes(const Name& dataPrefix, const std::vector<std::string>& attributes);

  std::string
  findMatchedPolicy(const Name& dataName);

  std::vector<std::string>
  findMatchedAttributes(const Name& dataName);

  shared_ptr <Data> getCkEncryptedData(const Name &dataName, const algo::CipherText &cipherText, const Name &ckName);

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  security::Certificate m_cert;
  Face& m_face;
  security::KeyChain& m_keyChain;
  Name m_attrAuthorityPrefix;
  Name m_dataOwnerPrefix;

  std::vector<PolicyTuple> m_policies; //for CP-ABE
  std::vector<AttributeTuple> m_attributes; //for KP-ABE
  RegisteredPrefixHandle m_registeredPrefixHandle;
  TrustConfig m_trustConfig;
  ParamFetcher m_paramFetcher;
};

} // namespace nacabe
} // namespace ndn

#endif // NAC_ABE_PRODUCER_HPP
