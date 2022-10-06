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

#ifndef NAC_ABE_PRODUCER_HPP
#define NAC_ABE_PRODUCER_HPP

#include <utility>

#include "algo/cipher-text.hpp"
#include "algo/content-key.hpp"
#include "param-fetcher.hpp"
#include "trust-config.hpp"

namespace ndn {
namespace nacabe {

class Producer : noncopyable
{
public:
  using ErrorCallback = std::function<void (const std::string&)>;
  using SuccessCallback = std::function<void (const Data&, const Data&)>;
  using PolicyTuple = std::pair<Name, std::string>;
  using AttributeTuple = std::pair<Name, std::vector<std::string>>;

public:
  /**
   * @brief Initialize a producer. Use when no data owner defined.
   */
  Producer(Face& face, KeyChain& keyChain,
           const security::Certificate& identityCert,
           const security::Certificate& attrAuthorityCertificate,
           Interest publicParamInterestTemplate = ParamFetcher::getDefaultInterestTemplate());

  /**
   * @brief Initialize a producer. Use when a data owner is defined.
   */
  Producer(Face& face, KeyChain& keyChain,
           const security::Certificate& identityCert,
           const security::Certificate& attrAuthorityCertificate,
           const security::Certificate& dataOwnerCertificate,
           Interest publicParamInterestTemplate = ParamFetcher::getDefaultInterestTemplate());

  virtual
  ~Producer();

  /**
   * @brief Produce CP-encrypted Data and corresponding encrypted CK Data
   *
   * Used when data owner is not used.
   *
   * @param dataNameSuffix The name of data, not including producer's prefix
   * @param dataSuffix The suffix of data.
   * @param accessPolicy The encryption policy, e.g., (ucla or mit) and professor
   * @param content The payload
   * @return The encrypted data and the encrypted CK data
   */
  virtual std::tuple<std::shared_ptr<Data>, std::shared_ptr<Data>>
  produce(const Name& dataNameSuffix, const Policy& accessPolicy, span<const uint8_t> content,
          std::shared_ptr<Data> ckTemplate = getDefaultCkTemplate(), shared_ptr<Data> dataTemplate = getDefaultEncryptedDataTemplate());

  /**
   * @brief Produce CP-encrypted CK Data
   *
   * Used when data owner is not used.
   *
   * @param accessPolicy The encryption policy, e.g., (ucla or mit) and professor
   * @return The content key and the encrypted CK data
   */
  std::pair<std::shared_ptr<algo::ContentKey>, std::shared_ptr<Data>>
  ckDataGen(const Policy& accessPolicy, std::shared_ptr<Data> dataTemplate = getDefaultCkTemplate());

  /**
   * @brief Produce KP-encrypted Data and corresponding encrypted CK Data
   *
   * Used when data owner is not used.
   *
   * @param dataNameSuffix The name of data, not including producer's prefix
   * @param dataSuffix The suffix of data.
   * @param attributes The encryption policy, e.g., (ucla or mit) and professor
   * @param content The payload
   * @return The encrypted data and the encrypted CK data
   */
  virtual std::tuple<std::shared_ptr<Data>, std::shared_ptr<Data>>
  produce(const Name& dataNameSuffix, const std::vector<std::string>& attributes,
          span<const uint8_t> content, std::shared_ptr<Data> ckTemplate = getDefaultCkTemplate(),
          shared_ptr<Data> dataTemplate = getDefaultEncryptedDataTemplate());

  /**
   * @brief Produce KP-encrypted CK Data
   *
   * Used when data owner is not used.
   *
   * @param attributes The encryption policy, e.g., (ucla or mit) and professor
   * @return The content key and the encrypted CK data
   */
  std::pair<std::shared_ptr<algo::ContentKey>, std::shared_ptr<Data>>
  ckDataGen(const std::vector<std::string>& attributes, std::shared_ptr<Data> dataTemplate = getDefaultCkTemplate());

  /**
   * @brief Produce encrypted Data and corresponding encrypted CK Data
   *
   * Used when the data owner is used and data owner has command the policy for the @p dataPrefix
   *
   * @param dataNameSuffix The name of data, not including producer's prefix
   * @param content The payload
   * @return The encrypted data and the encrypted CK data
   */
  std::tuple<std::shared_ptr<Data>, std::shared_ptr<Data>>
  produce(const Name& dataNameSuffix, span<const uint8_t> content,
          std::shared_ptr<Data> ckTemplate = getDefaultCkTemplate(), shared_ptr<Data> dataTemplate = getDefaultEncryptedDataTemplate());

  /**
   * @brief Produce encrypted Data and from CK Data
   *
   * Used when the CK is known
   *
   * @param dataNameSuffix The name of data, not including producer's prefix
   * @param content The payload
   * @return The encrypted data and the encrypted CK data
   */
  std::shared_ptr<Data>
  produce(std::shared_ptr<algo::ContentKey> key, const Name& keyName,
          const Name& dataNameSuffix, span<const uint8_t> content, shared_ptr<Data> dataTemplate = getDefaultEncryptedDataTemplate());

private:
  void
  onPolicyInterest(const Interest& interest);

  void
  addNewPolicy(const Name& dataPrefix, const Policy& policy);

  void
  addNewAttributes(const Name& dataPrefix, const std::vector<std::string>& attributes);

  shared_ptr<Data>
  getCkEncryptedData(const Name& dataNameSuffix, const algo::CipherText& cipherText, const Name& ckName, shared_ptr<Data> dataTemplate = getDefaultEncryptedDataTemplate());

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  std::string
  findMatchedPolicy(const Name& dataNameSuffix);

  std::vector<std::string>
  findMatchedAttributes(const Name& dataNameSuffix);

  inline void setPolicyReplyTemplate(Data d) {
    replyTemplate = std::move(d);
  }

protected:
  static std::shared_ptr<Data> getDefaultCkTemplate();
  static std::shared_ptr<Data> getDefaultEncryptedDataTemplate();

private:
  security::Certificate m_cert;
  Face& m_face;
  KeyChain& m_keyChain;
  Name m_attrAuthorityPrefix;
  Name m_dataOwnerPrefix;
  TrustConfig m_trustConfig;
  ScopedRegisteredPrefixHandle m_registeredPrefix;

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  std::vector<PolicyTuple> m_policies; // for CP-ABE
  std::vector<AttributeTuple> m_attributes; // for KP-ABE
  ParamFetcher m_paramFetcher;

  Data replyTemplate;
};

} // namespace nacabe
} // namespace ndn

#endif // NAC_ABE_PRODUCER_HPP
