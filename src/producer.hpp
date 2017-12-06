/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017, Regents of the University of California.
 *
 * This file is part of ndnabac, a certificate management system based on NDN.
 *
 * ndnabac is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation, either
 * version 3 of the License, or (at your option) any later version.
 *
 * ndnabac is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received copies of the GNU General Public License along with
 * ndnabac, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of ndnabac authors and contributors.
 */

#ifndef NDNABAC_PRODUCER_HPP
#define NDNABAC_PRODUCER_HPP

#include "ndnabac-common.hpp"
#include "trust-config.hpp"
#include "algo/public-params.hpp"

#include <ndn-cxx/security/verification-helpers.hpp>

namespace ndn {
namespace ndnabac {

class Producer
{
public:
  class Error : public std::runtime_error
  {
  public:
    using std::runtime_error::runtime_error;
  };

  using ErrorCallback = function<void (const std::string&)>;
  using SuccessCallback = function<void (const Data&)>;

public:
  /**
   * @brief Constructor
   *
   * @param identityCert the certificate for data signing
   * @param face the face for publishing data and sending interests
   * @param repeatAttempts the max retry times when timeout or nack
   */
  Producer(const security::v2::Certificate& identityCert, Face& face,
           security::v2::KeyChain& keyChain, const Name& attrAuthorityPrefix,
           uint8_t repeatAttempts = 3);

  ~Producer();

  /**
   * @brief Producing data packet
   *
   * @param accessPolicy
   * @param content
   * @param contentLen
   * @param errorCallBack
   */
  void
  produce(const Name& dataName, const std::string& accessPolicy,
          const uint8_t* content, size_t contentLen,
          const SuccessCallback& onDataProduceCb, const ErrorCallback& errorCallback);

  void
  produce(const Name& dataPrefix, const uint8_t* content, size_t contentLen,
          const SuccessCallback& onDataProduceCb, const ErrorCallback& errorCallback);

private:
  void
  onAttributePubParams(const Interest& request, const Data& pubParamData);

  void
  onPolicyInterest(const Interest& interest);

  void
  fetchPublicParams();

  void
  onRegisterFailed(const std::string& reason);

public:
  const static Name SET_POLICY;

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  security::v2::Certificate m_cert;
  Face& m_face;
  security::v2::KeyChain& m_keyChain;
  Name m_attrAuthorityPrefix;
  uint8_t m_repeatAttempts;

  std::map<Name/* data prefix */, std::string/* policy */> m_policyCache;
  std::list<const RegisteredPrefixId*> m_registeredPrefixIds;
  std::list<const InterestFilterId*> m_interestFilterIds;
  algo::PublicParams m_pubParamsCache;
  TrustConfig m_trustConfig;
};

} // namespace ndnabac
} // namespace ndn

#endif // NDNABAC_PRODUCER_HPP
