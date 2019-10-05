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

#include <ndn-cxx/security/verification-helpers.hpp>

namespace ndn {
namespace nacabe {

class Producer
{
public:
  class Error : public std::runtime_error
  {
  public:
    using std::runtime_error::runtime_error;
  };

  using ErrorCallback = function<void (const std::string&)>;
  using SuccessCallback = function<void (const Data&, const Data&)>;

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
  std::tuple<std::shared_ptr<Data>, std::shared_ptr<Data>>
  produce(const Name& dataPrefix, const std::string& accessPolicy,
          const uint8_t* content, size_t contentLen);

  std::tuple<std::shared_ptr<Data>, std::shared_ptr<Data>>
  produce(const Name& dataPrefix, const uint8_t* content, size_t contentLen);

private:
  void
  onAttributePubParams(const Data& pubParamData);

  void
  onPolicyInterest(const Interest& interest);

  void
  fetchPublicParams();

public:
  const static Name SET_POLICY;

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  security::v2::Certificate m_cert;
  Face& m_face;
  security::v2::KeyChain& m_keyChain;
  Name m_attrAuthorityPrefix;
  uint8_t m_repeatAttempts;

  std::map<Name/* data prefix */, std::string/* policy */> m_policyCache;
  std::list<InterestFilterHandle> m_interestFilterIds;
  algo::PublicParams m_pubParamsCache;
  TrustConfig m_trustConfig;
};

} // namespace nacabe
} // namespace ndn

#endif // NAC_ABE_PRODUCER_HPP
