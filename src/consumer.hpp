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

#ifndef NAC_ABE_CONSUMER_HPP
#define NAC_ABE_CONSUMER_HPP

#include "trust-config.hpp"
#include "algo/public-params.hpp"
#include "algo/private-key.hpp"
#include "algo/cipher-text.hpp"

namespace ndn {
namespace nacabe {

class Consumer
{
public:
  using OnDataCallback = function<void (const Interest&, const Data&)>;
  using ErrorCallback = function<void (const std::string&)>;
  using ConsumptionCallback = function<void (const Buffer&)>;

public:
  Consumer(Face& face,
           security::v2::KeyChain& keyChain,
           const security::v2::Certificate& identityCert,
           const security::v2::Certificate& attrAuthorityCertificate,
           uint8_t repeatAttempts = 3);

  void
  obtainAttributes();

  void
  consume(const Name& dataName,
          const ConsumptionCallback& consumptionCb,
          const ErrorCallback& errorCallback);

private:
  void
  decryptContent(const Data& data,
                 const ConsumptionCallback& successCallBack,
                 const ErrorCallback& errorCallback);

  void
  onAttributePubParams(const Interest& request, const Data& pubParamData);

  void
  onCkeyData(const Data& data, std::shared_ptr<algo::CipherText> cipherText,
                         const ConsumptionCallback& successCallBack,
                         const ErrorCallback& errorCallback);

  void
  handleNack(const Interest& interest, const lp::Nack& nack,
             const ErrorCallback& errorCallback);

  void
  handleTimeout(const Interest& interest, int nRetrials,
                const DataCallback& dataCallback, const ErrorCallback& errorCallback);

  void
  fetchPublicParams();

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  security::v2::Certificate m_cert;
  Face& m_face;
  security::v2::KeyChain& m_keyChain;
  Name m_attrAuthorityPrefix;
  uint8_t m_repeatAttempts;

  algo::PublicParams m_pubParamsCache;
  TrustConfig m_trustConfig;
  algo::PrivateKey m_keyCache;
};

} // namespace nacabe
} // namespace ndn

#endif // NAC_ABE_CONSUMER_HPP
