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

#ifndef NDNABAC_CONSUMER_HPP
#define NDNABAC_CONSUMER_HPP

#include "ndnabac-common.hpp"
#include "trust-config.hpp"
#include "algo/public-params.hpp"
#include "algo/private-key.hpp"
#include "algo/cipher-text.hpp"

namespace ndn {
namespace ndnabac {

class Consumer
{
public:
  class Error : public std::runtime_error
  {
  public:
    using std::runtime_error::runtime_error;
  };

  using OnDataCallback = function<void (const Interest&, const Data&)>;
  using ErrorCallback = function<void (const std::string&)>;
  using ConsumptionCallback = function<void (const Buffer&)>;

public:
  Consumer(const security::v2::Certificate& identityCert,
           Face& face, security::v2::KeyChain& keyChain,
           const Name& attrAuthorityPrefix,
           const Name& tokenIssuerPrefix,
           uint8_t repeatAttempts);

  void
  consume(const Name& dataName, const Name& tokenIssuerPrefix,
          const ConsumptionCallback& consumptionCb,
          const ErrorCallback& errorCallback);

private:
  void
  decryptContent(const Data& data, const Name& tokenIssuerPrefix,
                 const ConsumptionCallback& successCallBack,
                 const ErrorCallback& errorCallback);

  void
  onAttributePubParams(const Interest& request, const Data& pubParamData);


  void
  onTokenData(const Data& tokenData, const Name& tokenIssuerPrefix, algo::CipherText cipherText,
              const ConsumptionCallback& successCallBack,
              const ErrorCallback& errorCallback);

  void
  onDecryptionKeyData(const Data& keyData, const Data& tokenData,
                      const Name& tokenIssuerPrefix, algo::CipherText cipherText,
                      const ConsumptionCallback& successCallBack,
                      const ErrorCallback& errorCallback);

  void
  handleNack(const Interest& interest, const lp::Nack& nack,
             const ErrorCallback& errorCallback);

  void
  handleTimeout(const Interest& interest, int nRetrials,
                const DataCallback& dataCallback, const ErrorCallback& errorCallback);

  void
  loadTrustConfig(const TrustConfig& config);

private:
  security::v2::Certificate m_cert;
  Face& m_face;
  security::v2::KeyChain& m_keyChain;
  Name m_attrAuthorityPrefix;
  uint8_t m_repeatAttempts;

  algo::PublicParams m_pubParamsCache;
  std::list<security::v2::Certificate> m_trustAnchors;
  std::map<Name/*tokenIssuerPrefix*/, std::tuple<Data/*token*/, algo::PrivateKey>> m_keyCache;
};

} // namespace ndnabac
} // namespace ndn

#endif // NDNABAC_CONSUMER_HPP
