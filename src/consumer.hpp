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

#ifndef NAC_ABE_CONSUMER_HPP
#define NAC_ABE_CONSUMER_HPP

#include "trust-config.hpp"
#include "algo/public-params.hpp"
#include "algo/private-key.hpp"
#include "algo/cipher-text.hpp"
#include "param-fetcher.hpp"

namespace ndn {
namespace nacabe {

class Consumer
{
public:
  using OnDataCallback = std::function<void (const Interest&, const Data&)>;
  using ErrorCallback = std::function<void (const std::string&)>;
  using ConsumptionCallback = std::function<void (const Buffer&)>;

public:
  Consumer(Face& face, KeyChain& keyChain,
           const security::Certificate& identityCert,
           const security::Certificate& attrAuthorityCertificate);

  /**
   * @brief Obtain attributes (DKEY) from the attribute authority.
   *
   * Interest: /<attribute authority prefix>/DKEY/<decryptor name block>, signed
   */
  void
  obtainDecryptionKey();

  /**
   * @brief Consume an encrypted data packet
   *
   * The function will first fetch the encrypted data packet, then fetch the CK data packet.
   * After decrypting CK with cached DKEY, the CK will be used to cpDecrypt the data packet.
   *
   * @param dataName The packet name.
   * @param consumptionCb The success callback.
   * @param errorCallback The failure callback.
   */
  void
  consume(const Name& dataName,
          const ConsumptionCallback& consumptionCb,
          const ErrorCallback& errorCallback);

  /**
   * @brief Consume an encrypted data packet
   *
   * The function will first fetch the encrypted data packet with the given interest, then fetch the CK data packet.
   * After decrypting CK with cached DKEY, the CK will be used to cpDecrypt the data packet.
   *
   * @param dataInterest The packet fetch Interest.
   * @param consumptionCb The success callback.
   * @param errorCallback The failure callback.
   */
  void
  consume(const Interest& dataInterest,
          const ConsumptionCallback& consumptionCb,
          const ErrorCallback& errorCallback);

private:
  void
  decryptContent(const Data& data,
                 const ConsumptionCallback& successCallBack,
                 const ErrorCallback& errorCallback);

  void
  onCkeyData(const Data& data, std::shared_ptr<algo::CipherText> cipherText,
             const ConsumptionCallback& successCallBack,
             const ErrorCallback& errorCallback);

  void
  handleNack(const Interest& interest, const lp::Nack& nack,
             const ErrorCallback& errorCallback, std::string message);

  void
  handleTimeout(const Interest& interest, int nRetrials,
                const DataCallback& dataCallback, const ErrorCallback& errorCallback,
                std::string nackMessage, std::string timeoutMessage);

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  security::Certificate m_cert;
  Face& m_face;
  KeyChain& m_keyChain;
  Name m_attrAuthorityPrefix;

  TrustConfig m_trustConfig;
  algo::PrivateKey m_keyCache;
  ParamFetcher m_paramFetcher;
};

} // namespace nacabe
} // namespace ndn

#endif // NAC_ABE_CONSUMER_HPP
