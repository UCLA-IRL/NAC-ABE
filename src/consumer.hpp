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
  using SuccessCallback = function<void (const Buffer&)>;

public:
  Consumer(const security::v2::Certificate& identityCert,
           Face& face, uint8_t repeatAttempts = 3);

  void
  consume(const Name& dataName,
          const ConsumptionCallback& consumptionCb,
          const ErrorCallback& errorCb);

  void
  loadTrustConfig(const TrustConfig& config);

private:
  void
  sendInterest(const Interest& interest, int nRetrials,
               const OnDataValidated& validationCallback,
               const ErrorCallback& errorCallback);

  void
  decryptContent(const Data& data,
                 const SuccessCallback& SuccessCb,
                 const ErrorCallback& errorCb);

  void
  handleNack(const Interest& interest, const lp::Nack& nack,
             const OnDataValidated& callback, const ErrorCallback& errorCallback);

  void
  handleTimeout(const Interest& interest, int nRetrials,
                const OnDataValidated& callback, const ErrorCallback& errorCallback);

  void
  fetchDecryptionKey(const Name& attrAuthorityPrefix, const ErrorCallback& errorCb);

  void
  onDecryptionKey(const Data& data, const ErrorCallback& errorCb);

  /**
   * interest naming convention:
   *  /tokenIssuerPrefix/TOKEN/[identity-name block]/[sig]
   */
  void
  requestToken(const Name& tokenIssuerPrefix, const ErrorCallback& errorCb);

  void
  fetchAttributePubParams(const Name& attrAuthorityPrefix, const ErrorCallback& errorCb);

  void
  onAttributePubParams(const Data& data,
                       const ErrorCallback& errorCb);

private:
  security::v2::Certificate m_cert;
  unique_ptr<Validator> m_validator;
  Face& m_face;
  uint8_t m_repeatAttempts;

  unique_ptr<algo::PrivateKey> m_privateKey;
  unique_ptr<Data> m_token;
  algo::PublicParams m_pubParamsCache;
  std::list<security::v2::Certificate> m_trustAnchors;
};

} // namespace ndnabac
} // namespace ndn

#endif // NDNABAC_CONSUMER_HPP
