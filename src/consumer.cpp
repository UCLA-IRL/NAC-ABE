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

#include "consumer.hpp"
#include "attribute-authority.hpp"
#include "token-issuer.hpp"
#include "logging.hpp"

namespace ndn {
namespace ndnabac {

_LOG_INIT(ndnabac.consumer);

// public
Consumer::Consumer(const security::v2::Certificate& identityCert,
                   Face& face, uint8_t repeatAttempts)
  : m_cert(identityCert)
    //, m_validator(new Validator())
  , m_face(face)
  , m_repeatAttempts(repeatAttempts)
{
  //m_consumerName = identityCert.getIdentity();
}

void
Consumer::consume(const Name& dataName,
                  const ConsumptionCallback& consumptionCb,
                  const ErrorCallback& errorCb)
{
  // shared_ptr<Interest> interest = make_shared<Interest>(dataName);
  // sendInterest(*Interest);
  shared_ptr<Interest> interest = make_shared<Interest>(dataName);

  // prepare callback functions
  auto validationCallback = [=] (const shared_ptr<const Data>& validData) {
    // decrypt content
    decryptContent(*validData,
                   [=] (const Buffer& decryptContent) { consumptionCb(decryptContent); },
                   errorCb);
  };

  sendInterest(*interest, m_repeatAttempts, validationCallback, errorCb);
}

void
Consumer::sendInterest(const Interest& interest, int nRetrials,
                       const OnDataValidated& validationCallback,
                       const ErrorCallback& errorCallback)
{
  auto dataCallback = [=] (const Interest& contentInterest, const Data& contentData) {
    if (!contentInterest.matchesData(contentData))
      return;

    this->m_validator->validate(contentData, validationCallback,
                                [=] (const shared_ptr<const Data>& d, const std::string& e) {
                                  errorCallback(e);
                                });
  };

  // set link object if it is available

  m_face.expressInterest(interest, dataCallback,
                         std::bind(&Consumer::handleNack, this, _1, _2,
                                   validationCallback, errorCallback),
                         std::bind(&Consumer::handleTimeout, this, _1, nRetrials,
                                   validationCallback, errorCallback));
}

void
Consumer::handleNack(const Interest& interest, const lp::Nack& nack,
                     const OnDataValidated& callback, const ErrorCallback& errorCallback)
{
  // we run out of options, report retrieval failure.
  errorCallback("interest nack");
}

void
Consumer::handleTimeout(const Interest& interest, int nRetrials,
                        const OnDataValidated& callback, const ErrorCallback& errorCallback)
{
  if (nRetrials > 0) {
    sendInterest(interest, nRetrials - 1, callback, errorCallback);
  }
  else
    handleNack(interest, lp::Nack(), callback, errorCallback);
}

void
Consumer::decryptContent(const Data& data,
                         const SuccessCallback& successCallBack,
                         const ErrorCallback& errorCallback)
{
  // get encrypted content
  Block encryptedContent = data.getContent().blockFromValue();
  algo::CipherText cipherText;
  cipherText.wireDecode(encryptedContent);

  // check if key exist
  if (m_privateKey == nullptr) {
    // errorCallback("privateKey doesn't exist");
    // we need to fetch the privateKey here
    return;
  }

  Buffer result = algo::ABESupport::decrypt(m_pubParamsCache, *m_privateKey, cipherText);
  successCallBack(result);
}

void
Consumer::loadTrustConfig(const TrustConfig& config)
{}

void
Consumer::fetchDecryptionKey(const Name& attrAuthorityPrefix,
                             const ErrorCallback& errorCb)
{
  if (m_token == 0) {
    errorCb("token doesn't exist");
    return;
  }

  Name interestName = attrAuthorityPrefix;
  interestName.append(AttributeAuthority::DECRYPT_KEY);

  shared_ptr<Interest> interest = make_shared<Interest>(interestName);

  // prepare callback functions
  auto validationCallback =
    [=] (const shared_ptr<const Data>& validData) {
    // decrypt content
    onDecryptionKey(*validData, errorCb);
  };

  sendInterest(*interest, m_repeatAttempts, validationCallback, errorCb);
}

void
Consumer::onDecryptionKey(const Data& data, const ErrorCallback& errorCb)
{
  //set decryption key
}

void
Consumer::requestToken(const Name& tokenIssuerPrefix,
                       const ErrorCallback& errorCb)
{
  Name requestTokenName = tokenIssuerPrefix;
  requestTokenName.append(TokenIssuer::TOKEN_REQUEST);
  requestTokenName.append(m_cert.getIdentity());
  shared_ptr<Interest> interest = make_shared<Interest>(requestTokenName);

  // prepare callback functions
  auto validationCallback =
    [=] (const shared_ptr<const Data>& validData) {
    if (m_token != 0) {
      m_privateKey.reset();
      m_token.reset();
    }
    m_token = make_unique<Data>(*validData);
  };

  sendInterest(*interest, m_repeatAttempts, validationCallback, errorCb);
}

void
Consumer::fetchAttributePubParams(const Name& attrAuthorityPrefix, const ErrorCallback& errorCb)
{
  Name interestName = attrAuthorityPrefix;
  interestName.append(AttributeAuthority::PUBLIC_PARAMS);

  shared_ptr<Interest> interest = make_shared<Interest>(interestName);

  // prepare callback functions
  auto validationCallback =
    [=] (const shared_ptr<const Data>& validData) {
    // decrypt content
    onAttributePubParams(*validData, errorCb);
  };

  sendInterest(*interest, m_repeatAttempts, validationCallback, errorCb);
}

void
Consumer::onAttributePubParams(const Data& data, const ErrorCallback& errorCb)
{
  //addPubParam

}



} // namespace ndnabac
} // namespace ndn
