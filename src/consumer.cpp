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

#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>
#include <ndn-cxx/security/v2/certificate.hpp>

namespace ndn {
namespace ndnabac {

NDN_LOG_INIT(ndnabac.consumer);

// public
Consumer::Consumer(const security::v2::Certificate& identityCert,
                   Face& face, security::v2::KeyChain& keyChain,
                   const Name& attrAuthorityPrefix,
                   uint8_t repeatAttempts)
  : m_cert(identityCert)
  , m_face(face)
  , m_keyChain(keyChain)
  , m_attrAuthorityPrefix(attrAuthorityPrefix)
  , m_repeatAttempts(repeatAttempts)
{
  fetchPublicParams();
}

void
Consumer::consume(const Name& dataName, const Name& tokenIssuerPrefix,
                  const ConsumptionCallback& consumptionCb,
                  const ErrorCallback& errorCallback)
{
  Interest interest(dataName);
  interest.setMustBeFresh(true);

  DataCallback dataCb = std::bind(&Consumer::decryptContent, this, _2, tokenIssuerPrefix,
                                  consumptionCb, errorCallback);

  NDN_LOG_INFO(m_cert.getIdentity()<<" asking for data"<<interest.getName() );
  m_face.expressInterest(interest, dataCb,
                         std::bind(&Consumer::handleNack, this, _1, _2, errorCallback),
                         std::bind(&Consumer::handleTimeout, this, _1, m_repeatAttempts, dataCb, errorCallback));
}

void
Consumer::decryptContent(const Data& data, const Name& tokenIssuerPrefix,
                         const ConsumptionCallback& successCallBack,
                         const ErrorCallback& errorCallback)
{
  // get encrypted content

  NDN_LOG_INFO(m_cert.getIdentity()<<" get data "<<data.getName()<<" from producer" );
  Block encryptedContent = data.getContent();
  algo::CipherText cipherText;
  cipherText.wireDecode(encryptedContent);

  auto it = m_keyCache.find(tokenIssuerPrefix);
  if (it == m_keyCache.end()) {
    NDN_LOG_INFO(m_cert.getIdentity()<<" Private key is not there: we need to fetch token and private key");

    Name requestTokenName = tokenIssuerPrefix;
    requestTokenName.append(TokenIssuer::TOKEN_REQUEST);
    requestTokenName.append(m_cert.getIdentity().wireEncode());
    Interest interest(requestTokenName);
    m_keyChain.sign(interest, signingByCertificate(m_cert));
    interest.setMustBeFresh(true);

    DataCallback dataCb = std::bind(&Consumer::onTokenData, this, _2, tokenIssuerPrefix, cipherText,
                                    successCallBack, errorCallback);

    NDN_LOG_INFO(m_cert.getIdentity()<<"Request token:"<<interest.getName());
    m_face.expressInterest(interest, dataCb,
                           std::bind(&Consumer::handleNack, this, _1, _2, errorCallback),
                           std::bind(&Consumer::handleTimeout, this, _1, m_repeatAttempts, dataCb, errorCallback));
  }
  else {
    algo::PrivateKey prvKey;
    std::tie(std::ignore, prvKey) = it->second;

    Buffer result = algo::ABESupport::decrypt(m_pubParamsCache, prvKey, cipherText);
    successCallBack(result);
  }
}

void
Consumer::onAttributePubParams(const Interest& request, const Data& pubParamData)
{
  NDN_LOG_INFO(m_cert.getIdentity()<<" Get public parameters");
  Name attrAuthorityKey = pubParamData.getSignature().getKeyLocator().getName();
  for (auto anchor : m_trustConfig.m_trustAnchors) {
    if (anchor.getKeyName() == attrAuthorityKey) {
      BOOST_ASSERT(security::verifySignature(pubParamData, anchor));
      break;
    }
  }

  auto block = pubParamData.getContent();
  m_pubParamsCache.fromBuffer(Buffer(block.value(), block.value_size()));
}

void
Consumer::onTokenData(const Data& tokenData, const Name& tokenIssuerPrefix, algo::CipherText cipherText,
                      const ConsumptionCallback& successCallBack,
                      const ErrorCallback& errorCallback)
{
  NDN_LOG_INFO(m_cert.getIdentity()<<" get token data");
  Name interestName = m_attrAuthorityPrefix;
  interestName.append(AttributeAuthority::DECRYPT_KEY);
  interestName.append(tokenData.wireEncode());
  Interest interest(interestName);
  interest.setMustBeFresh(true);

  DataCallback dataCb = std::bind(&Consumer::onDecryptionKeyData, this, _2, tokenData,
                                  tokenIssuerPrefix, cipherText, successCallBack, errorCallback);
  m_face.expressInterest(interest, dataCb,
                         std::bind(&Consumer::handleNack, this, _1, _2, errorCallback),
                         std::bind(&Consumer::handleTimeout, this, _1, m_repeatAttempts, dataCb, errorCallback));
}

void
Consumer::onDecryptionKeyData(const Data& keyData, const Data& tokenData,
                              const Name& tokenIssuerPrefix, algo::CipherText cipherText,
                              const ConsumptionCallback& successCallBack,
                              const ErrorCallback& errorCallback)
{
  NDN_LOG_INFO(m_cert.getIdentity()<< " get decrypt key data");

  auto& tpm = m_keyChain.getTpm();

  const auto& block = keyData.getContent();
  auto prvBlock = tpm.decrypt(block.value(), block.value_size(),
                              security::v2::extractKeyNameFromCertName(m_cert.getName()));

  algo::PrivateKey prv;
  prv.fromBuffer(Buffer(prvBlock->data(), prvBlock->size()));

  m_keyCache[tokenIssuerPrefix] = make_tuple(keyData, prv);

  Buffer result = algo::ABESupport::decrypt(m_pubParamsCache, prv, cipherText);
  successCallBack(result);
}

void
Consumer::handleNack(const Interest& interest, const lp::Nack& nack,
                     const ErrorCallback& errorCallback)
{
  errorCallback("Got Nack");
}

void
Consumer::handleTimeout(const Interest& interest, int nRetrials,
                        const DataCallback& dataCallback, const ErrorCallback& errorCallback)
{
  if (nRetrials > 0) {
    m_face.expressInterest(interest, dataCallback,
                           std::bind(&Consumer::handleNack, this, _1, _2, errorCallback),
                           std::bind(&Consumer::handleTimeout, this, _1, nRetrials - 1,
                                     dataCallback, errorCallback));
  }
  else {
    errorCallback("Run out retries: still timeout");
  }
}

void
Consumer::fetchPublicParams()
{
  // fetch pub parameters
  Name interestName = m_attrAuthorityPrefix;
  interestName.append(AttributeAuthority::PUBLIC_PARAMS);
  Interest interest(interestName);
  interest.setMustBeFresh(true);

  NDN_LOG_INFO(m_cert.getIdentity()<< " Requeset public parameters:"<<interest.getName());
  m_face.expressInterest(interest, std::bind(&Consumer::onAttributePubParams, this, _1, _2),
                         nullptr, nullptr);
}

} // namespace ndnabac
} // namespace ndn
