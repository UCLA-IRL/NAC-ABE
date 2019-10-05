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

#include "consumer.hpp"
#include "attribute-authority.hpp"
#include "token-issuer.hpp"
#include "ndn-crypto/data-enc-dec.hpp"

#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>
#include <ndn-cxx/security/v2/certificate.hpp>

namespace ndn {
namespace nacabe {

NDN_LOG_INIT(nacabe.consumer);

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
Consumer::obtainAttributes(const Name& tokenIssuerPrefix)
{
    NDN_LOG_INFO(m_cert.getIdentity() << "Fetch token and private key");

    Name requestTokenName = tokenIssuerPrefix;
    requestTokenName.append(TokenIssuer::TOKEN_REQUEST);
    requestTokenName.append(m_cert.getIdentity().wireEncode());
    Interest interest(requestTokenName);
    m_keyChain.sign(interest, signingByCertificate(m_cert));
    interest.setMustBeFresh(true);
    interest.setCanBePrefix(true);

    NDN_LOG_INFO(m_cert.getIdentity() << " Request token: " << interest.getName());
    m_face.expressInterest(interest,
                           [&](const Interest&, const Data& tokenData) {
                             onTokenData(tokenData);
                           }, nullptr, nullptr);
}

void
Consumer::onTokenData(const Data& tokenData)
{
  NDN_LOG_INFO(m_cert.getIdentity() << " get token data");
  Name interestName = m_attrAuthorityPrefix;
  interestName.append("DKEY-TOKEN");
  interestName.append(tokenData.wireEncode());
  Interest interest(interestName);
  interest.setMustBeFresh(true);
  interest.setCanBePrefix(true);

  m_face.expressInterest(interest,
                         [&](const Interest&, const Data& keyData) {
                           NDN_LOG_INFO(m_cert.getIdentity() << " get decrypt key data");
                           const auto& tpm = m_keyChain.getTpm();
                            const auto& block = keyData.getContent();
                            auto prvBlock = decryptDataContent(block, tpm, m_cert.getName());
                            algo::PrivateKey prv;
                            prv.fromBuffer(Buffer(prvBlock.data(), prvBlock.size()));
                            m_keyCache = prv;
                         }, nullptr, nullptr);
}

void
Consumer::obtainAttributes()
{
  NDN_LOG_INFO(m_cert.getIdentity() << "Fetch private key");
  Name interestName = m_attrAuthorityPrefix;
  interestName.append("DKEY");
  interestName.append(m_cert.getIdentity().wireEncode());
  Interest interest(interestName);
  interest.setMustBeFresh(true);
  interest.setCanBePrefix(true);
  m_keyChain.sign(interest, signingByCertificate(m_cert));

  m_face.expressInterest(interest,
                         [&](const Interest&, const Data& keyData) {
                           NDN_LOG_INFO(m_cert.getIdentity() << " get decrypt key data");
                           const auto& tpm = m_keyChain.getTpm();
                            const auto& block = keyData.getContent();
                            auto prvBlock = decryptDataContent(block, tpm, m_cert.getName());
                            algo::PrivateKey prv;
                            prv.fromBuffer(Buffer(prvBlock.data(), prvBlock.size()));
                            m_keyCache = prv;
                         }, nullptr, nullptr);
}

void
Consumer::consume(const Name& dataName,
                  const ConsumptionCallback& consumptionCb,
                  const ErrorCallback& errorCallback)
{
  Interest interest(dataName);
  interest.setMustBeFresh(true);
  interest.setCanBePrefix(true);

  NDN_LOG_INFO(m_cert.getIdentity() << " Ask for data " << interest.getName() );
  m_face.expressInterest(interest,
                         [&] (const Interest&, const Data& data) {
                           decryptContent(data, consumptionCb, errorCallback);
                         }, nullptr, nullptr);
}

void
Consumer::decryptContent(const Data& data,
                         const ConsumptionCallback& successCallBack,
                         const ErrorCallback& errorCallback)
{
  // get encrypted content
  NDN_LOG_INFO(m_cert.getIdentity() << " Get content data " << data.getName());
  Block encryptedContent = data.getContent();
  encryptedContent.parse();
  auto encryptedContentTLV = encryptedContent.get(TLV_EncryptedContent);
  NDN_LOG_INFO("encrypted Content size is " << encryptedContentTLV.value_size());
  auto cipherText = std::make_shared<algo::CipherText>();
  cipherText->m_content = Buffer(encryptedContentTLV.value(), encryptedContentTLV.value_size());
  Name ckName(encryptedContent.get(tlv::Name));
  NDN_LOG_INFO("CK Name is " << ckName);

  Interest ckInterest(ckName);
  ckInterest.setMustBeFresh(true);
  ckInterest.setCanBePrefix(true);
  m_face.expressInterest(ckInterest,
                         [=] (const Interest&, const Data& data) {
                           onCkeyData(data, cipherText, successCallBack, errorCallback);
                         }, nullptr, nullptr);
}

void
Consumer::onCkeyData(const Data& data, std::shared_ptr<algo::CipherText> cipherText,
                         const ConsumptionCallback& successCallBack,
                         const ErrorCallback& errorCallback)
{
  NDN_LOG_INFO(m_cert.getIdentity() << " Get CKEY data " << data.getName());
  Block ckContent = data.getContent();
  ckContent.parse();
  auto encAesKey = ckContent.get(TLV_EncryptedAesKey);

  cipherText->m_cph = g_byte_array_new();
  g_byte_array_append(cipherText->m_cph, encAesKey.value(), static_cast<guint>(encAesKey.value_size()));
  cipherText->m_plainTextSize = readNonNegativeInteger(ckContent.get(TLV_PlainTextSize));

  NDN_LOG_INFO("content size : " << cipherText->m_content.size());
  NDN_LOG_INFO("plaintext size : " << cipherText->m_plainTextSize);
  NDN_LOG_INFO("encrypted aes key size : " << cipherText->m_cph->len);

  Buffer result;
  try{
    result = algo::ABESupport::decrypt(m_pubParamsCache, m_keyCache, *cipherText);
  }
  catch (const std::exception& e) {
    errorCallback(e.what());
    return;
  }
  NDN_LOG_INFO("result length : " << result.size());
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
Consumer::fetchPublicParams()
{
  // fetch pub parameters
  Name interestName = m_attrAuthorityPrefix;
  interestName.append(PUBLIC_PARAMS);
  Interest interest(interestName);
  interest.setMustBeFresh(true);
  interest.setCanBePrefix(true);

  NDN_LOG_INFO(m_cert.getIdentity()<< " Request public parameters:"<<interest.getName());
  m_face.expressInterest(interest, std::bind(&Consumer::onAttributePubParams, this, _1, _2),
                         nullptr, nullptr);
}

} // namespace nacabe
} // namespace ndn
