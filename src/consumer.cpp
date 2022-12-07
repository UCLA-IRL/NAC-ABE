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

#include "consumer.hpp"
#include "attribute-authority.hpp"
#include "algo/abe-support.hpp"
#include "ndn-crypto/data-enc-dec.hpp"

#include <ndn-cxx/security/verification-helpers.hpp>

namespace ndn {
namespace nacabe {

NDN_LOG_INIT(nacabe.Consumer);

Consumer::Consumer(Face& face, KeyChain& keyChain,
                   const security::Certificate& identityCert,
                   const security::Certificate& attrAuthorityCertificate,
                   Interest publicParamInterestTemplate)
  : m_cert(identityCert)
  , m_face(face)
  , m_keyChain(keyChain)
  , m_attrAuthorityPrefix(attrAuthorityCertificate.getIdentity())
  , m_paramFetcher(m_face, m_attrAuthorityPrefix, m_trustConfig, publicParamInterestTemplate)
{
  m_trustConfig.addOrUpdateCertificate(attrAuthorityCertificate);
  m_paramFetcher.fetchPublicParams();
}

void
Consumer::obtainDecryptionKey()
{
  auto identity = m_cert.getIdentity();
  NDN_LOG_INFO(identity << " Fetch private key");
  // /<attribute authority prefix>/DKEY/<decryptor name block>
  Name interestName = m_attrAuthorityPrefix;
  interestName.append(DECRYPT_KEY);
  interestName.append(identity.wireEncode().begin(), identity.wireEncode().end());
  Interest interest(interestName);
  interest.setMustBeFresh(true);
  interest.setCanBePrefix(true);

  m_face.expressInterest(interest,
    [this] (auto&&, const Data& keyData) {
      NDN_LOG_INFO(m_cert.getIdentity() << " get decrypt key data");
      auto prvBlock = decryptDataContent(keyData.getContent(), m_keyChain.getTpm(), m_cert.getName());
      algo::PrivateKey prv;
      prv.fromBuffer(Buffer(prvBlock.data(), prvBlock.size()));
      m_keyCache = prv;
    },
    [this] (auto&&, const auto& nack) {
      NDN_LOG_INFO("nack for " << m_cert.getIdentity() << " decrypt key data with reason " << nack.getReason());
    },
    [this] (auto&&) {
      NDN_LOG_INFO("timeout for " << m_cert.getIdentity() << " decrypt key data");
    });
}

bool
Consumer::readyForDecryption()
{
  // check if public params and private key are ready
  if (m_paramFetcher.getPublicParams().m_pub == "") {
    NDN_LOG_INFO("public parameters doesn't exist");
    return false;
  } else if (m_keyCache.m_prv.empty()) {
    NDN_LOG_INFO("Private decryption key doesn't exist");
    return false;
  }
  return true;
}

void
Consumer::consume(const Name& dataName,
                  const ConsumptionCallback& consumptionCb,
                  const ErrorCallback& errorCallback)
{
  Interest interest(dataName);
  interest.setMustBeFresh(true);
  interest.setCanBePrefix(true);
  consume(interest, consumptionCb, errorCallback);
}

void
Consumer::consume(const Interest& dataInterest,
                  const ConsumptionCallback& consumptionCb,
                  const ErrorCallback& errorCallback)
{
  // ready for decryption
  if (!readyForDecryption()) {
    errorCallback("public params or private decryption key doesn't exist");
    return;
  }

  std::string nackMessage = "nack for " + dataInterest.getName().toUri() + " data fetch with reason ";
  std::string timeoutMessage = "timeout for " + dataInterest.getName().toUri() + " data fetch";

  auto dataCallback = [=] (const Interest&, const Data& data) {
    decryptContent(data, consumptionCb, errorCallback);
  };

  NDN_LOG_INFO(m_cert.getIdentity() << " Ask for data " << dataInterest.getName() );
  m_face.expressInterest(dataInterest,
                         dataCallback,
                         std::bind(&Consumer::handleNack, this, _1, _2, errorCallback, nackMessage),
                         std::bind(&Consumer::handleTimeout, this, _1, 3,
                                   dataCallback, errorCallback, nackMessage, timeoutMessage));
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
  cipherText->m_plainTextSize = readNonNegativeInteger(encryptedContent.get(TLV_PlainTextSize));

  Name ckName(encryptedContent.get(tlv::Name));
  NDN_LOG_INFO("CK Name is " << ckName);
  Interest ckInterest(ckName);
  ckInterest.setMustBeFresh(true);
  ckInterest.setCanBePrefix(true);

  std::string nackMessage = "nack for " + ckName.toUri() + " content key fetch with reason ";

  std::string timeoutMessage = "timeout for " + ckName.toUri() + " content key fetch";

  auto dataCallback = [=] (const Interest&, const Data& data) {
    onCkeyData(data, cipherText, successCallBack, errorCallback);
  };

  NDN_LOG_INFO(m_cert.getIdentity() << " Ask for data " << ckInterest.getName() );
  m_face.expressInterest(ckInterest,
                         dataCallback,
                         std::bind(&Consumer::handleNack, this, _1, _2, errorCallback, nackMessage),
                         std::bind(&Consumer::handleTimeout, this, _1, 3,
                                   dataCallback, errorCallback, nackMessage, timeoutMessage));
}

void
Consumer::onCkeyData(const Data& data, std::shared_ptr<algo::CipherText> cipherText,
                         const ConsumptionCallback& successCallBack,
                         const ErrorCallback& errorCallback)
{
  NDN_LOG_INFO(m_cert.getIdentity() << " Get CKEY data " << data.getName());
  Block ckContent = data.getContent();
  ckContent.parse();

  auto encryptedAESKeyTLV = ckContent.get(TLV_EncryptedAesKey);
  cipherText->m_contentKey = std::make_shared<algo::ContentKey>();
  cipherText->m_contentKey->m_encAesKey = Buffer(encryptedAESKeyTLV.value(), encryptedAESKeyTLV.value_size());

  //std::string encryptedSymmetricKey(reinterpret_cast<char*>(cipherText->m_aesKey.data()));

  NDN_LOG_INFO("content size : " << cipherText->m_content.size());
  NDN_LOG_INFO("plaintext size : " << cipherText->m_plainTextSize);
  NDN_LOG_INFO("encrypted aes key size : " << cipherText->m_contentKey->m_encAesKey.size());

  Buffer result;
  try {
    if (m_paramFetcher.getAbeType() == ABE_TYPE_CP_ABE)
      result = algo::ABESupport::getInstance().cpDecrypt(m_paramFetcher.getPublicParams(), m_keyCache, *cipherText);
    else if (m_paramFetcher.getAbeType() == ABE_TYPE_KP_ABE)
      result = algo::ABESupport::getInstance().kpDecrypt(m_paramFetcher.getPublicParams(), m_keyCache, *cipherText);
    else
      errorCallback("Unsupported ABE type");
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
                     const ErrorCallback& errorCallback, std::string message)
{
  std::stringstream nackMessage;
  nackMessage << message << nack.getReason();
  errorCallback(nackMessage.str());
}

void
Consumer::handleTimeout(const Interest& interest, int nRetrials,
                        const DataCallback& dataCallback, const ErrorCallback& errorCallback,
                        std::string nackMessage, std::string timeoutMessage)
{
  if (nRetrials > 0) {
    NDN_LOG_INFO("timeout for: " << interest << ", retrying");
    m_face.expressInterest(interest, dataCallback,
                           std::bind(&Consumer::handleNack, this, _1, _2, errorCallback, nackMessage),
                           std::bind(&Consumer::handleTimeout, this, _1, nRetrials - 1,
                                     dataCallback, errorCallback, nackMessage, timeoutMessage));
  }
  else {
    errorCallback(timeoutMessage);
  }
}

} // namespace nacabe
} // namespace ndn
