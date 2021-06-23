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
#include "ndn-crypto/data-enc-dec.hpp"

#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>
#include <ndn-cxx/security/certificate.hpp>

namespace ndn {
namespace nacabe {

NDN_LOG_INIT(nacabe.consumer);

// public
Consumer::Consumer(Face& face, security::v2::KeyChain& keyChain,
                   const security::v2::Certificate& identityCert,
                   const security::v2::Certificate& attrAuthorityCertificate,
                   uint8_t repeatAttempts)
  : m_cert(identityCert)
  , m_face(face)
  , m_keyChain(keyChain)
  , m_attrAuthorityPrefix(attrAuthorityCertificate.getIdentity())
  , m_repeatAttempts(repeatAttempts)
  , m_paramFetcher(m_face, m_attrAuthorityPrefix, m_trustConfig)
{
  std::cout << "CONSUMER CONSTRUCTOR" << std::endl;
  m_trustConfig.addOrUpdateCertificate(attrAuthorityCertificate);
  m_paramFetcher.fetchPublicParams();
}

void
Consumer::obtainDecryptionKey()
{
  // /<attribute authority prefix>/DKEY/<decryptor name block>
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

  auto encryptedAESKeyTLV = ckContent.get(TLV_EncryptedAesKey);
  cipherText->m_aesKey = Buffer(encryptedAESKeyTLV.value(), encryptedAESKeyTLV.value_size());

  //std::string encryptedSymmetricKey(reinterpret_cast<char*>(cipherText->m_aesKey.data()));


  cipherText->m_plainTextSize = readNonNegativeInteger(ckContent.get(TLV_PlainTextSize));

  NDN_LOG_INFO("content size : " << cipherText->m_content.size());
  NDN_LOG_INFO("plaintext size : " << cipherText->m_plainTextSize);
  NDN_LOG_INFO("encrypted aes key size : " << cipherText->m_aesKey.size());

  Buffer result;
  try{
    if (m_paramFetcher.m_abeType == ABE_TYPE_CP_ABE)
      result = algo::ABESupport::getInstance().cpDecrypt(m_paramFetcher.getPublicParams(), m_keyCache, *cipherText);
    else if (m_paramFetcher.m_abeType == ABE_TYPE_KP_ABE)
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

} // namespace nacabe
} // namespace ndn
