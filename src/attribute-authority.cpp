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

#include "attribute-authority.hpp"
#include "json-helper.hpp"
#include "algo/abe-support.hpp"
#include "ndn-crypto/data-enc-dec.hpp"

#include <ndn-cxx/security/verification-helpers.hpp>

namespace ndn {
namespace nacabe {

NDN_LOG_INIT(nacabe.AttributeAuthority);

AttributeAuthority::AttributeAuthority(const security::Certificate& identityCert, Face& face,
                                       security::Validator& validator, KeyChain& keyChain,
                                       const AbeType& abeType, size_t maxSegmentSize)
  : m_cert(identityCert)
  , m_face(face)
  , m_validator(validator)
  , m_keyChain(keyChain)
  , m_abeType(abeType)
  , m_maxSegmentSize(maxSegmentSize)
{
  // ABE setup
  if (m_abeType == ABE_TYPE_CP_ABE) {
    NDN_LOG_INFO("Using CP-ABE");
    algo::ABESupport::getInstance().cpInit(m_pubParams, m_masterKey);
  } else if (m_abeType == ABE_TYPE_KP_ABE) {
    NDN_LOG_INFO("Using KP-ABE");
    algo::ABESupport::getInstance().kpInit(m_pubParams, m_masterKey);
  } else {
    NDN_LOG_ERROR("Unsupported ABE type: " << m_abeType);
    NDN_THROW(std::runtime_error("Unsupported ABE type: " + m_abeType));
  }

  // prefix registration
  m_registeredPrefix = m_face.registerPrefix(m_cert.getIdentity(),
    [this] (const Name& name) {
      NDN_LOG_TRACE("Prefix " << name << " registered successfully");

      // public parameters filter
      auto hdl1 = m_face.setInterestFilter(Name(name).append(PUBLIC_PARAMS),
                                           std::bind(&AttributeAuthority::onPublicParamsRequest, this, _2));
      m_interestFilters.emplace_back(hdl1);
      NDN_LOG_TRACE("InterestFilter " << Name(name).append(PUBLIC_PARAMS) << " set");

      // decryption key filter
      // this filter registration has been moved to the children constructors.
    },
    [] (const Name&, const auto& reason) {
      NDN_LOG_ERROR("Failed to register prefix: " << reason);
    });
}

AttributeAuthority::~AttributeAuthority() = default;

void
AttributeAuthority::onDecryptionKeyRequest(const Interest& request)
{
  // naming1: /AA-prefix/DKEY/<key name block>
  // naming2: /AA-prefix/DKEY/<key name block>/<version>/<segment>
  Name requestName = request.getName();
  Name supposedKeyName(request.getName().at(m_cert.getIdentity().size() + 1).blockFromValue());
  if (requestName.at(-1).isSegment() && requestName.at(-2).isVersion()) {
    NDN_LOG_DEBUG("For DKEY segment --------> " << requestName);
    auto mapIterator = m_segmentMap.find(requestName.getPrefix(-1));
    if (mapIterator != m_segmentMap.end()) {
      for (auto data : mapIterator->second) {
        if (requestName == data->getName()) {
          m_face.put(*data); 
        }
      }
    }
  }
  else if (security::isValidKeyName(supposedKeyName)) {
    NDN_LOG_DEBUG("KeyName --------> " << supposedKeyName);
    Name identityName = security::extractIdentityFromKeyName(supposedKeyName);
    // fetch corresponding certificate
    auto optionalCert = m_trustConfig.findCertificateFromLocal(supposedKeyName);
    if (optionalCert) {
      NDN_LOG_INFO("Found local certificate for " << supposedKeyName << ", bypass certificate fetching...");
      auto dkSegments = generateDecryptionKeySegments(Name(request.getName()).appendVersion(), *optionalCert);
      if (dkSegments.size() > 0) {
        m_face.put(*dkSegments.at(0));
      }
    }
    else {
      m_trustConfig.findCertificateFromNetwork(m_face, m_validator, supposedKeyName,
        [&] (const security::Certificate& cert) {
          NDN_LOG_INFO("Validated consumer(decryptor) certificate: " << cert.getName());
          auto dkSegments = generateDecryptionKeySegments(Name(request.getName()).appendVersion(), cert);
          if (dkSegments.size() > 0) {
            m_face.put(*dkSegments.at(0));
          }
        },
        [supposedKeyName] (const std::string& errorInfo) {
          NDN_LOG_INFO("Cannot encrypt DKEY: no verified certificate for " << supposedKeyName << ", errorInfo:" << errorInfo);
        }
      );
    };
  }
  else {
    // ignore
  }
}

SPtrVector<Data>
AttributeAuthority::generateDecryptionKeySegments(const Name& objName, const security::Certificate& cert)
{
  // prepare segments
  auto ABEPrvKey = getPrivateKey(cert.getIdentity());
  auto prvBuffer = ABEPrvKey.toBuffer();
  Block dkBlock = encryptDataContentWithCK(prvBuffer, cert.getPublicKey());
  span<const uint8_t> dkSpan = make_span(dkBlock.data(), dkBlock.size());
  // the freshness period should be configurable, but this value shouldn't affect much
  auto dkSegments = m_segmenter.segment(dkSpan, objName, m_maxSegmentSize, 4_s);

  m_segmentMap.emplace(objName, dkSegments);
  return dkSegments;
}

void
AttributeAuthority::onPublicParamsRequest(const Interest& interest)
{
  // naming: /AA-prefix/PUBPARAMS
  NDN_LOG_INFO("on public params request: " << interest.getName());
  Data result;
  Name dataName = interest.getName();
  dataName.append(m_abeType);
  dataName.appendVersion();
  result.setName(dataName);
  result.setFreshnessPeriod(5_s);
  const auto& contentBuf = m_pubParams.toBuffer();
  result.setContent(contentBuf);
  m_keyChain.sign(result, signingByCertificate(m_cert));

  NDN_LOG_TRACE("Reply public params request.");
  NDN_LOG_TRACE("Pub params size: " << contentBuf.size());

  m_face.put(result);
}

CpAttributeAuthority::CpAttributeAuthority(const security::Certificate& identityCert, Face& face,
                                           security::Validator& validator, KeyChain& keyChain)
  : AttributeAuthority(identityCert, face, validator, keyChain, ABE_TYPE_CP_ABE)
{
  // decryption key filter
  m_face.setInterestFilter(Name(m_cert.getIdentity()).append(DECRYPT_KEY),
                           std::bind(&CpAttributeAuthority::onDecryptionKeyRequest, this, _2));
}

void
CpAttributeAuthority::addNewPolicy(const Name& decryptorIdentityName,
                                   const std::list<std::string>& attributes)
{
  m_tokens.insert(std::make_pair(decryptorIdentityName, attributes));
}

void
CpAttributeAuthority::addNewPolicy(const security::Certificate& decryptorCert,
                                   const std::list<std::string>& attributes)
{
  m_trustConfig.addOrUpdateCertificate(decryptorCert);
  addNewPolicy(decryptorCert.getIdentity(), attributes);
}

algo::PrivateKey
CpAttributeAuthority::getPrivateKey(Name identityName)
{
  const auto& attributes = m_tokens.at(identityName);
  std::vector<std::string> attrs(attributes.begin(), attributes.end());

  // generate ABE private key and do encryption
  return algo::ABESupport::getInstance().cpPrvKeyGen(m_pubParams, m_masterKey, attrs);
}

void
CpAttributeAuthority::onDecryptionKeyRequest(const Interest& request)
{
  Name requestName = request.getName();
  NDN_LOG_INFO("CpAA Got DKEY request: " << requestName);

  Name supposedKeyName(request.getName().at(m_cert.getIdentity().size() + 1).blockFromValue());
  Name identityName = security::extractIdentityFromKeyName(supposedKeyName);
  if (m_tokens.find(identityName) != m_tokens.end()) {
    AttributeAuthority::onDecryptionKeyRequest(request);
  }
}

KpAttributeAuthority::KpAttributeAuthority(const security::Certificate& identityCert, Face& face,
                                           security::Validator& validator, KeyChain& keyChain,
                                           size_t maxSegmentSize)
  : AttributeAuthority(identityCert, face, validator, keyChain, ABE_TYPE_KP_ABE, maxSegmentSize)
{
  // decryption key filter
  m_face.setInterestFilter(Name(m_cert.getIdentity()).append(DECRYPT_KEY),
                           std::bind(&KpAttributeAuthority::onDecryptionKeyRequest, this, _2));
}

void
KpAttributeAuthority::addNewPolicy(const Name& decryptorIdentityName, const Policy& policy)
{
  m_tokens.insert(std::make_pair(decryptorIdentityName, policy));
}

void
KpAttributeAuthority::addNewPolicy(const security::Certificate& decryptorCert, const Policy& policy)
{
  m_trustConfig.addOrUpdateCertificate(decryptorCert);
  addNewPolicy(decryptorCert.getIdentity(), policy);
}

algo::PrivateKey
KpAttributeAuthority::getPrivateKey(Name identityName)
{
  const auto& policy = m_tokens.at(identityName);

  // generate ABE private key and do encryption
  return algo::ABESupport::getInstance().kpPrvKeyGen(m_pubParams, m_masterKey, policy);
}

void
KpAttributeAuthority::onDecryptionKeyRequest(const Interest& request)
{
  Name requestName = request.getName();
  NDN_LOG_INFO("KpAA Got DKEY request: " << requestName);

  Name supposedKeyName(request.getName().at(m_cert.getIdentity().size() + 1).blockFromValue());
  Name identityName = security::extractIdentityFromKeyName(supposedKeyName);
  if (m_tokens.find(identityName) != m_tokens.end()) {
    AttributeAuthority::onDecryptionKeyRequest(request);
  }
}

} // namespace nacabe
} // namespace ndn
