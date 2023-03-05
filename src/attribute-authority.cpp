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

#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>

namespace ndn {
namespace nacabe {

NDN_LOG_INIT(nacabe.AttributeAuthority);

AttributeAuthority::AttributeAuthority(const security::Certificate& identityCert, Face& face,
                                       KeyChain& keyChain, const AbeType& abeType)
  : m_cert(identityCert)
  , m_face(face)
  , m_keyChain(keyChain)
  , m_abeType(abeType)
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
      auto hdl2 = m_face.setInterestFilter(Name(name).append(DECRYPT_KEY),
                                           std::bind(&AttributeAuthority::onDecryptionKeyRequest, this, _2));
      m_interestFilters.emplace_back(hdl2);
      NDN_LOG_TRACE("InterestFilter " << Name(name).append(DECRYPT_KEY) << " set");
    },
    [] (const Name&, const auto& reason) {
      NDN_LOG_ERROR("Failed to register prefix: " << reason);
    });
}

AttributeAuthority::~AttributeAuthority() = default;

void
AttributeAuthority::onDecryptionKeyRequest(const Interest& request)
{
  // naming: /AA-prefix/DKEY/<identity name block>
  NDN_LOG_INFO("Got DKEY request: " << request.getName());
  Name identityName(request.getName().at(m_cert.getIdentity().size() + 1).blockFromValue());

  // verify request and generate token
  auto optionalCert = m_trustConfig.findCertificate(identityName);
  if (!optionalCert) {
    NDN_LOG_INFO("DKEY Request Interest cannot be authenticated: no certificate for " << identityName);
    return;
  }
  NDN_LOG_INFO("Find consumer(decryptor) certificate: " << optionalCert->getName());

  auto ABEPrvKey = getPrivateKey(identityName);
  auto prvBuffer = ABEPrvKey.first.toBuffer();

  // reply interest with encrypted private key
  Data result;
  result.setName(request.getName());
  result.setFreshnessPeriod(5_s);
  result.setContent(encryptDataContentWithCK(prvBuffer, optionalCert->getPublicKey()));
  m_keyChain.sign(result, signingByCertificate(m_cert));
  m_face.put(result);
}

void
AttributeAuthority::onPublicParamsRequest(const Interest& interest)
{
  // naming: /AA-prefix/PUBPARAMS
  NDN_LOG_INFO("on public params request: " << interest.getName());
  Data result;
  Name dataName = interest.getName();
  dataName.append(m_abeType);
  dataName.appendTimestamp();
  result.setName(dataName);
  result.setFreshnessPeriod(5_s);
  const auto& contentBuf = m_pubParams.toBuffer();
  result.setContent(contentBuf);
  NDN_LOG_DEBUG("before sign");
  m_keyChain.sign(result, signingByCertificate(m_cert));

  NDN_LOG_TRACE("Reply public params request.");
  NDN_LOG_TRACE("Pub params size: " << contentBuf.size());

  m_face.put(result);
}

CpAttributeAuthority::CpAttributeAuthority(const security::Certificate& identityCert,
                                           Face& face, KeyChain& keyChain)
  : AttributeAuthority(identityCert, face, keyChain, ABE_TYPE_CP_ABE)
{
}

void
CpAttributeAuthority::addNewPolicy(const Name& decryptorIdentityName,
                                   const std::list<std::string>& attributes)
{
  m_tokens.emplace(decryptorIdentityName, std::make_pair(attributes, time::system_clock::now()));
}

void
CpAttributeAuthority::addNewPolicy(const security::Certificate& decryptorCert,
                                   const std::list<std::string>& attributes)
{
  m_trustConfig.addOrUpdateCertificate(decryptorCert);
  addNewPolicy(decryptorCert.getIdentity(), attributes);
}

std::pair<algo::PrivateKey, time::system_clock::time_point>
CpAttributeAuthority::getPrivateKey(const Name& identityName)
{
  const auto& pair = m_tokens.at(identityName);
  std::vector<std::string> attrs(pair.first.begin(), pair.first.end());

  // generate ABE private key and do encryption
  return std::make_pair(algo::ABESupport::getInstance().cpPrvKeyGen(m_pubParams, m_masterKey, attrs), pair.second);
}

KpAttributeAuthority::KpAttributeAuthority(const security::Certificate& identityCert,
                                           Face& face, KeyChain& keyChain)
  : AttributeAuthority(identityCert, face, keyChain, ABE_TYPE_KP_ABE)
{
}

void
KpAttributeAuthority::addNewPolicy(const Name& decryptorIdentityName, const Policy& policy)
{
  m_tokens.emplace(decryptorIdentityName, std::make_pair(policy, time::system_clock::now()));
}

void
KpAttributeAuthority::addNewPolicy(const security::Certificate& decryptorCert, const Policy& policy)
{
  m_trustConfig.addOrUpdateCertificate(decryptorCert);
  addNewPolicy(decryptorCert.getIdentity(), policy);
}

std::pair<algo::PrivateKey, time::system_clock::time_point>
KpAttributeAuthority::getPrivateKey(const Name& identityName)
{
  const auto& pair = m_tokens.at(identityName);

  // generate ABE private key and do encryption
  return std::make_pair(algo::ABESupport::getInstance().kpPrvKeyGen(m_pubParams, m_masterKey, pair.first), pair.second);
}

} // namespace nacabe
} // namespace ndn
