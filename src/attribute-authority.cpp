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

#include "attribute-authority.hpp"
#include "json-helper.hpp"
#include "ndn-crypto/data-enc-dec.hpp"

#include <ndn-cxx/security/transform/public-key.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>

namespace ndn {
namespace nacabe {

NDN_LOG_INIT(nacabe.attribute-authority);

//public
AttributeAuthority::AttributeAuthority(const security::Certificate& identityCert, Face& face,
                                           security::KeyChain& keyChain, const AbeType &abeType)
  : m_cert(identityCert)
  , m_face(face)
  , m_keyChain(keyChain)
  , m_abeType(abeType)
{
  // ABE setup
  if (m_abeType == ABE_TYPE_CP_ABE) {
    NDN_LOG_INFO("Using CP-ABE. Set up public parameters and master key.");
    algo::ABESupport::getInstance().cpInit(m_pubParams, m_masterKey);
  } else if (m_abeType == ABE_TYPE_KP_ABE) {
    NDN_LOG_INFO("Using KP-ABE. Set up public parameters and master key.");
    algo::ABESupport::getInstance().kpInit(m_pubParams, m_masterKey);
  } else {
    NDN_LOG_ERROR("Unsupported ABE type.");
    NDN_THROW(std::runtime_error("Unsupported ABE type."));
  }

  // prefix registration
  auto prefixId = m_face.registerPrefix(m_cert.getIdentity(),
    [&] (const Name& name) {
      NDN_LOG_TRACE("Prefix " << name << " got registered");

      // public parameter filter
      auto filterId = m_face.setInterestFilter(Name(name).append(PUBLIC_PARAMS),
                                          bind(&CpAttributeAuthority::onPublicParamsRequest, this, _2));
      m_interestFilterIds.push_back(filterId);
      NDN_LOG_TRACE("InterestFilter " << Name(name).append(PUBLIC_PARAMS) << " got set");

      // decryption key filter
      filterId = m_face.setInterestFilter(Name(name).append(DECRYPT_KEY),
                                          bind(&CpAttributeAuthority::onDecryptionKeyRequest, this, _2));
      m_interestFilterIds.push_back(filterId);
      NDN_LOG_TRACE("InterestFilter " << Name(name).append(DECRYPT_KEY) << " got set");
    },
    bind(&CpAttributeAuthority::onRegisterFailed, this, _2));
  m_registeredPrefixIds.push_back(prefixId);
}

AttributeAuthority::~AttributeAuthority()
{
  for (const auto& prefixId : m_interestFilterIds) {
    prefixId.cancel();
  }
  for (auto& prefixId : m_registeredPrefixIds) {
    prefixId.unregister();
  }
}

void
AttributeAuthority::onDecryptionKeyRequest(const Interest& request)
{
  // naming: /AA-prefix/DKEY/<identity name block>/<signature>
  NDN_LOG_INFO("get DKEY request:"<<request.getName());
  Name identityName(request.getName().at(m_cert.getIdentity().size() + 1).blockFromValue());

  // verify request and generate token
  JsonSection root;
  auto optionalCert = m_trustConfig.findCertificate(identityName);
  if (optionalCert) {
    NDN_LOG_INFO("Find consumer(decryptor) certificate.");
    if (!security::verifySignature(request, *optionalCert)) {
      NDN_LOG_INFO("DKEY Request Interest cannot be authenticated: bad signature");
      return;
    }
  }
  else {
    NDN_LOG_INFO("DKEY Request Interest cannot be authenticated: no certificate");
    return;
  }

  auto ABEPrvKey = getPrivateKey(identityName);
  auto prvBuffer = ABEPrvKey.toBuffer();

  // reply interest with encrypted private key
  Data result;
  result.setName(request.getName());
  result.setFreshnessPeriod(5_s);
  result.setContent(encryptDataContentWithCK(prvBuffer.data(), prvBuffer.size(),
                                             optionalCert->getPublicKey().data(),
                                             optionalCert->getPublicKey().size()));
  m_keyChain.sign(result, signingByCertificate(m_cert));
  m_face.put(result);
}

void
AttributeAuthority::onPublicParamsRequest(const Interest& interest)
{
  // naming: /AA-prefix/PUBPARAMS
  NDN_LOG_INFO("on public Params request:"<<interest.getName());
  Data result;
  Name dataName = interest.getName();
  dataName.append(m_abeType);
  dataName.appendTimestamp();
  result.setName(dataName);
  const auto& contentBuf = m_pubParams.toBuffer();
  result.setFreshnessPeriod(5_s);
  result.setContent(makeBinaryBlock(ndn::tlv::Content,
                                    contentBuf.data(), contentBuf.size()));
  NDN_LOG_DEBUG("before sign");
  m_keyChain.sign(result, signingByCertificate(m_cert));

  NDN_LOG_TRACE("Reply public params request.");
  NDN_LOG_TRACE("Pub params size: " << contentBuf.size());

  m_face.put(result);
}

void
AttributeAuthority::onRegisterFailed(const std::string& reason)
{
  NDN_LOG_TRACE("Error: failed to register prefix in local hub's daemon, REASON: " << reason);
}

CpAttributeAuthority::CpAttributeAuthority(const security::Certificate& identityCert, Face& m_face,
                                           security::KeyChain& keyChain)
    : AttributeAuthority(identityCert, m_face, keyChain, ABE_TYPE_CP_ABE){

}

CpAttributeAuthority::~CpAttributeAuthority() {};

void
CpAttributeAuthority::addNewPolicy(const Name& decryptorIdentityName, const std::list<std::string>& attributes)
{
  m_tokens.insert(std::make_pair(decryptorIdentityName, attributes));
}

void
CpAttributeAuthority::addNewPolicy(const security::Certificate& decryptorCert, const std::list<std::string>& attributes)
{
  m_trustConfig.addOrUpdateCertificate(decryptorCert);
  addNewPolicy(decryptorCert.getIdentity(), attributes);
}

algo::PrivateKey CpAttributeAuthority::getPrivateKey(Name identityName) {
  const auto& attributes = m_tokens.at(identityName);
  std::vector<std::string> attrs(attributes.begin(), attributes.end());

  // generate ABE private key and do encryption
  return algo::ABESupport::getInstance().cpPrvKeyGen(m_pubParams, m_masterKey, attrs);
}

KpAttributeAuthority::KpAttributeAuthority(const security::Certificate& identityCert, Face& m_face,
                                           security::KeyChain& keyChain)
    : AttributeAuthority(identityCert, m_face, keyChain, ABE_TYPE_KP_ABE){

}

KpAttributeAuthority::~KpAttributeAuthority() {};

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

algo::PrivateKey KpAttributeAuthority::getPrivateKey(Name identityName) {
  const auto& policy = m_tokens.at(identityName);

  // generate ABE private key and do encryption
  return algo::ABESupport::getInstance().kpPrvKeyGen(m_pubParams, m_masterKey, policy);
}


} // namespace nacabe
} // namespace ndn
