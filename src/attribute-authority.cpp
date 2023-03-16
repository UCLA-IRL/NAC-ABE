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
  , prefixRegistered(false)
  , m_paraProducer(face, identityCert.getIdentity().append(PUBLIC_PARAMS))
  , m_latestParaTimestamp(time::system_clock::now())
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
      m_paraProducer.setInterestFilter([this](){
      return m_latestParaTimestamp;
    }, [this](time::system_clock::time_point ts) {
      return m_pubParams.toBuffer();
    }, [this](auto& data){
      // sign metadata
      MetaInfo info = data.getMetaInfo();
      info.addAppMetaInfo(makeStringBlock(TLV_AbeType, m_abeType));
      data.setMetaInfo(info);
      m_keyChain.sign(data, signingByCertificate(m_cert));
    });

      prefixRegistered = true;
      for (auto it = m_UnregisteredDecKeyProducer.begin(); it != m_UnregisteredDecKeyProducer.end();) {
        auto it2 = it;
        it++;
        auto decrypter = it2->first;
        setDecrypterInterestFilter(decrypter);
      }
    },
    [] (const Name&, const auto& reason) {
      NDN_LOG_ERROR("Failed to register prefix: " << reason);
    });
}

AttributeAuthority::~AttributeAuthority() = default;

void AttributeAuthority::updatePublicParam() {
  if (m_abeType == ABE_TYPE_CP_ABE) {
    NDN_LOG_INFO("Refresh CP-ABE key");
    algo::ABESupport::getInstance().cpInit(m_pubParams, m_masterKey);
  } else if (m_abeType == ABE_TYPE_KP_ABE) {
    NDN_LOG_INFO("Refresh KP-ABE key");
    algo::ABESupport::getInstance().kpInit(m_pubParams, m_masterKey);
  } else {
    NDN_LOG_ERROR("Unsupported ABE type: " << m_abeType);
    NDN_THROW(std::runtime_error("Unsupported ABE type: " + m_abeType));
  }

  m_latestParaTimestamp = std::max(time::system_clock::now(), m_latestParaTimestamp + time::milliseconds(1));
  for (auto& i: m_decKeyLastTimestamp) {
    i.second = std::max(time::system_clock::now(), i.second + time::milliseconds(1));
  }
}

void AttributeAuthority::insertPolicy(const security::Certificate& identityCert) {
  Name decrypterIdentity = identityCert.getIdentity();
  if (m_trustConfig.findCertificate(decrypterIdentity) == nullopt) {
    m_trustConfig.addOrUpdateCertificate(identityCert);

    if (m_removedDecKeyProducer.count(decrypterIdentity)) {
      auto it = m_removedDecKeyProducer.find(decrypterIdentity);
      m_decKeyProducer.emplace(it->first, std::move(it->second));
      m_removedDecKeyProducer.erase(it);
    } else {
      Name decObjectName = m_cert.getIdentity();
      decObjectName.append(DECRYPT_KEY).append(decrypterIdentity.wireEncode().begin(),
                                               decrypterIdentity.wireEncode().end());
      RdrProducer rdrProducer(m_face, decObjectName);
      m_UnregisteredDecKeyProducer.emplace(identityCert.getIdentity(), std::move(rdrProducer));
      if (prefixRegistered) {
        setDecrypterInterestFilter(decrypterIdentity);
      }
    }
  } else if (m_trustConfig.findCertificate(decrypterIdentity) != identityCert) {
    m_trustConfig.addOrUpdateCertificate(identityCert);
  }

  for (auto it = m_removedDecKeyProducer.begin(); it != m_removedDecKeyProducer.end();) {
    auto it2 = it;
    it++;
    if (it2->second.checkCancel()) {
      m_decKeyLastTimestamp.erase(it2->first);
      m_removedDecKeyProducer.erase(it2);
    }
  }
}

void AttributeAuthority::updatePolicyLastTimestamp(const Name& identityName)
{
  auto time = time::system_clock::now();
  if (m_decKeyLastTimestamp.count(identityName) > 0 && time - m_decKeyLastTimestamp.at(identityName) < time::milliseconds(1)) {
    time = m_decKeyLastTimestamp.at(identityName) + time::milliseconds(1);
  }
  m_decKeyLastTimestamp[identityName] = time;
}

void
AttributeAuthority::removePolicy(const Name& decrypterIdentityName)
{
  removePolicyState(decrypterIdentityName);
  if (m_decKeyProducer.count(decrypterIdentityName)) {
    auto it = m_decKeyProducer.find(decrypterIdentityName);
    m_removedDecKeyProducer.emplace(it->first, std::move(it->second));
    m_decKeyProducer.erase(it);
    updatePolicyLastTimestamp(decrypterIdentityName);
  } else if (m_UnregisteredDecKeyProducer.count(decrypterIdentityName)) {
    auto it = m_UnregisteredDecKeyProducer.find(decrypterIdentityName);
    m_removedDecKeyProducer.emplace(it->first, std::move(it->second));
    m_UnregisteredDecKeyProducer.erase(it);
    updatePolicyLastTimestamp(decrypterIdentityName);
  }

  for (auto it = m_removedDecKeyProducer.begin(); it != m_removedDecKeyProducer.end();) {
    auto it2 = it;
    it++;
    if (it2->second.checkCancel()) {
      m_decKeyLastTimestamp.erase(it2->first);
      m_removedDecKeyProducer.erase(it2);
    }
  }
}

void
AttributeAuthority::setDecrypterInterestFilter(const Name& decrypterIdentityName)
{
  auto it = m_UnregisteredDecKeyProducer.find(decrypterIdentityName);
  if (it != m_UnregisteredDecKeyProducer.end()) {
    if (m_decKeyProducer.count(decrypterIdentityName)) {
      NDN_THROW("multiple instance of decrypter producer exists: " + decrypterIdentityName.toUri());
    }
    m_decKeyProducer.emplace(decrypterIdentityName, std::move(it->second));
    m_UnregisteredDecKeyProducer.erase(it);

    auto& p = m_decKeyProducer.at(decrypterIdentityName);
    p.setInterestFilter([this, decrypterIdentityName](){
      NDN_LOG_INFO("Got DKEY request on: " << decrypterIdentityName);
      return m_decKeyLastTimestamp.at(decrypterIdentityName);
    }, [this, decrypterIdentityName](time::system_clock::time_point ts) {
      auto optionalCert = m_trustConfig.findCertificate(decrypterIdentityName);
      NDN_LOG_INFO("Produced DKEY for " << decrypterIdentityName);
      auto ABEPrvKey = getPrivateKey(decrypterIdentityName);
      auto prvBuffer = ABEPrvKey.toBuffer();
      auto block = encryptDataContentWithCK(prvBuffer, optionalCert->getPublicKey());
      block.encode();
      NDN_LOG_INFO("Produced DKEY size is " << block.size());
      return *block.getBuffer();
    }, [this](auto& data){
      MetaInfo info = data.getMetaInfo();
      info.addAppMetaInfo(makeNestedBlock(TLV_ParamVersion, Name().appendTimestamp(m_latestParaTimestamp).get(0)));
      data.setMetaInfo(info);
      m_keyChain.sign(data, signingByCertificate(m_cert));
    });
  }
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
  if (!m_trustConfig.findCertificate(decryptorIdentityName)) {
    NDN_THROW("Cannot find certificate for adding policy: " + decryptorIdentityName.toUri());
  }
  updatePolicyLastTimestamp(decryptorIdentityName);
  m_tokens[decryptorIdentityName] = attributes;
}

void
CpAttributeAuthority::addNewPolicy(const security::Certificate& decryptorCert,
                                   const std::list<std::string>& attributes)
{
  insertPolicy(decryptorCert);
  addNewPolicy(decryptorCert.getIdentity(), attributes);
}

void
CpAttributeAuthority::removePolicyState(const Name& decryptorIdentityName) {
  m_tokens.erase(decryptorIdentityName);
}

algo::PrivateKey
CpAttributeAuthority::getPrivateKey(const Name& identityName)
{
  if (!m_tokens.count(identityName)) {
    algo::PrivateKey k;
    k.fromBuffer(Buffer());
    return k;
  }
  const auto& att = m_tokens.at(identityName);
  std::vector<std::string> attrs(att.begin(), att.end());

  // generate ABE private key and do encryption
  return algo::ABESupport::getInstance().cpPrvKeyGen(m_pubParams, m_masterKey, attrs);
}

KpAttributeAuthority::KpAttributeAuthority(const security::Certificate& identityCert,
                                           Face& face, KeyChain& keyChain)
  : AttributeAuthority(identityCert, face, keyChain, ABE_TYPE_KP_ABE)
{
}

void
KpAttributeAuthority::addNewPolicy(const Name& decryptorIdentityName, const Policy& policy)
{
  if (!m_trustConfig.findCertificate(decryptorIdentityName)) {
    NDN_THROW("Cannot find certificate for adding policy: " + decryptorIdentityName.toUri());
  }
  updatePolicyLastTimestamp(decryptorIdentityName);
  m_tokens[decryptorIdentityName] = policy;
}

void
KpAttributeAuthority::addNewPolicy(const security::Certificate& decryptorCert, const Policy& policy)
{
  insertPolicy(decryptorCert);
  addNewPolicy(decryptorCert.getIdentity(), policy);
}

void
KpAttributeAuthority::removePolicyState(const Name& decryptorIdentityName) {
  m_tokens.erase(decryptorIdentityName);
}

algo::PrivateKey
KpAttributeAuthority::getPrivateKey(const Name& identityName)
{
  if (!m_tokens.count(identityName)) {
    algo::PrivateKey k;
    k.fromBuffer(Buffer());
    return k;
  }
  const auto& pair = m_tokens.at(identityName);

  NDN_LOG_INFO("Produced DKEY of policy " << pair);
  // generate ABE private key and do encryption
  return algo::ABESupport::getInstance().kpPrvKeyGen(m_pubParams, m_masterKey, pair);
}

} // namespace nacabe
} // namespace ndn
