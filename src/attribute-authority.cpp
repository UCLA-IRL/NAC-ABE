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
  , m_paraProducer(face, identityCert.getIdentity())
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
      m_latestParaTimestamp = systemClock->getNow();
      return m_latestParaTimestamp;
    }, [this, block=Block()](time::system_clock::time_point ts) mutable {
      Data result;
      Name dataName = m_cert.getIdentity();
      dataName.append(PUBLIC_PARAMS);
      dataName.append(m_abeType);
      dataName.appendTimestamp(ts);
      result.setName(dataName);
      result.setFreshnessPeriod(5_s);
      const auto& contentBuf = m_pubParams.toBuffer();
      result.setContent(contentBuf);
      m_keyChain.sign(result, signingByCertificate(m_cert));
      Block resultBlock = result.wireEncode();
      return span<const uint8_t>(resultBlock.wire(), resultBlock.size());
    }, [this](auto& data){
      // sign metadata
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

void AttributeAuthority::insertPolicy(const security::Certificate& identityCert) {
  Name decrypterIdentity = identityCert.getIdentity();
  if (m_trustConfig.findCertificate(decrypterIdentity) == nullopt) {
    m_trustConfig.addOrUpdateCertificate(identityCert);

    if (m_removedDecKeyProducer.count(decrypterIdentity)) {
      auto it = m_removedDecKeyProducer.find(decrypterIdentity);
      m_decKeyProducer.emplace(it->first, std::move(it->second.first));
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
    if (it->second.first.checkCancel()) {
      m_removedDecKeyProducer.erase(it2);
    }
  }
}

void
AttributeAuthority::removePolicy(const Name& decrypterIdentityName)
{
  removePolicyState(decrypterIdentityName);
  if (m_decKeyProducer.count(decrypterIdentityName)) {
    auto it = m_decKeyProducer.find(decrypterIdentityName);
    m_removedDecKeyProducer.emplace(it->first, std::make_pair(std::move(it->second), time::system_clock::now()));
    m_decKeyProducer.erase(it);
  } else if (m_UnregisteredDecKeyProducer.count(decrypterIdentityName)) {
    auto it = m_UnregisteredDecKeyProducer.find(decrypterIdentityName);
    m_removedDecKeyProducer.emplace(it->first, std::make_pair(std::move(it->second), time::system_clock::now()));
    m_UnregisteredDecKeyProducer.erase(it);
  }

  for (auto it = m_removedDecKeyProducer.begin(); it != m_removedDecKeyProducer.end();) {
    auto it2 = it;
    it++;
    if (it->second.first.checkCancel()) {
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
      if (m_removedDecKeyProducer.count(decrypterIdentityName)) return m_removedDecKeyProducer.at(decrypterIdentityName).second;
      return getLastPrivateKeyTimestamp(decrypterIdentityName);
    }, [this, decrypterIdentityName, block=Block()](time::system_clock::time_point ts) mutable {
      auto optionalCert = m_trustConfig.findCertificate(decrypterIdentityName);
      auto ABEPrvKey = getPrivateKey(decrypterIdentityName);
      auto prvBuffer = ABEPrvKey.toBuffer();
      block = encryptDataContentWithCK(prvBuffer, optionalCert->getPublicKey());
      block.encode();
      return span<const uint8_t>(block.wire(), block.size());
    }, [this](auto& data){
      //TODO add metadata: public key version
      m_keyChain.sign(data, signingByCertificate(m_cert));
    });
  }
}

void
AttributeAuthority::onPublicParamsRequest(const Interest& interest)
{
  // naming: /AA-prefix/PUBPARAMS
  // NDN_LOG_INFO("on public params request: " << interest.getName());
  // Data result;
  // Name dataName = interest.getName();
  // dataName.append(m_abeType);
  // dataName.appendTimestamp();
  // result.setName(dataName);
  // result.setFreshnessPeriod(5_s);
  // const auto& contentBuf = m_pubParams.toBuffer();
  // result.setContent(contentBuf);
  // NDN_LOG_DEBUG("before sign");
  // m_keyChain.sign(result, signingByCertificate(m_cert));

  // NDN_LOG_TRACE("Reply public params request.");
  // NDN_LOG_TRACE("Pub params size: " << contentBuf.size());

  // m_face.put(result);


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
  auto time = time::system_clock::now();
  if (m_tokens.count(decryptorIdentityName) > 0 && time - m_tokens.at(decryptorIdentityName).second < time::milliseconds(1)) {
    time = m_tokens.at(decryptorIdentityName).second + time::milliseconds(1);
  }
  m_tokens.emplace(decryptorIdentityName, std::make_pair(attributes, time));
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
  const auto& pair = m_tokens.at(identityName);
  std::vector<std::string> attrs(pair.first.begin(), pair.first.end());

  // generate ABE private key and do encryption
  return algo::ABESupport::getInstance().cpPrvKeyGen(m_pubParams, m_masterKey, attrs);
}

time::system_clock::time_point
CpAttributeAuthority::getLastPrivateKeyTimestamp(const Name& identityName)
{
  const auto& pair = m_tokens.at(identityName);
  return pair.second;
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
  auto time = time::system_clock::now();
  if (m_tokens.count(decryptorIdentityName) > 0 && time - m_tokens.at(decryptorIdentityName).second < time::milliseconds(1)) {
    time = m_tokens.at(decryptorIdentityName).second + time::milliseconds(1);
  }
  m_tokens.emplace(decryptorIdentityName, std::make_pair(policy, time));
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

  // generate ABE private key and do encryption
  return algo::ABESupport::getInstance().kpPrvKeyGen(m_pubParams, m_masterKey, pair.first);
}

time::system_clock::time_point
KpAttributeAuthority::getLastPrivateKeyTimestamp(const Name& identityName)
{
  const auto& pair = m_tokens.at(identityName);
  return pair.second;
}

} // namespace nacabe
} // namespace ndn
