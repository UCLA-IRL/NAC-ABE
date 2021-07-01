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

#include "producer.hpp"
#include "attribute-authority.hpp"
#include <ndn-cxx/util/random.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/encoding/block-helpers.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>

namespace ndn {
namespace nacabe {

NDN_LOG_INIT(nacabe.producer);

Producer::Producer(Face& face,
                   security::KeyChain& keyChain,
                   const security::Certificate& identityCert,
                   const security::Certificate& attrAuthorityCertificate)
  : m_cert(identityCert)
    , m_face(face)
    , m_keyChain(keyChain)
    , m_attrAuthorityPrefix(attrAuthorityCertificate.getIdentity())
    , m_paramFetcher(m_face, m_attrAuthorityPrefix, m_trustConfig)
{
  m_trustConfig.addOrUpdateCertificate(attrAuthorityCertificate);
  m_paramFetcher.fetchPublicParams();
}

//public
Producer::Producer(Face& face,
                   security::KeyChain& keyChain,
                   const security::Certificate& identityCert,
                   const security::Certificate& attrAuthorityCertificate,
                   const security::Certificate& dataOwnerCertificate)
    : Producer(face, keyChain, identityCert, attrAuthorityCertificate)
{
  m_dataOwnerPrefix = dataOwnerCertificate.getIdentity();
  m_trustConfig.addOrUpdateCertificate(dataOwnerCertificate);

  // prefix registration
  m_registeredPrefixHandle = m_face.setInterestFilter(Name(m_cert.getIdentity()).append(SET_POLICY),
                                                      [this](auto &&, auto && PH2) { onPolicyInterest(std::forward<decltype(PH2)>(PH2)); },
                                                      [](const Name&, const std::string&) {
                                                        NDN_THROW(std::runtime_error("Cannot register the prefix to the local NFD"));
                                                      });
  NDN_LOG_DEBUG("set prefix:" << m_cert.getIdentity());
}

Producer::~Producer()
{
  m_registeredPrefixHandle.unregister();
}

std::tuple<std::shared_ptr<Data>, std::shared_ptr<Data>>
Producer::produce(const Name& dataName, const std::string& accessPolicy,
                  const uint8_t* content, size_t contentLen)
{
  // do encryption
  if (m_paramFetcher.getPublicParams().m_pub == "") {
    NDN_LOG_INFO("public parameters doesn't exist" );
    return std::make_tuple(nullptr, nullptr);
  } else if (m_paramFetcher.getAbeType() != ABE_TYPE_CP_ABE) {
    NDN_LOG_INFO("Not a CP-ABE encrypted data" );
    return std::make_tuple(nullptr, nullptr);
  }
  else {
    NDN_LOG_INFO("cpEncrypt data:" << dataName);
    auto cipherText = algo::ABESupport::getInstance().cpEncrypt(m_paramFetcher.getPublicParams(), accessPolicy,
                                                                Buffer(content, contentLen));

    Name ckName = security::extractIdentityFromCertName(m_cert.getName());
    ckName.append("CK").append(std::to_string(random::generateSecureWord32()));

    shared_ptr<Data> data = getCkEncryptedData(dataName, cipherText, ckName);

    Name ckDataName = ckName;
    ckDataName.append("ENC-BY").append(accessPolicy);
    auto ckData = std::make_shared<Data>(ckDataName);
    ckData->setContent(cipherText.makeCKContent());
    ckData->setFreshnessPeriod(5_s);
    m_keyChain.sign(*ckData, signingByCertificate(m_cert));

    NDN_LOG_TRACE(*ckData);
    NDN_LOG_TRACE("CK Data length: " << ckData->wireEncode().size());
    NDN_LOG_TRACE("CK Name length: " << ckData->getName().wireEncode().size());
    NDN_LOG_TRACE("=================================");

    return std::make_tuple(data, ckData);
  }
}

std::tuple<std::shared_ptr<Data>, std::shared_ptr<Data>>
Producer::produce(const Name& dataName, const std::vector<std::string>& attributes,
        const uint8_t* content, size_t contentLen)
{
  // do encryption
  if (m_paramFetcher.getPublicParams().m_pub == "") {
    NDN_LOG_INFO("public parameters doesn't exist" );
    return std::make_tuple(nullptr, nullptr);
  } else if (m_paramFetcher.getAbeType() != ABE_TYPE_KP_ABE) {
    NDN_LOG_INFO("Not a KP-ABE encrypted data" );
    return std::make_tuple(nullptr, nullptr);
  }
  else {
    NDN_LOG_INFO("cpEncrypt data:" << dataName);
    auto cipherText = algo::ABESupport::getInstance().kpEncrypt(m_paramFetcher.getPublicParams(), attributes,
                                                                Buffer(content, contentLen));

    Name ckName = security::extractIdentityFromCertName(m_cert.getName());
    ckName.append("CK").append(std::to_string(random::generateSecureWord32()));

    shared_ptr<Data> data = getCkEncryptedData(dataName, cipherText, ckName);

    Name ckDataName = ckName;
    Block b(tlv::GenericNameComponent);
    for (const auto& i : attributes) b.push_back(makeStringBlock(TLV_Attribute, i));
    ckDataName.append("ENC-BY").append(b);
    auto ckData = std::make_shared<Data>(ckDataName);
    ckData->setContent(cipherText.makeCKContent());
    ckData->setFreshnessPeriod(5_s);
    m_keyChain.sign(*ckData, signingByCertificate(m_cert));

    NDN_LOG_TRACE(*ckData);
    NDN_LOG_TRACE("CK Data length: " << ckData->wireEncode().size());
    NDN_LOG_TRACE("CK Name length: " << ckData->getName().wireEncode().size());
    NDN_LOG_TRACE("=================================");

    return std::make_tuple(data, ckData);
  }
}

std::tuple<std::shared_ptr<Data>, std::shared_ptr<Data>>
Producer::produce(const Name& dataName, const uint8_t* content, size_t contentLen)
{
  // Encrypt data based on data prefix.
  if (m_paramFetcher.getAbeType() == ABE_TYPE_CP_ABE) {
    auto policy = findMatchedPolicy(dataName);
    if (policy == "") {
      return std::make_tuple(nullptr, nullptr);
    }
    return produce(dataName, policy, content, contentLen);
  } else if (m_paramFetcher.getAbeType() == ABE_TYPE_KP_ABE) {
    auto attributes = findMatchedAttributes(dataName);
    if (attributes.empty()) {
      return std::make_tuple(nullptr, nullptr);
    }
    return produce(dataName, attributes, content, contentLen);
  } else {
    return std::make_tuple(nullptr, nullptr);
  }
}

void
Producer::addNewPolicy(const Name& dataPrefix, const std::string& policy)
{
  NDN_LOG_INFO("insert data prefix " << dataPrefix << " with policy " << policy);
  for (auto& item : m_policies) {
    if (std::get<0>(item) == dataPrefix) {
      std::get<1>(item) = policy;
      return;
    }
  }
  m_policies.emplace_back(dataPrefix, policy);
}

void
Producer::addNewAttributes(const Name& dataPrefix, const std::vector<std::string>& attributes)
{
  std::stringstream ss("|");
  for (const auto& i : attributes) ss << i << "|";
  NDN_LOG_INFO("insert data prefix " << dataPrefix << " with attributes " << ss.str());
  for (auto& item : m_attributes) {
    if (std::get<0>(item) == dataPrefix) {
      std::get<1>(item) = attributes;
      return;
    }
  }
  m_attributes.emplace_back(dataPrefix, attributes);
}

std::string
Producer::findMatchedPolicy(const Name& dataName) {
  std::string s;
  std::string &index = s;
  size_t maxMatchedComponents = 0;
  for (const auto &item : m_policies) {
    const auto &prefix = item.first;
    if (prefix.isPrefixOf(dataName) && prefix.size() > maxMatchedComponents) {
      index = item.second;
      maxMatchedComponents = prefix.size();
    }
  }
  return index;
}

std::vector<std::string>
Producer::findMatchedAttributes(const Name& dataName)
{
  std::vector<std::string> s;
  std::vector<std::string> &index = s;
  size_t maxMatchedComponents = 0;
  for (const auto &item : m_attributes) {
    const auto &prefix = item.first;
    if (prefix.isPrefixOf(dataName) && prefix.size() > maxMatchedComponents) {
      index = item.second;
      maxMatchedComponents = prefix.size();
    }
  }
  return index;
}

void
Producer::onPolicyInterest(const Interest& interest)
{
  NDN_LOG_DEBUG("on policy Interest:"<<interest.getName());
  auto dataPrefixBlock = interest.getName().at(m_cert.getIdentity().size() + 1);
  auto dataPrefix = Name(dataPrefixBlock.blockFromValue());
  NDN_LOG_DEBUG("policy applies to data prefix" << dataPrefix);
  auto optionalDataOwnerKey = m_trustConfig.findCertificate(m_dataOwnerPrefix);
  if (optionalDataOwnerKey) {
    if (!security::verifySignature(interest, *optionalDataOwnerKey)) {
      NDN_LOG_INFO("policy interest cannot be authenticated: bad signature");
      return;
    }
  }
  else {
    NDN_LOG_INFO("policy interest cannot be authenticated: no certificate");
    return;
  }
  bool success = false;
  if (m_paramFetcher.getAbeType() == ABE_TYPE_CP_ABE) {
    addNewPolicy(dataPrefix, encoding::readString(interest.getName().at(m_cert.getIdentity().size() + 2)));
    success = true;
  } else if (m_paramFetcher.getAbeType() == ABE_TYPE_KP_ABE) {
    auto &attrBlock = interest.getName().at(m_cert.getIdentity().size() + 2);
    attrBlock.parse();
    std::vector<std::string> attrs;
    for (const auto& e: attrBlock.elements()) {
      attrs.emplace_back(readString(e));
    }
    addNewAttributes(dataPrefix, attrs);
    success = true;
  }
  Data reply;
  reply.setName(interest.getName());
  reply.setContent(makeStringBlock(tlv::Content, success ? "success" : "failure"));
  reply.setFreshnessPeriod(5_s);
  NDN_LOG_DEBUG("before sign");
  m_keyChain.sign(reply, signingByCertificate(m_cert));
  NDN_LOG_DEBUG("after sign");
  m_face.put(reply);
}

shared_ptr<Data> Producer::getCkEncryptedData(const Name &dataName,const algo::CipherText &cipherText, const Name &ckName) {
  Name contentDataName = m_cert.getIdentity();
  contentDataName.append(dataName);
  auto data = std::make_shared<Data>(contentDataName);
  auto dataBlock = makeEmptyBlock(tlv::Content);
  dataBlock.push_back(cipherText.makeDataContent());
  dataBlock.push_back(ckName.wireEncode());
  dataBlock.encode();
  data->setContent(dataBlock);
  data->setFreshnessPeriod(5_s);
  m_keyChain.sign(*data, security::signingByCertificate(m_cert));

  NDN_LOG_TRACE(*data);
  NDN_LOG_TRACE("Content Data length: " << data->wireEncode().size());
  NDN_LOG_TRACE("Content Name length: " << data->getName().wireEncode().size());
  NDN_LOG_TRACE("=================================");
  return data;
}

} // namespace nacabe
} // namespace ndn
