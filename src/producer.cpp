  /* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2017-2023, Regents of the University of California.
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
#include "algo/abe-support.hpp"

#include <ndn-cxx/encoding/block-helpers.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <utility>
#include <ndn-cxx/security/verification-helpers.hpp>
#include <ndn-cxx/util/random.hpp>

namespace ndn {
namespace nacabe {

NDN_LOG_INIT(nacabe.Producer);

Producer::Producer(Face& face, KeyChain& keyChain,
                   security::Validator& validator,
                   const security::Certificate& identityCert,
                   const security::Certificate& attrAuthorityCertificate,
                   Interest publicParamInterestTemplate)
  : m_cert(identityCert)
  , m_face(face)
  , m_validator(validator)
  , m_keyChain(keyChain)
  , m_attrAuthorityPrefix(attrAuthorityCertificate.getIdentity())
  , m_paramFetcher(m_face, validator, m_attrAuthorityPrefix, m_trustConfig, publicParamInterestTemplate)
{
  m_trustConfig.addOrUpdateCertificate(attrAuthorityCertificate);
  m_paramFetcher.fetchPublicParams();
  replyTemplate.setFreshnessPeriod(5_s);
}

Producer::Producer(Face& face, KeyChain& keyChain, 
                   security::Validator& m_validator,
                   const security::Certificate& identityCert,
                   const security::Certificate& attrAuthorityCertificate,
                   const security::Certificate& dataOwnerCertificate,
                   Interest publicParamInterestTemplate)
  : Producer(face, keyChain, m_validator, identityCert, attrAuthorityCertificate, publicParamInterestTemplate)
{
  m_dataOwnerKeyName = dataOwnerCertificate.getKeyName();
  m_trustConfig.addOrUpdateCertificate(dataOwnerCertificate);

  // prefix registration
  m_registeredPrefix = m_face.setInterestFilter(Name(m_cert.getIdentity()).append(SET_POLICY),
    [this] (auto&&, const auto& interest) {
      onPolicyInterest(interest);
    },
    [] (auto&&...) {
      NDN_THROW(std::runtime_error("Cannot register the prefix to the local NFD"));
    });
  NDN_LOG_DEBUG("Set prefix:" << m_cert.getIdentity());
}

Producer::~Producer() = default;

std::tuple<SPtrVector<Data>, SPtrVector<Data>>
Producer::produce(const Name& dataNameSuffix, const std::string& accessPolicy,
                  span<const uint8_t> content, const security::SigningInfo& info,
                  std::shared_ptr<Data> ckTemplate, shared_ptr<Data> dataTemplate,
                  size_t maxSegmentSize)
{

  auto contentKey = ckDataGen(accessPolicy, info, std::move(ckTemplate), maxSegmentSize);
  if (contentKey.first == nullptr) {
    return std::make_tuple(SPtrVector<Data>(), SPtrVector<Data>());
  }
  else {
    // the last component should always be version number
    Name ckObjName = contentKey.second.at(0)->getName().getPrefix(-1);
    auto data = produce(contentKey.first, ckObjName, dataNameSuffix,
                        content, info, std::move(dataTemplate), maxSegmentSize);
    return std::make_tuple(data, contentKey.second);
  }
}

std::pair<std::shared_ptr<algo::ContentKey>, SPtrVector<Data>>
Producer::ckDataGen(const Policy& accessPolicy,
                    const security::SigningInfo& info,
                    std::shared_ptr<Data> dataTemplate,
                    size_t maxSegmentSize)
{
  // do encryption
  if (m_paramFetcher.getPublicParams().m_pub == "") {
    NDN_LOG_INFO("Public parameters doesn't exist" );
    return std::make_pair(nullptr, SPtrVector<Data>());
  }
  else if (m_paramFetcher.getAbeType() != ABE_TYPE_CP_ABE) {
    NDN_LOG_INFO("Not a CP-ABE encrypted data" );
    return std::make_pair(nullptr, SPtrVector<Data>());
  }
  else {
    NDN_LOG_INFO("CK data for:" << accessPolicy);
    auto contentKey = algo::ABESupport::getInstance().cpContentKeyGen(m_paramFetcher.getPublicParams(), accessPolicy);
    Name ckName = security::extractIdentityFromCertName(m_cert.getName());
    ckName.append(CONTENT_KEY).append(std::to_string(random::generateSecureWord32()));
    Name ckDataName = ckName;
    util::Segmenter segmenter(m_keyChain, info);
    Block ckBlock = contentKey->makeCKContent();
    span<const uint8_t> ckSpan = make_span(ckBlock.data(), ckBlock.size());
    ckDataName.append(ENCRYPT_BY).append(accessPolicy.c_str());
    auto ckSegments = segmenter.segment(ckSpan, ckDataName, maxSegmentSize,
                                        dataTemplate->getFreshnessPeriod(),
                                        dataTemplate->getContentType());
    return std::make_pair(contentKey, ckSegments);
  }
}

std::tuple<SPtrVector<Data>, SPtrVector<Data>>
Producer::produce(const Name& dataNameSuffix, const std::vector<std::string>& attributes,
                  span<const uint8_t> content, const security::SigningInfo& info,
                  std::shared_ptr<Data> ckTemplate, shared_ptr<Data> dataTemplate,
                  size_t maxSegmentSize)
{
  auto contentKey = ckDataGen(attributes, info, std::move(ckTemplate), maxSegmentSize);
  if (contentKey.first == nullptr) {
    return std::make_tuple(SPtrVector<Data>(), SPtrVector<Data>());
  }
  else {
    // the last component should always be version number
    Name ckObjName = contentKey.second.at(0)->getName().getPrefix(-1);
    auto data = produce(contentKey.first, ckObjName, dataNameSuffix,
                        content, info, std::move(dataTemplate), maxSegmentSize);
    return std::make_tuple(data, contentKey.second);
  }
}

std::pair<std::shared_ptr<algo::ContentKey>, SPtrVector<Data>>
Producer::ckDataGen(const std::vector<std::string>& attributes,
                    const security::SigningInfo& info,
                    std::shared_ptr<Data> dataTemplate,
                    size_t maxSegmentSize)
{
  // do encryption
  if (m_paramFetcher.getPublicParams().m_pub.empty()) {
    NDN_LOG_INFO("Public parameters doesn't exist" );
    return std::make_pair(nullptr, SPtrVector<Data>());
  }
  else if (m_paramFetcher.getAbeType() != ABE_TYPE_KP_ABE) {
    NDN_LOG_INFO("Not a KP-ABE encrypted data" );
    return std::make_pair(nullptr, SPtrVector<Data>());
  }
  else {
    std::string s("|");
    for (const auto& a : attributes)
      s += a + '|';
    NDN_LOG_INFO("Generate CK data: " << s);
    auto contentKey = algo::ABESupport::getInstance().kpContentKeyGen(m_paramFetcher.getPublicParams(), attributes);

    name::Component nc;
    for (const auto& a : attributes)
      nc.push_back(makeStringBlock(TLV_Attribute, a));
    Name ckDataName = security::extractIdentityFromCertName(m_cert.getName())
                      .append(CONTENT_KEY)
                      .append(std::to_string(random::generateSecureWord32()))
                      .append(ENCRYPT_BY)
                      .append(nc);
    util::Segmenter segmenter(m_keyChain, info);
    Block ckBlock = contentKey->makeCKContent();
    span<const uint8_t> ckSpan = make_span(ckBlock.data(), ckBlock.size());
    auto ckSegments = segmenter.segment(ckSpan, ckDataName, maxSegmentSize,
                                        dataTemplate->getFreshnessPeriod(),
                                        dataTemplate->getContentType());
    return std::make_pair(contentKey, ckSegments);
  }
}

std::tuple<SPtrVector<Data>, SPtrVector<Data>>
Producer::produce(const Name& dataNameSuffix, span<const uint8_t> content,
                  const security::SigningInfo& info,
                  std::shared_ptr<Data> ckTemplate, shared_ptr<Data> dataTemplate,
                  size_t maxSegmentSize)
{
  // Encrypt data based on data prefix.
  if (m_paramFetcher.getAbeType() == ABE_TYPE_CP_ABE) {
    auto policy = findMatchedPolicy(dataNameSuffix);
    if (policy.empty()) {
      return std::make_tuple(SPtrVector<Data>(), SPtrVector<Data>());
    }
    return produce(dataNameSuffix, policy, content, info,
                   std::move(ckTemplate), std::move(dataTemplate),
                   maxSegmentSize);
  }
  else if (m_paramFetcher.getAbeType() == ABE_TYPE_KP_ABE) {
    auto attributes = findMatchedAttributes(dataNameSuffix);
    if (attributes.empty()) {
      return std::make_tuple(SPtrVector<Data>(), SPtrVector<Data>());
    }
    return produce(dataNameSuffix, attributes, content,
                   info, std::move(ckTemplate), std::move(dataTemplate),
                   maxSegmentSize);
  }
  else {
    return std::make_tuple(SPtrVector<Data>(), SPtrVector<Data>());
  }
}

SPtrVector<Data>
Producer::produce(std::shared_ptr<algo::ContentKey> key,
                  const Name& keyName, const Name& dataNameSuffix,
                  span<const uint8_t> content, const security::SigningInfo& info,
                  shared_ptr<Data> dataTemplate,
                  size_t maxSegmentSize)
{
  NDN_LOG_INFO("Encrypt on data:" << dataNameSuffix);
  auto cipherText = algo::ABESupport::getInstance().encrypt(std::move(key), Buffer(content.begin(), content.end()));
  return getCkEncryptedData(dataNameSuffix, cipherText, keyName, info, std::move(dataTemplate), maxSegmentSize);
}

void
Producer::addNewPolicy(const Name& dataPrefix, const Policy& policy)
{
  NDN_LOG_INFO("Insert data prefix " << dataPrefix << " with policy " << policy);
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
  std::string s("|");
  for (const auto& a : attributes)
    s += a + '|';
  NDN_LOG_INFO("Insert data prefix " << dataPrefix << " with attributes " << s);
  for (auto& item : m_attributes) {
    if (std::get<0>(item) == dataPrefix) {
      std::get<1>(item) = attributes;
      return;
    }
  }
  m_attributes.emplace_back(dataPrefix, attributes);
}

std::string
Producer::findMatchedPolicy(const Name& dataName)
{
  std::string s;
  std::string &index = s;
  size_t maxMatchedComponents = 0;
  for (const auto& item : m_policies) {
    const auto& prefix = item.first;
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
  for (const auto& item : m_attributes) {
    const auto& prefix = item.first;
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
  NDN_LOG_DEBUG("On policy Interest:"<< interest.getName());
  auto dataPrefixBlock = interest.getName().at(m_cert.getIdentity().size() + 1);
  auto dataPrefix = Name(dataPrefixBlock.blockFromValue());
  NDN_LOG_DEBUG("Policy applies to data prefix" << dataPrefix);
  auto optionalDataOwnerKey = m_trustConfig.findCertificateFromLocal(m_dataOwnerKeyName);
  auto generateReply = [&] (const Interest& interest) {
    bool success = false;
    if (m_paramFetcher.getAbeType() == ABE_TYPE_CP_ABE) {
      addNewPolicy(dataPrefix, encoding::readString(interest.getName().at(m_cert.getIdentity().size() + 2)));
      success = true;
    }
    else if (m_paramFetcher.getAbeType() == ABE_TYPE_KP_ABE) {
      auto& attrBlock = interest.getName().at(m_cert.getIdentity().size() + 2);
      attrBlock.parse();
      std::vector<std::string> attrs;
      for (const auto& e: attrBlock.elements()) {
        attrs.emplace_back(readString(e));
      }
      addNewAttributes(dataPrefix, attrs);
      success = true;
    }
    Data reply = replyTemplate;
    reply.setName(interest.getName());
    reply.setContent(makeStringBlock(tlv::Content, success ? "success" : "failure"));
    m_keyChain.sign(reply, signingByCertificate(m_cert));
    m_face.put(reply);
  };
  if (optionalDataOwnerKey) {
    if (!security::verifySignature(interest, *optionalDataOwnerKey)) {
      NDN_LOG_INFO("Policy interest cannot be authenticated: bad signature");
      return;
    }
    generateReply(interest);
  }
  else {
    // Policy Interest is signed, using validator instead.
    m_validator.validate(interest, 
      [&] (const Interest& interest) {
        NDN_LOG_INFO("Policy interest validated");
        generateReply(interest);
      },
      [] (auto&&, const ndn::security::ValidationError& error) {
        NDN_LOG_INFO("Policy interest validator failure: " << error.getInfo());
      }
    );
  }
}

SPtrVector<Data>
Producer::getCkEncryptedData(const Name& dataNameSuffix, const algo::CipherText& cipherText,
                             const Name& ckName, const security::SigningInfo& info,
                             shared_ptr<Data> dataTemplate, size_t maxSegmentSize)
{
  Name contentDataName = m_cert.getIdentity();
  contentDataName.append(dataNameSuffix);
  auto dataBlock = cipherText.makeDataContent();
  dataBlock.push_back(ckName.wireEncode());
  dataBlock.encode();
  util::Segmenter segmenter(m_keyChain, info);
  span<const uint8_t> ckSpan = make_span(dataBlock.data(), dataBlock.size());
  auto ckSegments = segmenter.segment(ckSpan, contentDataName, maxSegmentSize,
                                      dataTemplate->getFreshnessPeriod(),
                                      dataTemplate->getContentType());
  return ckSegments;
}

std::shared_ptr<Data> Producer::getDefaultCkTemplate() {
  auto data = std::make_shared<Data>();
  data->setFreshnessPeriod(5_s);
  return data;
}

std::shared_ptr<Data> Producer::getDefaultEncryptedDataTemplate() {
  auto data = std::make_shared<Data>();
  data->setFreshnessPeriod(5_s);
  return data;
}

} // namespace nacabe
} // namespace ndn