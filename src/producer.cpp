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
  }
  else {
    NDN_LOG_INFO("cpEncrypt data:" << dataName);
    auto cipherText = algo::ABESupport::getInstance().cpEncrypt(m_paramFetcher.getPublicParams(), accessPolicy,
                                                                Buffer(content, contentLen));

    Name ckName = security::extractIdentityFromCertName(m_cert.getName());
    ckName.append("CK").append(std::to_string(random::generateSecureWord32()));

    Name contentDataName = m_cert.getIdentity();
    contentDataName.append(dataName);
    auto data = std::make_shared<Data>(contentDataName);
    auto dataBlock = makeEmptyBlock(tlv::Content);
    dataBlock.push_back(cipherText.makeDataContent());
    dataBlock.push_back(ckName.wireEncode());
    dataBlock.encode();
    data->setContent(dataBlock);
    data->setFreshnessPeriod(5_s);
    m_keyChain.sign(*data, signingByCertificate(m_cert));

    std::cout << *data;
    std::cout << "Content Data length: " << data->wireEncode().size() << std::endl;
    std::cout << "Content Name length: " << data->getName().wireEncode().size() << std::endl;
    std::cout << "=================================\n";

    Name ckDataName = ckName;
    ckDataName.append("ENC-BY").append(accessPolicy);
    auto ckData = std::make_shared<Data>(ckDataName);
    ckData->setContent(cipherText.makeCKContent());
    ckData->setFreshnessPeriod(5_s);
    m_keyChain.sign(*ckData, signingByCertificate(m_cert));

    std::cout << *ckData;
    std::cout << "CK Data length: " << ckData->wireEncode().size() << std::endl;
    std::cout << "CK Name length: " << ckData->getName().wireEncode().size() << std::endl;
    std::cout << "=================================\n";

    return std::make_tuple(data, ckData);
  }
}

std::tuple<std::shared_ptr<Data>, std::shared_ptr<Data>>
Producer::produce(const Name& dataName, const uint8_t* content, size_t contentLen)
{
  // Encrypt data based on data prefix.
  auto policy = findMatchedPolicy(dataName);
  if (policy == "") {
    return std::make_tuple(nullptr, nullptr);
  }
  return produce(dataName, policy, content, contentLen);
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
  m_policies.push_back(std::make_tuple(dataPrefix, policy));
}

std::string
Producer::findMatchedPolicy(const Name& dataName)
{
  size_t index = 0;
  size_t maxMatchedComponents = 0;
  for (size_t i = 0; i < m_policies.size(); i++) {
    const auto& prefix = std::get<0>(m_policies[i]);
    if (prefix.isPrefixOf(dataName) && prefix.size() > maxMatchedComponents) {
      index = i;
      maxMatchedComponents = prefix.size();
    }
  }
  if (maxMatchedComponents == 0) {
    return "";
  }
  else {
    return std::get<1>(m_policies[index]);
  }
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
  addNewPolicy(dataPrefix, encoding::readString(interest.getName().at(m_cert.getIdentity().size() + 2)));
  Data reply;
  reply.setName(interest.getName());
  reply.setContent(makeStringBlock(tlv::Content, "success"));
  reply.setFreshnessPeriod(5_s);
  NDN_LOG_DEBUG("before sign");
  m_keyChain.sign(reply, signingByCertificate(m_cert));
  NDN_LOG_DEBUG("after sign");
  m_face.put(reply);
}

} // namespace nacabe
} // namespace ndn
