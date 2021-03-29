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

//public
Producer::Producer(Face& face,
                   security::v2::KeyChain& keyChain,
                   const security::v2::Certificate& identityCert,
                   const security::v2::Certificate& attrAuthorityCertificate,
                   const security::v2::Certificate& dataOwnerCertificate,
                   uint8_t repeatAttempts)
  : m_cert(identityCert)
  , m_face(face)
  , m_keyChain(keyChain)
  , m_attrAuthorityPrefix(attrAuthorityCertificate.getIdentity())
  , m_dataOwnerPrefix(dataOwnerCertificate.getIdentity())
  , m_repeatAttempts(repeatAttempts)
{
  // prefix registration
  m_registeredPrefixHandle = m_face.setInterestFilter(Name(m_cert.getIdentity()).append(SET_POLICY),
                                           bind(&Producer::onPolicyInterest, this, _2),
                                           [](const Name&, const std::string&) {
    NDN_THROW(std::runtime_error("Cannot register the prefix to the local NFD"));
  });
  NDN_LOG_DEBUG("set prefix:" << m_cert.getIdentity());

  m_trustConfig.addOrUpdateCertificate(attrAuthorityCertificate);
  m_trustConfig.addOrUpdateCertificate(dataOwnerCertificate);
  fetchPublicParams();
}

Producer::Producer(Face& face,
                   security::v2::KeyChain& keyChain,
                   const security::v2::Certificate& identityCert,
                   const security::v2::Certificate& attrAuthorityCertificate,
                   uint8_t repeatAttempts)
  : m_cert(identityCert)
    , m_face(face)
    , m_keyChain(keyChain)
    , m_attrAuthorityPrefix(attrAuthorityCertificate.getIdentity())
    , m_repeatAttempts(repeatAttempts)
{
  // prefix registration
  m_registeredPrefixHandle = m_face.setInterestFilter(Name(m_cert.getIdentity()).append(SET_POLICY),
                                                      bind(&Producer::onPolicyInterest, this, _2),
                                                      [](const Name&, const std::string&) {
                                                        NDN_THROW(std::runtime_error("Cannot register the prefix to the local NFD"));
                                                      });
  NDN_LOG_DEBUG("set prefix:" << m_cert.getIdentity());

  m_trustConfig.addOrUpdateCertificate(attrAuthorityCertificate);
  fetchPublicParams();
}

Producer::~Producer()
{
  m_registeredPrefixHandle.unregister();
}

void
Producer::onAttributePubParams(const Data& pubParamData)
{
  NDN_LOG_INFO("Get public parameters");
  auto optionalAAKey = m_trustConfig.findCertificate(m_attrAuthorityPrefix);
  if (optionalAAKey) {
    if (!security::verifySignature(pubParamData, *optionalAAKey)) {
      NDN_THROW(std::runtime_error("Fetched public parameters cannot be authenticated: bad signature"));
    }
  }
  else {
    NDN_THROW(std::runtime_error("Fetched public parameters cannot be authenticated: no certificate"));
  }
  auto block = pubParamData.getContent();
  m_pubParamsCache.fromBuffer(Buffer(block.value(), block.value_size()));
}

std::tuple<std::shared_ptr<Data>, std::shared_ptr<Data>>
Producer::produce(const Name& dataPrefix, const std::string& accessPolicy,
                  const uint8_t* content, size_t contentLen)
{
  // do encryption
  if (m_pubParamsCache.m_pub == "") {
    NDN_LOG_INFO("public parameters doesn't exist" );
    return std::make_tuple(nullptr, nullptr);
  }
  else {
    NDN_LOG_INFO("encrypt data:"<<dataPrefix);
    auto cipherText = algo::ABESupport::getInstance().encrypt(m_pubParamsCache, accessPolicy, Buffer(content, contentLen));

    Name ckName = security::v2::extractIdentityFromCertName(m_cert.getName());
    ckName.append("CK").append(std::to_string(random::generateSecureWord32()));

    Name dataName = m_cert.getIdentity();
    dataName.append(dataPrefix);
    auto data = std::make_shared<Data>(dataName);
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
Producer::produce(const Name& dataPrefix, const uint8_t* content, size_t contentLen)
{
  // Encrypt data based on data prefix.
  auto it = m_policyCache.find(dataPrefix);
  if (it == m_policyCache.end()) {
    NDN_LOG_INFO("policy doesn't exist");
    return std::make_tuple(nullptr, nullptr);
  }
  return produce(dataPrefix, it->second, content, contentLen);
}

//private:
void
Producer::onPolicyInterest(const Interest& interest)
{
  NDN_LOG_DEBUG("on policy Interest:"<<interest.getName());
  Name dataPrefix = Name(interest.getName().at(m_cert.getIdentity().size() + 1));
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
  std::pair<std::map<Name,std::string>::iterator, bool> ret;
  ret = m_policyCache.insert(std::pair<Name, std::string>(Name(dataPrefix),
                                                          encoding::readString(interest.getName().at(m_cert.getIdentity().size() + 2))));

  Data reply;
  reply.setName(interest.getName());
  if (ret.second==false) {
    NDN_LOG_DEBUG("dataPrefix already exist");

    NDN_LOG_INFO("insert data prefix "<<dataPrefix<<" policy failed");
    reply.setContent(makeStringBlock(tlv::Content, "exist"));
  }
  else {
    NDN_LOG_DEBUG("insert success");
    NDN_LOG_INFO("insert data prefix "<<dataPrefix<<" with policy "<<encoding::readString(interest.getName().at(3)) );
    reply.setContent(makeStringBlock(tlv::Content, "success"));
  }
  reply.setFreshnessPeriod(5_s);
  NDN_LOG_DEBUG("before sign");
  m_keyChain.sign(reply, signingByCertificate(m_cert));
  NDN_LOG_DEBUG("after sign");
  m_face.put(reply);
}

void
Producer::fetchPublicParams()
{
  // fetch pub parameters
  Name interestName = m_attrAuthorityPrefix;
  interestName.append(PUBLIC_PARAMS);
  Interest interest(interestName);
  interest.setMustBeFresh(true);
  interest.setCanBePrefix(true);

  NDN_LOG_INFO("Request public parameters:"<<interest.getName());
  m_face.expressInterest(interest,
                         [this] (const Interest&, const Data& data) { onAttributePubParams(data); },
                         [=](const Interest&, const lp::Nack&){ NDN_LOG_INFO("NACK"); },
                         [=](const Interest&){ NDN_LOG_INFO("Timeout"); });
}

} // namespace nacabe
} // namespace ndn
