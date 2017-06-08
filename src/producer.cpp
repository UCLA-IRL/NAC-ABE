/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017, Regents of the University of California.
 *
 * This file is part of ndnabac, a certificate management system based on NDN.
 *
 * ndnabac is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation, either
 * version 3 of the License, or (at your option) any later version.
 *
 * ndnabac is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received copies of the GNU General Public License along with
 * ndnabac, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of ndnabac authors and contributors.
 */

#include "producer.hpp"
#include "logging.hpp"
#include "attribute-authority.hpp"

#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/encoding/block-helpers.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>

namespace ndn {
namespace ndnabac {

_LOG_INIT(ndnabac.producer);

const Name Producer::SET_POLICY = "/SET_POLICY";

//public
Producer::Producer(const security::v2::Certificate& identityCert, Face& face,
                   security::v2::KeyChain& keyChain, const Name& attrAuthorityPrefix,
                   uint8_t repeatAttempts)
  : m_cert(identityCert)
  , m_face(face)
  , m_keyChain(keyChain)
  , m_attrAuthorityPrefix(attrAuthorityPrefix)
  , m_repeatAttempts(repeatAttempts)
{
  // prefix registration
  const InterestFilterId* filterId;
  filterId = m_face.setInterestFilter(Name(m_cert.getIdentity()).append(SET_POLICY),
                                      bind(&Producer::onPolicyInterest, this, _2));
  _LOG_DEBUG("set prefix:"<<m_cert.getIdentity());
  m_interestFilterIds.push_back(filterId);
  fetchPublicParams();
}

Producer::~Producer()
{
  for (auto prefixId : m_interestFilterIds) {
    m_face.unsetInterestFilter(prefixId);
  }
}

void
Producer::onAttributePubParams(const Interest& request, const Data& pubParamData)
{
  Name attrAuthorityKey = pubParamData.getSignature().getKeyLocator().getName();
  for (auto anchor : m_trustConfig.m_trustAnchors) {
    if (anchor.getKeyName() == attrAuthorityKey) {
      BOOST_ASSERT(security::verifySignature(pubParamData, anchor));
      break;
    }
  }
  auto block = pubParamData.getContent();
  m_pubParamsCache.fromBuffer(Buffer(block.value(), block.value_size()));
}

void
Producer::produce(const Name& dataPrefix, const std::string& accessPolicy,
                  const uint8_t* content, size_t contentLen,
                  const SuccessCallback& onDataProduceCb, const ErrorCallback& errorCallback)
{
  // do encryption
  if (m_pubParamsCache.m_pub == nullptr) {
    errorCallback("public key missing");
  }
  else {
    auto cipherText = algo::ABESupport::encrypt(m_pubParamsCache, accessPolicy,
                                                Buffer(content, contentLen));

    Name dataName = m_cert.getIdentity();
    dataName.append(dataPrefix);
    Data data(dataName);
    data.setContent(cipherText.wireEncode());
    m_keyChain.sign(data, signingByCertificate(m_cert));
    onDataProduceCb(data);    
  }
}

//private:
void
Producer::onPolicyInterest(const Interest& interest)
{
  //*** need verify signature ****
  _LOG_DEBUG("on policy Interest:"<<interest.getName());
  Name dataPrefix = interest.getName().getSubName(2,1);
  Name policy = interest.getName().getSubName(3,1);
  _LOG_DEBUG(dataPrefix<<", "<<policy);

  std::pair<std::map<Name,std::string>::iterator,bool> ret;
  ret = m_policyCache.insert(std::pair<Name, std::string>(Name(dataPrefix), policy.toUri()));

  Data reply;
  reply.setName(interest.getName());
  if (ret.second==false) {

    _LOG_DEBUG("dataPrefix already exist");
    reply.setContent(makeStringBlock(tlv::Content, "exist"));
  }
  else {
    _LOG_DEBUG("insert success");
    reply.setContent(makeStringBlock(tlv::Content, "success"));
  }
  _LOG_DEBUG("before sign");
  m_keyChain.sign(reply, signingByCertificate(m_cert));
  _LOG_DEBUG("after sign");
  m_face.put(reply);
}

void
Producer::fetchPublicParams()
{
  // fetch pub parameters
  Name interestName = m_attrAuthorityPrefix;
  interestName.append(AttributeAuthority::PUBLIC_PARAMS);
  Interest interest(interestName);
  interest.setMustBeFresh(true);

  m_face.expressInterest(interest, std::bind(&Producer::onAttributePubParams, this, _1, _2),
                         nullptr, nullptr);
}

} // namespace ndnabac
} // namespace ndn
