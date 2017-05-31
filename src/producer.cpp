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
  m_interestFilterIds.push_back(filterId);
}

Producer::~Producer()
{
  for (auto prefixId : m_interestFilterIds) {
    m_face.unsetInterestFilter(prefixId);
  }
}

// need to determine how to parse accessPolicy
void
Producer::produce(const Name& dataPrefix, const std::string& accessPolicy,
                  const uint8_t* content, size_t contentLen,
                  const SuccessCallback& onDataProduceCb, const ErrorCallback& errorCallback)
{
  Name dataName = m_cert.getIdentity();
  dataName.append(dataPrefix);
  shared_ptr<Data> data = make_shared<Data>(dataName);

  //parse policy then encrypt
  //algo::EncryptParams params(tlv::AlgorithmAesCbc, 16);
  //algo::encryptData(data, content, contentLen, contentKeyName,
  //                  contentKey.buf(), contentKey.size(), params);
  //encryptWithPolicy(data, content, accessPolicy, errorCallback);
  //m_keyChain.sign(data);
  onDataProduceCb(*data);

}

//private:
void
Producer::onPolicyInterest(const Interest& interest)
{
  Name dataPrefix = interest.getName().at(2).toUri();
  Name policy = interest.getName().at(3).toUri();

  std::pair<std::map<Name,std::string>::iterator,bool> ret;
  ret = m_policyCache.insert(std::pair<Name, std::string>(Name(dataPrefix), policy.toUri()));

  Data reply;
  reply.setName(interest.getName());
  if (ret.second==false) {
    std::cout << "dataPrefix already exist";
    reply.setContent(makeStringBlock(tlv::Content, "exist"));
  }
  else {
    reply.setContent(makeStringBlock(tlv::Content, "success"));
  }
  m_keyChain.sign(reply, signingByCertificate(m_cert));
  m_face.put(reply);
}


void
Producer::fetchAuthorityPubParams(const Name& attrAuthorityPrefix, const ErrorCallback& errorCb)
{
  Name interestName = attrAuthorityPrefix;
  interestName.append(AttributeAuthority::PUBLIC_PARAMS);

  shared_ptr<Interest> interest = make_shared<Interest>(interestName);

  auto dataCallback =
    [=] (const Interest& contentInterest, const Data& contentData) {
    if (!contentInterest.matchesData(contentData))
      return;

    // check signature
    Name issuerKey = contentData.getSignature().getKeyLocator().getName();
    for (auto anchor : m_trustAnchors) {
      if (anchor.getKeyName() == issuerKey) {
        if (!security::verifySignature(token, anchor)) {
          _LOG_TRACE("Invalid sig fo public parameters from authority");
          return;
        }
        break;
      }
    }

    //add Pub Param
  };

  // set link object if it is available
  m_face.expressInterest(*interest, dataCallback, nullptr,
                         [=] (const Interest&) {
                           errorCb("time out");
                         });
}

} // namespace ndnabac
} // namespace ndn
