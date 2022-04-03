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

#include "data-owner.hpp"

#include <boost/range/adaptor/reversed.hpp>
#include <ndn-cxx/encoding/block-helpers.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>

namespace ndn {
namespace nacabe {

NDN_LOG_INIT(nacabe.dataOwner);

DataOwner::DataOwner(const security::Certificate& identityCert, Face& face,
                     security::KeyChain& keyChain)
  : m_cert(identityCert)
  , m_face(face)
  , m_keyChain(keyChain)
{
}

void
DataOwner::commandProducerPolicyImpl(const Name& prefix, const Name& dataPrefix,
                                     span<const uint8_t> policy,
                                     const SuccessCallback& successCb,
                                     const ErrorCallback& errorCb)
{
  Name policyName = prefix;
  policyName.append(SET_POLICY);
  policyName.append(dataPrefix.wireEncode().begin(), dataPrefix.wireEncode().end());
  policyName.append(policy.begin(), policy.end());
  auto interest = std::make_shared<Interest>(policyName);
  interest->setMustBeFresh(true);
  interest->setInterestLifetime(time::seconds(1));
  m_keyChain.sign(*interest, signingByCertificate(m_cert));

  // prepare callback functions
  auto validationCallback = [=] (const Data& validData) {
    // try to know if register success
    if (readString(validData.getContent()) != "success") {
      errorCb("register failed");
    }
    else {
      successCb(validData);
    }
  };

  auto dataCallback = [=] (const Interest& contentInterest, const Data& contentData) {
    if (!contentInterest.matchesData(contentData))
      return;

    validationCallback(contentData);
  };

  // set link object if it is available
  m_face.expressInterest(*interest, dataCallback,
                         [=] (const Interest&, const lp::Nack&) {
                           errorCb("nack");
                         },
                         [=] (const Interest&) {
                           errorCb("time out");
                         });
}

void
DataOwner::commandProducerPolicy(const Name &producerPrefix, const Name &dataPrefix,
                                 const Policy &policy,
                                 const DataOwner::SuccessCallback &successCb,
                                 const DataOwner::ErrorCallback &errorCb)
{
  NDN_LOG_INFO("Set data " << dataPrefix << " in Producer " << producerPrefix << " with policy " << policy);
  commandProducerPolicyImpl(producerPrefix, dataPrefix,
                            {reinterpret_cast<const uint8_t*>(policy.data()), policy.size()},
                            successCb, errorCb);
}

void
DataOwner::commandProducerPolicy(const Name &producerPrefix, const Name &dataPrefix,
                                 const std::vector<std::string> &attributes,
                                 const DataOwner::SuccessCallback &successCb,
                                 const DataOwner::ErrorCallback &errorCb)
{
  EncodingBuffer enc;
  std::string s("|");
  for (const auto& a : attributes | boost::adaptors::reversed) {
    prependStringBlock(enc, TLV_Attribute, a);
    s = '|' + a + s;
  }

  NDN_LOG_INFO("Set data " << dataPrefix << " in Producer " << producerPrefix << " with attributes " << s);
  commandProducerPolicyImpl(producerPrefix, dataPrefix, enc, successCb, errorCb);
}

} // namespace nacabe
} // namespace ndn
