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

#include "data-owner.hpp"

#include <ndn-cxx/encoding/block-helpers.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>

namespace ndn {
namespace nacabe {

NDN_LOG_INIT(nacabe.dataOwner);

DataOwner::DataOwner(const security::v2::Certificate& identityCert, Face& face,
                     security::v2::KeyChain& keyChain)
  : m_cert(identityCert)
  , m_face(face)
  , m_keyChain(keyChain)
{
}

void
DataOwner::commandProducerPolicy(const Name& prefix, const Name& dataPrefix, const std::string& policy,
                                 const SuccessCallback& SuccessCb, const ErrorCallback& errorCb)
{
  NDN_LOG_INFO("Set data " << dataPrefix<<" in Producer "<<prefix<<" with policy "<<policy);
  Name policyName = prefix;
  policyName.append(SET_POLICY);
  policyName.append(dataPrefix.wireEncode());
  policyName.append(policy);
  shared_ptr<Interest> interest = make_shared<Interest>(policyName);
  interest->setCanBePrefix(false);
  interest->setMustBeFresh(true);
  m_keyChain.sign(*interest, signingByCertificate(m_cert));

  // prepare callback functions
  auto validationCallback =
    [=] (const Data& validData) {
    //try to know if register success;
    if (readString(validData.getContent()) != "success") {
      errorCb("register failed");
    }
    else {
      SuccessCb(validData);
    }
  };

  auto dataCallback = [=] (const Interest& contentInterest, const Data& contentData) {
    if (!contentInterest.matchesData(contentData))
      return;

    validationCallback(contentData);
  };

  // set link object if it is available
  m_face.expressInterest(*interest, dataCallback,
                         nullptr,
                         [=] (const Interest&) {
                           errorCb("time out");
                         });
}

} // namespace nacabe
} // namespace ndn
