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

const Name DataOwner::SET_POLICY = "/SET_POLICY";
NDN_LOG_INIT(nacabe.dataOwner);

DataOwner::DataOwner(const security::v2::Certificate& identityCert, Face& face,
                     security::v2::KeyChain& keyChain)
  : m_cert(identityCert)
  , m_face(face)
  , m_keyChain(keyChain)
{
}

/**
 * send command:
 *  /producer-prefix/data-prefix/POLICY/<policy string>/[sig]
 * data-prefix contains the producer prefix and data prefix
 */
void
DataOwner::commandProducerPolicy(const Name& prefix, const Name& dataPrefix, const std::string& policy,
                                 const SuccessCallback& SuccessCb, const ErrorCallback& errorCb)
{
  Data kek;
  Name kekName = prefix;
  kekName.append("NAC").append(dataPrefix).append("KEK").append(policy);
  kek.setName(kekName);
  m_keyChain.sign(kek, signingByCertificate(m_cert));

  std::cout << kek;
  std::cout << "kek Data length: " << kek.wireEncode().size() << std::endl;
  std::cout << "kek Name length: " << kek.getName().wireEncode().size() << std::endl;
  std::cout << "=================================\n";


  // shared_ptr<Interest> interest = make_shared<Interest>(dataName);
  // sendInterest(*Interest);
  NDN_LOG_INFO("Set data " << dataPrefix<<" in Producer "<<prefix<<" with policy "<<policy);
  Name policyName = prefix;
  policyName.append(SET_POLICY);
  policyName.append(dataPrefix);
  policyName.append(policy);
  //add sig

  shared_ptr<Interest> interest = make_shared<Interest>(policyName);
  interest->setCanBePrefix(false);
  interest->setMustBeFresh(true);

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
