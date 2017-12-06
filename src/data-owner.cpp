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

#include "data-owner.hpp"
#include "logging.hpp"

#include <ndn-cxx/encoding/block-helpers.hpp>

namespace ndn {
namespace ndnabac {

const Name DataOwner::SET_POLICY = "/SET_POLICY";
_LOG_INIT(ndnabac.dataOwner);

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
  // shared_ptr<Interest> interest = make_shared<Interest>(dataName);
  // sendInterest(*Interest);
  NDN_LOG_INFO("Set data " << dataPrefix<<" in Producer "<<prefix<<" with policy "<<policy);
  Name policyName = prefix;
  policyName.append(SET_POLICY);
  policyName.append(dataPrefix);
  policyName.append(policy);
  //add sig

  shared_ptr<Interest> interest = make_shared<Interest>(policyName);

  // prepare callback functions
  auto validationCallback =
    [=] (const Data& validData) {
    NDN_LOG_INFO("validate:"<<validData.getName()<<","<<readString(validData.getContent()));
    //try to know if register success;
    if (readString(validData.getContent()) != "success") {
      NDN_LOG_INFO("validate failed");
      errorCb("register failed");
    }
    else {
      NDN_LOG_INFO("validate success");
      SuccessCb(validData);
    }
  };

  auto dataCallback = [=] (const Interest& contentInterest, const Data& contentData) {
    NDN_LOG_INFO("data received"<<contentData.getName());
    if (!contentInterest.matchesData(contentData))
      return;

    validationCallback(contentData);
  };

  // set link object if it is available

  NDN_LOG_INFO(interest->getName().toUri());
  interest->setMustBeFresh(true);
  m_face.expressInterest(*interest, dataCallback,
                         [=] (const Interest&, const lp::Nack&) {
                           errorCb("Nack");
                         },
                         [=] (const Interest&) {
                           errorCb("time out");
                         });

}

} // namespace ndnabac
} // namespace ndn
