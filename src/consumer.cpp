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

#include "consumer.hpp"

namespace ndn {
namespace ndnabac {

static const Name REQUEST_TOKEN = "/token";

// public
Consumer::Consumer(const security::v2::Certificate& identityCert, Face& face,
                   uint8_t repeatAttempts)
  : m_cert(identityCert)
  , m_face(face)
  , m_repeatAttempts(repeatAttempts)
{
}

void
Consumer::consume(const Name& dataName,
                  const ConsumptionCallback& consumptionCb,
                  const ErrorCallback& errorCb)
{
  // shared_ptr<Interest> interest = make_shared<Interest>(dataName);
  // sendInterest(*Interest);
}

void
Consumer::loadTrustConfig(const TrustConfig& config)
{}

void
Consumer::fetchDecryptionKey(const Name& attrAuthorityPrefix, const Data& token)
{}

void
Consumer::requestToken(const Name& tokenIssuerPrefix)
{}

void
Consumer::tokenDataCallback(const Interest& interest, Data& data)
{}

void
Consumer::tokenTimeoutCb(const Interest& interest)
{}

void
Consumer::fetchAttributePubParams(const Name& attrAuthorityPrefix)
{}



} // namespace ndnabac
} // namespace ndn
