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

#include "token-issuer.hpp"

namespace ndn {
namespace ndnabac {

//public
TokenIssuer::TokenIssuer(Face& face, const Name ownerPrefix)
  : m_face(face)
  , m_ownerPrefix(ownerPrefix)
{
  m_face.setInterestFilter(InterestFilter(m_ownerPrefix),
                           bind(&TokenIssuer::onInterest, this, _1, _2),
                           RegisterPrefixSuccessCallback(),
                           RegisterPrefixFailureCallback());
}

void
TokenIssuer::onTokenRequest()
{
}

void
createProducer(const Name producerName)
{
  Name producerPrefix = m_ownerPrefix.append(producerName);
  std::shared_ptr<Face> face = std::make_shared<Face>();
  std::shared_ptr<Producer> producer = std::make_shared<Producer>(cert, *face, producerPrefix);
  producers.push_back(producer);
}

//private
void
onInterest(const InterestFilter& forwardingHint, const Interest& interest);
{
}

} // namespace ndnabac
} // namespace ndn
