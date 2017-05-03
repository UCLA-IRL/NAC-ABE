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

#ifndef NDNABAC_TOKEN_ISSUER_HPP
#define NDNABAC_TOKEN_ISSUER_HPP

#include "ndnabac-common.hpp"

namespace ndn {
namespace ndnabac {

class TokenIssuer
{
public:
  TokenIssuer(Face& face, const Name ownerPrefix);

  void
  onTokenRequest(const Interest& request);

  void
  createProducer(const Name producerName);

private:
  void
  onInterest(const InterestFilter& forwardingHint, const Interest& interest);


public:
  const static std::string TOKEN_USER;
  const static std::string TOKEN_ATTR_SET;
  const static std::string TOKEN_ATTR_NAME;
  const static std::string TOKEN_ATTR_VALUE;

private:
	Face& m_face;
	Name m_ownerPrefix;
  security::v2::Certificate m_cert;
  std::list<Name, Data> m_tokens;
  std::list<std::shared_ptr<Producer>> producers;
};

} // namespace ndnabac
} // namespace ndn

#endif // NDNABAC_TOKEN_ISSUER_HPP
