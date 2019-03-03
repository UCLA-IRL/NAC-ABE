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

#include "trust-config.hpp"
#include "json-helper.hpp"
#include <list>

namespace ndn {
namespace ndnabac {

class TokenIssuer
{
public:
  TokenIssuer(const security::v2::Certificate& identityCert, Face& face,
              security::v2::KeyChain& keyChain);

  ~TokenIssuer();

  bool
  insertAttributes(std::pair<Name, std::list<std::string>>);

  void
  addCert(const security::v2::Certificate& cert);

private:
  void
  onTokenRequest(const Interest& request);

public:
  /**
   * TOKEN_USER: public key bits
   * TOKEN_ATTR_SET [
   * {
   *     TOKEN_ATTR_NAME: attr1
   * },
   * ...
   * ]
   */
  const static std::string TOKEN_USER;
  const static std::string TOKEN_ATTR_SET;
  const static std::string TOKEN_ATTR_NAME;

  const static Name TOKEN_REQUEST;

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  security::v2::Certificate m_cert;
  Face& m_face;
  security::v2::KeyChain& m_keyChain;

  TrustConfig m_trustConfig;
  std::list<InterestFilterHandle> m_interestFilterIds;
  std::map<Name/* Consumer Identity */, std::list<std::string>/* Attr */> m_tokens;
};

} // namespace ndnabac
} // namespace ndn

#endif // NDNABAC_TOKEN_ISSUER_HPP
