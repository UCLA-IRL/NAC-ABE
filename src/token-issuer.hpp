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

#ifndef NAC_ABE_TOKEN_ISSUER_HPP
#define NAC_ABE_TOKEN_ISSUER_HPP

#include "trust-config.hpp"
#include "json-helper.hpp"
#include <list>

namespace ndn {
namespace nacabe {

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

} // namespace nacabe
} // namespace ndn

#endif // NAC_ABE_TOKEN_ISSUER_HPP
