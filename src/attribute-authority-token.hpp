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

#ifndef NAC_ABE_ATTRIBUTE_AUTHORITY_TOKEN_HPP
#define NAC_ABE_ATTRIBUTE_AUTHORITY_TOKEN_HPP

#include "common.hpp"
#include "trust-config.hpp"
#include "algo/abe-support.hpp"

namespace ndn {
namespace nacabe {

class AttributeAuthorityToken
{
public:
  AttributeAuthorityToken(const security::v2::Certificate& identityCert, Face& m_face,
                          security::v2::KeyChain& keyChain);

  ~AttributeAuthorityToken();

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  void
  onDecryptionKeyRequest(const Interest& interest);

  void
  onPublicParamsRequest(const Interest& interest);

  void
  onRegisterFailed(const std::string& reason);

  void
  init();

public:
  const static Name PUBLIC_PARAMS;
  const static Name DECRYPT_KEY;

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  security::v2::Certificate m_cert;
  Face& m_face;
  security::v2::KeyChain& m_keyChain;

  algo::PublicParams m_pubParams;
  algo::MasterKey m_masterKey;

  TrustConfig m_trustConfig;

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  std::list<RegisteredPrefixHandle> m_registeredPrefixIds;
  std::list<InterestFilterHandle> m_interestFilterIds;
};

} // namespace nacabe
} // namespace ndn

#endif // NAC_ABE_ATTRIBUTE_AUTHORITY_HPP
