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

#ifndef NDNABAC_ATTRIBUTE_AUTHORITY_HPP
#define NDNABAC_ATTRIBUTE_AUTHORITY_HPP

#include "ndnabac-common.hpp"
#include "trust-config.hpp"
#include "algo/abe-support.hpp"

namespace ndn {
namespace ndnabac {

class AttributeAuthority
{
public:
  AttributeAuthority(const security::v2::Certificate& identityCert, Face& m_face,
                     security::v2::KeyChain& keyChain);

  ~AttributeAuthority();

private:
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

private:
  security::v2::Certificate m_cert;
  Face& m_face;
  security::v2::KeyChain& m_keyChain;

  algo::PublicParams m_pubParams;
  algo::MasterKey m_masterKey;
  std::list<security::v2::Certificate> m_trustAnchors;
  TrustConfig m_trustConfig;

private:
  std::list<const RegisteredPrefixId*> m_registeredPrefixIds;
  std::list<const InterestFilterId*> m_interestFilterIds;
};

} // namespace ndnabac
} // namespace ndn

#endif // NDNABAC_ATTRIBUTE_AUTHORITY_HPP
