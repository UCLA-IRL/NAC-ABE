/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2017-2022, Regents of the University of California.
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

#ifndef NAC_ABE_ATTRIBUTE_AUTHORITY_HPP
#define NAC_ABE_ATTRIBUTE_AUTHORITY_HPP

#include "algo/master-key.hpp"
#include "algo/private-key.hpp"
#include "algo/public-params.hpp"
#include "trust-config.hpp"

#include <list>

namespace ndn {
namespace nacabe {

class AttributeAuthority
{
protected:
  AttributeAuthority(const security::Certificate& identityCert, Face& m_face,
                       security::KeyChain& keyChain, const AbeType& abeType);

  virtual ~AttributeAuthority();
protected:
  virtual algo::PrivateKey getPrivateKey(Name identityName) = 0;

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  void
  onDecryptionKeyRequest(const Interest& interest);

  void
  onPublicParamsRequest(const Interest& interest);

  void
  onRegisterFailed(const std::string& reason);

PUBLIC_WITH_TESTS_ELSE_PROTECTED:
  security::Certificate m_cert;
  Face& m_face;
  security::KeyChain& m_keyChain;

  AbeType m_abeType;
  algo::PublicParams m_pubParams;
  algo::MasterKey m_masterKey;

  TrustConfig m_trustConfig;

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  std::list<RegisteredPrefixHandle> m_registeredPrefixIds;
  std::list<InterestFilterHandle> m_interestFilterIds;
};

class CpAttributeAuthority: public AttributeAuthority
{
public:
  CpAttributeAuthority(const security::Certificate& identityCert, Face& m_face,
                       security::KeyChain& keyChain);

  ~CpAttributeAuthority();

  /**
   * @brief Add a new policy <decryptor name, decryptor attributes> into the state.
   *
   * Note that we only support RSA decryptor certificate for the purpose of key encryption.
   *
   * @param decryptorCert The decryptor's certificate, will be added into known identities as well.
   * @param attributes The attributes owned by the decryptor.
   */
  void
  addNewPolicy(const security::Certificate& decryptorCert, const std::list<std::string>& attributes);

  /**
   * @brief Add a new policy <decryptor name, decryptor attributes> into the state.
   * @param decryptorIdentityName The decryptor's name.
   *                              This assumes its certificate has already been stored in the known identities.
   *                              Otherwise it will throw an error when the decryptor asks for the key.
   * @param attributes The attributes owned by the decryptor.
   */
  void
  addNewPolicy(const Name& decryptorIdentityName, const std::list<std::string>& attributes);

protected:
  algo::PrivateKey getPrivateKey(Name identityName) override;

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  std::map<Name/* Consumer Identity */, std::list<std::string>/* Attr */> m_tokens;
};

class KpAttributeAuthority: public AttributeAuthority
{
public:
  KpAttributeAuthority(const security::Certificate& identityCert, Face& m_face,
                       security::KeyChain& keyChain);

  ~KpAttributeAuthority();

  /**
   * @brief Add a new policy <decryptor name, decryptor attributes> into the state.
   *
   * Note that we only support RSA decryptor certificate for the purpose of key encryption.
   *
   * @param decryptorCert The decryptor's certificate, will be added into known identities as well.
   * @param policy The access policy of the decryptor.
   */
  void
  addNewPolicy(const security::Certificate& decryptorCert, const Policy& policy);

  /**
   * @brief Add a new policy <decryptor name, decryptor attributes> into the state.
   * @param decryptorIdentityName The decryptor's name.
   *                              This assumes its certificate has already been stored in the known identities.
   *                              Otherwise it will throw an error when the decryptor asks for the key.
   * @param policy The access policy of the decryptor.
   */
  void
  addNewPolicy(const Name& decryptorIdentityName, const Policy& policy);

  algo::PrivateKey getPrivateKey(Name identityName) override;

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  std::map<Name/* Consumer Identity */, Policy> m_tokens;
};

} // namespace nacabe
} // namespace ndn

#endif // NAC_ABE_ATTRIBUTE_AUTHORITY_HPP
