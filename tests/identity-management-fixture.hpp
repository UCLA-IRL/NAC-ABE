/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2014-2017, Regents of the University of California,
 *                          Arizona Board of Regents,
 *                          Colorado State University,
 *                          University Pierre & Marie Curie, Sorbonne University,
 *                          Washington University in St. Louis,
 *                          Beijing Institute of Technology,
 *                          The University of Memphis.
 *
 * This file, originally written as part of NFD (Named Data Networking Forwarding Daemon),
 * is a part of ndnabac, a certificate management system based on NDN.
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

#ifndef NDNABAC_TESTS_IDENTITY_MANAGEMENT_FIXTURE_HPP
#define NDNABAC_TESTS_IDENTITY_MANAGEMENT_FIXTURE_HPP

#include "test-common.hpp"
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/v2/key-chain.hpp>
#include <ndn-cxx/security/v2/additional-description.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>

namespace ndn {
namespace ndnabac {
namespace tests {

/** \brief a fixture that cleans up KeyChain identities and certificate files upon destruction
 */
class IdentityManagementFixture : public virtual BaseFixture
{
public:
  IdentityManagementFixture();

  /** \brief deletes created identities and saved certificate files
   */
  ~IdentityManagementFixture();

  /** \brief add identity
   *  \return whether successful
   */
  bool
  addIdentity(const Name& identity,
              const ndn::KeyParams& params = ndn::KeyChain::DEFAULT_KEY_PARAMS);

  /** \brief save identity certificate to a file
   *  \param identity identity name
   *  \param filename file name, should be writable
   *  \param wantAdd if true, add new identity when necessary
   *  \return whether successful
   */
  bool
  saveIdentityCertificate(const Name& identity, const std::string& filename, bool wantAdd = false);

protected:
  ndn::KeyChain m_keyChain;

private:
  std::vector<ndn::Name> m_identities;
  std::vector<std::string> m_certFiles;
};

/**
 * @brief A test suite level fixture to help with identity management
 *
 * Test cases in the suite can use this fixture to create identities.  Identities,
 * certificates, and saved certificates are automatically removed during test teardown.
 */
class IdentityManagementV2Fixture
{
public:
  IdentityManagementV2Fixture();

  /**
   * @brief Add identity @p identityName
   * @return name of the created self-signed certificate
   */
  security::Identity
  addIdentity(const Name& identityName, const KeyParams& params = security::v2::KeyChain::getDefaultKeyParams());

  /**
   *  @brief Save identity certificate to a file
   *  @param identity identity
   *  @param filename file name, should be writable
   *  @return whether successful
   */
  bool
  saveIdentityCertificate(const security::Identity& identity, const std::string& filename);

  /**
   * @brief Issue a certificate for \p subIdentityName signed by \p issuer
   *
   *  If identity does not exist, it is created.
   *  A new key is generated as the default key for identity.
   *  A default certificate for the key is signed by the issuer using its default certificate.
   *
   *  @return the sub identity
   */
  security::Identity
  addSubCertificate(const Name& subIdentityName, const security::Identity& issuer,
                    const KeyParams& params = security::v2::KeyChain::getDefaultKeyParams());

  /**
   * @brief Add a self-signed certificate to @p key with issuer ID @p issuer
   */
  security::v2::Certificate
  addCertificate(const security::Key& key, const std::string& issuer);

  bool
  saveCertToFile(const Data& obj, const std::string& filename);

protected:
  std::set<Name> m_identities;
  std::set<std::string> m_certFiles;
  security::v2::KeyChain m_keyChain;
};

/** \brief convenience base class for inheriting from both UnitTestTimeFixture
 *         and IdentityManagementFixture
 */
class IdentityManagementTimeFixture : public UnitTestTimeFixture
                                    , public IdentityManagementFixture
{
};

/** \brief convenience base class for inheriting from both UnitTestTimeFixture
 *         and IdentityManagementV2Fixture
 */
class IdentityManagementV2TimeFixture : public UnitTestTimeFixture
                                      , public IdentityManagementV2Fixture
{
};

} // namespace tests
} // namespace ndnabac
} // namespace ndn

#endif // NDNABAC_TESTS_IDENTITY_MANAGEMENT_FIXTURE_HPP
