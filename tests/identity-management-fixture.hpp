/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2014-2016, Regents of the University of California,
 *                          Arizona Board of Regents,
 *                          Colorado State University,
 *                          University Pierre & Marie Curie, Sorbonne University,
 *                          Washington University in St. Louis,
 *                          Beijing Institute of Technology,
 *                          The University of Memphis.
 *
 * This file, originally written as part of NFD (Named Data Networking Forwarding Daemon),
 * is a part of ChronoShare, a decentralized file sharing application over NDN.
 *
 * ChronoShare is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation, either
 * version 3 of the License, or (at your option) any later version.
 *
 * ChronoShare is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received copies of the GNU General Public License along with
 * ChronoShare, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of ChronoShare authors and contributors.
 */

#ifndef NDNABAC_TESTS_IDENTITY_MANAGEMENT_FIXTURE_HPP
#define NDNABAC_TESTS_IDENTITY_MANAGEMENT_FIXTURE_HPP

#include "test-common.hpp"

#include <ndn-cxx/security/key-chain.hpp>

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

  /**
   * @brief Add identity @p identityName
   * @return name of the created self-signed certificate
   */
  security::Identity
  addIdentity(const Name& identityName, const KeyParams& params = security::v2::KeyChain::getDefaultKeyParams());

  bool
  saveCertToFile(const Data& obj, const std::string& filename);

  /**
   *  @brief Save identity certificate to a file
   *  @param identity identity
   *  @param filename file name, should be writable
   *  @return whether successful
   */
  bool
  saveIdentityCertificate(const security::Identity& identity, const std::string& filename);

protected:
  security::v2::KeyChain m_keyChain;

private:
  std::set<Name> m_identities;
  std::set<std::string> m_certFiles;
};

/** \brief convenience base class for inheriting from both UnitTestTimeFixture
 *         and IdentityManagementFixture
 */
class IdentityManagementTimeFixture : public UnitTestTimeFixture
                                    , public IdentityManagementFixture
{
};

} // namespace tests
} // namespace ndnabac
} // namespace ndn

#endif // NDNABAC_TESTS_IDENTITY_MANAGEMENT_FIXTURE_HPP
