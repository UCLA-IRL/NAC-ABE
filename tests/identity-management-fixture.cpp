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

#include "identity-management-fixture.hpp"

#include <ndn-cxx/util/io.hpp>
#include <boost/filesystem.hpp>

namespace ndn {
namespace ndnabac {
namespace tests {

IdentityManagementFixture::IdentityManagementFixture()
  : m_keyChain("pib-memory", "tmp-memory:")
{
}

IdentityManagementFixture::~IdentityManagementFixture()
{
  boost::system::error_code ec;
  for (const auto& certFile : m_certFiles) {
    boost::filesystem::remove(certFile, ec); // ignore error
  }
}

security::Identity
IdentityManagementFixture::addIdentity(const Name& identityName, const KeyParams& params)
{
  auto identity = m_keyChain.createIdentity(identityName, params);
  m_identities.insert(identityName);
  return identity;
}

bool
IdentityManagementFixture::saveCertToFile(const Data& obj, const std::string& filename)
{
  m_certFiles.insert(filename);
  try {
    io::save(obj, filename);
    return true;
  }
  catch (const io::Error&) {
    return false;
  }
}

bool
IdentityManagementFixture::saveIdentityCertificate(const security::Identity& identity,
                                                   const std::string& filename)
{
  try {
    auto cert = identity.getDefaultKey().getDefaultCertificate();
    return saveCertToFile(cert, filename);
  }
  catch (const security::Pib::Error&) {
    return false;
  }
}

} // namespace tests
} // namespace ndnabac
} // namespace ndn
