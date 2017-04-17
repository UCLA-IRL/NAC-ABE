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

#include "identity-management-fixture.hpp"

#include <ndn-cxx/util/io.hpp>
#include <boost/filesystem.hpp>

namespace ndn {
namespace ndnabac {
namespace tests {

IdentityManagementFixture::IdentityManagementFixture()
  : m_keyChain("sqlite3", "file")
{
  m_keyChain.getDefaultCertificate(); // side effect: create a default cert if it doesn't exist
}

IdentityManagementFixture::~IdentityManagementFixture()
{
  for (const auto& id : m_identities) {
    m_keyChain.deleteIdentity(id);
  }

  boost::system::error_code ec;
  for (const auto& certFile : m_certFiles) {
    boost::filesystem::remove(certFile, ec); // ignore error
  }
}

bool
IdentityManagementFixture::addIdentity(const Name& identity, const ndn::KeyParams& params)
{
  try {
    m_keyChain.createIdentity(identity, params);
    m_identities.push_back(identity);
    return true;
  }
  catch (std::runtime_error&) {
    return false;
  }
}

bool
IdentityManagementFixture::saveIdentityCertificate(const Name& identity,
                                                   const std::string& filename, bool wantAdd)
{
  shared_ptr<ndn::IdentityCertificate> cert;
  try {
    cert = m_keyChain.getCertificate(m_keyChain.getDefaultCertificateNameForIdentity(identity));
  }
  catch (const ndn::SecPublicInfo::Error&) {
    if (wantAdd && this->addIdentity(identity)) {
      return this->saveIdentityCertificate(identity, filename, false);
    }
    return false;
  }

  m_certFiles.push_back(filename);
  try {
    ndn::io::save(*cert, filename);
    return true;
  }
  catch (const ndn::io::Error&) {
    return false;
  }
}

IdentityManagementV2Fixture::IdentityManagementV2Fixture()
  : m_keyChain("pib-memory:", "tpm-memory:")
{
}

security::Identity
IdentityManagementV2Fixture::addIdentity(const Name& identityName, const KeyParams& params)
{
  auto identity = m_keyChain.createIdentity(identityName, params);
  m_identities.insert(identityName);
  return identity;
}

bool
IdentityManagementV2Fixture::saveIdentityCertificate(const security::Identity& identity,
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

security::Identity
IdentityManagementV2Fixture::addSubCertificate(const Name& subIdentityName,
                                               const security::Identity& issuer, const KeyParams& params)
{
  auto subIdentity = addIdentity(subIdentityName, params);

  security::v2::Certificate request = subIdentity.getDefaultKey().getDefaultCertificate();

  request.setName(request.getKeyName().append("parent").appendVersion());

  SignatureInfo info;
  info.setValidityPeriod(security::ValidityPeriod(time::system_clock::now(),
                                                  time::system_clock::now() + time::days(7300)));

  security::v2::AdditionalDescription description;
  description.set("type", "sub-certificate");
  info.appendTypeSpecificTlv(description.wireEncode());

  m_keyChain.sign(request, signingByIdentity(issuer).setSignatureInfo(info));
  m_keyChain.setDefaultCertificate(subIdentity.getDefaultKey(), request);

  return subIdentity;
}

security::v2::Certificate
IdentityManagementV2Fixture::addCertificate(const security::Key& key, const std::string& issuer)
{
  Name certificateName = key.getName();
  certificateName
    .append(issuer)
    .appendVersion();
  security::v2::Certificate certificate;
  certificate.setName(certificateName);

  // set metainfo
  certificate.setContentType(tlv::ContentType_Key);
  certificate.setFreshnessPeriod(time::hours(1));

  // set content
  certificate.setContent(key.getPublicKey().buf(), key.getPublicKey().size());

  // set signature-info
  SignatureInfo info;
  info.setValidityPeriod(security::ValidityPeriod(time::system_clock::now(),
                                                  time::system_clock::now() + time::days(10)));

  m_keyChain.sign(certificate, signingByKey(key).setSignatureInfo(info));
  return certificate;
}

bool
IdentityManagementV2Fixture::saveCertToFile(const Data& obj, const std::string& filename)
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

} // namespace tests
} // namespace ndnabac
} // namespace ndn
