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

#include "attribute-authority.hpp"
#include "logging.hpp"

namespace ndn {
namespace ndnabac {

_LOG_INIT(ndnabac.attribute-authority);

//public
AttributeAuthority::AttributeAuthority(const security::v2::Certificate& identityCert,
                                       Face& face,
                                       security::v2::KeyChain& keyChain)
  : m_cert(identityCert)
  , m_face(face)
  , m_keyChain(keyChain)
{
  // ABE setup
  algo::ABESupport::setup(m_pubParams, m_masterKey);

  // prefix registration
  const RegisteredPrefixId* prefixId = m_face.registerPrefix(m_cert.getIdentity(),
        [&] (const Name& name) {
          _LOG_TRACE("Prefix " << name << " got registered");
          const InterestFilterId* filterId;

          // public parameter filter
          filterId = m_face.setInterestFilter(Name(name).append("PUBPARAMS"),
                                              bind(&AttributeAuthority::onPublicParamsRequest, this, _2));
          m_interestFilterIds.push_back(filterId);
          _LOG_TRACE("InterestFilter " << Name(name).append("PUBPARAMS") << " got set");

          // decryption key filter
          filterId = m_face.setInterestFilter(Name(name).append("DKEY"),
                                              bind(&AttributeAuthority::onDecryptionKeyRequest, this, _2));
          m_interestFilterIds.push_back(filterId);
          _LOG_TRACE("InterestFilter " << Name(name).append("PUBPARAMS") << " got set");
        },
        bind(&AttributeAuthority::onRegisterFailed, this, _2));
  m_registeredPrefixIds.push_back(prefixId);
}

AttributeAuthority::~AttributeAuthority()
{
  for (auto prefixId : m_interestFilterIds) {
    m_face.unsetInterestFilter(prefixId);
  }
  for (auto prefixId : m_registeredPrefixIds) {
    m_face.unregisterPrefix(prefixId, nullptr, nullptr);
  }
}

void
AttributeAuthority::onDecryptionKeyRequest(const Interest& interest)
{
  //naming: /AA-prefix/DKEY/<token>
}

void
AttributeAuthority::onPublicParamsRequest(const Interest& interest)
{
  //naming: /AA-prefix/PUBLICPARAMS

  // Data result;
  // result.setName(interest.getName());
  // result.setContent();
  // m_keyChain.sign(result, signingByCertificate(caItem.m_anchor));
  // m_face.put(result);
}

void
AttributeAuthority::onRegisterFailed(const std::string& reason)
{
  _LOG_TRACE("Error: failed to register prefix in local hub's daemon, REASON: " << reason);
}

algo::PrivateKey
AttributeAuthority::issueDecryptionKey(const std::list<std::string>& attrList)
{
  return algo::PrivateKey();
}

void
AttributeAuthority::init()
{}

} // namespace ndnabac
} // namespace ndn
