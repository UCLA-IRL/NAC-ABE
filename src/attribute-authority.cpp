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
  const RegisteredPrefixId* prefixId = m_face.registerPrefix(m_cert.getIdentity(),
        [&] (const Name& name) {
          _LOG_TRACE("Prefix " << name << " got registered");
          const InterestFilterId* filterId;

          // public parameter filter
          filterId = m_face.setInterestFilter(Name(name).append("PUBPARAMS"),
                                              bind(&CaModule::onPublicParamsRequest, this, _2, item));
          m_interestFilterIds.push_back(filterId);
          _LOG_TRACE("InterestFilter " << Name(name).append("PUBPARAMS") << " got set");

          // decryption key filter
          filterId = m_face.setInterestFilter(Name(name).append("DKEY"),
                                              bind(&CaModule::onDecryptionKeyRequest, this, _2, item));
          m_interestFilterIds.push_back(filterId);
          _LOG_TRACE("InterestFilter " << Name(name).append("PUBPARAMS") << " got set");
        },
        bind(&CaModule::onRegisterFailed, this, _2));
  m_registeredPrefixIds.push_back(prefixId);
}

AttributeAuthority::~AttributeAuthority()
{

}

void
AttributeAuthority::onDecryptionKeyRequest(const Interest& interest)
{}

void
AttributeAuthority::onPublicParamsRequest(const Interest& interest)
{}

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
