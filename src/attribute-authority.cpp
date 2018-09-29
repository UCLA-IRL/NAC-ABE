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
#include "json-helper.hpp"
#include "token-issuer.hpp"
#include "ndn-crypto/data-enc-dec.hpp"

#include <ndn-cxx/security/transform/public-key.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>

namespace ndn {
namespace ndnabac {

NDN_LOG_INIT(ndnabac.attribute-authority);

const Name AttributeAuthority::PUBLIC_PARAMS = "/PUBPARAMS";
const Name AttributeAuthority::DECRYPT_KEY = "/DKEY";

//public
AttributeAuthority::AttributeAuthority(const security::v2::Certificate& identityCert, Face& face,
                                       security::v2::KeyChain& keyChain)
  : m_cert(identityCert)
  , m_face(face)
  , m_keyChain(keyChain)
{
  // ABE setup
  NDN_LOG_INFO("Set up public parameters and master key.");
  algo::ABESupport::setup(m_pubParams, m_masterKey);

  // prefix registration
  const RegisteredPrefixId* prefixId = m_face.registerPrefix(m_cert.getIdentity(),
    [&] (const Name& name) {
      NDN_LOG_TRACE("Prefix " << name << " got registered");
      const InterestFilterId* filterId;

      // public parameter filter
      filterId = m_face.setInterestFilter(Name(name).append(PUBLIC_PARAMS),
                                          bind(&AttributeAuthority::onPublicParamsRequest, this, _2));
      m_interestFilterIds.push_back(filterId);
      NDN_LOG_TRACE("InterestFilter " << Name(name).append(PUBLIC_PARAMS) << " got set");

      // decryption key filter
      filterId = m_face.setInterestFilter(Name(name).append(DECRYPT_KEY),
                                          bind(&AttributeAuthority::onDecryptionKeyRequest, this, _2));
      m_interestFilterIds.push_back(filterId);
      NDN_LOG_TRACE("InterestFilter " << Name(name).append(DECRYPT_KEY) << " got set");
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
AttributeAuthority::onDecryptionKeyRequest(const Interest& request)
{
  // naming: /AA-prefix/DKEY/<identity name block>/<signature>

  NDN_LOG_INFO("get DKEY request:"<<request.getName());
  Name identityName(request.getName().at(m_cert.getIdentity().size() + 1).blockFromValue());

  // verify request and generate token
  JsonSection root;
  security::v2::Certificate consumerCert;
  for (auto anchor : m_trustConfig.m_trustAnchors) {
    if (anchor.getIdentity() == identityName) {
      if (!security::verifySignature(request, anchor)) {
        NDN_LOG_TRACE("Interest is with bad signature");
        return;
      }
      consumerCert = anchor;
      break;
    }
  }
  std::vector<std::string> attrs;
  for (auto attrName : m_tokens[identityName]) {
    attrs.push_back(attrName);
  }

  // generate ABE private key and do encryption
  algo::PrivateKey ABEPrvKey = algo::ABESupport::prvKeyGen(m_pubParams, m_masterKey, attrs);
  auto prvBuffer = ABEPrvKey.toBuffer();

  // reply interest with encrypted private key
  Data result;
  result.setName(request.getName());
  result.setContent(encryptDataContentWithCK(prvBuffer.data(), prvBuffer.size(),
                                             consumerCert.getPublicKey().data(),
                                             consumerCert.getPublicKey().size()));
  m_keyChain.sign(result, signingByCertificate(m_cert));
  m_face.put(result);
}

void
AttributeAuthority::onPublicParamsRequest(const Interest& interest)
{
  // naming: /AA-prefix/PUBLICPARAMS
  NDN_LOG_INFO("on public Params request:"<<interest.getName());
  Data result;
  Name dataName = interest.getName();
  dataName.appendTimestamp();
  result.setName(dataName);
  const auto& contentBuf = m_pubParams.toBuffer();
  result.setContent(makeBinaryBlock(ndn::tlv::Content,
                                    contentBuf.data(), contentBuf.size()));
  NDN_LOG_DEBUG("before sign");
  m_keyChain.sign(result, signingByCertificate(m_cert));

  NDN_LOG_TRACE("Reply public params request.");
  NDN_LOG_TRACE("Pub params size: " << contentBuf.size());

  m_face.put(result);
}

void
AttributeAuthority::onRegisterFailed(const std::string& reason)
{
  NDN_LOG_TRACE("Error: failed to register prefix in local hub's daemon, REASON: " << reason);
}

void
AttributeAuthority::init()
{
  // do noting for now
}

} // namespace ndnabac
} // namespace ndn
