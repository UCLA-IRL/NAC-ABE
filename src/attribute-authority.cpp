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
#include "algo/rsa.hpp"
#include "logging.hpp"

#include <ndn-cxx/security/transform/public-key.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>

namespace ndn {
namespace ndnabac {

_LOG_INIT(ndnabac.attribute-authority);


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
      _LOG_TRACE("Prefix " << name << " got registered");
      const InterestFilterId* filterId;

      // public parameter filter
      filterId = m_face.setInterestFilter(Name(name).append(PUBLIC_PARAMS),
                                          bind(&AttributeAuthority::onPublicParamsRequest, this, _2));
      m_interestFilterIds.push_back(filterId);
      _LOG_TRACE("InterestFilter " << Name(name).append(PUBLIC_PARAMS) << " got set");

      // decryption key filter
      filterId = m_face.setInterestFilter(Name(name).append(DECRYPT_KEY),
                                          bind(&AttributeAuthority::onDecryptionKeyRequest, this, _2));
      m_interestFilterIds.push_back(filterId);
      _LOG_TRACE("InterestFilter " << Name(name).append(DECRYPT_KEY) << " got set");
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
  // naming: /AA-prefix/DKEY/<token>

  // get token
  NDN_LOG_INFO("get decryption key request:"<<interest.getName());
  Data token;
  try {
    token.wireDecode(interest.getName().at(m_cert.getIdentity().size() + 1).blockFromValue());
  }
  catch (const std::exception& e) {
    _LOG_TRACE("Unrecognized token " << e.what());
    return;
  }

  // verify token
  Name tokenIssuerKey = token.getSignature().getKeyLocator().getName();
  for (auto anchor : m_trustConfig.m_trustAnchors) {
    if (anchor.getKeyName() == tokenIssuerKey) {
      if (!security::verifySignature(token, anchor)) {
        _LOG_TRACE("Invalid token");
        return;
      }
      break;
    }
  }

  // parse token
  std::vector<std::string> attrs;
  JsonSection tokenJson = JsonHelper::getJsonFromDataContent(token);
  std::string pubKeyStr = tokenJson.get<std::string>(TokenIssuer::TOKEN_USER);
  JsonSection attrList = tokenJson.get_child(TokenIssuer::TOKEN_ATTR_SET);
  auto it = attrList.begin();
  for (; it != attrList.end(); it++) {
    std::string attrName = it->second.get(TokenIssuer::TOKEN_ATTR_NAME, "");
    attrs.push_back(attrName);
  }

  // generate private key
  // security::transform::PublicKey pubKey;
  // std::stringstream ss(pubKeyStr);
  // _LOG_TRACE("key bits " << pubKeyStr);
  // pubKey.loadPkcs8Base64(ss);

  algo::PrivateKey prvKey = algo::ABESupport::prvKeyGen(m_pubParams, m_masterKey, attrs);
  auto prvBuffer = prvKey.toBuffer();
  // auto encryptedKey = pubKey.encrypt(prvBuffer.buf(), prvBuffer.size());

  // reply interest with encrypted private key
  Data result;
  result.setName(interest.getName());
  // result.setContent(Block(ndn::tlv::Content, encryptedKey));
  result.setContent(makeBinaryBlock(tlv::Content, prvBuffer.get(), prvBuffer.size()));
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
                                    contentBuf.buf(), contentBuf.size()));
  _LOG_DEBUG("before sign");
  m_keyChain.sign(result, signingByCertificate(m_cert));

  _LOG_TRACE("Reply public params request.");
  _LOG_TRACE("Pub params size: " << contentBuf.size());

  m_face.put(result);
}

void
AttributeAuthority::onRegisterFailed(const std::string& reason)
{
  _LOG_TRACE("Error: failed to register prefix in local hub's daemon, REASON: " << reason);
}

void
AttributeAuthority::init()
{
  // do noting for now
}

} // namespace ndnabac
} // namespace ndn
