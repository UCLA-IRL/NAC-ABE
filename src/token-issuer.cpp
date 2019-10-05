/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017-2019, Regents of the University of California.
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

#include "token-issuer.hpp"

#include <ndn-cxx/security/transform.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>

namespace ndn {
namespace nacabe {

NDN_LOG_INIT(nacabe.token-issuer);

const Name TokenIssuer::TOKEN_REQUEST = "/TOKEN";

const std::string TokenIssuer::TOKEN_USER = "user-pub-key";
const std::string TokenIssuer::TOKEN_ATTR_SET = "attribute-set";
const std::string TokenIssuer::TOKEN_ATTR_NAME = "attribute-name";

TokenIssuer::TokenIssuer(const security::v2::Certificate& identityCert, Face& face,
                         security::v2::KeyChain& keyChain)
  : m_cert(identityCert)
  , m_face(face)
  , m_keyChain(keyChain)
{
  // prefix registration
  auto filterId = m_face.setInterestFilter(Name(m_cert.getIdentity()).append(TOKEN_REQUEST),
                                            bind(&TokenIssuer::onTokenRequest, this, _2));
  m_interestFilterIds.push_back(filterId);
}

TokenIssuer::~TokenIssuer()
{
  for (auto prefixId : m_interestFilterIds) {
    prefixId.cancel();
  }
}

bool
TokenIssuer::insertAttributes(std::pair<Name, std::list<std::string>> nameWithAttr)
{
  m_tokens.insert(nameWithAttr);
  return true;
}

void
TokenIssuer::addCert(const security::v2::Certificate& cert)
{
  m_trustConfig.m_trustAnchors.push_back(cert);
}

void
TokenIssuer::onTokenRequest(const Interest& request)
{
  // Name: /token-issuer-name/TOKEN/<identity name block>/<signature>

  NDN_LOG_INFO("get token request:"<<request.getName());
  Name identityName(request.getName().at(m_cert.getIdentity().size() + 1).blockFromValue());

  // verify request and generate token
  JsonSection root;
  for (auto anchor : m_trustConfig.m_trustAnchors) {
    if (anchor.getIdentity() == identityName) {
      if (!security::verifySignature(request, anchor)) {
        NDN_LOG_TRACE("Interest is with bad signature");
        return;
      }

      std::stringstream ss;
      namespace t = ndn::security::transform;
      t::bufferSource(anchor.getPublicKey().data(), anchor.getPublicKey().size())
        >> t::base64Encode() >> t::streamSink(ss);
      std::string keyBitsStr = ss.str();

      NDN_LOG_TRACE("Token identity field: " << keyBitsStr);

      root.put(TOKEN_USER, keyBitsStr);
      break;
    }
  }

//  {
//    user-pub-key: xxx,
//    attribute-set: [
//      {
//        attribute-name: AA
//      },
//      {
//        attribute-name: BB
//      }
//    ],
//  }

  // rest part of the token
  JsonSection attrList;
  for (auto attrName : m_tokens[identityName]) {
    JsonSection attr;
    attr.put(TOKEN_ATTR_NAME, attrName);
    attrList.push_back(std::make_pair("", attr));
  }
  root.add_child(TOKEN_ATTR_SET, attrList);

  // wrap the token
  Data token;
  token.setFreshnessPeriod(5_s);
  token.setName(request.getName());
  token.setContent(JsonHelper::dataContentFromJson(root));
  m_keyChain.sign(token, signingByCertificate(m_cert));
  m_face.put(token);
}

} // namespace nacabe
} // namespace ndn
