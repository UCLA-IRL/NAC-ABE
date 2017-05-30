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

#include "abe-support.hpp"

namespace ndn {
namespace ndnabac {
namespace algo {

void
ABESupport::setup(PublicParams& pubParams, MasterKey& masterKey)
{
  bswabe_pub_t* pub = pubParams.m_pub;
  bswabe_msk_t* msk = masterKey.m_msk;

  bswabe_setup(&pub, &msk);
}

PrivateKey
ABESupport::prvKeyGen(const PublicParams& pubParams, const MasterKey& masterKey,
                      const std::vector<std::string>& attrList)
{
  bswabe_pub_t* pub = pubParams.m_pub;
  bswabe_msk_t* msk = masterKey.m_msk;

  // change list<string> to char**
  char* attrs[attrList.size() + 1];
  for (size_t i = 0; i < attrList.size(); i++) {
    char *cstr = new char[attrList[i].length() + 1];
    std::strcpy(cstr, attrList[i].c_str());
    attrs[i] = cstr;
  }
  attrs[attrList.size()] = nullptr;

  bswabe_prv_t* prv = bswabe_keygen(pub, msk, attrs);
  PrivateKey privateKey;
  privateKey.m_prv = prv;
  return privateKey;
}

CipherText
ABESupport::encrypt(const PublicParams& pubParams,
                    const std::string& policy, const Buffer& plainText)
{
  return CipherText;
}

Buffer
ABESupport::decrypt(const PublicParams& pubParams,
                    const PrivateKey& prvKey, const CipherText& cipherText)
{
  return Buffer;
}

} // namespace algo
} // namespace ndnabac
} // namespace ndn
