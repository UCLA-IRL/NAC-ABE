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

#include "rsa.hpp"
#include "error.hpp"
#include <ndn-cxx/encoding/buffer-stream.hpp>
#include <ndn-cxx/security/transform/private-key.hpp>
#include <ndn-cxx/security/transform/public-key.hpp>

namespace ndn {
namespace nacabe {

Buffer
Rsa::generateKey(RsaKeyParams& params)
{
  auto privateKey = security::transform::generatePrivateKey(params);

  OBufferStream os;
  privateKey->savePkcs1(os);

  return *os.buf();
}

Buffer
Rsa::deriveEncryptKey(const Buffer& keyBits)
{
  security::transform::PrivateKey sKey;
  sKey.loadPkcs1(keyBits.get<uint8_t>(), keyBits.size());

  ConstBufferPtr pKeyBits = sKey.derivePublicKey();
  security::transform::PublicKey pKey;
  pKey.loadPkcs8(pKeyBits->data(), pKeyBits->size());

  OBufferStream os;
  pKey.savePkcs8(os);

  return *os.buf();
}

Buffer
Rsa::decrypt(const uint8_t* key, size_t keyLen,
             const uint8_t* payload, size_t payloadLen)
{
  security::transform::PrivateKey sKey;
  sKey.loadPkcs1(key, keyLen);

  auto decrypted = sKey.decrypt(payload, payloadLen);
  return *decrypted;
}

Buffer
Rsa::encrypt(const uint8_t* key, size_t keyLen,
             const uint8_t* payload, size_t payloadLen)
{
  security::transform::PublicKey pKey;
  pKey.loadPkcs8(key, keyLen);

  auto cipherText = pKey.encrypt(payload, payloadLen);
  return *cipherText;
}

} // namespace nacabe
} // namespace ndn
