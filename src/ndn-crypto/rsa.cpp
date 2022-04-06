/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2017-2022, Regents of the University of California.
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
Rsa::generateKey(const RsaKeyParams& params)
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
  sKey.loadPkcs1(keyBits);

  auto pKeyBits = sKey.derivePublicKey();
  security::transform::PublicKey pKey;
  pKey.loadPkcs8(*pKeyBits);

  OBufferStream os;
  pKey.savePkcs8(os);
  return *os.buf();
}

Buffer
Rsa::decrypt(span<const uint8_t> key, span<const uint8_t> payload)
{
  security::transform::PrivateKey sKey;
  sKey.loadPkcs1(key);

  auto decrypted = sKey.decrypt(payload);
  return *decrypted;
}

Buffer
Rsa::encrypt(span<const uint8_t> key, span<const uint8_t> payload)
{
  security::transform::PublicKey pKey;
  pKey.loadPkcs8(key);

  auto cipherText = pKey.encrypt(payload);
  return *cipherText;
}

} // namespace nacabe
} // namespace ndn
