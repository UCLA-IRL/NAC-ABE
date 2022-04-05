/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2018-2022,  Regents of the University of California
 *
 * This file is part of NAC-ABE.
 * See AUTHORS.md for complete list of NAC authors and contributors.
 *
 * NAC-ABE is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * NAC-ABE is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * NAC-ABE, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @author Zhiyi Zhang <zhiyi@cs.ucla.edu>
 */

#ifndef NAC_ABE_CRYPTO_AES_HPP
#define NAC_ABE_CRYPTO_AES_HPP

#include "crypto-common.hpp"

#include <ndn-cxx/security/transform/block-cipher.hpp>
#include <ndn-cxx/security/key-params.hpp>

namespace ndn {
namespace nacabe {

class Aes
{
public:
  static Buffer
  generateKey(const AesKeyParams& keyParams);

  static Buffer
  generateIV(uint8_t ivLength = 16);

  static Buffer
  deriveEncryptKey(const Buffer& keyBits);

  static Buffer
  decrypt(span<const uint8_t> key,
          span<const uint8_t> payload,
          const Buffer& iv,
          AES_BLOCK_CIPHER_MODE mode = AES_CBC);

  static Buffer
  encrypt(span<const uint8_t> key,
          span<const uint8_t> payload,
          const Buffer& iv,
          AES_BLOCK_CIPHER_MODE mode = AES_CBC);
};

} // namespace nacabe
} // namespace ndn

#endif // NAC_ABE_CRYPTO_AES_HPP
