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

#ifndef NAC_ABE_CRYPTO_RSA_HPP
#define NAC_ABE_CRYPTO_RSA_HPP

#include <ndn-cxx/security/key-params.hpp>

namespace ndn {
namespace nacabe {

class Rsa
{
public:
  static Buffer
  generateKey(const RsaKeyParams& params);

  static Buffer
  deriveEncryptKey(const Buffer& keyBits);

  static Buffer
  decrypt(span<const uint8_t> key, span<const uint8_t> payload);

  static Buffer
  encrypt(span<const uint8_t> key, span<const uint8_t> payload);
};

} // namespace nacabe
} // namespace ndn

#endif // NAC_ABE_CRYPTO_RSA_HPP
