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

#ifndef NAC_ABE_ALGO_ABE_SUPPORT_HPP
#define NAC_ABE_ALGO_ABE_SUPPORT_HPP

#include "algo-common.hpp"
#include "public-params.hpp"
#include "master-key.hpp"
#include "private-key.hpp"
#include "cipher-text.hpp"

#include <openssl/aes.h>
#include <openssl/sha.h>

namespace ndn {
namespace nacabe {
namespace algo {

class ABESupport
{
public:
  static void
  setup(PublicParams& pubParams, MasterKey& masterKey);

  /**
   * The policy is specified as a simple string which encodes a postorder
   * traversal of threshold tree defining the access policy. As an
   * example:
   * "foo bar fim 2of3 baf 1of2"
   */
  static PrivateKey
  prvKeyGen(PublicParams& pubParams, MasterKey& masterKey,
            const std::vector<std::string>& attrList);

  static CipherText
  encrypt(const PublicParams& pubParams,
          const std::string& policy, Buffer plaintext);

  static Buffer
  decrypt(const PublicParams& pubParams,
          const PrivateKey& prvKey, CipherText cipherText);

public:
  static void
  prependToArray(GByteArray* pt, const guint8 *data, guint dataSize);

  static void
  removeFrontFromArray(GByteArray* pt, uint32_t dataSize);

  static GByteArray*
  aes_128_encrypt(GByteArray* pt, element_t k);

  static GByteArray*
  aes_128_decrypt(GByteArray* ct, element_t k, uint32_t outputSize);

  static void
  init_aes(element_t k, int enc, AES_KEY* key, unsigned char* iv);
};

} // namespace algo
} // namespace nacabe
} // namespace ndn

#endif // NAC_ABE_ALGO_ABE_SUPPORT_HPP
