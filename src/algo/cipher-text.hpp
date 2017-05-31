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

#ifndef NDNABAC_ALGO_CIPHER_TEXT_HPP
#define NDNABAC_ALGO_CIPHER_TEXT_HPP

#include "algo-common.hpp"
#include "public-params.hpp"

namespace ndn {
namespace ndnabac {
namespace algo {

class CipherText
{
public:
  /**
   * @brief Fast encoding or block size estimation
   */
  template<encoding::Tag TAG>
  size_t
  wireEncode(EncodingImpl<TAG>& encoder) const;

  /**
   * @brief Encode to a wire format
   */
  const Block&
  wireEncode() const;

  /**
   * @brief Decode the input from wire format
   */
  void
  wireDecode(const Block& wire);

private:
  static const uint32_t TLV_EncryptedAesKey;
  static const uint32_t TLV_EncryptedContent;
  static const uint32_t TLV_PlainTextSize;

public:
  GByteArray* m_cph; // encrypted AES key
  Buffer m_content; // encrypted content
  uint32_t m_plainTextSize; // plain text length

  mutable Block m_wire;
};

} // namespace algo
} // namespace ndnabac
} // namespace ndn

#endif // NDNABAC_ALGO_CIPHER_TEXT_HPP
