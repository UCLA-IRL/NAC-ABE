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

#include "cipher-text.hpp"
#include <ndn-cxx/util/concepts.hpp>

namespace ndn {
namespace nacabe {
namespace algo {

NDN_LOG_INIT(nacabe.ciphertext);

Block
CipherText::makeDataContent() const
{
  auto encryptedBlock = makeBinaryBlock(TLV_EncryptedContent,
                                        m_content.data(), m_content.size());
  return encryptedBlock;
}

Block
CipherText::makeCKContent()
{
  NDN_LOG_INFO("plaintext size : " << m_plainTextSize);
  NDN_LOG_INFO("encrypted aes key size : " << m_aesKey.size());
  auto ckBlock = makeEmptyBlock(tlv::Content);
  ckBlock.push_back(makeBinaryBlock(TLV_EncryptedAesKey, m_aesKey.data(), m_aesKey.size()));
  ckBlock.push_back(makeNonNegativeIntegerBlock(TLV_PlainTextSize, m_plainTextSize));
  ckBlock.encode();
  return ckBlock;
}

} // namespace algo
} // namespace nacabe
} // namespace ndn
