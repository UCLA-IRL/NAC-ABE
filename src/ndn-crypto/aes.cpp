/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2018-2022,  Regents of the University of California
 *
 * This file is part of NAC-ABE.
 * See AUTHORS.md for complete list of NAC-ABE authors and contributors.
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

#include "aes.hpp"
#include "error.hpp"

#include <ndn-cxx/encoding/buffer-stream.hpp>
#include <ndn-cxx/security/transform/buffer-source.hpp>
#include <ndn-cxx/security/transform/stream-sink.hpp>
#include <ndn-cxx/util/random.hpp>

namespace ndn {
namespace nacabe {

Buffer
Aes::generateKey(const AesKeyParams& keyParams)
{
  size_t length = keyParams.getKeySize() / 8;
  Buffer key(length);
  try {
    random::generateSecureBytes(key);
  }
  catch (const std::runtime_error&) {
    BOOST_THROW_EXCEPTION(NacAlgoError("Cannot generate random AES key of length " + std::to_string(length)));
  }
  return key;
}

Buffer
Aes::generateIV(uint8_t ivLength)
{
  if (ivLength == 0) {
    BOOST_THROW_EXCEPTION(NacAlgoError("IV length cannot be zero"));
  }

  Buffer iv(ivLength);
  try {
    random::generateSecureBytes(iv);
  }
  catch (const std::runtime_error&) {
    BOOST_THROW_EXCEPTION(NacAlgoError("Cannot generate random IV of length " + std::to_string(ivLength)));
  }
  return iv;
}

Buffer
Aes::deriveEncryptKey(const Buffer& keyBits)
{
  Buffer copy = keyBits;
  return copy;
}

Buffer
Aes::decrypt(span<const uint8_t> key, span<const uint8_t> payload,
             const Buffer& iv, AES_BLOCK_CIPHER_MODE mode)
{
  if (mode != AES_CBC) {
    BOOST_THROW_EXCEPTION(NacAlgoError("unsupported AES decryption mode"));
  }

  OBufferStream os;
  security::transform::bufferSource(payload)
    >> security::transform::blockCipher(BlockCipherAlgorithm::AES_CBC,
                                        CipherOperator::DECRYPT, key, iv)
    >> security::transform::streamSink(os);

  auto result = os.buf();
  return *result;
}

Buffer
Aes::encrypt(span<const uint8_t> key, span<const uint8_t> payload,
             const Buffer& iv, AES_BLOCK_CIPHER_MODE mode)
{
  if (mode != AES_CBC) {
    BOOST_THROW_EXCEPTION(NacAlgoError("unsupported AES decryption mode"));
  }

  OBufferStream os;
  security::transform::bufferSource(payload)
    >> security::transform::blockCipher(BlockCipherAlgorithm::AES_CBC,
                                        CipherOperator::ENCRYPT, key, iv)
    >> security::transform::streamSink(os);

  auto result = os.buf();
  return *result;
}

} // namespace nacabe
} // namespace ndn
