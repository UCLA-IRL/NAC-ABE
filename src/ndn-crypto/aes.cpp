/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2018-2019,  Regents of the University of California
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
#include <ndn-cxx/util/random.hpp>
#include <ndn-cxx/encoding/buffer-stream.hpp>
#include <ndn-cxx/security/transform/buffer-source.hpp>
#include <ndn-cxx/security/transform/stream-sink.hpp>

namespace ndn {
namespace ndnabac {

Buffer
Aes::generateKey(const AesKeyParams& keyParams)
{
  int length = keyParams.getKeySize() / 8;
  uint8_t key[length];

  try {
    random::generateSecureBytes(key, sizeof(key));
  }
  catch (const std::runtime_error& e) {
    BOOST_THROW_EXCEPTION(NacAlgoError("Cannot generate random AES key of length " + std::to_string(length)));
  }
  return Buffer(key, sizeof(key));
}

Buffer
Aes::generateIV(const uint8_t& ivLength)
{
  if (ivLength == 0) {
    BOOST_THROW_EXCEPTION(NacAlgoError("IV length cannot be zero"));
  }

  Buffer iv;
  iv.resize(ivLength);
  try {
    random::generateSecureBytes(iv.data(), iv.size());
  }
  catch (const std::runtime_error& e) {
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
Aes::decrypt(const uint8_t* key, size_t keyLen,
             const uint8_t* payload, size_t payloadLen,
             const Buffer& iv, const AES_BLOCK_CIPHER_MODE& mode)
{
  if (mode != AES_CBC) {
    BOOST_THROW_EXCEPTION(NacAlgoError("unsupported AES decryption mode"));
  }

  OBufferStream os;
  security::transform::bufferSource(payload, payloadLen)
    >> security::transform::blockCipher(BlockCipherAlgorithm::AES_CBC,
                                        CipherOperator::DECRYPT,
                                        key, keyLen, iv.data(), iv.size())
    >> security::transform::streamSink(os);

  auto result = os.buf();
  return *result;
}

Buffer
Aes::encrypt(const uint8_t* key, size_t keyLen,
             const uint8_t* payload, size_t payloadLen,
             const Buffer& iv, const AES_BLOCK_CIPHER_MODE& mode)
{
  if (mode != AES_CBC) {
    BOOST_THROW_EXCEPTION(NacAlgoError("unsupported AES decryption mode"));
  }

  OBufferStream os;
  security::transform::bufferSource(payload, payloadLen)
    >> security::transform::blockCipher(BlockCipherAlgorithm::AES_CBC,
                                        CipherOperator::ENCRYPT,
                                        key, keyLen, iv.data(), iv.size())
    >> security::transform::streamSink(os);

  auto result = os.buf();
  return *result;
}

} // namespace ndnabac
} // namespace ndn
