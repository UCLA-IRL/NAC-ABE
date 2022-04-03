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

#include "data-enc-dec.hpp"
#include "aes.hpp"
#include "rsa.hpp"

namespace ndn {
namespace nacabe {

Block
encryptDataContentWithCK(span<const uint8_t> payload, span<const uint8_t> rsaKey)
{
  // first create AES key and cpEncrypt the payload
  AesKeyParams params;
  auto aesKey = Aes::generateKey(params);
  auto iv = Aes::generateIV();
  auto encryptedPayload = Aes::encrypt(aesKey, payload, iv);

  // second use RSA key to cpEncrypt the AES key
  auto encryptedAesKey = Rsa::encrypt(rsaKey, aesKey);

  // create the content block
  auto content = makeEmptyBlock(tlv::Content);
  content.push_back(makeBinaryBlock(TLV_EncryptedContent, encryptedPayload));
  content.push_back(makeBinaryBlock(TLV_EncryptedAesKey, encryptedAesKey));
  content.push_back(makeBinaryBlock(TLV_InitialVector, iv));
  content.encode();
  return content;
}

Buffer
decryptDataContent(const Block& dataBlock, span<const uint8_t> key)
{
  dataBlock.parse();
  Buffer iv(dataBlock.get(TLV_InitialVector).value(),
            dataBlock.get(TLV_InitialVector).value_size());
  Buffer encryptedAesKey(dataBlock.get(TLV_EncryptedAesKey).value(),
                         dataBlock.get(TLV_EncryptedAesKey).value_size());
  Buffer encryptedPayload(dataBlock.get(TLV_EncryptedContent).value(),
                          dataBlock.get(TLV_EncryptedContent).value_size());

  auto aesKey = Rsa::decrypt(key, encryptedAesKey);
  auto payload = Aes::decrypt(aesKey, encryptedPayload, iv);
  return payload;
}

Buffer
decryptDataContent(const Block& dataBlock, const security::Tpm& tpm, const Name& certName)
{
  dataBlock.parse();
  Buffer iv(dataBlock.get(TLV_InitialVector).value(),
            dataBlock.get(TLV_InitialVector).value_size());
  Buffer encryptedAesKey(dataBlock.get(TLV_EncryptedAesKey).value(),
                         dataBlock.get(TLV_EncryptedAesKey).value_size());
  Buffer encryptedPayload(dataBlock.get(TLV_EncryptedContent).value(),
                          dataBlock.get(TLV_EncryptedContent).value_size());

  // auto aesKey = Rsa::cpDecrypt(key, keyLen, encryptedAesKey.data(), encryptedAesKey.size());
  auto aesKey = tpm.decrypt(encryptedAesKey, security::extractKeyNameFromCertName(certName));
  auto payload = Aes::decrypt(*aesKey, encryptedPayload, iv);
  return payload;
}

} // namespace nacabe
} // namespace ndn
