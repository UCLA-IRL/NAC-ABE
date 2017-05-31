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

#include "abe-support.hpp"

namespace ndn {
namespace ndnabac {
namespace algo {

void
ABESupport::setup(PublicParams& pubParams, MasterKey& masterKey)
{
  bswabe_pub_t* pub = pubParams.m_pub;
  bswabe_msk_t* msk = masterKey.m_msk;

  bswabe_setup(&pub, &msk);
}

PrivateKey
ABESupport::prvKeyGen(const PublicParams& pubParams, const MasterKey& masterKey,
                      const std::vector<std::string>& attrList)
{
  bswabe_pub_t* pub = pubParams.m_pub;
  bswabe_msk_t* msk = masterKey.m_msk;

  // change list<string> to char**
  char* attrs[attrList.size() + 1];
  for (size_t i = 0; i < attrList.size(); i++) {
    char *cstr = new char[attrList[i].length() + 1];
    std::strcpy(cstr, attrList[i].c_str());
    attrs[i] = cstr;
  }
  attrs[attrList.size()] = nullptr;

  bswabe_prv_t* prv = bswabe_keygen(pub, msk, attrs);
  PrivateKey privateKey;
  privateKey.m_prv = prv;
  return privateKey;
}

CipherText
ABESupport::encrypt(const PublicParams& pubParams,
                    const std::string& policy, Buffer plainText)
{
  element_t m;
  CipherText result;

  char *policyCharArray = new char[policy.length() + 1];
  strcpy(policyCharArray, policy.c_str());

  result.m_cph = bswabe_enc(pubParams.m_pub, m, policyCharArray);

  delete [] policyCharArray;

  GByteArray content{plainText.buf(), static_cast<guint>(plainText.size())};
  GByteArray* encryptedContent = aes_128_encrypt(&content, m);

  result.m_content = Buffer(encryptedContent->data, encryptedContent->len);
  return result;
}

Buffer
ABESupport::decrypt(const PublicParams& pubParams,
                    const PrivateKey& prvKey, CipherText cipherText)
{
  element_t m;

  bswabe_dec(pubParams.m_pub, prvKey.m_prv, cipherText.m_cph, m);

  GByteArray content{cipherText.m_content.buf(), static_cast<guint>(cipherText.m_content.size())};
  GByteArray* result = aes_128_decrypt(&content, m);
  return Buffer(result->data, result->len);
}

void
ABESupport::init_aes(element_t k, int enc, AES_KEY* key, unsigned char* iv)
{
  int key_len;
  unsigned char* key_buf;

  key_len = element_length_in_bytes(k) < 17 ? 17 : element_length_in_bytes(k);
  key_buf = (unsigned char*) malloc(key_len);
  element_to_bytes(key_buf, k);

  if( enc )
    AES_set_encrypt_key(key_buf + 1, 128, key);
  else
    AES_set_decrypt_key(key_buf + 1, 128, key);
  free(key_buf);

  memset(iv, 0, 16);
}

GByteArray*
ABESupport::aes_128_encrypt(GByteArray* pt, element_t k)
{
  AES_KEY key;
  unsigned char iv[16];
  GByteArray* ct;
  guint8 len[4];
  guint8 zero;

  init_aes(k, 1, &key, iv);

  /* stuff in real length (big endian) before padding */
  len[0] = (pt->len & 0xff000000)>>24;
  len[1] = (pt->len & 0xff0000)>>16;
  len[2] = (pt->len & 0xff00)>>8;
  len[3] = (pt->len & 0xff)>>0;
  g_byte_array_prepend(pt, len, 4);

  /* pad out to multiple of 128 bit (16 byte) blocks */
  zero = 0;
  while( pt->len % 16 )
    g_byte_array_append(pt, &zero, 1);

  ct = g_byte_array_new();
  g_byte_array_set_size(ct, pt->len);

  AES_cbc_encrypt(pt->data, ct->data, pt->len, &key, iv, AES_ENCRYPT);

  return ct;
}

GByteArray*
ABESupport::aes_128_decrypt(GByteArray* ct, element_t k)
{
  AES_KEY key;
  unsigned char iv[16];
  GByteArray* pt;
  unsigned int len;

  init_aes(k, 0, &key, iv);

  pt = g_byte_array_new();
  g_byte_array_set_size(pt, ct->len);

  AES_cbc_encrypt(ct->data, pt->data, ct->len, &key, iv, AES_DECRYPT);

  /* get real length */
  len = 0;
  len = len
    | ((pt->data[0])<<24) | ((pt->data[1])<<16)
    | ((pt->data[2])<<8)  | ((pt->data[3])<<0);
  g_byte_array_remove_index(pt, 0);
  g_byte_array_remove_index(pt, 0);
  g_byte_array_remove_index(pt, 0);
  g_byte_array_remove_index(pt, 0);

  /* truncate any garbage from the padding */
  g_byte_array_set_size(pt, len);

  return pt;
}

} // namespace algo
} // namespace ndnabac
} // namespace ndn
