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
#include "../ndn-crypto/error.hpp"
#include <ndn-cxx/util/logger.hpp>

namespace ndn {
namespace ndnabac {
namespace algo {

NDN_LOG_INIT(ndnabac.ABESupport);

void
ABESupport::setup(PublicParams& pubParams, MasterKey& masterKey)
{
  bswabe_pub_t* pub;
  bswabe_msk_t* msk;
  bswabe_setup(&pub, &msk);

  pubParams.m_pub = bswabe_pub_serialize(pub);
  masterKey.m_msk = bswabe_msk_serialize(msk);
}

PrivateKey
ABESupport::prvKeyGen(PublicParams& pubParams, MasterKey& masterKey,
                      const std::vector<std::string>& attrList)
{
  // change list<string> to char**
  char** attrs = new char*[attrList.size() + 1];
  for (size_t i = 0; i < attrList.size(); i++) {
    char *cstr = new char[attrList[i].length() + 1];
    std::strcpy(cstr, attrList[i].c_str());
    cstr[attrList[i].length()] = 0;
    attrs[i] = cstr;
  }
  attrs[attrList.size()] = 0;

  bswabe_pub_t* pub = bswabe_pub_unserialize(pubParams.m_pub, 0);
  bswabe_msk_t* msk = bswabe_msk_unserialize(pub, masterKey.m_msk, 0);
  bswabe_prv_t* prv = bswabe_keygen(pub, msk, attrs);

  PrivateKey privateKey;
  privateKey.m_prv = bswabe_prv_serialize(prv);

  for (size_t i = 0; i < attrList.size(); i++) {
    delete [] attrs[i];
  }
  delete [] attrs;
  return privateKey;
}

CipherText
ABESupport::encrypt(const PublicParams& pubParams,
                    const std::string& policy, Buffer plainText)
{
  bswabe_pub_t* pub = bswabe_pub_unserialize(pubParams.m_pub, 0);

  char *policyCharArray = new char[policy.length() + 1];
  strcpy(policyCharArray, policy.c_str());

  element_t m;
  bswabe_cph_t* cph = bswabe_enc(pub, m, policyCharArray);
  CipherText result;
  result.m_cph = bswabe_cph_serialize(cph);
  bswabe_cph_free(cph);
  delete [] policyCharArray;

  GByteArray content{plainText.data(), static_cast<guint>(plainText.size())};
  // GByteArray* content = new GByteArray{buf, length};
  GByteArray* encryptedContent = aes_128_encrypt(&content, m);
  element_clear(m);

  result.m_content = Buffer(encryptedContent->data, encryptedContent->len);
  result.m_plainTextSize = plainText.size();
  return result;
}

Buffer
ABESupport::decrypt(const PublicParams& pubParams,
                    const PrivateKey& prvKey, CipherText cipherText)
{
  bswabe_pub_t* pub = bswabe_pub_unserialize(pubParams.m_pub, 0);
  bswabe_prv_t* prv = bswabe_prv_unserialize(pub, prvKey.m_prv, 0);
  bswabe_cph_t* cph = bswabe_cph_unserialize(pub, cipherText.m_cph, 0);
  element_t m;

  if (!bswabe_dec(pub, prv, cph, m)) {
    NDN_LOG_ERROR("Decryption error!" + std::string(bswabe_error()));
    BOOST_THROW_EXCEPTION(NacAlgoError("Decryption error!" + std::string(bswabe_error())));
  }

  GByteArray content{cipherText.m_content.data(), static_cast<guint>(cipherText.m_content.size())};
  GByteArray* result = aes_128_decrypt(&content, m, cipherText.m_plainTextSize);
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

  if(enc)
    AES_set_encrypt_key(key_buf + 1, 128, key);
  else
    AES_set_decrypt_key(key_buf + 1, 128, key);
  free(key_buf);

  memset(iv, 0, 16);
}

void
ABESupport::prependToArray(GByteArray* pt, const guint8 *data, guint dataSize)
{
  std::vector<guint8> v(pt->data, pt->data + pt->len);
  auto it = v.begin();
  v.insert(it, data, data + dataSize);
  pt->data = &v[0];
  pt->len += dataSize;
}

void
ABESupport::removeFrontFromArray(GByteArray* pt, uint32_t dataSize)
{
  std::vector<guint8> v(pt->data, pt->data + pt->len);
  auto it = v.begin();
  v.erase(it, it + dataSize);
  pt->data = &v[0];
  pt->len -= dataSize;
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
  prependToArray(pt, len, 4);

  /* pad out to multiple of 128 bit (16 byte) blocks */
  zero = 0;
  while( pt->len % 16 ) {
    prependToArray(pt, &zero, 1);
  }

  ct = g_byte_array_new();
  g_byte_array_set_size(ct, pt->len);

  AES_cbc_encrypt(pt->data, ct->data, pt->len, &key, iv, AES_ENCRYPT);

  return ct;
}

GByteArray*
ABESupport::aes_128_decrypt(GByteArray* ct, element_t k, uint32_t outputSize)
{
  AES_KEY key;
  unsigned char iv[16];
  GByteArray* pt;

  init_aes(k, 0, &key, iv);

  pt = g_byte_array_new();
  g_byte_array_set_size(pt, ct->len);

  AES_cbc_encrypt(ct->data, pt->data, ct->len, &key, iv, AES_DECRYPT);

  g_byte_array_remove_index(pt, 0);
  g_byte_array_remove_index(pt, 0);
  g_byte_array_remove_index(pt, 0);
  g_byte_array_remove_index(pt, 0);

  removeFrontFromArray(pt, pt->len - outputSize);
  return pt;
}

} // namespace algo
} // namespace ndnabac
} // namespace ndn
