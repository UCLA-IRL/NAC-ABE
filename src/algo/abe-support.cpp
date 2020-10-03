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

#include "abe-support.hpp"
#include "../ndn-crypto/error.hpp"
#include <ndn-cxx/util/logger.hpp>

using namespace oabe;
using namespace oabe::crypto;

namespace ndn {
namespace nacabe {
namespace algo {

NDN_LOG_INIT(nacabe.ABESupport);

void
ABESupport::setup(PublicParams& pubParams, MasterKey& masterKey)
{
  InitializeOpenABE();
  OpenABECryptoContext kpabe("KP-ABE");
  kpabe.generateParams();
  std::string mpk, msk;
  kpabe.exportPublicParams(mpk);
  kpabe.exportSecretParams(msk);
  pubParams.m_pub = mpk;
  masterKey.m_msk = msk;
  ShutdownOpenABE();
}

PrivateKey
ABESupport::prvKeyGen(PublicParams& pubParams, MasterKey& masterKey,
                      const std::vector<std::string>& attrList)
{
  InitializeOpenABE();
  std::string privKey;
  try {
    OpenABECryptoContext kpabe("KP-ABE");
    kpabe.importPublicParams(pubParams.m_pub);
    kpabe.importSecretParams(masterKey.m_msk);

    kpabe.keygen(attrList[0], "abe-priv-key");
    kpabe.exportUserKey("abe-priv-key", privKey);
    kpabe.deleteKey("abe-priv-key");
    ShutdownOpenABE();
  } catch (oabe::ZCryptoBoxException& ex) {
    ShutdownOpenABE();
    BOOST_THROW_EXCEPTION(NacAlgoError("cannot generate private key for the policy"));
  }

  PrivateKey privateKey;
  privateKey.m_prv = privKey;
  return privateKey;
}

CipherText
ABESupport::encrypt(const PublicParams& pubParams,
                    const std::string& policy, Buffer plainText)
{
  // step 0: set up ABE Context
  InitializeOpenABE();
  try {
    OpenABECryptoContext kpabe("KP-ABE");
    kpabe.importPublicParams(pubParams.m_pub);
  
    // step 1: generate a AES symmetric key
    OpenABESymKey symKey;
    symKey.generateSymmetricKey(DEFAULT_SYM_KEY_BYTES);
    std::string symmetricKey = symKey.toString();

    // step 2: use publicParams and policy to encrypt this symmetric key
    std::string encryptedSymmetricKey;
    kpabe.encrypt(policy, symmetricKey, encryptedSymmetricKey);

    // step 3: use the AES symmetric key to encrypt the plain text
    OpenABESymKeyEnc aes(symmetricKey);
    std::string ciphertext = aes.encrypt(
      (uint8_t*) plainText.data(),
      (uint32_t) plainText.size());


    // step 4: put encryptedSymmetricKey and ciphertext in CipherText object
    //           and return the CipherText Object
    CipherText result;
    Buffer aesKeySegment((uint8_t*) encryptedSymmetricKey.c_str(),
                         (uint32_t) encryptedSymmetricKey.size() + 1);

    Buffer cipherContentSegment((uint8_t*) ciphertext.c_str(),
                                (uint32_t) ciphertext.size() + 1);
                                
    result.m_aesKey = aesKeySegment;
    result.m_content = cipherContentSegment;
    result.m_plainTextSize = plainText.size();

    // step 5: shut down ABE Context
    ShutdownOpenABE();
    return result;
  } catch (oabe::ZCryptoBoxException& ex) {
    ShutdownOpenABE();
    BOOST_THROW_EXCEPTION(NacAlgoError(
      "cannot encrypt the plaintext using given public paramater and policy."));
  }
}

Buffer
ABESupport::decrypt(const PublicParams& pubParams,
                    const PrivateKey& prvKey, CipherText cipherText)
{
  // step 0: set up ABE Context
  InitializeOpenABE();

  try {
     OpenABECryptoContext kpabe("KP-ABE");
    kpabe.importPublicParams(pubParams.m_pub);
  
    // step 1: import prvKey into OpenABE
    kpabe.enableKeyManager("user1");
    kpabe.importUserKey("key1", prvKey.m_prv);

    // step 2: decrypt cipherText.aesKey, which is the encrypted symmetric key
    std::string encryptedSymmetricKey(reinterpret_cast<char*>(cipherText.m_aesKey.data()));
    std::string symmetricKey;
    bool result = kpabe.decrypt(encryptedSymmetricKey, symmetricKey);
    if (!result) {
      BOOST_THROW_EXCEPTION(NacAlgoError("Decryption error!"));
    }
  
    // step 3: use the decrypted symmetricKey to AES decrypt cipherText.m_content
    OpenABESymKeyEnc aes(symmetricKey);
    std::string cipherContentStr(reinterpret_cast<char*>(cipherText.m_content.data()));
    std::string recoveredContent = aes.decrypt(cipherContentStr);

    // step 4: set up a Buffer for the decrypted content, and return the Buffer
    Buffer ret((uint8_t*) recoveredContent.c_str(),
                  (uint32_t) recoveredContent.size());

    // step 5: finalize
    ShutdownOpenABE();
    return ret;
  } catch (oabe::ZCryptoBoxException& ex) {
    ShutdownOpenABE();
    BOOST_THROW_EXCEPTION(NacAlgoError(
      "cannot decrypt the ciphertext using given private key."));
  }
}

} // namespace algo
} // namespace nacabe
} // namespace ndn