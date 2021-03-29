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

NDN_LOG_INIT(nacabe.abesupport);

ABESupport&
ABESupport::getInstance()
{
  static ABESupport instance;
  return instance;
}

ABESupport::ABESupport()
{
  InitializeOpenABE();
}

ABESupport::~ABESupport()
{
  ShutdownOpenABE();
}

void
ABESupport::init(PublicParams& pubParams, MasterKey& masterKey)
{
  OpenABECryptoContext cpabe("CP-ABE");
  cpabe.generateParams();
  std::string mpk, msk;
  cpabe.exportPublicParams(mpk);
  cpabe.exportSecretParams(msk);
  pubParams.m_pub = mpk;
  masterKey.m_msk = msk;
}

PrivateKey
ABESupport::prvKeyGen(PublicParams& pubParams, MasterKey& masterKey,
                      const std::vector <std::string>& attrList)
{
  std::string privKey;
  try {
    // step 0: set up ABE Context
    OpenABECryptoContext cpabe("CP-ABE");
    cpabe.importPublicParams(pubParams.m_pub);
    cpabe.importSecretParams(masterKey.m_msk);

    std::string policyString = "|";
    for (auto it = attrList.begin(); it != attrList.end(); it++) {
      policyString = policyString + *it + "|";
    }
    policyString.pop_back();

    cpabe.keygen(policyString, "abe-priv-key");
    cpabe.exportUserKey("abe-priv-key", privKey);
    cpabe.deleteKey("abe-priv-key");
  }
  catch (const oabe::ZCryptoBoxException& ex) {
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
  try {
    // step 0: set up ABE Context
    OpenABECryptoContext cpabe("CP-ABE");
    cpabe.importPublicParams(pubParams.m_pub);

    // step 1: generate a AES symmetric key
    OpenABESymKey symKey;
    symKey.generateSymmetricKey(DEFAULT_SYM_KEY_BYTES);
    std::string symmetricKey = symKey.toString();

    // step 2: use publicParams and policy to encrypt this symmetric key
    std::string encryptedSymmetricKey;
    cpabe.encrypt(policy, symmetricKey, encryptedSymmetricKey);

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

    return result;
  }
  catch (oabe::ZCryptoBoxException& ex) {
    BOOST_THROW_EXCEPTION(NacAlgoError(
      "cannot encrypt the plaintext using given public paramater and policy."));
  }
}

Buffer
ABESupport::decrypt(const PublicParams& pubParams,
                    const PrivateKey& prvKey, CipherText cipherText)
{
  try {
    // step 0: set up ABE Context
    OpenABECryptoContext cpabe("CP-ABE");
    cpabe.importPublicParams(pubParams.m_pub);

    // step 1: import prvKey into OpenABE
    cpabe.enableKeyManager("user1");
    cpabe.importUserKey("key1", prvKey.m_prv);

    // step 2: decrypt cipherText.aesKey, which is the encrypted symmetric key
    std::string encryptedSymmetricKey(reinterpret_cast<char*>(cipherText.m_aesKey.data()));
    std::string symmetricKey;
    bool result = cpabe.decrypt(encryptedSymmetricKey, symmetricKey);
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
    return ret;
  }
  catch (oabe::ZCryptoBoxException& ex) {
    BOOST_THROW_EXCEPTION(NacAlgoError(
      "cannot decrypt the ciphertext using given private key."));
  }
}

} // namespace algo
} // namespace nacabe
} // namespace ndn