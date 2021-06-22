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
#include <utility>

using namespace oabe;
using namespace oabe::crypto;

namespace ndn {
namespace nacabe {
namespace algo {

NDN_LOG_INIT(nacabe.abesupport);

const char *ABESupport::SCHEMA_CPABE = "CP-ABE";
const char *ABESupport::SCHEMA_KPABE = "KP-ABE";

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
ABESupport::cpInit(PublicParams& pubParams, MasterKey& masterKey)
{
  OpenABECryptoContext cpabe(SCHEMA_CPABE);
  init(cpabe, pubParams, masterKey);
}

PrivateKey
ABESupport::cpPrvKeyGen(PublicParams& pubParams, MasterKey& masterKey,
                        const std::vector <std::string>& attrList)
{
  OpenABECryptoContext cpabe(SCHEMA_CPABE);
  std::string policyString;
  for (const auto & it : attrList) {
    policyString += it + "|";
  }
  policyString.pop_back();
  return prvKeyGen(cpabe, pubParams, masterKey, policyString);
}

CipherText
ABESupport::cpEncrypt(const PublicParams& pubParams,
                      const std::string& policy, Buffer plaintext)
{
  OpenABECryptoContext cpabe(SCHEMA_CPABE);
  return encrypt(cpabe, pubParams, policy, std::move(plaintext));
}

Buffer
ABESupport::cpDecrypt(const PublicParams& pubParams,
                      const PrivateKey& prvKey, CipherText cipherText)
{
  OpenABECryptoContext cpabe(SCHEMA_CPABE);
  return decrypt(cpabe, pubParams, prvKey, std::move(cipherText));
}

void
ABESupport::kpInit(PublicParams &pubParams, MasterKey &masterKey)
{
  OpenABECryptoContext kpabe(SCHEMA_KPABE);
  init(kpabe, pubParams, masterKey);
}

PrivateKey
ABESupport::kpPrvKeyGen(PublicParams &pubParams, MasterKey &masterKey,
            const Policy &policy)
{
  OpenABECryptoContext kpabe(SCHEMA_KPABE);
  return prvKeyGen(kpabe, pubParams, masterKey, policy);
}

CipherText
ABESupport::kpEncrypt(const PublicParams &pubParams,
          const std::vector<std::string> &attrList, Buffer plaintext)
{
  OpenABECryptoContext kpabe(SCHEMA_KPABE);
  std::string policyString;
  for (const auto & it : attrList) {
    policyString += it + "|";
  }
  policyString.pop_back();
  return encrypt(kpabe, pubParams, policyString, std::move(plaintext));
}

Buffer
ABESupport::kpDecrypt(const PublicParams &pubParams,
          const PrivateKey &prvKey, CipherText cipherText)
{
  OpenABECryptoContext kpabe(SCHEMA_KPABE);
  return decrypt(kpabe, pubParams, prvKey, std::move(cipherText));
}

void
ABESupport::init(oabe::OpenABECryptoContext& context, PublicParams &pubParams, MasterKey &masterKey)
{
  context.generateParams();
  std::string mpk, msk;
  context.exportPublicParams(mpk);
  context.exportSecretParams(msk);
  pubParams.m_pub = mpk;
  masterKey.m_msk = msk;
}

PrivateKey
ABESupport::prvKeyGen(oabe::OpenABECryptoContext& context, PublicParams &pubParams, MasterKey &masterKey,
          const std::string &policyOrAttribute)
{
  std::string privKey;
  try {
    // step 0: set up ABE Context
    context.importPublicParams(pubParams.m_pub);
    context.importSecretParams(masterKey.m_msk);

    context.keygen(policyOrAttribute, "abe-priv-key");
    context.exportUserKey("abe-priv-key", privKey);
    context.deleteKey("abe-priv-key");
  }
  catch (const oabe::ZCryptoBoxException& ex) {
    BOOST_THROW_EXCEPTION(NacAlgoError("cannot generate private key for the policy"));
  }

  PrivateKey privateKey;
  privateKey.m_prv = privKey;
  return privateKey;
}

CipherText
ABESupport::encrypt(oabe::OpenABECryptoContext& context, const PublicParams &pubParams,
        const std::string &policyOrAttribute, Buffer plaintext)
{
  try {
    // step 0: set up ABE Context
    context.importPublicParams(pubParams.m_pub);

    // step 1: generate a AES symmetric key
    OpenABESymKey symKey;
    symKey.generateSymmetricKey(DEFAULT_SYM_KEY_BYTES);
    std::string symmetricKey = symKey.toString();

    // step 2: use publicParams and policy to cpEncrypt this symmetric key
    std::string encryptedSymmetricKey;
    context.encrypt(policyOrAttribute, symmetricKey, encryptedSymmetricKey);

    // step 3: use the AES symmetric key to cpEncrypt the plain text
    OpenABESymKeyEnc aes(symmetricKey);
    std::string ciphertext = aes.encrypt(
        (uint8_t*) plaintext.data(),
        (uint32_t) plaintext.size());


    // step 4: put encryptedSymmetricKey and ciphertext in CipherText object
    //           and return the CipherText Object
    CipherText result;
    Buffer aesKeySegment((uint8_t*) encryptedSymmetricKey.c_str(),
                         (uint32_t) encryptedSymmetricKey.size() + 1);

    Buffer cipherContentSegment((uint8_t*) ciphertext.c_str(),
                                (uint32_t) ciphertext.size() + 1);

    result.m_aesKey = aesKeySegment;
    result.m_content = cipherContentSegment;
    result.m_plainTextSize = plaintext.size();

    return result;
  }
  catch (oabe::ZCryptoBoxException& ex) {
    BOOST_THROW_EXCEPTION(NacAlgoError(
                              "cannot encrypt the plaintext using given public paramater and policy."));
  }
}

Buffer
ABESupport::decrypt(oabe::OpenABECryptoContext& context, const PublicParams &pubParams,
        const PrivateKey &prvKey, CipherText cipherText)
{
  try {
    // step 0: set up ABE Context
    context.importPublicParams(pubParams.m_pub);

    // step 1: import prvKey into OpenABE
    context.enableKeyManager("user1");
    context.importUserKey("key1", prvKey.m_prv);

    // step 2: cpDecrypt cipherText.aesKey, which is the encrypted symmetric key
    std::string encryptedSymmetricKey(reinterpret_cast<char*>(cipherText.m_aesKey.data()));
    std::string symmetricKey;
    bool result = context.decrypt(encryptedSymmetricKey, symmetricKey);
    if (!result) {
      BOOST_THROW_EXCEPTION(NacAlgoError("Decryption error!"));
    }

    // step 3: use the decrypted symmetricKey to AES cpDecrypt cipherText.m_content
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
        "cannot encrypt the ciphertext using given private key."));
  }
}

} // namespace algo
} // namespace nacabe
} // namespace ndn