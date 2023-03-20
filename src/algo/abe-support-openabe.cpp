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

#include "abe-support-openabe.hpp"
#include "../ndn-crypto/error.hpp"

using namespace oabe;
using namespace oabe::crypto;

namespace ndn {
namespace nacabe {
namespace algo {

const char* ABESupportOpenABE::SCHEMA_CPABE = "CP-ABE";
const char* ABESupportOpenABE::SCHEMA_KPABE = "KP-ABE";

ABESupport&
ABESupport::getInstance()
{
  static ABESupportOpenABE instance;
  return instance;
}

ABESupportOpenABE::ABESupportOpenABE()
{
  InitializeOpenABE();
}

ABESupportOpenABE::~ABESupportOpenABE()
{
  ShutdownOpenABE();
}

void
ABESupportOpenABE::cpInit(PublicParams& pubParams, MasterKey& masterKey)
{
  OpenABECryptoContext cpabe(SCHEMA_CPABE);
  init(cpabe, pubParams, masterKey);
}

PrivateKey
ABESupportOpenABE::cpPrvKeyGen(PublicParams& pubParams, MasterKey& masterKey,
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

Buffer
ABESupportOpenABE::cpContentKeyEncrypt(const PublicParams &pubParams,
                            const std::string& policy, std::string contentKey)
{
  OpenABECryptoContext cpabe(SCHEMA_CPABE);
  return contentKeyEncrypt(cpabe, pubParams, policy, contentKey);
}

std::string
ABESupportOpenABE::cpContentKeyDecrypt(const PublicParams& pubParams,
                      const PrivateKey& prvKey, Buffer encContentKey)
{
  OpenABECryptoContext cpabe(SCHEMA_CPABE);
  return contentKeyDecrypt(cpabe, pubParams, prvKey, std::move(encContentKey));
}

void
ABESupportOpenABE::kpInit(PublicParams &pubParams, MasterKey &masterKey)
{
  OpenABECryptoContext kpabe(SCHEMA_KPABE);
  init(kpabe, pubParams, masterKey);
}

PrivateKey
ABESupportOpenABE::kpPrvKeyGen(PublicParams &pubParams, MasterKey &masterKey,
            const Policy &policy)
{
  OpenABECryptoContext kpabe(SCHEMA_KPABE);
  return prvKeyGen(kpabe, pubParams, masterKey, policy);
}

Buffer
ABESupportOpenABE::kpContentKeyEncrypt(const PublicParams &pubParams,
                const std::vector<std::string> &attrList, std::string contentKey) {
  OpenABECryptoContext kpabe(SCHEMA_KPABE);
  std::string policyString;
  for (const auto & it : attrList) {
    policyString += it + "|";
  }
  policyString.pop_back();
  return contentKeyEncrypt(kpabe, pubParams, policyString, contentKey);
}

std::string
ABESupportOpenABE::kpContentKeyDecrypt(const PublicParams &pubParams,
          const PrivateKey &prvKey, Buffer encContentKey)
{
  OpenABECryptoContext kpabe(SCHEMA_KPABE);
  return contentKeyDecrypt(kpabe, pubParams, prvKey, std::move(encContentKey));
}

void
ABESupportOpenABE::init(oabe::OpenABECryptoContext& context, PublicParams &pubParams, MasterKey &masterKey)
{
  context.generateParams();
  std::string mpk, msk;
  context.exportPublicParams(mpk);
  context.exportSecretParams(msk);
  pubParams.m_pub = mpk;
  masterKey.m_msk = msk;
}

PrivateKey
ABESupportOpenABE::prvKeyGen(oabe::OpenABECryptoContext& context, PublicParams &pubParams, MasterKey &masterKey,
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

Buffer
ABESupportOpenABE::contentKeyEncrypt(oabe::OpenABECryptoContext &context, const PublicParams &pubParams,
                                     const std::string &policyOrAttribute, std::string contentKey)
{
  try {
    // step 0: set up ABE Context
    context.importPublicParams(pubParams.m_pub);

    // step 2: use publicParams and policy to cpEncrypt this symmetric key
    std::string encryptedSymmetricKey;
    context.encrypt(policyOrAttribute, contentKey, encryptedSymmetricKey);

    Buffer encAesKeySegment((uint8_t*) encryptedSymmetricKey.data(),
                            (uint32_t) encryptedSymmetricKey.size());
    return encAesKeySegment;
  }
  catch (oabe::ZCryptoBoxException& ex) {
    BOOST_THROW_EXCEPTION(NacAlgoError(
                              "cannot encrypt the plaintext using given public paramater and policy."));
  }
}

std::string
ABESupportOpenABE::contentKeyDecrypt(oabe::OpenABECryptoContext &context, const PublicParams &pubParams,
                                     const PrivateKey &prvKey, Buffer encContentKey)
{
  try {
    // step 0: set up ABE Context
    context.importPublicParams(pubParams.m_pub);

    // step 1: import prvKey into OpenABE
    context.enableKeyManager("user1");
    context.importUserKey("key1", prvKey.m_prv);

    // step 2: cpDecrypt cipherText.aesKey, which is the encrypted symmetric key
    std::string encryptedSymmetricKey(reinterpret_cast<char*>(encContentKey.data()), encContentKey.size());
    std::string symmetricKey;
    bool result = context.decrypt(encryptedSymmetricKey, symmetricKey);
    if (!result) {
      BOOST_THROW_EXCEPTION(NacAlgoError("Decryption error!"));
    }

    return std::move(symmetricKey);
  }
  catch (oabe::ZCryptoBoxException& ex) {
    BOOST_THROW_EXCEPTION(NacAlgoError(
        "cannot encrypt the ciphertext using given private key."));
  }
}

} // namespace algo
} // namespace nacabe
} // namespace ndn
