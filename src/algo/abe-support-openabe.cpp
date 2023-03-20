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
#include "../ndn-crypto/aes.hpp"

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

std::shared_ptr<ContentKey>
ABESupportOpenABE::cpContentKeyGen(const PublicParams &pubParams,
                            const std::string& policy)
{
  OpenABECryptoContext cpabe(SCHEMA_CPABE);
  return contentKeyGen(cpabe, pubParams, policy);
}

CipherText
ABESupportOpenABE::cpEncrypt(const PublicParams& pubParams,
                      const std::string& policy, Buffer plaintext)
{
  OpenABECryptoContext cpabe(SCHEMA_CPABE);
  auto ck = contentKeyGen(cpabe, pubParams, policy);
  return encrypt(ck, std::move(plaintext));
}

Buffer
ABESupportOpenABE::cpDecrypt(const PublicParams& pubParams,
                      const PrivateKey& prvKey, CipherText cipherText)
{
  OpenABECryptoContext cpabe(SCHEMA_CPABE);
  return decrypt(cpabe, pubParams, prvKey, std::move(cipherText));
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

std::shared_ptr<ContentKey>
ABESupportOpenABE::kpContentKeyGen(const PublicParams &pubParams,
                const std::vector<std::string> &attrList) {
  OpenABECryptoContext kpabe(SCHEMA_KPABE);
  std::string policyString;
  for (const auto & it : attrList) {
    policyString += it + "|";
  }
  policyString.pop_back();
  return contentKeyGen(kpabe, pubParams, policyString);
}

CipherText
ABESupportOpenABE::kpEncrypt(const PublicParams &pubParams,
          const std::vector<std::string> &attrList, Buffer plaintext)
{
  OpenABECryptoContext kpabe(SCHEMA_KPABE);
  std::string policyString;
  for (const auto & it : attrList) {
    policyString += it + "|";
  }
  policyString.pop_back();
  auto ck = contentKeyGen(kpabe, pubParams, policyString);
  return encrypt(ck, std::move(plaintext));
}

Buffer
ABESupportOpenABE::kpDecrypt(const PublicParams &pubParams,
          const PrivateKey &prvKey, CipherText cipherText)
{
  OpenABECryptoContext kpabe(SCHEMA_KPABE);
  return decrypt(kpabe, pubParams, prvKey, std::move(cipherText));
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

std::shared_ptr<ContentKey>
ABESupportOpenABE::contentKeyGen(oabe::OpenABECryptoContext &context, const PublicParams &pubParams,
              const std::string &policyOrAttribute)
{
  try {
    // step 0: set up ABE Context
    context.importPublicParams(pubParams.m_pub);

    // step 1: generate a AES symmetric key
    AesKeyParams params;
    Buffer symKey = Aes::generateKey(params);
    std::string symmetricKey((const char*) symKey.data(), symKey.size());

    // step 2: use publicParams and policy to cpEncrypt this symmetric key
    std::string encryptedSymmetricKey;
    context.encrypt(policyOrAttribute, symmetricKey, encryptedSymmetricKey);

    Buffer encAesKeySegment((uint8_t*) encryptedSymmetricKey.c_str(),
                            (uint32_t) encryptedSymmetricKey.size() + 1);
    auto contentKey = std::make_shared<ContentKey>(symmetricKey, std::move(encAesKeySegment));

    return contentKey;
  }
  catch (oabe::ZCryptoBoxException& ex) {
    BOOST_THROW_EXCEPTION(NacAlgoError(
                              "cannot encrypt the plaintext using given public paramater and policy."));
  }
}

CipherText
ABESupportOpenABE::encrypt(std::shared_ptr<ContentKey> contentKey, Buffer plaintext) {
  try {
    // step 3: use the AES symmetric key to cpEncrypt the plain text
    Buffer aesKey(contentKey->m_aesKey.data(), contentKey->m_aesKey.size());
    auto iv = Aes::generateIV();
    auto ciphertext = Aes::encrypt(aesKey, plaintext, iv);

    // step 4: put encryptedSymmetricKey and ciphertext in CipherText object
    //           and return the CipherText Object
    CipherText result;
    assert(iv.size() < std::numeric_limits<uint8_t>::max());
    Buffer cipherContentSegment{(uint8_t) iv.size()};
    cipherContentSegment.reserve(1 + iv.size() + ciphertext.size());
    cipherContentSegment.insert(cipherContentSegment.end(), iv.begin(), iv.end());
    cipherContentSegment.insert(cipherContentSegment.end(), ciphertext.begin(), ciphertext.end());

    result.m_contentKey = contentKey;
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
ABESupportOpenABE::decrypt(oabe::OpenABECryptoContext& context, const PublicParams &pubParams,
        const PrivateKey &prvKey, CipherText cipherText)
{
  try {
    // step 0: set up ABE Context
    context.importPublicParams(pubParams.m_pub);

    // step 1: import prvKey into OpenABE
    context.enableKeyManager("user1");
    context.importUserKey("key1", prvKey.m_prv);

    // step 2: cpDecrypt cipherText.aesKey, which is the encrypted symmetric key
    std::string encryptedSymmetricKey(reinterpret_cast<char*>(cipherText.m_contentKey->m_encAesKey.data()));
    bool result = context.decrypt(encryptedSymmetricKey, cipherText.m_contentKey->m_aesKey);
    if (!result) {
      BOOST_THROW_EXCEPTION(NacAlgoError("Decryption error!"));
    }

    // step 3: use the decrypted symmetricKey to AES cpDecrypt cipherText.m_content
    Buffer aesKey(cipherText.m_contentKey->m_aesKey.data(), cipherText.m_contentKey->m_aesKey.size());
    auto iv = Buffer(cipherText.m_content.data() + 1, cipherText.m_content.at(0));
    auto cipherContent = Buffer(cipherText.m_content.data() + 1 + iv.size(), cipherText.m_content.size() - 1 - iv.size());
    Buffer recoveredContent = Aes::decrypt(aesKey, cipherContent, iv);

    // step 5: finalize
    return recoveredContent;
  }
  catch (oabe::ZCryptoBoxException& ex) {
    BOOST_THROW_EXCEPTION(NacAlgoError(
        "cannot encrypt the ciphertext using given private key."));
  }
}

} // namespace algo
} // namespace nacabe
} // namespace ndn
