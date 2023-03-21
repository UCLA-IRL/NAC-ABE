//
// Created by Tyler on 3/19/23.
//

#include "abe-support.hpp"
#include "../ndn-crypto/aes.hpp"

namespace ndn {
namespace nacabe {
namespace algo {

CipherText
ABESupport::cpEncrypt(const PublicParams& pubParams,
                      const std::string& policy, Buffer plaintext)
{
  auto ck = cpContentKeyGen(pubParams, policy);
  return encrypt(ck, std::move(plaintext));
}

CipherText
ABESupport::kpEncrypt(const PublicParams &pubParams,
                      const std::vector<std::string> &attrList, Buffer plaintext)
{
  auto ck = kpContentKeyGen(pubParams, attrList);
  return encrypt(ck, std::move(plaintext));
}

CipherText
ABESupport::encrypt(std::shared_ptr<ContentKey> contentKey, Buffer plaintext) {
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

Buffer ABESupport::decrypt(CipherText cipherText) {
  // step 3: use the decrypted symmetricKey to AES cpDecrypt cipherText.m_content
  Buffer aesKey(cipherText.m_contentKey->m_aesKey.data(), cipherText.m_contentKey->m_aesKey.size());
  auto iv = Buffer(cipherText.m_content.data() + 1, cipherText.m_content.at(0));
  auto cipherContent = Buffer(cipherText.m_content.data() + 1 + iv.size(), cipherText.m_content.size() - 1 - iv.size());
  Buffer recoveredContent = Aes::decrypt(aesKey, cipherContent, iv);

  // step 5: finalize
  return recoveredContent;
}

Buffer ABESupport::cpDecrypt(const PublicParams &pubParams, const PrivateKey &prvKey, CipherText cipherText) {
  cipherText.m_contentKey->m_aesKey = cpContentKeyDecrypt(pubParams, prvKey, cipherText.m_contentKey->m_encAesKey);
  return ABESupport::decrypt(cipherText);
}

Buffer ABESupport::kpDecrypt(const PublicParams &pubParams, const PrivateKey &prvKey, CipherText cipherText) {
  cipherText.m_contentKey->m_aesKey = kpContentKeyDecrypt(pubParams, prvKey, cipherText.m_contentKey->m_encAesKey);
  return ABESupport::decrypt(cipherText);
}

} // namespace algo
} // namespace nacabe
} // namespace ndn
