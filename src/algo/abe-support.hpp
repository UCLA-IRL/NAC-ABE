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

#ifndef NAC_ABE_ALGO_ABE_SUPPORT_HPP
#define NAC_ABE_ALGO_ABE_SUPPORT_HPP

#include "public-params.hpp"
#include "master-key.hpp"
#include "private-key.hpp"
#include "cipher-text.hpp"

#include <openabe/openabe.h>
#include <openabe/zsymcrypto.h>
#include <openssl/aes.h>
#include <openssl/sha.h>

namespace ndn {
namespace nacabe {
namespace algo {

class ABESupport
{
public:
  static ABESupport &
  getInstance();

  virtual ~ABESupport() = default;

  ABESupport() = default;
  ABESupport(ABESupport const &) = delete;

  void operator=(ABESupport const &) = delete;

public:
  virtual void
  cpInit(PublicParams &pubParams, MasterKey &masterKey) = 0;

  virtual PrivateKey
  cpPrvKeyGen(PublicParams &pubParams, MasterKey &masterKey,
              const std::vector<std::string> &attrList) = 0;

  virtual std::shared_ptr<ContentKey>
  cpContentKeyGen(const PublicParams &pubParams,
                  const Policy &policy) = 0;

  virtual CipherText
  cpEncrypt(const PublicParams &pubParams,
            const Policy &policy, Buffer plaintext) = 0;

  virtual Buffer
  cpDecrypt(const PublicParams &pubParams,
            const PrivateKey &prvKey, CipherText cipherText) = 0;

public:
  virtual void
  kpInit(PublicParams &pubParams, MasterKey &masterKey) = 0;

  virtual PrivateKey
  kpPrvKeyGen(PublicParams &pubParams, MasterKey &masterKey,
              const Policy &policy) = 0;

  virtual std::shared_ptr<ContentKey>
  kpContentKeyGen(const PublicParams &pubParams,
                  const std::vector<std::string> &attrList) = 0;

  virtual CipherText
  kpEncrypt(const PublicParams &pubParams,
            const std::vector<std::string> &attrList, Buffer plaintext) = 0;

  virtual CipherText
  encrypt(std::shared_ptr<ContentKey> contentKey, Buffer plaintext) = 0;

  virtual Buffer
  kpDecrypt(const PublicParams &pubParams,
            const PrivateKey &prvKey, CipherText cipherText) = 0;
};

} // namespace algo
} // namespace nacabe
} // namespace ndn

#endif // NAC_ABE_ALGO_ABE_SUPPORT_HPP
