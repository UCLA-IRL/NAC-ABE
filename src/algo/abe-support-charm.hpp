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

#ifndef NAC_ABE_ALGO_ABE_SUPPORT_CHARM_HPP
#define NAC_ABE_ALGO_ABE_SUPPORT_CHARM_HPP

#include "abe-support.hpp"
#include <openssl/sha.h>
#include <boost/process.hpp>

namespace ndn {
namespace nacabe {
namespace algo {

class ABESupportCharm : public ABESupport
{
public:

  ABESupportCharm();
  ~ABESupportCharm() override;

  ABESupportCharm(ABESupportCharm const &) = delete;

  void operator=(ABESupportCharm const &) = delete;

public:
  void
  cpInit(PublicParams &pubParams, MasterKey &masterKey) override;

  PrivateKey
  cpPrvKeyGen(PublicParams &pubParams, MasterKey &masterKey,
              const std::vector<std::string> &attrList) override;

  std::shared_ptr<ContentKey> cpContentKeyGen(const PublicParams &pubParams,
                                              const Policy &policy) override;

  std::string cpContentKeyDecrypt(const PublicParams &pubParams,
                                          const PrivateKey &prvKey,
                                          Buffer encContentKey) override;

public:
  void
  kpInit(PublicParams &pubParams, MasterKey &masterKey) override;

  PrivateKey
  kpPrvKeyGen(PublicParams &pubParams, MasterKey &masterKey,
              const Policy &policy) override;

  std::shared_ptr<ContentKey> kpContentKeyGen(const PublicParams &pubParams,
                                              const std::vector<std::string> &attrList) override;

  virtual std::string kpContentKeyDecrypt(const PublicParams &pubParams,
                                          const PrivateKey &prvKey,
                                          Buffer encContentKey) override;
private:
  boost::process::pstream m_outStream;
  boost::process::opstream m_inStream;
  std::unique_ptr<boost::process::child> m_adapter;

};

} // namespace algo
} // namespace nacabe
} // namespace ndn

#endif // NAC_ABE_ALGO_ABE_SUPPORT_CHARM_HPP
