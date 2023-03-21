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

#include "abe-support-charm.hpp"
#include "../ndn-crypto/error.hpp"
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/transform_width.hpp>

std::string decode64(const std::string &val) {
  using namespace boost::archive::iterators;
  using It = transform_width<binary_from_base64<std::string::const_iterator>, 8, 6>;
  auto tmp = std::string(It(std::begin(val)), It(std::end(val)));
  auto equals = val.size() - val.find_last_not_of('=') - 1;
  return tmp.substr(0, tmp.size() - equals);
}

std::string encode64(const std::string &val) {
  using namespace boost::archive::iterators;
  using It = base64_from_binary<transform_width<std::string::const_iterator, 6, 8>>;
  auto tmp = std::string(It(std::begin(val)), It(std::end(val)));
  return tmp.append((3 - val.size() % 3) % 3, '=');
}

using namespace boost::process;

namespace ndn {
namespace nacabe {
namespace algo {

ABESupportCharm::ABESupportCharm()
{
  m_adapter = std::make_unique<child>("python3 /NAC-ABE/charm_adapter.py", std_in < m_inStream, std_out > m_outStream);
}

ABESupportCharm::~ABESupportCharm()
{
  m_inStream << "exit" << std::endl;
  if (m_adapter->running()) m_adapter->wait();
}

void
ABESupportCharm::cpInit(PublicParams& pubParams, MasterKey& masterKey)
{
  m_inStream << "cpInit" << std::endl;
  std::string pub, msk;
  std::getline(m_outStream, pub);
  pubParams.m_pub = decode64(pub);
  std::getline(m_outStream, msk);
  masterKey.m_msk = decode64(msk);
  assert(m_adapter->running());
}

PrivateKey
ABESupportCharm::cpPrvKeyGen(PublicParams& pubParams, MasterKey& masterKey,
                        const std::vector <std::string>& attrList)
{
  m_inStream << "cpPrvKeyGen" << std::endl;
  m_inStream << encode64(pubParams.m_pub) << std::endl;
  m_inStream << encode64(masterKey.m_msk) << std::endl;
  for (const auto& i: attrList) {
    m_inStream << encode64(i) << " ";
  }
  m_inStream << std::endl;
  std::string prvKey;
  std::getline(m_outStream, prvKey);
  PrivateKey key;
  key.m_prv = decode64(prvKey);
  assert(m_adapter->running());
  return key;
}

std::shared_ptr<ContentKey>
ABESupportCharm::cpContentKeyGen(const PublicParams &pubParams,
                                 const Policy &policy)
{
  m_inStream << "cpContentKeyGen" << std::endl;
  m_inStream << encode64(pubParams.m_pub) << std::endl;
  m_inStream << encode64(policy) << std::endl;
  auto key = std::make_shared<ContentKey>();
  std::string keyStr;
  std::getline(m_outStream, keyStr);
  key->m_aesKey = decode64(keyStr);
  std::string encKeyStr;
  std::getline(m_outStream, encKeyStr);
  auto re = decode64(encKeyStr);
  key->m_encAesKey = {re.data(), re.size()};
  assert(m_adapter->running());
  return key;
}

std::string
ABESupportCharm::cpContentKeyDecrypt(const PublicParams& pubParams,
                      const PrivateKey& prvKey, Buffer encContentKey)
{
  m_inStream << "cpContentKeyDecrypt" << std::endl;
  m_inStream << encode64(pubParams.m_pub) << std::endl;
  m_inStream << encode64(prvKey.m_prv) << std::endl;
  m_inStream << encode64(std::string((const char *) encContentKey.data(), encContentKey.size())) << std::endl;
  std::string status;
  std::getline(m_outStream, status);
  if (status != "True") BOOST_THROW_EXCEPTION(NacAlgoError("cannot encrypt the ciphertext using given private key."));
  std::string clearText;
  std::getline(m_outStream, clearText);
  assert(m_adapter->running());
  return decode64(clearText);
}

void
ABESupportCharm::kpInit(PublicParams &pubParams, MasterKey &masterKey)
{
}

PrivateKey
ABESupportCharm::kpPrvKeyGen(PublicParams &pubParams, MasterKey &masterKey,
            const Policy &policy)
{
  return {};
}

std::shared_ptr<ContentKey>
ABESupportCharm::kpContentKeyGen(const PublicParams &pubParams,
                                 const std::vector<std::string> &attrList) {
  return std::make_shared<ContentKey>();
}

std::string
ABESupportCharm::kpContentKeyDecrypt(const PublicParams &pubParams,
          const PrivateKey &prvKey, Buffer encContentKey)
{
  return "";
}

} // namespace algo
} // namespace nacabe
} // namespace ndn
