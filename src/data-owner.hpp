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

#ifndef NDNABAC_DATA_OWNER_HPP
#define NDNABAC_DATA_OWNER_HPP

#include "ndnabac-common.hpp"

namespace ndn {
namespace ndnabac {

class DataOwner
{
public:
  using ErrorCallback = function<void (const std::string&)>;
  using SuccessCallback = function<void (const Data&)>;

public:
  DataOwner(const security::v2::Certificate& identityCert, Face& face,
            security::v2::KeyChain& keyChain);

  /**
   * send command:
   *  /producer-prefix/data-prefix/SET_POLICY/<policy string>/[sig]
   * data-prefix contains the producer prefix and data prefix
   */
  void
  commandProducerPolicy(const Name& producerPrefix, const Name& dataPrefix, const std::string& policy,
                        const SuccessCallback& SuccessCb, const ErrorCallback& errorCb);

public:
  const static Name SET_POLICY;

private:
  security::v2::Certificate m_cert;
  Face& m_face;
  security::v2::KeyChain& m_keyChain;
  unique_ptr<Validator> m_validator;
};

} // namespace ndnabac
} // namespace ndn

#endif // NDNABAC_DATA_OWNER_HPP
