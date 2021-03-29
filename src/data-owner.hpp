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

#ifndef NAC_ABE_DATA_OWNER_HPP
#define NAC_ABE_DATA_OWNER_HPP

#include "common.hpp"

namespace ndn {
namespace nacabe {

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

private:
  security::v2::Certificate m_cert;
  Face& m_face;
  security::v2::KeyChain& m_keyChain;
  unique_ptr<security::v2::Validator> m_validator;
};

} // namespace nacabe
} // namespace ndn

#endif // NAC_ABE_DATA_OWNER_HPP
