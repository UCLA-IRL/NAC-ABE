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

#ifndef NDNABAC_CONSUMER_HPP
#define NDNABAC_CONSUMER_HPP

namespace ndn {
namespace ndnabac {

class Consumer
{
public:
  class Error : public std::runtime_error
  {
  public:
    using std::runtime_error::runtime_error;
  };

  using ErrorCallback = function<void (const std::string&)>;
  using ConsumptionCallback = function<void (const Buffer&)>;
  using SuccessCallback = function<void (const Data&)>;

public:
  Consumer(const security::v2::Certificate& identityCert, Face& face,
           uint8_t repeatAttempts = 3);

  void
  consume(const Name& dataName, const ConsumptionCallback& consumptionCb,
          const ErrorCallback& errorCb);

  void
  fetchDecryptionKey(const Name& attrAuthorityPrefix, const Data& token);

private:
  void
  fetchAttributePubParams(const Name& attrAuthorityPrefix, const SuccessCallback& onPublicParamsCb);

private:
  security::v2::Certificate m_cert;
  Face& m_face;
  uint8_t m_repeatAttempts;

  algo::PrivateKey m_privateKey;
  std::map<Name, Data> m_tokens;
  algo::PublicParams m_pubParamsCache;
};

} // namespace ndnabac
} // namespace ndn

#endif // NDNABAC_CONSUMER_HPP
