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

#ifndef NDN_ABAC_ENCRYPT_PARAMS_HPP
#define NDN_ABAC_ENCRYPT_PARAMS_HPP

#include <ndn-cxx/encoding/buffer-stream.hpp>

namespace ndn {
namespace abac {
namespace algo {

enum AlgorithmTypeValue {
  AlgorithmAesEcb = 0,
  AlgorithmAesCbc = 1,
  AlgorithmRsaPkcs = 2,
  AlgorithmRsaOaep = 3
};

class EncryptParams
{
public:
  EncryptParams(AlgorithmTypeValue algorithm, uint8_t ivLength = 0);

  void
  setIV(const uint8_t* iv, size_t ivLen);

  void
  setAlgorithmType(AlgorithmTypeValue algorithm);

  Buffer
  getIV() const;

  AlgorithmTypeValue
  getAlgorithmType() const;

private:
  AlgorithmTypeValue m_algo;
  Buffer m_iv;
};

} // namespace algo
} // namespace abac
} // namespace ndn

#endif // NDN_ABAC_ENCRYPT_PARAMS_HPP
