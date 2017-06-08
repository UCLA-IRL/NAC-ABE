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

#include "random-number-generator.hpp"
#include "encrypt-params.hpp"

namespace ndn {
namespace abac {
namespace algo {

EncryptParams::EncryptParams(AlgorithmTypeValue algorithm, uint8_t ivLength)
  : m_algo(algorithm)
{
  if (ivLength != 0){
    RandomNumberGenerator rng;
    m_iv.resize(ivLength);
    rng.GenerateBlock(m_iv.buf(), m_iv.size());
  }
}

void
EncryptParams::setIV(const uint8_t* iv, size_t ivLen)
{
  m_iv = Buffer(iv, ivLen);
}

void
EncryptParams::setAlgorithmType(AlgorithmTypeValue algorithm)
{
  m_algo = algorithm;
}

Buffer
EncryptParams::getIV() const
{
  return m_iv;
}

AlgorithmTypeValue
EncryptParams::getAlgorithmType() const
{
  return m_algo;
}

} // namespace algo
} // namespace abac
} // namespace ndn
