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

#include "public-params.hpp"

namespace ndn {
namespace nacabe {
namespace algo {

Buffer
PublicParams::toBuffer()
{
  const char *begin = m_pub.c_str();
  const char *end = begin + m_pub.size() + 1;
  return Buffer(begin, end);
}

void
PublicParams::fromBuffer(const Buffer& buffer)
{
  Buffer tempBuf(buffer.data(), buffer.size());
  m_pub = std::string((char*)tempBuf.data());
}

} // namespace algo
} // namespace nacabe
} // namespace ndn