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

#include "private-key.hpp"

namespace ndn {
namespace ndnabac {
namespace algo {

// Buffer
// PrivateKey::toBuffer(const PrivateKey& privateKey)
// {
//   // From Glib:
//   // struct GByteArray {
//   //   guint8 *data;
//   //   guint len;
//   // }
//   GByteArray* bytes = bswabe_prv_serialize(privateKey.m_prv);
//   Buffer result(bytes->data, bytes->len);
//   return result;
// }

} // namespace algo
} // namespace ndnabac
} // namespace ndn
