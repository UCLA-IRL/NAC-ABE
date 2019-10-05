/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2018,  Regents of the University of California
 *
 * This file is part of NAC (Name-based Access Control for NDN).
 * See AUTHORS.md for complete list of NAC authors and contributors.
 *
 * NAC is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * NAC is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * NAC, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @author Zhiyi Zhang <zhiyi@cs.ucla.edu>
 */

#ifndef NAC_CRYPTO_ERROR_HPP
#define NAC_CRYPTO_ERROR_HPP

#include <stdexcept>

namespace ndn {
namespace ndnabac {

class NacAlgoError : public std::runtime_error
{
public:
  explicit
  NacAlgoError(const std::string& what)
    : std::runtime_error(what)
  {
  }
};

} // namespace ndnabac
} // namespace ndn

#endif // NAC_CRYPTO_ERROR_HPP
