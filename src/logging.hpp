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

#ifndef NDNABAC_LOGGING_HPP
#define NDNABAC_LOGGING_HPP

#include <ndn-cxx/util/logger.hpp>

namespace ndn {
namespace ndnabac {

#define _LOG_INIT(name) NDN_LOG_INIT(ndncert.name)

#define _LOG_DEBUG(x) NDN_LOG_DEBUG(__FILE__ << ":" << __LINE__ << ":" << " " << x)

#define _LOG_TRACE(x) NDN_LOG_TRACE(__FILE__ << ":" << __LINE__ << ":" << " " << x)

#define _LOG_ERROR(x) NDN_LOG_ERROR(x)

} // ndnabac
} // ndn

#endif // NDNABAC_LOGGING_HPP
