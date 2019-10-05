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

#ifndef NAC_ABE_COMMON_HPP
#define NAC_ABE_COMMON_HPP

#include "nac-abe-config.hpp"

#ifdef HAVE_TESTS
#define VIRTUAL_WITH_TESTS virtual
#define PUBLIC_WITH_TESTS_ELSE_PROTECTED public
#define PUBLIC_WITH_TESTS_ELSE_PRIVATE public
#define PROTECTED_WITH_TESTS_ELSE_PRIVATE protected
#else
#define VIRTUAL_WITH_TESTS
#define PUBLIC_WITH_TESTS_ELSE_PROTECTED public
#define PUBLIC_WITH_TESTS_ELSE_PRIVATE public
#define PROTECTED_WITH_TESTS_ELSE_PRIVATE private
#endif

#include <cstddef>
#include <cstdint>
#include <functional>
#include <list>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>

#include <ndn-cxx/interest.hpp>
#include <ndn-cxx/data.hpp>
#include <ndn-cxx/face.hpp>
#include <ndn-cxx/name.hpp>
#include <ndn-cxx/encoding/block.hpp>
#include <ndn-cxx/lp/nack.hpp>
#include <ndn-cxx/util/backports.hpp>
#include <ndn-cxx/util/signal.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/V2/certificate.hpp>
#include <ndn-cxx/security/V2/validator.hpp>
#include <ndn-cxx/util/logger.hpp>

#include <iostream>

#include <boost/algorithm/string.hpp>
#include <boost/assert.hpp>
#include <boost/noncopyable.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/info_parser.hpp>
#include <boost/throw_exception.hpp>

namespace ndn {
namespace nacabe {

using std::size_t;

using boost::noncopyable;

using std::shared_ptr;
using std::unique_ptr;
using std::weak_ptr;
using std::make_shared;
using ndn::make_unique;
using std::enable_shared_from_this;

using std::function;
using std::bind;

using ndn::Interest;
using ndn::Data;
using ndn::Name;
using ndn::PartialName;
using ndn::Block;
using ndn::time::system_clock;
using ndn::time::toUnixTimestamp;

const uint32_t TLV_EncryptedAesKey = 601;
const uint32_t TLV_EncryptedContent = 602;
const uint32_t TLV_PlainTextSize = 603;
const uint32_t TLV_AesKeyId = 604;
const uint32_t TLV_InitialVector = 605;

static const Name PUBLIC_PARAMS = "/PUBPARAMS";
static const Name DECRYPT_KEY = "/DKEY";

} // namespace nacabe
} // namespace ndn

#endif // NAC_ABE_COMMON_HPP
