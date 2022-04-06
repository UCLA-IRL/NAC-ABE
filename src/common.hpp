/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2017-2022, Regents of the University of California.
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

#ifndef NAC_ABE_CMAKE_BUILD
#include "nac-abe-config.hpp"
#endif

#ifdef HAVE_TESTS
#define VIRTUAL_WITH_TESTS virtual
#define PUBLIC_WITH_TESTS_ELSE_PROTECTED public
#define PUBLIC_WITH_TESTS_ELSE_PRIVATE public
#define PROTECTED_WITH_TESTS_ELSE_PRIVATE protected
#else
#define VIRTUAL_WITH_TESTS
#define PUBLIC_WITH_TESTS_ELSE_PROTECTED protected
#define PUBLIC_WITH_TESTS_ELSE_PRIVATE private
#define PROTECTED_WITH_TESTS_ELSE_PRIVATE private
#endif

#include <cstddef>
#include <cstdint>
#include <functional>
#include <iosfwd>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>

#include <ndn-cxx/interest.hpp>
#include <ndn-cxx/data.hpp>
#include <ndn-cxx/face.hpp>
#include <ndn-cxx/name.hpp>
#include <ndn-cxx/encoding/block.hpp>
#include <ndn-cxx/lp/nack.hpp>
#include <ndn-cxx/util/backports.hpp>
#include <ndn-cxx/util/signal.hpp>
#include <ndn-cxx/security/certificate.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/validator.hpp>
#include <ndn-cxx/util/logger.hpp>
#include <ndn-cxx/util/span.hpp>

#include <boost/algorithm/string.hpp>
#include <boost/assert.hpp>
#include <boost/noncopyable.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/throw_exception.hpp>

namespace ndn {
namespace nacabe {

using std::size_t;

using boost::noncopyable;

using std::shared_ptr;
using std::unique_ptr;
using std::make_shared;
using std::make_unique;

using ndn::Interest;
using ndn::Data;
using ndn::Name;
using ndn::PartialName;
using ndn::Block;

const uint32_t TLV_EncryptedAesKey = 601;
const uint32_t TLV_EncryptedContent = 602;
const uint32_t TLV_PlainTextSize = 603;
const uint32_t TLV_AesKeyId = 604;
const uint32_t TLV_InitialVector = 605;
const uint32_t TLV_Attribute = 606;

static const std::string PUBLIC_PARAMS = "PUBPARAMS";
static const std::string DECRYPT_KEY = "DKEY";
static const std::string SET_POLICY = "SET_POLICY";

using AbeType = std::string;
static const std::string ABE_TYPE_CP_ABE = "CP-ABE";
static const std::string ABE_TYPE_KP_ABE = "KP-ABE";

/**
 * The policy is specified as a simple string which encodes an in-order
 * traversal of threshold tree defining the access policy.
 */
using Policy = std::string;

} // namespace nacabe
} // namespace ndn

#endif // NAC_ABE_COMMON_HPP
