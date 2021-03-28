/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2014-2019, Regents of the University of California,
 *                          Arizona Board of Regents,
 *                          Colorado State University,
 *                          University Pierre & Marie Curie, Sorbonne University,
 *                          Washington University in St. Louis,
 *                          Beijing Institute of Technology,
 *                          The University of Memphis.
 *
 * This file, originally written as part of NFD (Named Data Networking Forwarding Daemon),
 * is a part of NAC-ABE.
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

#ifndef CHRONOSHARE_TESTS_TEST_COMMON_HPP
#define CHRONOSHARE_TESTS_TEST_COMMON_HPP

#include "boost-test.hpp"

#include <boost/asio/io_service.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

#include <ndn-cxx/name.hpp>
#include <ndn-cxx/data.hpp>
#include <ndn-cxx/lp/nack.hpp>
#include <ndn-cxx/link.hpp>
#include <ndn-cxx/util/time-unit-test-clock.hpp>
#include <ndn-cxx/util/string-helper.hpp>
#include <ndn-cxx/util/logger.hpp>
#include <ndn-cxx/util/random.hpp>


namespace ndn {
namespace nacabe {
namespace tests {

/** \brief create an Interest
 *  \param name Interest name
 *  \param nonce if non-zero, set Nonce to this value
 *               (useful for creating Nack with same Nonce)
 */
shared_ptr<Interest>
makeInterest(const Name& name, uint32_t nonce = 0);

/** \brief create a Data with fake signature
 *  \note Data may be modified afterwards without losing the fake signature.
 *        If a real signature is desired, sign again with KeyChain.
 */
shared_ptr<Data>
makeData(const Name& name);

/** \brief create a Nack
 *  \param name Interest name
 *  \param nonce Interest nonce
 *  \param reason Nack reason
 */
lp::Nack
makeNack(const Name& name, uint32_t nonce, lp::NackReason reason);

/** \brief replace a name component
 *  \param[inout] name name
 *  \param index name component index
 *  \param a arguments to name::Component constructor
 */
template<typename...A>
void
setNameComponent(Name& name, ssize_t index, const A& ...a)
{
  Name name2 = name.getPrefix(index);
  name2.append(name::Component(a...));
  name2.append(name.getSubName(name2.size()));
  name = name2;
}

template<typename Packet, typename...A>
void
setNameComponent(Packet& packet, ssize_t index, const A& ...a)
{
  Name name = packet.getName();
  setNameComponent(name, index, a...);
  packet.setName(name);
}

/** \brief convert file to digest
 */
ndn::ConstBufferPtr
digestFromFile(const boost::filesystem::path& filename);

} // namespace tests
} // namespace nacabe
} // namespace ndn

#include "identity-management-fixture.hpp"

#endif // CHRONOSHARE_TESTS_TEST_COMMON_HPP
