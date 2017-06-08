/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2013-2017, Regents of the University of California.
 *
 * This file is part of ChronoShare, a decentralized file sharing application over NDN.
 *
 * ChronoShare is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation, either
 * version 3 of the License, or (at your option) any later version.
 *
 * ChronoShare is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received copies of the GNU General Public License along with
 * ChronoShare, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of ChronoShare authors and contributors.
 */

#include "dummy-forwarder.hpp"

#include <boost/asio/io_service.hpp>

namespace ndn {
namespace ndnabac {

DummyForwarder::DummyForwarder(boost::asio::io_service& io)
  : m_io(io)
{
}

Face&
DummyForwarder::addFace()
{
  auto face = std::make_shared<util::DummyClientFace>(m_io, util::DummyClientFace::Options{true, true});
  face->onSendInterest.connect([this, face] (const Interest& interest) {
      for (auto& otherFace : m_faces) {
        if (&*face == &*otherFace) {
          continue;
        }
        otherFace->receive(interest);
      }
    });
  face->onSendData.connect([this, face] (const Data& data) {
      //std::cout << data.getName() << std::endl;
      for (auto& otherFace : m_faces) {
        if (&*face == &*otherFace) {
          continue;
        }
        otherFace->receive(data);
      }
    });

  face->onSendNack.connect([this, face] (const lp::Nack& nack) {
      for (auto& otherFace : m_faces) {
        if (&*face == &*otherFace) {
          continue;
        }
        otherFace->receive(nack);
      }
    });

  m_faces.push_back(face);
  return *face;
}

} // namespace ndnabac
} // namespace ndn
