/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2017-2023, Regents of the University of California.
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

#ifndef NAC_ABE_CRYPTO_EXECUTOR_HPP
#define NAC_ABE_CRYPTO_EXECUTOR_HPP

#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>
#include <thread>

namespace ndn {
namespace nacabe {

/**
 * @brief Single background thread for ABE operations, shared by all Producers/Consumers.
 *
 * Keeps slow ABE work off the Face thread. One thread only, since ABESupport's
 * content-key cache is not synchronized. A Producer/Consumer must outlive its
 * in-flight produceAsync()/consume() calls.
 */
class CryptoExecutor
{
public:
  static CryptoExecutor&
  getInstance();

  CryptoExecutor(const CryptoExecutor&) = delete;
  CryptoExecutor&
  operator=(const CryptoExecutor&) = delete;

  boost::asio::io_context&
  ioContext()
  {
    return m_io;
  }

private:
  CryptoExecutor();
  ~CryptoExecutor();

  boost::asio::io_context m_io;
  boost::asio::executor_work_guard<boost::asio::io_context::executor_type> m_work;
  std::thread m_thread;
};

} // namespace nacabe
} // namespace ndn

#endif // NAC_ABE_CRYPTO_EXECUTOR_HPP
