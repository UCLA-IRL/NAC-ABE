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
#include <boost/version.hpp>
#include <boost/filesystem.hpp>

#include "test-common.hpp"

namespace ndn {
namespace nacabe {
namespace tests {

class GlobalConfigurationFixture : boost::noncopyable
{
public:
  GlobalConfigurationFixture()
  {
    if (getenv("HOME") != nullptr) {
      m_home = getenv("HOME");
    }
    if (getenv("NDN_CLIENT_PIB") != nullptr) {
      m_pib = getenv("NDN_CLIENT_PIB");
    }
    if (getenv("NDN_CLIENT_TPM") != nullptr) {
      m_tpm = getenv("NDN_CLIENT_TPM");
    }

    boost::filesystem::path dir(UNIT_TEST_CONFIG_PATH);
    dir /= "test-home";
    setenv("HOME", dir.generic_string().c_str(), 1);

    if (exists(dir)) {
      remove_all(dir);
    }

    setenv("NDN_CLIENT_PIB", ("pib-sqlite3:" + dir.string()).c_str(), 1);
    setenv("NDN_CLIENT_TPM", ("tpm-file:" + dir.string()).c_str(), 1);
    create_directories(dir);
  }

  ~GlobalConfigurationFixture()
  {
    if (!m_home.empty()) {
      setenv("HOME", m_home.c_str(), 1);
    }
    if (!m_pib.empty()) {
      setenv("NDN_CLIENT_PIB", m_pib.c_str(), 1);
    }
    if (!m_tpm.empty()) {
      setenv("NDN_CLIENT_TPM", m_tpm.c_str(), 1);
    }
  }

private:
  std::string m_home;
  std::string m_pib;
  std::string m_tpm;
};

BOOST_GLOBAL_FIXTURE(GlobalConfigurationFixture)
#if (BOOST_VERSION >= 105900)
;
#endif // BOOST_VERSION >= 105900

} // namespace tests
} // namespace nacabe
} // namespace ndn
