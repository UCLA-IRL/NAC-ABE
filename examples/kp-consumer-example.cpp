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

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/certificate.hpp>
#include <ndn-cxx/security/key-chain.hpp>

#include <consumer.hpp> // or <nac-abe/consumer.hpp>

#include <iostream>

using namespace ndn::time_literals;
namespace examples {

class Consumer
{
public:
  Consumer()
    : m_consumerCert(m_keyChain.getPib().getIdentity("/example/consumer").getDefaultKey().getDefaultCertificate())
  {
    m_validator.load("trust-schema.conf");
    m_face.registerPrefix(m_consumerCert.getIdentity(),
      [this] (const ndn::Name& name) {
        m_face.setInterestFilter(m_consumerCert.getKeyName(),
          [=] (const auto&, const auto& interest) {
            std::cout << ">> I: " << interest << std::endl;
            // for own certificate
            m_face.put(m_consumerCert);
          }
        );
        m_consumer = std::make_shared<ndn::nacabe::Consumer>(
          m_face, m_keyChain, m_validator, m_consumerCert,
          m_keyChain.getPib().getIdentity("/example/aa").getDefaultKey().getDefaultCertificate()
        );
        m_consumer->obtainDecryptionKey();
      },
      [this] (const auto& prefix, const std::string& reason) {
        std::cerr << "ERROR: Failed to register prefix '" << prefix
                  << "' with the local forwarder (" << reason << ")" << std::endl;
        m_face.shutdown();
      }
    );
  }

  void
  run()
  {
    m_consumer->consume("/example/producer/randomData",
      [] (const auto& result) {
        std::cout << "Received data: " << std::string(result.begin(), result.end()) << std::endl;
      },
      [] (const auto& error) {
        std::cout << "Error: " << error << std::endl;
      }
    );
    processEvents(1_s);
  }

  void processEvents(ndn::time::milliseconds ms)
  {
    m_face.processEvents(ms);
  }

private:
  ndn::Face m_face;
  ndn::KeyChain m_keyChain;
  ndn::ValidatorConfig m_validator{m_face};
  ndn::security::Certificate m_consumerCert;
  std::shared_ptr<ndn::nacabe::Consumer> m_consumer;
};

} // namespace examples

int
main(int argc, char** argv)
{

  try {
    examples::Consumer consumer;
    consumer.processEvents(1_s);
    consumer.run();
    return 0;
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
    return 1;
  }
}
