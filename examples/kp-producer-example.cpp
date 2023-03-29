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
#include <ndn-cxx/security/signing-helpers.hpp>

#include <producer.hpp> // or <nac-abe/producer.hpp>

#include <iostream>

namespace examples {

class Producer
{
public:
  Producer()
    : m_producerCert(m_keyChain.getPib().getIdentity("/producerPrefix").getDefaultKey().getDefaultCertificate())
    , m_producer(m_face, m_keyChain, m_producerCert,
                 m_keyChain.getPib().getIdentity("/aaPrefix").getDefaultKey().getDefaultCertificate())
  {
    m_signingInfo = signingByCertificate(m_producerCert);
  }

  void
  run()
  {
    const std::string plainText = "Hello world";
    const std::vector<std::string> attributes = {"attribute"};

    std::shared_ptr<ndn::Data> contentData, ckData;
    while (!m_producer.readyForEncryption()) usleep(1);
    std::tie(contentData, ckData) = m_producer.produce("/randomData", attributes,
                                                       {reinterpret_cast<const uint8_t*>(plainText.data()),
                                                        plainText.size()}, m_signingInfo);

    std::cout << "Content data name: " << contentData->getName() << std::endl;

    m_face.setInterestFilter(m_producerCert.getIdentity(),
                             [=] (const auto&, const auto& interest) {
                               std::cout << ">> I: " << interest << std::endl;
                               if (interest.getName().isPrefixOf(contentData->getName())) {
                                 std::cout << "<< D: " << contentData->getName() << std::endl;
                                 m_face.put(*contentData);
                               }
                               if (interest.getName().isPrefixOf(ckData->getName())) {
                                 std::cout << "<< D: " << ckData->getName() << std::endl;
                                 m_face.put(*ckData);
                               }
                             },
                             [this] (const auto& prefix, const std::string& reason) {
                               std::cerr << "ERROR: Failed to register prefix '" << prefix
                                         << "' with the local forwarder (" << reason << ")" << std::endl;
                               m_face.shutdown();
                             });

    m_face.processEvents();
  }

  void processEvents(ndn::time::milliseconds ms)
  {
    m_face.processEvents(ms);
  }

private:
  ndn::Face m_face;
  ndn::KeyChain m_keyChain;
  ndn::security::Certificate m_producerCert;
  ndn::nacabe::Producer m_producer;
  ndn::security::SigningInfo m_signingInfo;
};

} // namespace examples

int
main(int argc, char** argv)
{
  using namespace ndn::time_literals;

  try {
    examples::Producer producer;
    producer.processEvents(5_s);
    producer.run();
    return 0;
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
    return 1;
  }
}
