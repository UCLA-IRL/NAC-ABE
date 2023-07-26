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
 * NAC-ABE, e.g., in COPYING.md file.  If not,ndn see <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of NAC-ABE authors and contributors.
 */

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/certificate.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/util/time.hpp>

#include <producer.hpp> // or <nac-abe/producer.hpp>

#include <iostream>

namespace examples {

ndn::KeyChain m_keyChain;
ndn::security::Certificate m_cert = m_keyChain.getPib().getIdentity("/example/producer").getDefaultKey().getDefaultCertificate();
class Producer
{
public:
  Producer()
    : m_producerCert(m_cert)
    , m_producer(m_face, m_keyChain, m_validator, m_producerCert,
                 m_keyChain.getPib().getIdentity("/example/aa").getDefaultKey().getDefaultCertificate())
  {
    m_validator.load("trust-schema.conf");
    m_signingInfo = signingByCertificate(m_producerCert);
  }

  void
  run()
  {
    const std::string plainText = "Hello world";
    const std::vector<std::string> attributes = {"attribute"};
    auto longlivedData = std::make_shared<ndn::Data>();
    longlivedData->setFreshnessPeriod(ndn::time::hours(1));

    std::vector<std::shared_ptr<ndn::Data>> contentData, ckData;
    std::tie(contentData, ckData) = m_producer.produce("/randomData", attributes,
                                                       {reinterpret_cast<const uint8_t*>(plainText.data()),
                                                        plainText.size()}, m_signingInfo,
                                                        longlivedData, longlivedData, 50);

    std::cout << "Content data object name: " << contentData.at(0)->getName().getPrefix(-1) << std::endl;
    m_face.setInterestFilter(m_producerCert.getIdentity(),
                              [=] (const auto&, const auto& interest) {
                                std::cout << ">> I: " << interest << std::endl;
                                if (interest.getName().isPrefixOf(m_cert.getName())) {
                                  m_face.put(m_cert);
                                }
                                for (auto seg : contentData) {
                                  bool exactSeg = interest.getName() == seg->getName();
                                  bool probeSeg = (interest.getName() == seg->getName().getPrefix(-1)) &&
                                                   interest.getCanBePrefix();
                                  if (exactSeg || probeSeg) {
                                    std::cout << "<< D: " << seg->getName() << std::endl;
                                    m_face.put(*seg);
                                    std::cout << seg->getContent().size() << " bytes" << std::endl;
                                    break;
                                  }
                                }
                                for (auto seg : ckData) {
                                  bool exactSeg = interest.getName() == seg->getName();
                                  bool probeSeg = (interest.getName() == seg->getName().getPrefix(-1)) &&
                                                   interest.getCanBePrefix();
                                  if (exactSeg || probeSeg) {
                                    std::cout << "<< D: " << seg->getName() << std::endl;
                                    m_face.put(*seg);
                                    std::cout << seg->getContent().size() << " bytes" << std::endl;
                                    break;
                                  }
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
  ndn::ValidatorConfig m_validator{m_face};
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
    producer.processEvents(1_s);
    producer.run();
    return 0;
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
    return 1;
  }
}
