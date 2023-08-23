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
#include <ndn-cxx/security/key-chain.hpp>

#include <attribute-authority.hpp> // or <nac-abe/attribute-authority.hpp>

#include <iostream>

namespace examples {

using ndn::nacabe::KpAttributeAuthority;
class AttributeAuthority
{
public:
  AttributeAuthority()
    : m_aaCert(m_keyChain.getPib().getIdentity("/example/aa").getDefaultKey().getDefaultCertificate())
    , m_aa(m_aaCert, m_face, m_validator, m_keyChain)
  {
    auto consumerCert1 = m_keyChain.getPib().getIdentity("/example/consumer").getDefaultKey().getDefaultCertificate();
    // 1. this approach will directly use the certificate passed in without validation
    // m_aa.addNewPolicy(consumerCert1, "attribute");
    // 2. this approach will try fetch corresponding certificate when receiving 
    //    corresponding DKEY Interest
    m_aa.addNewPolicy("/example/consumer", "attribute");
    m_validator.load("trust-schema.conf");

    // self certificate filter
    m_face.setInterestFilter(m_aaCert.getKeyName(),
      [this] (auto&...) {
        m_face.put(m_aaCert); 
      }
    );
  }

  void
  run()
  {
    m_face.processEvents();
  }

private:
  ndn::Face m_face;
  ndn::KeyChain m_keyChain;
  ndn::ValidatorConfig m_validator{m_face};
  ndn::security::Certificate m_aaCert;
  KpAttributeAuthority m_aa;
};

} // namespace examples

int
main(int argc, char** argv)
{
  try {
    examples::AttributeAuthority aa;
    aa.run();
    return 0;
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
    return 1;
  }
}
