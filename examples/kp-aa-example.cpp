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
    : m_aa(m_keyChain.getPib().getIdentity("/aaPrefix").getDefaultKey().getDefaultCertificate(),
           m_face, m_keyChain)
  {
    auto consumerCert1 = m_keyChain.getPib().getIdentity("/consumerPrefix1").getDefaultKey().getDefaultCertificate();
    m_aa.addNewPolicy(consumerCert1, "attribute");
  }

  void
  run()
  {
    m_face.processEvents();
  }

private:
  ndn::Face m_face;
  ndn::KeyChain m_keyChain;
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
