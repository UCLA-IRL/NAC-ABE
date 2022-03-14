#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>

#include <iostream>
#include <attribute-authority.hpp>

// Enclosing code in ndn simplifies coding (can also use `using namespace ndn`)
namespace ndn {
// Additional nested namespaces should be used to prevent/limit name conflicts
namespace examples {

class AttributeAuthority
{
public:

  AttributeAuthority(KeyChain& keyChain)
  : m_keyChain(keyChain)
  , m_aa(keyChain.getPib().getIdentity("/aaPrefix").getDefaultKey().getDefaultCertificate(), m_face, m_keyChain) {

  }

  void
  run()
  {
    auto consumerCert1 = m_keyChain.getPib().getIdentity("/consumerPrefix1").getDefaultKey().getDefaultCertificate();
    m_aa.addNewPolicy(consumerCert1, "attribute");
  }

  void processEvents() {
    m_face.processEvents();
  }

  void processEvents(time::seconds s) {
    m_face.processEvents(s);
  }

private:
  Face m_face;
  KeyChain& m_keyChain;
  ndn::nacabe::KpAttributeAuthority m_aa;
};

} // namespace examples
} // namespace ndn

int
main(int argc, char** argv)
{
  try {
    ndn::KeyChain keyChain;
    ndn::examples::AttributeAuthority producer(keyChain);
    producer.run();
    producer.processEvents();
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
    return 1;
  }
}