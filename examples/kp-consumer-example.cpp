#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/validator-config.hpp>

#include <iostream>
#include "consumer.hpp"

// Enclosing code in ndn simplifies coding (can also use `using namespace ndn`)
namespace ndn {
// Additional nested namespaces should be used to prevent/limit name conflicts
namespace examples {

class Consumer
{
public:
  Consumer(KeyChain& keyChain) :
      m_keyChain(keyChain),
      consumerCert1(keyChain.getPib().getIdentity("/consumerPrefix1").getDefaultKey().getDefaultCertificate()),
      consumer1(m_face, keyChain, consumerCert1, keyChain.getPib().getIdentity("/aaPrefix").getDefaultKey().getDefaultCertificate()) {
    producerCert = m_keyChain.getPib().getIdentity("/producerPrefix").getDefaultKey().getDefaultCertificate();
    consumer1.obtainDecryptionKey();
  }

  void
  run()
  {
    Name dataName("/randomData");
    consumer1.consume(producerCert.getIdentity().append(dataName),
                        [&] (const Buffer& result) {
                        std::cout << "Received Data " << std::string(result.begin(), result.end()) << std::endl;
                        },
                        [&] (const auto& result) {
                          std::cout << "Error: " << result << std::endl;
                        }
  );

  }

  void processEvents() {
    m_face.processEvents();
  }

  void processEvents(boost::chrono::duration<int_least64_t, boost::milli> s) {
    m_face.processEvents(s);
  }

private:
  Face m_face;
  security::Certificate consumerCert1;
  security::Certificate producerCert;
  ndn::nacabe::Consumer consumer1;
  KeyChain& m_keyChain;
};

} // namespace examples
} // namespace ndn

int
main(int argc, char** argv)
{
  try {
    ndn::KeyChain keyChain;
    ndn::examples::Consumer consumer(keyChain);
    consumer.processEvents(ndn::time::milliseconds(5000));
    consumer.run();
    consumer.processEvents();
    return 0;
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
    return 1;
  }
}