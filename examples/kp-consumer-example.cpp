#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/certificate.hpp>
#include <ndn-cxx/security/key-chain.hpp>

#include <consumer.hpp> // or <nac-abe/consumer.hpp>

#include <iostream>

namespace examples {

class Consumer
{
public:
  Consumer()
    : m_producerCert(m_keyChain.getPib().getIdentity("/producerPrefix").getDefaultKey().getDefaultCertificate())
    , m_consumerCert(m_keyChain.getPib().getIdentity("/consumerPrefix1").getDefaultKey().getDefaultCertificate())
    , m_consumer(m_face, m_keyChain, m_consumerCert,
                 m_keyChain.getPib().getIdentity("/aaPrefix").getDefaultKey().getDefaultCertificate())
  {
    m_consumer.obtainDecryptionKey();
  }

  void
  run()
  {
    ndn::Name dataName("/randomData");
    while (!m_consumer.readyForDecryption()) usleep(1);
    m_consumer.consume(m_producerCert.getIdentity().append(dataName),
                       [] (const auto& result) {
                         std::cout << "Received data: " << std::string(result.begin(), result.end()) << std::endl;
                       },
                       [] (const auto& error) {
                         std::cout << "Error: " << error << std::endl;
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
  ndn::security::Certificate m_consumerCert;
  ndn::nacabe::Consumer m_consumer;
};

} // namespace examples

int
main(int argc, char** argv)
{
  using namespace ndn::time_literals;

  try {
    examples::Consumer consumer;
    consumer.processEvents(5_s);
    consumer.run();
    return 0;
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
    return 1;
  }
}
