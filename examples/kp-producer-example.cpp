#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/certificate.hpp>
#include <ndn-cxx/security/key-chain.hpp>

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
                                                        plainText.size()});
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
