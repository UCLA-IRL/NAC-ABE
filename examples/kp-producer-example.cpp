#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>

#include <iostream>
#include <producer.hpp>

// Enclosing code in ndn simplifies coding (can also use `using namespace ndn`)
namespace ndn {
// Additional nested namespaces should be used to prevent/limit name conflicts
namespace examples {

class Producer
{
public:

  Producer(KeyChain& keyChain)
  : m_keyChain(keyChain)
  , m_producer(m_face, m_keyChain,
             keyChain.getPib().getIdentity("/producerPrefix").getDefaultKey().getDefaultCertificate(),
             keyChain.getPib().getIdentity("/aaPrefix").getDefaultKey().getDefaultCertificate()) {
    producerCert = keyChain.getPib().getIdentity("/producerPrefix").getDefaultKey().getDefaultCertificate();
  }

  void
  run()
  {
    Name dataName("randomData");
    const std::string plainText = "Hello world";
    std::vector<std::string> attributes;
    attributes.emplace_back("attribute");

    std::shared_ptr<Data> contentData, ckData;
    std::tie(contentData, ckData) = m_producer.produce(dataName, attributes,
                                                       {reinterpret_cast<const uint8_t*>(plainText.data()),
                                                        plainText.size()});
    std::cout << "content data name: " << contentData->getName() << std::endl;

    m_face.setInterestFilter(producerCert.getIdentity(),
                                   [this, contentData, ckData] (const ndn::InterestFilter&, const ndn::Interest& interest) {
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
                                   [&](const Name& prefix, const std::string& reason) {
                                     std::cerr << "ERROR: Failed to register prefix '" << prefix
                                               << "' with the local forwarder (" << reason << ")" << std::endl;
                                     m_face.shutdown();
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
  KeyChain& m_keyChain;
  ndn::nacabe::Producer m_producer;
  security::Certificate producerCert;
};

} // namespace examples
} // namespace ndn

int
main(int argc, char** argv)
{
  try {
    ndn::KeyChain keyChain;
    ndn::examples::Producer producer(keyChain);
    producer.processEvents(ndn::time::milliseconds(500));
    producer.run();
    producer.processEvents();
    return 0;
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
    return 1;
  }
}
