//
// Created by Tyler on 8/14/21.
//

#ifndef NAC_ABE_CACHEPRODUCER_H
#define NAC_ABE_CACHEPRODUCER_H

#include "producer.hpp"

namespace ndn {
namespace nacabe {

/**
 * A producer that automatically reuses same key for same attributes
 */
class CacheProducer : public Producer {
public:
/**
   * Initialize a producer. Use when no data owner defined.
   * @param face
   * @param keyChain
   * @param identityCert
   * @param attrAuthorityCertificate
   * @param repeatAttempts
   */
  CacheProducer(Face &face,
                security::KeyChain &keyChain,
                const security::Certificate &identityCert,
                const security::Certificate &attrAuthorityCertificate);

  /**
   * Initialize a producer. Use when a data owner defined.
   * @param face
   * @param keyChain
   * @param identityCert
   * @param attrAuthorityCertificate
   */
  CacheProducer(Face &face,
                security::KeyChain &keyChain,
                const security::Certificate &identityCert,
                const security::Certificate &attrAuthorityCertificate,
                const security::Certificate &dataOwnerCertificate);

  ~CacheProducer() {};

  void clearCache();

  /**
   * @brief Produce CP-encrypted Data and corresponding encrypted CK Data
   *
   * Used when data owner is not used.
   *
   * @param dataName The name of data, not including producer's prefix
   * @param dataSuffix The suffix of data.
   * @param accessPolicy The encryption policy, e.g., (ucla or mit) and professor
   * @param content The payload
   * @param contentLen The payload length
   * @return The encrypted data and the encrypted CK data
   */
  std::tuple<std::shared_ptr<Data>, std::shared_ptr<Data>>
  produce(const Name &dataName, const Policy &accessPolicy,
          const uint8_t *content, size_t contentLen) override;

  /**
   * @brief Produce KP-encrypted Data and corresponding encrypted CK Data
   *
   * Used when data owner is not used.
   *
   * @param dataName The name of data, not including producer's prefix
   * @param dataSuffix The suffix of data.
   * @param accessPolicy The encryption policy, e.g., (ucla or mit) and professor
   * @param content The payload
   * @param contentLen The payload length
   * @return The encrypted data and the encrypted CK data
   */
  std::tuple<std::shared_ptr<Data>, std::shared_ptr<Data>>
  produce(const Name &dataName, const std::vector<std::string> &attributes,
          const uint8_t *content, size_t contentLen) override;

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  std::map<std::string, std::pair<std::shared_ptr<algo::ContentKey>, std::shared_ptr<Data>>> m_cpKeyCache;
  std::map<std::string, std::pair<std::shared_ptr<algo::ContentKey>, std::shared_ptr<Data>>> m_kpKeyCache;
};

}
}

#endif //NAC_ABE_CACHEPRODUCER_H
