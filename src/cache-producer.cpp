//
// Created by Tyler on 8/14/21.
//

#include "cache-producer.hpp"

namespace ndn {
namespace nacabe {

CacheProducer::CacheProducer(Face
                             &face,
                             security::KeyChain &keyChain,
                             const security::Certificate &identityCert,
                             const security::Certificate &attrAuthorityCertificate) :
    Producer(face, keyChain, identityCert, attrAuthorityCertificate) {}

CacheProducer::CacheProducer(Face &face,
                             security::KeyChain &keyChain,
                             const security::Certificate &identityCert,
                             const security::Certificate &attrAuthorityCertificate,
                             const security::Certificate &dataOwnerCertificate) :
    Producer(face, keyChain, identityCert, attrAuthorityCertificate, dataOwnerCertificate) {}

void CacheProducer::clearCache() {
  m_cpKeyCache.clear();
  m_kpKeyCache.clear();
}

std::tuple<std::shared_ptr<Data>, std::shared_ptr<Data>>
CacheProducer::produce(const Name& dataName, const Policy& accessPolicy,
                       span<const uint8_t> content)
{
  if (m_cpKeyCache.count(accessPolicy) == 0) {
    auto k = ckDataGen(accessPolicy);
    if (k.first == nullptr || k.second == nullptr) {
      return std::make_tuple(nullptr, nullptr);
    }
    m_cpKeyCache.emplace(accessPolicy, k);
  }
  auto& key = m_cpKeyCache.at(accessPolicy);
  auto data = Producer::produce(key.first, key.second->getName(), dataName, content);
  return std::make_tuple(key.second, data);
}

std::tuple<std::shared_ptr<Data>, std::shared_ptr<Data>>
CacheProducer::produce(const Name& dataName, const std::vector<std::string>& attributes,
                       span<const uint8_t> content)
{
  std::stringstream ss;
  for (auto& i : attributes) ss << i << "|";
  auto attStr = ss.str();
  if (m_kpKeyCache.count(attStr) == 0) {
    auto k = ckDataGen(attributes);
    if (k.first == nullptr || k.second == nullptr) {
      return std::make_tuple(nullptr, nullptr);
    }
    m_kpKeyCache.emplace(attStr, k);
  }
  auto& key = m_kpKeyCache.at(attStr);
  auto data = Producer::produce(key.first, key.second->getName(), dataName, content);
  return std::make_tuple(key.second, data);
}

}
}
