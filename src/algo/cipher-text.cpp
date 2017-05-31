/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017, Regents of the University of California.
 *
 * This file is part of ndnabac, a certificate management system based on NDN.
 *
 * ndnabac is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation, either
 * version 3 of the License, or (at your option) any later version.
 *
 * ndnabac is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received copies of the GNU General Public License along with
 * ndnabac, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of ndnabac authors and contributors.
 */

#include "cipher-text.hpp"
#include <ndn-cxx/util/concepts.hpp>

namespace ndn {
namespace ndnabac {
namespace algo {

const uint32_t CipherText::TLV_EncryptedAesKey = 1;
const uint32_t CipherText::TLV_EncryptedContent = 2;
const uint32_t CipherText::TLV_PlainTextSize = 3;

template<encoding::Tag TAG>
size_t
CipherText::wireEncode(EncodingImpl<TAG>& encoder) const
{
  size_t totalLength = 0;

  // encrypted symmetric key
  Buffer aesKeyBuf(m_cph->data, m_cph->len);
  totalLength += encoder.prependByteArrayBlock(TLV_EncryptedAesKey,
                                               aesKeyBuf.get(), aesKeyBuf.size());

  // encrypted content
  totalLength += encoder.prependByteArrayBlock(TLV_EncryptedContent,
                                               m_content.get(), m_content.size());

  // plain text length
  totalLength += prependNonNegativeIntegerBlock(encoder, TLV_PlainTextSize, m_plainTextSize);

  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::Content);

  return totalLength;
}

template size_t
CipherText::wireEncode<encoding::EncoderTag>(EncodingImpl<encoding::EncoderTag>& encoder) const;

template size_t
CipherText::wireEncode<encoding::EstimatorTag>(EncodingImpl<encoding::EstimatorTag>& encoder) const;

const Block&
CipherText::wireEncode() const
{
  EncodingEstimator estimator;
  size_t estimatedSize = wireEncode(estimator);

  EncodingBuffer buffer(estimatedSize, 0);
  wireEncode(buffer);

  this->m_wire = buffer.block();
  return m_wire;
}

void
CipherText::wireDecode(const Block& wire)
{
  if (wire.type() != tlv::Content)
    BOOST_THROW_EXCEPTION(tlv::Error("Unexpected TLV type when decoding cipher text"));

  this->m_wire = wire;
  m_wire.parse();

  Block::element_const_iterator it = m_wire.elements_begin();

  // plain text length
  if (it != m_wire.elements_end() && it->type() == TLV_PlainTextSize) {
    this->m_plainTextSize = static_cast<uint8_t>(readNonNegativeInteger(*it));
    it++;
  }

  // encrypted content
  if (it != m_wire.elements_end() && it->type() == TLV_EncryptedContent) {
    this->m_content = Buffer(it->value(), it->value_size());
    it++;
  }
  else
    BOOST_THROW_EXCEPTION(tlv::Error("Unexpected TLV structure when decoding encrypted content"));

  // encrypted symmetric key
  if (it != m_wire.elements_end() && it->type() == TLV_EncryptedAesKey) {
    Buffer cphBuffer(it->value(), it->value_size());
    GByteArray cphArray{cphBuffer.buf(), static_cast<guint>(cphBuffer.size())};
    this->m_cph = &cphArray;
    it++;
  }
  else
    BOOST_THROW_EXCEPTION(tlv::Error("Unexpected TLV structure when decoding encrypted AES key"));

  // Check if end
  if (it != m_wire.elements_end())
    BOOST_THROW_EXCEPTION(tlv::Error("Unexpected TLV structure after decoding the block"));
}

} // namespace algo
} // namespace ndnabac
} // namespace ndn
