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

#include "producer.hpp"

namespace ndn {
namespace ndnabac {

//public
Producer::Producer(const security::v2::Certificate& identityCert, Face& face,
				   				 const Name producerName, uint8_t repeatAttempts = 3)
  : m_cert(identityCert)
  , m_face(face)
  , m_producerName(producerName)
  , m_repeatAttempts(repeatAttempts)
{
	m_face.setInterestFilter(InterestFilter(producerName),
							 						 bind(&Producer::onInterest, this, _1, _2),
							 						 RegisterPrefixSuccessCallback(),
							 						 RegisterPrefixFailureCallback());
}

void
Producer::produce(const std::string& accessPolicy,
	              	const Name& attrAuthorityPrefix,
          		  	const uint8_t* content, size_t contentLen,
                  const SuccessCallback& onDataProduceCb,
                  const ErrorCallback& errorCallback)
{}

//private:
void
onInterest(const InterestFilter& forwardingHint, const Interest& interest)
{
	
}


void
Producer::fetchAuthorityPubParams(const Name& attrAuthorityPrefix,
	                	              const SuccessCallback& onPublicParamsCb)
{}

} // namespace ndnabac
} // namespace ndn
