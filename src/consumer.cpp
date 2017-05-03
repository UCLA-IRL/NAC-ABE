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

#include "consumer.hpp"

namespace ndn {
namespace ndnabac {

static const Name REQUEST_TOKEN = "/token";

// public
Consumer::Consumer(const security::v2::Certificate& identityCert, Face& face,
									 const Name& consumerPrefix, uint8_t repeatAttempts = 3)
  : m_identityCert(identityCert)
  , m_face(face)
  , m_prefix(consumerPrefix)
  , m_repeatAttempts(repeatAttempts)
{
}

void
Consumer::consume(const Name& dataName,
				  				const ConsumptionCallback& consumptionCb,
				  				const ErrorCallback& errorCb)
{
	shared_ptr<Interest> interest = make_shared<Interest>(dataName);
	sendInterest(*Interest);
}

void
Consumer::requestToken(const Name ownerPrefix)
{
	Name requestPrefix = Name(ownerPrefix);
	requestPrefix.append(REQUEST_TOKEN);
	//add certificate
	sendTokenInterest(Interest(requestPrefix), m_repeatAttempts);
}

void
Consumer::sendTokenInterest(const Interest& interest, uint8_t repeatTimes)
{
	m_face.expressInterest(interest,
												 bind(&Consumer::handleTokenData, this, _1, _2),
												 bind(&Consumer::handleTokenTimeout, this, repeatTimes, _1));

}

void
Consumer::handleTokenData(const Interest& interest, Data& data)
{
}

void
Consumer::handleTokenTimeout(uint8_t repeatTimes, const Interest& interest)
{
	if (repeatTimes == 0) {
		//throw exception
	}
	else {
		repeatTimes--;
		sendTokenInterest(interest, repeatTimes);
	}
}

void
Consumer::fetchDecryptionKey(const Name& attrAuthorityPrefix,
							 							 const Data& token)
{}

//private
void
Consumer::fetchAttributePubParams(const Name& attrAuthorityPrefix,
								  								const SuccessCallback& onPublicParamsCb)
{ew
}



} // namespace ndnabac
} // namespace ndn
