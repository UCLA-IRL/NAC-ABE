/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2017-2022, Regents of the University of California.
 *
 * This file is part of NAC-ABE.
 *
 * NAC-ABE is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation, either
 * version 3 of the License, or (at your option) any later version.
 *
 * NAC-ABE is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received copies of the GNU General Public License along with
 * NAC-ABE, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of NAC-ABE authors and contributors.
 */

#ifndef NAC_ABE_PARAM_FETCHER_HPP
#define NAC_ABE_PARAM_FETCHER_HPP

#include "algo/public-params.hpp"
#include "trust-config.hpp"
#include "rdr-fetcher.hpp"

namespace ndn {
namespace nacabe {

/**
 * @brief Internal class for fetching parameters.
 */
class ParamFetcher
{
public:
  ParamFetcher(Face& face, const Name& attrAuthorityPrefix, const TrustConfig& trustConfig,
               Interest interestTemplate = RdrFetcher::getDefaultInterestTemplate());

  void
  fetchPublicParams();

  AbeType
  getAbeType() const
  {
    return m_abeType;
  }

  algo::PublicParams
  getPublicParams() const
  {
    return m_pubParamsCache;
  }

private:
  const Name& m_attrAuthorityPrefix;
  const TrustConfig& m_trustConfig;
  RdrFetcher m_rdrFetcher;

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  AbeType m_abeType;
  algo::PublicParams m_pubParamsCache;
  Interest m_interestTemplate;
};

} // namespace nacabe
} // namespace ndn

#endif // NAC_ABE_PARAM_FETCHER_HPP
