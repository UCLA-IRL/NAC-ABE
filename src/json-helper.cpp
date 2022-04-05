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

#include "json-helper.hpp"

#include <boost/property_tree/json_parser.hpp>

namespace ndn {
namespace nacabe {

Block
JsonHelper::dataContentFromJson(const JsonSection& jsonSection)
{
  std::stringstream ss;
  boost::property_tree::write_json(ss, jsonSection);
  return makeStringBlock(ndn::tlv::Content, ss.str());
}

std::string
JsonHelper::convertJson2String(const JsonSection& json)
{
  std::stringstream ss;
  boost::property_tree::write_json(ss, json);
  return ss.str();
}

JsonSection
JsonHelper::convertString2Json(const std::string& jsonContent)
{
  std::istringstream ss(jsonContent);
  JsonSection json;
  boost::property_tree::json_parser::read_json(ss, json);
  return json;
}

JsonSection
JsonHelper::getJsonFromDataContent(const Data& data)
{
  Block jsonBlock = data.getContent();
  std::string jsonString = encoding::readString(jsonBlock);
  std::istringstream ss(jsonString);
  JsonSection json;
  boost::property_tree::json_parser::read_json(ss, json);
  return json;
}

} // namespace ndn
} // namespace nacabe
