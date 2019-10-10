/**
 * @brief AES_GCM_aux_data
 * @author Jacob Schloss <jacob@schloss.io>
 * @copyright Copyright (c) 2019 Jacob Schloss. All rights reserved.
 * @license Licensed under the 3-Clause BSD license. See LICENSE for details
*/

#include "mbedtls_util/AES_GCM_aux_data.hpp"

#include "common_util/Byte_util.hpp"

#include "tinyxml2_util/tinyxml2_helper.hpp"

bool AES_GCM_aux_data::set_iv(const char iv_str[])
{
	return mbed_aes128_gcm::iv_from_str(iv_str, &m_iv);
}

bool AES_GCM_aux_data::set_tag(const char tag_str[])
{
	return mbed_aes128_gcm::tag_from_str(tag_str, &m_tag);
}

bool AES_GCM_aux_data::to_xml(tinyxml2::XMLDocument* const doc) const
{
	doc->Clear();

	{
		tinyxml2::XMLDeclaration* const decl = doc->NewDeclaration("xml version=\"1.0\" standalone=\"yes\" encoding=\"UTF-8\"");
		doc->InsertFirstChild(decl);
	}

	tinyxml2::XMLElement* const doc_root = doc->NewElement("app");
	doc->InsertEndChild(doc_root);

	{
		std::array<char, 33> iv_str;
		iv_str.back() = '\0';
		for(size_t i = 0; i < 16; i++)
		{
			Byte_util::u8_to_hex(m_iv[i], iv_str.data() + 2*i);
		}

		tinyxml2::XMLElement* const iv_node = doc->NewElement("iv");
		iv_node->SetText(iv_str.data());
		doc_root->InsertEndChild(iv_node);
	}

	{
		std::array<char, 33> tag_str;
		tag_str.back() = '\0';
		for(size_t i = 0; i < 16; i++)
		{
			Byte_util::u8_to_hex(m_tag[i], tag_str.data() + 2*i);
		}

		tinyxml2::XMLElement* const tag_node = doc->NewElement("tag");
		tag_node->SetText(tag_str.data());
		doc_root->InsertEndChild(tag_node);
	}

	return true;
}

bool AES_GCM_aux_data::from_xml(const tinyxml2::XMLDocument& doc)
{
	const tinyxml2::XMLElement* doc_root = doc.FirstChildElement("app");
	if(doc_root == nullptr)
	{
		return false;
	}

	{
		char const * iv_str = nullptr;
		if(!get_str_text(doc_root, "iv", &iv_str))
		{
			return false;
		}

		if(!set_iv(iv_str))
		{
			return false;
		}
	}

	{
		char const * tag_str = nullptr;
		if(!get_str_text(doc_root, "tag", &tag_str))
		{
			return false;
		}
		
		if(!set_tag(tag_str))
		{
			return false;
		}
	}

	return true;
}