#include "AES_GCM_aux_data.hpp"

#include "common_util/Byte_util.hpp"

#include "tinyxml2_helper.hpp"

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

		if(strnlen(iv_str, 32) != 32)
		{
			return false;
		}

		for(size_t i = 0; i < 16; i++)
		{
			if(!Byte_util::hex_to_byte(iv_str + i*2, m_iv.data() + i))
			{
				return false;
			}
		}
	}

	{
		char const * tag_str = nullptr;
		if(!get_str_text(doc_root, "tag", &tag_str))
		{
			return false;
		}
		
		if(strnlen(tag_str, 32) != 32)
		{
			return false;
		}

		for(size_t i = 0; i < 16; i++)
		{
			if(!Byte_util::hex_to_byte(tag_str + i*2, m_tag.data() + i))
			{
				return false;
			}
		}
	}

	return true;
}