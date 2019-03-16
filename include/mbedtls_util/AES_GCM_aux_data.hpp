#pragma once

#include "mbedtls_util/mbed_aes128_gcm.hpp"

#include "../external/tinyxml2/tinyxml2.h"

class AES_GCM_aux_data
{
public:

	bool from_xml(const tinyxml2::XMLDocument& doc);
	bool to_xml(tinyxml2::XMLDocument* const doc) const;

	bool set_iv(const char iv_str[]);
	void set_iv(const mbed_aes128_gcm::IVType& iv)
	{
		m_iv = iv;
	}

	bool set_tag(const char tag_str[]);
	void set_tag(const mbed_aes128_gcm::TagType& tag)
	{
		m_tag = tag;
	}

	const mbed_aes128_gcm::IVType& get_iv() const
	{
		return m_iv;
	}
	const mbed_aes128_gcm::TagType& get_tag() const
	{
		return m_tag;
	}
protected:

	mbed_aes128_gcm::IVType m_iv;
	mbed_aes128_gcm::TagType m_tag;
};