#pragma once

#include "mbed_aes128_gcm.hpp"

#include "../external/tinyxml2/tinyxml2.h"

#include <array>
#include <cstdint>

class AES_GCM_aux_data
{
public:

	bool from_xml(const tinyxml2::XMLDocument& doc);
	bool to_xml(tinyxml2::XMLDocument* const doc) const;

	void set_iv(const mbed_aes128_gcm::IVType& iv)
	{
		m_iv = iv;
	}
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