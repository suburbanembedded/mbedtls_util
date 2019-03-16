#pragma once

#include <mbedtls/cipher.h>

#include <array>

class mbed_aes128_gcm
{
public:

	static constexpr size_t TAG_SIZE   = 128 / CHAR_BIT;
	static constexpr size_t BLOCK_SIZE   = 128 / CHAR_BIT;
	static constexpr size_t KEY_LEN_BITS = 128;
	static constexpr size_t KEY_SIZE = 128 / CHAR_BIT;

	typedef std::array<unsigned char, BLOCK_SIZE> BlockType;
	typedef std::array<unsigned char, KEY_SIZE> KeyType;
	typedef std::array<unsigned char, BLOCK_SIZE> IVType;
	typedef std::array<unsigned char, TAG_SIZE> TagType;

	void set_key(const KeyType& key)
	{
		m_key = key;
	}

	const KeyType& get_key() const
	{
		return m_key;
	}

	static bool key_from_str(const char key_str[], KeyType* const out_key);
	static bool iv_from_str(const char iv_str[], IVType* const out_iv);
	static bool tag_from_str(const char tag_str[], TagType* const out_tag);

	void set_iv(const IVType& iv)
	{
		m_iv = iv;
	}

	const IVType& get_iv() const
	{
		return m_iv;
	}

	void set_tag(const TagType& tag)
	{
		m_tag = tag;
	}

	const TagType& get_tag() const
	{
		return m_tag;
	}

	bool update(const BlockType& in_block, const size_t in_block_len, BlockType* const out_block, size_t* const out_len);

protected:
	std::array<unsigned char, KEY_SIZE> m_key;
	std::array<unsigned char, BLOCK_SIZE> m_iv;
	std::array<unsigned char, TAG_SIZE> m_tag;

	mbedtls_cipher_context_t ctx;
};
