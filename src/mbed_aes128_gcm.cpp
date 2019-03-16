#include "mbedtls_util/mbed_aes128_gcm.hpp"

#include "common_util/Byte_util.hpp"

#include <cstring>

bool mbed_aes128_gcm::key_from_str(const char key_str[], KeyType* const out_key)
{
	constexpr size_t str_len = std::tuple_size<KeyType>::value*2;
	constexpr size_t arr_len = std::tuple_size<KeyType>::value;

	if(strnlen(key_str, str_len) != str_len)
	{
		return false;
	}

	for(size_t i = 0; i < arr_len; i++)
	{
		if(!Byte_util::hex_to_byte(key_str + i*2, out_key->data() + i))
		{
			return false;
		}
	}

	return true;
}
bool mbed_aes128_gcm::iv_from_str(const char iv_str[], IVType* const out_iv)
{
	constexpr size_t str_len = std::tuple_size<IVType>::value*2;
	constexpr size_t arr_len = std::tuple_size<IVType>::value;

	if(strnlen(iv_str, str_len) != str_len)
	{
		return false;
	}

	for(size_t i = 0; i < arr_len; i++)
	{
		if(!Byte_util::hex_to_byte(iv_str + i*2, out_iv->data() + i))
		{
			return false;
		}
	}

	return true;
}
bool mbed_aes128_gcm::tag_from_str(const char tag_str[], TagType* const out_tag)
{
	constexpr size_t str_len = std::tuple_size<TagType>::value*2;
	constexpr size_t arr_len = std::tuple_size<TagType>::value;

	if(strnlen(tag_str, str_len) != str_len)
	{
		return false;
	}

	for(size_t i = 0; i < arr_len; i++)
	{
		if(!Byte_util::hex_to_byte(tag_str + i*2, out_tag->data() + i))
		{
			return false;
		}
	}

	return true;
}

bool mbed_aes128_gcm::update(const BlockType& in_block, const size_t in_block_len, BlockType* const out_block, size_t* const out_len)
{
	if(mbedtls_cipher_update(&ctx, in_block.data(), in_block_len, out_block->data(), out_len) != 0)
	{
		return false;
	}

	return true;
}