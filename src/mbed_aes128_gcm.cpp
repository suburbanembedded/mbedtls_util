#include "mbed_aes128_gcm.hpp"

bool mbed_aes128_gcm::update(const BlockType& in_block, const size_t in_block_len, BlockType* const out_block, size_t* const out_len)
{
	if(mbedtls_cipher_update(&ctx, in_block.data(), in_block_len, out_block->data(), out_len) != 0)
	{
		return false;
	}

	return true;
}