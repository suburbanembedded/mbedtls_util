/**
 * @brief mbed_aes128_gcm
 * @author Jacob Schloss <jacob@schloss.io>
 * @copyright Copyright (c) 2019 Jacob Schloss. All rights reserved.
 * @license Licensed under the 3-Clause BSD license. See LICENSE for details
*/

#include "mbedtls_util/mbed_aes128_gcm.hpp"

bool mbed_aes128_gcm::update(const BlockType& in_block, const size_t in_block_len, BlockType* const out_block, size_t* const out_len)
{
	if(mbedtls_cipher_update(&ctx, in_block.data(), in_block_len, out_block->data(), out_len) != 0)
	{
		return false;
	}

	return true;
}