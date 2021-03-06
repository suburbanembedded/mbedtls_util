/**
 * @brief mbed_aes128_gcm_dec
 * @author Jacob Schloss <jacob@schloss.io>
 * @copyright Copyright (c) 2019 Jacob Schloss. All rights reserved.
 * @license Licensed under the 3-Clause BSD license. See LICENSE for details
*/

#pragma once

#include "mbedtls_util/mbed_aes128_gcm.hpp"

class mbed_aes128_gcm_dec : public mbed_aes128_gcm
{
public:

	/**
	* 1) set key
	* 2) set iv
	* 3) set tag
	* 4) call init
	* 5) call update
	* 6) call finish
	**/

	bool initialize(unsigned char* add_data, size_t add_data_len);

	bool finish(BlockType* const out_block, size_t* const out_len, int* const mbedtls_ret);

protected:
	
};