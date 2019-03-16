#pragma once

#include "mbed_aes128_gcm.hpp"

class mbed_aes128_gcm_enc : public mbed_aes128_gcm
{
public:

	/**
	* 1) set key
	* 2) set iv
	* 3) call init
	* 4) call update
	* 4) call finish
	**/

	bool initialize(unsigned char* add_data, size_t add_data_len);

	bool finish(BlockType* const out_block, size_t* const out_len);

protected:
	
};