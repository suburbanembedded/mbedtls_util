#include "mbed_aes128_gcm_dec.hpp"

bool mbed_aes128_gcm_dec::initialize(unsigned char* add_data, size_t add_data_len)
{
	int ret = 0;
	
	mbedtls_cipher_init(&ctx);

	ret = mbedtls_cipher_setup(&ctx, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_GCM));
	if(ret != 0)
	{
		return false;
	}

	ret = mbedtls_cipher_setkey(&ctx, m_key.data(), KEY_LEN_BITS, MBEDTLS_DECRYPT);
	if(ret != 0)
	{
		return false;
	}

	ret = mbedtls_cipher_set_iv(&ctx, m_iv.data(), m_iv.size());
	if(ret != 0)
	{
		return false;
	}

	ret = mbedtls_cipher_update_ad(&ctx, add_data, add_data_len);
	if(ret != 0)
	{
		return false;
	}

	return true;
}

bool mbed_aes128_gcm_dec::finish(BlockType* const out_block, size_t* const out_len, int* const mbedtls_ret)
{
	*mbedtls_ret = mbedtls_cipher_finish(&ctx, out_block->data(), out_len);
	if(*mbedtls_ret != 0)
	{
		return false;
	}

	*mbedtls_ret = mbedtls_cipher_check_tag(&ctx, m_tag.data(), m_tag.size());
	if(*mbedtls_ret != 0)
	{
		return false;
	}

	mbedtls_cipher_free(&ctx);

	return true;
}
