add_library(mbedtls_util
	src/AES_GCM_aux_data.cpp
	src/mbed_aes128_gcm.cpp
	src/mbed_aes128_gcm_dec.cpp
	src/mbed_aes128_gcm_enc.cpp

)

target_include_directories(mbedtls_util PUBLIC
	include/
)

target_link_libraries(mbedtls_util
	common_util
	tinyxml2_util
)

if(DEFINED Doxygen::doxygen)
	doxygen_add_docs(mbedtls_util_docs
		include/
		src/
	)
endif()
