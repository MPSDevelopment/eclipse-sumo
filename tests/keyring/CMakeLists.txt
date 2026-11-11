add_executable(keyring_encrypt keyring_encrypt.cpp)
target_link_libraries(keyring_encrypt OpenSSL::Crypto)
set_property(TARGET keyring_encrypt PROPERTY FOLDER "tests")

set(KEYRING_TEST_CASES
    plain_loads
    encrypted_loads
    encrypted_config_loads
    no_plaintext_on_disk
    encrypted_gzip_net_loads
    tampered_gzip_net_fails
    tampered_file_fails
    wrong_key_fails
    invalid_frame_fails
    hardened_refuses_plain_file
    hardened_requires_keyring
    hardened_refuses_output_options
    hardened_refuses_traci_load
    traci_bind_address
    hardened_refuses_ssm_device
    hardened_refuses_option_from_config
    hardened_accepts_darts_options)

foreach (KEYRING_CASE ${KEYRING_TEST_CASES})
    add_test(NAME keyring_${KEYRING_CASE}
             COMMAND ${Python_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/run_keyring_test.py
                     --sumo $<TARGET_FILE:sumo> --encrypt $<TARGET_FILE:keyring_encrypt>
                     --data ${CMAKE_CURRENT_SOURCE_DIR}/data --hardened ${SUMO_HARDENED} ${KEYRING_CASE})
    set_tests_properties(keyring_${KEYRING_CASE} PROPERTIES TIMEOUT 180 SKIP_RETURN_CODE 77 LABELS keyring
                         ENVIRONMENT "SUMO_HOME=${CMAKE_SOURCE_DIR}")
endforeach ()
