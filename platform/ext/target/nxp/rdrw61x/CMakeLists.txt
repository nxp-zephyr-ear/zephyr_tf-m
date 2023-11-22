#-------------------------------------------------------------------------------
# Copyright (c) 2020-2022, Arm Limited. All rights reserved.
# Copyright (c) 2023, NXP Semiconductors. All rights reserved.
# Copyright (c) 2020, Linaro. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

cmake_policy(SET CMP0076 NEW)

message("Using nxp mcux source code from ${TFM_PLATFORM_NXP_HAL_FILE_PATH}.")
set(NXP_HAL_FILE_PATH ${TFM_PLATFORM_NXP_HAL_FILE_PATH})

# configuration options for library builds of els_pkc and psa_crypto_driver
set(CONFIG_BUILD_WITH_TFM ON)
set(CONFIG_SOC_SERIES_RW6XX ON)
set(MCUX_PSA_CRYPTO_DRIVER_ELS_PKC ON)

string(TOLOWER "${CMAKE_BUILD_TYPE}" BUILD_TYPE_LOWER)
if (BL2 AND ${BUILD_TYPE_LOWER} STREQUAL "debug")
    Message(FATAL_ERROR "If BL2 is enabled, \"${CMAKE_BUILD_TYPE}\" build type cannot be selected as it is currently not \
                         supported on ${TFM_PLATFORM}. For more information please refer to the platform's README file.")
endif()

set(HARDENING_COMPILE_DEFINITION "HARDENING_MACROS_ENABLED")
if (DEFINED USE_HARDENED_PLATFORM_INIT)
    if(NOT ${USE_HARDENED_PLATFORM_INIT})
        set(HARDENING_COMPILE_DEFINITION "")
    endif()
endif()

#========================= Platform region defs ===============================#

target_include_directories(platform_region_defs
    INTERFACE
        partition
)

#========================= Platform common defs ===============================#

# Specify the location of platform specific build dependencies.
target_sources(tfm_s
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/Device/Source/startup_rdrw61x.c
)
target_add_scatter_file(tfm_s
    $<$<C_COMPILER_ID:GNU>:${CMAKE_SOURCE_DIR}/platform/ext/common/gcc/tfm_common_s.ld>
    $<$<C_COMPILER_ID:IAR>:${CMAKE_SOURCE_DIR}/platform/ext/common/iar/tfm_common_s.icf>
)

if(NS)
    target_sources(tfm_ns
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/Device/Source/startup_rdrw61x.c
    )
    target_add_scatter_file(tfm_ns
        $<$<C_COMPILER_ID:GNU>:${CMAKE_SOURCE_DIR}/platform/ext/common/gcc/tfm_common_ns.ld>
        $<$<C_COMPILER_ID:IAR>:${CMAKE_SOURCE_DIR}/platform/ext/common/iar/tfm_common_ns.icf>
    )
    target_link_libraries(CMSIS_5_tfm_ns
        INTERFACE
            CMSIS_5_RTX_V8MMN
    )
endif()

#========================= Platform Secure ====================================#

target_compile_definitions(platform_s
    PUBLIC
        FSL_SDK_DRIVER_QUICK_ACCESS_ENABLE=1
        ${HARDENING_COMPILE_DEFINITION}
)

target_include_directories(platform_s
    PUBLIC
        .
        project_template/s
        Device/Config
        Device/Include
        partition
        ${PLATFORM_DIR}/ext/target/nxp/common/CMSIS_Driver
        ${PLATFORM_DIR}/ext/target/nxp/common/Native_Driver
        ${PLATFORM_DIR}/ext/target/nxp/rdrw61x/CMSIS_Driver

        ${NXP_HAL_FILE_PATH}/devices/RW612
        ${NXP_HAL_FILE_PATH}/devices/RW612/drivers
        ${NXP_HAL_FILE_PATH}/devices/RW612/drivers/romapi
        ${NXP_HAL_FILE_PATH}/devices/RW612/drivers/romapi
        ${NXP_HAL_FILE_PATH}/devices/RW612/drivers/romapi/bootloader
        ${NXP_HAL_FILE_PATH}/devices/RW612/drivers/romapi/flexspi
        ${NXP_HAL_FILE_PATH}/devices/RW612/drivers/romapi/iap
        ${NXP_HAL_FILE_PATH}/devices/RW612/drivers/romapi/nboot
        ${NXP_HAL_FILE_PATH}/devices/RW612/drivers/romapi/otp

        ${NXP_HAL_FILE_PATH}/drivers/common
        ${NXP_HAL_FILE_PATH}/drivers/ctimer
        ${NXP_HAL_FILE_PATH}/drivers/cache/cache64
        ${NXP_HAL_FILE_PATH}/drivers/flexcomm
        ${NXP_HAL_FILE_PATH}/drivers/flexspi
        ${NXP_HAL_FILE_PATH}/drivers/trng

        ${NXP_HAL_FILE_PATH}/components/lists
        ${NXP_HAL_FILE_PATH}/components/serial_manager
        ${NXP_HAL_FILE_PATH}/components/uart

        ${NXP_HAL_FILE_PATH}/utilities/debug_console
        ${NXP_HAL_FILE_PATH}/utilities/str
)

target_sources(platform_s
    PRIVATE
        ../common/CMSIS_Driver/Driver_USART.c
        ../common/Native_Driver/mpu_armv8m_drv.c
        project_template/s/board.c
        project_template/s/clock_config.c
        project_template/s/pin_mux.c
        mbedtls_entropy.c

        ${PLATFORM_DIR}/ext/target/nxp/rdrw61x/CMSIS_Driver/Driver_Flash_iap_rw61x.c
        ${PLATFORM_DIR}/ext/target/nxp/rdrw61x/CMSIS_Driver/Driver_Flash_iap_rw61x_iped.c

        ${NXP_HAL_FILE_PATH}/devices/RW612/system_RW612.c
        ${NXP_HAL_FILE_PATH}/devices/RW612/drivers/fsl_clock.c
        ${NXP_HAL_FILE_PATH}/devices/RW612/drivers/fsl_iped.c
        ${NXP_HAL_FILE_PATH}/devices/RW612/drivers/fsl_power.c
        ${NXP_HAL_FILE_PATH}/devices/RW612/drivers/fsl_reset.c
        ${NXP_HAL_FILE_PATH}/devices/RW612/drivers/fsl_ocotp.c
        ${NXP_HAL_FILE_PATH}/devices/RW612/drivers/romapi/bootloader/fsl_romapi.c
        ${NXP_HAL_FILE_PATH}/devices/RW612/drivers/romapi/flexspi/fsl_romapi_flexspi.c
        ${NXP_HAL_FILE_PATH}/devices/RW612/drivers/romapi/iap/fsl_romapi_iap.c
        ${NXP_HAL_FILE_PATH}/devices/RW612/drivers/romapi/nboot/fsl_romapi_nboot.c
        ${NXP_HAL_FILE_PATH}/devices/RW612/drivers/romapi/otp/fsl_romapi_otp.c

        ${NXP_HAL_FILE_PATH}/components/lists/fsl_component_generic_list.c
        ${NXP_HAL_FILE_PATH}/components/serial_manager/fsl_component_serial_manager.c
        ${NXP_HAL_FILE_PATH}/components/serial_manager/fsl_component_serial_port_uart.c
        ${NXP_HAL_FILE_PATH}/components/uart/fsl_adapter_usart.c

        ${NXP_HAL_FILE_PATH}/drivers/common/fsl_common_arm.c
        ${NXP_HAL_FILE_PATH}/drivers/flexcomm/fsl_flexcomm.c
        ${NXP_HAL_FILE_PATH}/drivers/flexcomm/fsl_usart.c
        ${NXP_HAL_FILE_PATH}/drivers/cache/cache64/fsl_cache.c
        ${NXP_HAL_FILE_PATH}/drivers/flexspi/fsl_flexspi.c
        ${NXP_HAL_FILE_PATH}/drivers/trng/fsl_trng.c

        ${NXP_HAL_FILE_PATH}/utilities/assert/fsl_assert.c
        ${NXP_HAL_FILE_PATH}/utilities/debug_console/fsl_debug_console.c
        ${NXP_HAL_FILE_PATH}/utilities/str/fsl_str.c

        $<$<NOT:$<BOOL:${PLATFORM_DEFAULT_NV_COUNTERS}>>:${PLATFORM_DIR}/ext/target/nxp/rdrw61x/nv_counters.c>

        $<$<BOOL:${TFM_PARTITION_PLATFORM}>:${PLATFORM_DIR}/ext/target/nxp/common/plat_test.c>
        $<$<BOOL:${TFM_PARTITION_PLATFORM}>:${PLATFORM_DIR}/ext/target/nxp/common/services/src/tfm_platform_system.c>
        # ${NXP_HAL_FILE_PATH}/common/plat_attest_hal.c
)

add_subdirectory(${NXP_HAL_FILE_PATH}/components/els_pkc els_pkc)

target_link_libraries(platform_s
    PRIVATE
    # For attest HAL strnlen
        tfm_sprt
        McuxElsPkc
)

if (MCUX_PSA_CRYPTO_DRIVER_ELS_PKC)
    add_subdirectory(${NXP_HAL_FILE_PATH}/components/psa_crypto_driver psa_crypto_driver)
    target_link_libraries(platform_s
        PRIVATE
            McuxPsaCryptoDriverElsPkc
    )
endif()

target_compile_options(platform_s
    PUBLIC
        ${COMPILER_CMSE_FLAG}
)

# GNU ld has some strange behaviour to do with weak functions, and does not deal
# well with strong functions in static libraries overriding weak functions in
# object files. For this reason, the file hardware_init is linked directly to
# the s binary as an object file. This issue does not affect armclang, but the
# fix is compatible.
target_sources(tfm_s
    PRIVATE
        project_template/s/hardware_init.c
)

#========================= Platform Non-Secure ================================#

target_compile_definitions(platform_ns
    PUBLIC
        ${HARDENING_COMPILE_DEFINITION}
)

target_include_directories(platform_ns
    PUBLIC
        .
        Device/Config
        Device/Include
        Native_Driver
        project_template/ns

        ${NXP_HAL_FILE_PATH}/devices/RW612
        ${NXP_HAL_FILE_PATH}/devices/RW612/drivers

        ${NXP_HAL_FILE_PATH}/drivers/common
        ${NXP_HAL_FILE_PATH}/drivers/ctimer
        ${NXP_HAL_FILE_PATH}/drivers/flexcomm

        ${NXP_HAL_FILE_PATH}/components/lists
        ${NXP_HAL_FILE_PATH}/components/serial_manager
        ${NXP_HAL_FILE_PATH}/components/uart

        ${NXP_HAL_FILE_PATH}/utilities/debug_console
        ${NXP_HAL_FILE_PATH}/utilities/str
)

target_sources(platform_ns
    PRIVATE
        ../common/CMSIS_Driver/Driver_USART.c
        ${NXP_HAL_FILE_PATH}/devices/RW612/system_RW612.c
        ${NXP_HAL_FILE_PATH}/drivers/flexcomm/fsl_flexcomm.c
        ${NXP_HAL_FILE_PATH}/drivers/flexcomm/fsl_usart.c
        $<$<BOOL:${TFM_PARTITION_PLATFORM}>:${PLATFORM_DIR}/ext/target/nxp/common/plat_test.c>
)


#========================= Platform customizations ============================================#

if (TFM_PARTITION_CRYPTO)

    target_compile_options(platform_crypto_keys
        PUBLIC
            ${COMPILER_CMSE_FLAG}
    )

    target_sources(platform_crypto_keys
        PRIVATE
            crypto_keys.c
    )

    target_include_directories(platform_crypto_keys
        PUBLIC
            ./Device/Include
            ./Device/Config
            # platform_crypto_keys does not link against els_pkc and PsaCryptoDriverElsPkc, but we need to include it's
            # header files to have the function declarations, typedefs and defines available.
            # Those directories are declared in the included library cmake file and can be
            # used here:
            "$<TARGET_PROPERTY:McuxElsPkc,INTERFACE_INCLUDE_DIRECTORIES>"
    )

    target_compile_definitions(platform_crypto_keys
        PUBLIC
            $<$<BOOL:${USE_ELS_PKC_HUK}>:USE_ELS_PKC_HUK>
            $<$<BOOL:${USE_ELS_PKC_IAK}>:USE_ELS_PKC_IAK>
    )
if (MCUX_PSA_CRYPTO_DRIVER_ELS_PKC)

    target_include_directories(platform_crypto_keys
        PUBLIC
            "$<TARGET_PROPERTY:McuxPsaCryptoDriverElsPkc,INTERFACE_INCLUDE_DIRECTORIES>"
    )
    target_include_directories(tfm_psa_rot_partition_crypto
        PUBLIC
            # tfm_psa_rot_partition_crypto does not link against PsaCryptoDriverElsPkc directly, but we need to include it's
            # header files to have the function declarations, typedefs and defines available.
            # Those directories are declared in the included library cmake file and can be used here:
            "$<TARGET_PROPERTY:McuxPsaCryptoDriverElsPkc,INTERFACE_INCLUDE_DIRECTORIES>"
    )
    target_include_directories(crypto_service_mbedcrypto
        PUBLIC
            # crypto_service_mbedcrypto does not link against PsaCryptoDriverElsPkc directly, but we need to include it's
            # header files to have the function declarations, typedefs and defines available.
            # Those directories are declared in the included library cmake file and can be used here:
            "$<TARGET_PROPERTY:McuxPsaCryptoDriverElsPkc,INTERFACE_INCLUDE_DIRECTORIES>"
    )

    target_compile_definitions(crypto_service_mbedcrypto
        PUBLIC
            $<$<BOOL:${MCUX_PSA_CRYPTO_DRIVER_ELS_PKC}>:PSA_CRYPTO_DRIVER_ELS_PKC>
    )
endif()
endif()
#========================= tfm_spm ============================================#

target_sources(tfm_spm
    PRIVATE
        target_cfg.c
        ../common/faults.c
        tfm_hal_isolation.c
        tfm_hal_platform.c
)


#========================= Install platform specific interface files ===============================#

install(FILES
    ${CMAKE_CURRENT_LIST_DIR}/Device/Include/tfm_builtin_key_ids.h
    DESTINATION "${TFM_INSTALL_PATH}/interface/include"
)
