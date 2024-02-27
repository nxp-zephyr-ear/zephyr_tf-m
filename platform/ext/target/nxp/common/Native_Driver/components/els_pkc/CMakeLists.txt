#-------------------------------------------------------------------------------
# Copyright (c) 2023 NXP.
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

add_library(McuxElsPkc) 

target_compile_options(
    McuxElsPkc
    PUBLIC
        ${TOOLCHAIN_C_FLAGS}
        -mcmse  # Why is this not even part of the default zephyr build options?
)

target_link_options(
    McuxElsPkc
    PRIVATE
        ${TOOLCHAIN_LD_FLAGS}
)

target_include_directories(McuxElsPkc
    PRIVATE
        # SDK driver header files
        ${NXP_HAL_FILE_PATH}/common/Native_Driver/drivers
        ${NXP_HAL_FILE_PATH}/rdrw61x/Native_Driver
        ${NXP_HAL_FILE_PATH}/rdrw61x/Native_Driver/drivers
        # psa/crypto.h and psa/crypto_types.h
        ${MBEDCRYPTO_PATH}/include
        ${MBEDCRYPTO_PATH}/include/psa
        # for psa driver wrapper
        ${MBEDCRYPTO_PATH}/library
)

if(CONFIG_BUILD_WITH_TFM)
    target_compile_options(
        McuxElsPkc
        PUBLIC
            ${COMPILER_CP_FLAG}
    )
endif()

if(CONFIG_SOC_SERIES_RW6XX)

    target_compile_definitions(
        McuxElsPkc 
        PUBLIC
            CPU_RW612ETA2I
    ) 

    target_include_directories(McuxElsPkc
        PRIVATE
            # cmsis required to build els_pkc
            src/platforms/rw61x/cmsis_cortex_m_5_5_1/inc
    )

    target_include_directories(McuxElsPkc
        PUBLIC
            src/platforms/rw61x/
            src/platforms/rw61x/inc
            ${NXP_HAL_FILE_PATH}/rdrw61x/Native_Driver
            ${NXP_HAL_FILE_PATH}/rdrw61x/Native_Driver/drivers
    )

    target_sources(McuxElsPkc
        PRIVATE
            src/platforms/rw61x/mcux_els.c
            src/platforms/rw61x/mcux_pkc.c
    )
endif()

if(CONFIG_EXPORT_MCUX_ELS_PKC_TARGETS)
export(TARGETS McuxElsPkc
    FILE "${CMAKE_CURRENT_BINARY_DIR}/McuxElsPkcTargets.cmake"
    NAMESPACE McuxElsPkc::
)
endif()
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/src)
