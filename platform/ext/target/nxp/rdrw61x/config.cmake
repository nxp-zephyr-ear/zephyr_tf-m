#-------------------------------------------------------------------------------
# Copyright (c) 2020-2023, Arm Limited. All rights reserved.
# Copyright (c) 2023-2024 NXP.
# Copyright (c) 2022 Cypress Semiconductor Corporation (an Infineon company)
# or an affiliate of Cypress Semiconductor Corporation. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

################################## Dependencies ################################
#set(TFM_PLATFORM_NXP_HAL_FILE_PATH      "DOWNLOAD"      CACHE STRING    "Path to the NXP SDK hal (or DOWNLOAD to fetch automatically)")
#set(NXP_SDK_GIT_TAG                     "MCUX_2.15.0"   CACHE STRING    "The version of the NXP MCUXpresso SDK")

############################ Platform ##########################################
#set(PLATFORM_DEFAULT_ATTEST_HAL         OFF             CACHE BOOL      "Use default attest hal implementation.")

############################ BL2 ########################################
#set(BL2_S_IMAGE_START                   "0x8000"        CACHE STRING    "Base address of the secure image in configuration with BL2")
#set(BL2_NS_IMAGE_START                  "0x30000"       CACHE STRING    "Base address of the non secure image in configuration with BL2")

# Platform-specific configurations
set(CONFIG_TFM_USE_TRUSTZONE            ON              CACHE BOOL      "Enable use of TrustZone to transition between NSPE and SPE")
set(TFM_MULTI_CORE_TOPOLOGY             OFF             CACHE BOOL      "Whether to build for a dual-cpu architecture")

set(ITS_RAM_FS ON CACHE BOOL "")
set(PS_RAM_FS ON CACHE BOOL "")

################################## Adding Platform Specific Partition ################################
set(TFM_EXTRA_MANIFEST_LIST_FILES "${CMAKE_CURRENT_SOURCE_DIR}/platform/ext/target/nxp/rdrw61x/partitions/tfm_manifest_list.yaml;"  CACHE PATH "Path to extra generated file list. Appended to stardard TFM generated file list." FORCE)

set(TFM_EXTRA_PARTITION_PATHS "${CMAKE_CURRENT_SOURCE_DIR}/platform/ext/target/nxp/rdrw61x/partitions/loader_service;"  CACHE PATH "Path to extra generated file list. Appended to stardard TFM generated file list." FORCE)
