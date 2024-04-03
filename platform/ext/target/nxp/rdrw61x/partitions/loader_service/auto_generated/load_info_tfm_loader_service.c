/*
 * Copyright (c) 2021-2022, Arm Limited. All rights reserved.
 * Copyright 2024 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

/***********  WARNING: This is an auto-generated file. Do not edit!  ***********/

#include <stdint.h>
#include <stddef.h>
#include "region.h"
#include "region_defs.h"
#include "spm.h"
#include "load/interrupt_defs.h"
#include "load/partition_defs.h"
#include "load/service_defs.h"
#include "load/asset_defs.h"
#include "tfm_peripherals_def.h"
#include "psa_manifest/pid.h"
#include "psa_manifest/sid.h"
#include "tfm_lds_config.h"
#include "tfm_lds_pid.h"
#include "tfm_lds_sid.h"
#include "psa_manifest/tfm_loader_service.h"

#define TFM_SP_LDS_NDEPS                                        (1)
#define TFM_SP_LDS_NSERVS                                       (1)
#if TFM_LVL == 3
#define TFM_SP_LDS_NASSETS                                      (0 + 1)
#else
#define TFM_SP_LDS_NASSETS                                      (0)
#endif
#define TFM_SP_LDS_NIRQS                                        (0)

/* Memory region declaration */
#if TFM_LVL == 3
REGION_DECLARE(Image$$, PT_TFM_SP_LDS_PRIVATE, _DATA_START$$Base);
REGION_DECLARE(Image$$, PT_TFM_SP_LDS_PRIVATE, _DATA_END$$Base);
#endif

extern uint8_t tfm_sp_lds_stack[];

extern psa_status_t tfm_lds_entry(void);

/* Interrupt init functions */

/* partition load info type definition */
struct partition_tfm_sp_lds_load_info_t {
    /* common length load data */
    struct partition_load_info_t    load_info;
    /* per-partition variable length load data */
    uintptr_t                       stack_addr;
    uintptr_t                       heap_addr;
    uint32_t                        deps[TFM_SP_LDS_NDEPS];
    struct service_load_info_t      services[TFM_SP_LDS_NSERVS];
#if TFM_LVL == 3
    struct asset_desc_t             assets[TFM_SP_LDS_NASSETS];
#else
#endif
} __attribute__((aligned(4)));

/* Partition load, deps, service load data. Put to a dedicated section. */
#if defined(__ICCARM__)
#pragma location = ".part_load_priority_normal"
__root
#endif /* __ICCARM__ */
const struct partition_tfm_sp_lds_load_info_t tfm_sp_lds_load
    __attribute__((used, section(".part_load_priority_normal"))) = {
    .load_info = {
        .psa_ff_ver                 = 0x0101 | PARTITION_INFO_MAGIC,
        .pid                        = TFM_SP_LDS,
        .flags                      = 0
                                    | PARTITION_MODEL_PSA_ROT
                                    | PARTITION_PRI_NORMAL,
        .entry                      = ENTRY_TO_POSITION(tfm_lds_entry),
        .stack_size                 = LDS_STACK_SIZE,
        .heap_size                  = 0,
        .ndeps                      = TFM_SP_LDS_NDEPS,
        .nservices                  = TFM_SP_LDS_NSERVS,
        .nassets                    = TFM_SP_LDS_NASSETS,
        .nirqs                      = TFM_SP_LDS_NIRQS,
    },
    .stack_addr                     = (uintptr_t)tfm_sp_lds_stack,
    .heap_addr                      = 0,
    .deps = {
        TFM_PLATFORM_SERVICE_SID,
    },
    .services = {
        {
            .name_strid             = STRING_PTR_TO_STRID("TFM_LOADER_SERVICE"),
            .sfn                    = ENTRY_TO_POSITION(tfm_loader_service_sfn),
            .signal                 = 1,

            .sid                    = 0x000000B0,
            .flags                  = 0
                                    | SERVICE_FLAG_NS_ACCESSIBLE
                                    | SERVICE_FLAG_STATELESS | 0xa
                                    | SERVICE_FLAG_MM_IOVEC
                                    | SERVICE_VERSION_POLICY_STRICT,
            .version                = 1,
        },
    },
#if TFM_LVL == 3
    .assets                         = {
        {
            .mem.start              = (uintptr_t)&REGION_NAME(Image$$,PT_TFM_SP_LDS_PRIVATE, _DATA_START$$Base),
            .mem.limit              = (uintptr_t)&REGION_NAME(Image$$,PT_TFM_SP_LDS_PRIVATE, _DATA_END$$Base),
            .attr                   = ASSET_ATTR_READ_WRITE,
        },
    },
#else
#endif
};

/* Placeholder for partition and service runtime space. Do not reference it. */
#if defined(__ICCARM__)
#pragma location=".bss.part_runtime_priority_normal"
__root
#endif /* __ICCARM__ */
static struct partition_t tfm_sp_lds_partition_runtime_item
    __attribute__((used, section(".bss.part_runtime_priority_normal")));
#if defined(__ICCARM__)
#pragma location = ".bss.serv_runtime_priority_normal"
__root
#endif /* __ICCARM__ */
static struct service_t tfm_sp_lds_service_runtime_item[TFM_SP_LDS_NSERVS]
    __attribute__((used, section(".bss.serv_runtime_priority_normal")));