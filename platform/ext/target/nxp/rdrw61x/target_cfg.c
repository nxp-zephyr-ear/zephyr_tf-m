/*
 * Copyright (c) 2018-2021 Arm Limited. All rights reserved.
 * Copyright (c) 2019-2020, 2022-2023 NXP. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "target_cfg.h"
#include "Driver_Common.h"
#include "platform_description.h"
#include "device_definition.h"
#include "region_defs.h"
#include "tfm_plat_defs.h"
#include "region.h"
#include "utilities.h"
#include "tfm_spm_log.h"

/* The section names come from the scatter file */
REGION_DECLARE(Load$$LR$$, LR_NS_PARTITION, $$Base);
REGION_DECLARE(Image$$, ER_VENEER, $$Base);
REGION_DECLARE(Image$$, VENEER_ALIGN, $$Limit);
#ifdef TFM_PARTITION_WIFI_FLASH_REGION
REGION_DECLARE(Load$$LR$$, LR_WIFI_FLASH_REGION, $$Base);
#endif /* TFM_PARTITION_WIFI_FLASH_REGION */
#ifdef TFM_PARTITION_EL2GO_DATA_IMPORT_REGION
REGION_DECLARE(Load$$LR$$, LR_EL2GO_DATA_IMPORT_REGION, $$Base);
#endif // TFM_PARTITION_EL2GO_DATA_IMPORT_REGION
#ifdef BL2
REGION_DECLARE(Load$$LR$$, LR_SECONDARY_PARTITION, $$Base);
#endif /* BL2 */

const struct memory_region_limits memory_regions =
{
    .non_secure_code_start      = (uint32_t)&REGION_NAME(Load$$LR$$, LR_NS_PARTITION, $$Base) + BL2_HEADER_SIZE,
    .non_secure_partition_base  = (uint32_t)&REGION_NAME(Load$$LR$$, LR_NS_PARTITION, $$Base),
    .non_secure_partition_limit = (uint32_t)&REGION_NAME(Load$$LR$$, LR_NS_PARTITION, $$Base) + NS_PARTITION_SIZE - 1,
    .veneer_base                = (uint32_t)&REGION_NAME(Image$$, ER_VENEER, $$Base),
    .veneer_limit               = (uint32_t)&REGION_NAME(Image$$, VENEER_ALIGN, $$Limit),
#ifdef TFM_PARTITION_WIFI_FLASH_REGION
    .wifi_flash_region_base   = (uint32_t)&REGION_NAME(Load$$LR$$, LR_WIFI_FLASH_REGION, $$Base),
    .wifi_flash_region_limit  = (uint32_t)&REGION_NAME(Load$$LR$$, LR_WIFI_FLASH_REGION, $$Base) + WIFI_FLASH_REGION_SIZE - 1,
#endif /* TFM_PARTITION_WIFI_FLASH_REGION */
#ifdef TFM_PARTITION_EL2GO_DATA_IMPORT_REGION
    .el2go_data_import_region_base   = (uint32_t)&REGION_NAME(Load$$LR$$, LR_EL2GO_DATA_IMPORT_REGION, $$Base),
    .el2go_data_import_region_limit  = (uint32_t)&REGION_NAME(Load$$LR$$, LR_EL2GO_DATA_IMPORT_REGION, $$Base) + EL2GO_DATA_IMPORT_REGION_SIZE - 1,
#endif // TFM_PARTITION_EL2GO_DATA_IMPORT_REGION
#ifdef BL2
    .secondary_partition_base   = (uint32_t)&REGION_NAME(Load$$LR$$, LR_SECONDARY_PARTITION, $$Base),
    .secondary_partition_limit  = (uint32_t)&REGION_NAME(Load$$LR$$, LR_SECONDARY_PARTITION, $$Base) +
                                  SECONDARY_PARTITION_SIZE - 1,
#endif /* BL2 */
};

/* Allows software, via SAU, to define the code region as a NSC */
#define NSCCFG_CODENSC (1)

/* Define Peripherals NS address range for the platform */
#define PERIPHERALS_BASE_NS_START (0x40000000)
#define PERIPHERALS_BASE_NS_END   (0x4FFFFFFF)

/* Enable system reset request for CPU 0 */
#define ENABLE_CPU0_SYSTEM_RESET_REQUEST (1U << 4U)

/* To write into AIRCR register, 0x5FA value must be write to the VECTKEY field, otherwise the processor ignores
 * the write.
 */
#define SCB_AIRCR_WRITE_MASK ((0x5FAUL << SCB_AIRCR_VECTKEY_Pos))

struct platform_data_t tfm_peripheral_std_uart =
{
    USART0_BASE_NS,
    USART0_BASE_NS + 0xFFF,
    0,
    0
};

struct platform_data_t tfm_peripheral_timer0 =
{
    CTIMER2_BASE,
    CTIMER2_BASE + 0xFFF,
    &(AHB_SECURE_CTRL->APB_GRP1_MEM_RULE1),
    AHB_SECURE_CTRL_APB_GRP1_MEM_RULE1_CT32BIT2_RULE2_SHIFT
};

enum tfm_plat_err_t enable_fault_handlers(void)
{
    /* Explicitly set secure fault priority to the highest */
    NVIC_SetPriority(SecureFault_IRQn, 0);

    /* Enables BUS, MEM, USG and Secure faults */
    SCB->SHCSR |= SCB_SHCSR_USGFAULTENA_Msk
                  | SCB_SHCSR_BUSFAULTENA_Msk
                  | SCB_SHCSR_MEMFAULTENA_Msk
                  | SCB_SHCSR_SECUREFAULTENA_Msk;

    return TFM_PLAT_ERR_SUCCESS;
}

enum tfm_plat_err_t system_reset_cfg(void)
{
    uint32_t reg_value = SCB->AIRCR;

    /* Clear SCB_AIRCR_VECTKEY value */
    reg_value &= ~(uint32_t)(SCB_AIRCR_VECTKEY_Msk);

    /* Enable system reset request only to the secure world */
    reg_value |= (uint32_t)(SCB_AIRCR_WRITE_MASK | SCB_AIRCR_SYSRESETREQS_Msk);

    SCB->AIRCR = reg_value;

    return TFM_PLAT_ERR_SUCCESS;
}

enum tfm_plat_err_t init_debug(void)
{
#if !defined(DAUTH_CHIP_DEFAULT)
    #error "Debug features are set during provisioning. Application is not able to change them as the SYSCTRL->DEBUG_LOCK_EN is locked by the MCU secure boot.  "
#endif /* !DAUTH_CHIP_DEFAULT */

    return TFM_PLAT_ERR_SUCCESS;
}

/*----------------- NVIC interrupt target state to NS configuration ----------*/
enum tfm_plat_err_t nvic_interrupt_target_state_cfg(void)
{
    /* Target every interrupt to NS; unimplemented interrupts will be WI */
    for (uint8_t i = 0; i < ARRAY_SIZE(NVIC->ITNS); i++)
    {
        NVIC->ITNS[i] = 0xFFFFFFFF;
    }

    /* Make sure that MPC and PPC are targeted to S state */
    NVIC_ClearTargetState(SEC_VIO_IRQn);

    return TFM_PLAT_ERR_SUCCESS;
}

/*----------------- NVIC interrupt enabling for S peripherals ----------------*/
enum tfm_plat_err_t nvic_interrupt_enable(void)
{
    /* MPC/PPC interrupt enabling */
    NVIC_EnableIRQ(SEC_VIO_IRQn);

    return TFM_PLAT_ERR_SUCCESS;
}

/*------------------- SAU/IDAU configuration functions -----------------------*/
void sau_and_idau_cfg(void)
{
    /* Enables SAU Control register: Enable SAU and All Secure (applied only if disabled) */
    SECURE_WRITE_REGISTER(&(SAU->CTRL), ((1U << SAU_CTRL_ENABLE_Pos) & SAU_CTRL_ENABLE_Msk));

    /* Configures SAU regions to be non-secure */
    SECURE_WRITE_REGISTER(&(SAU->RNR), 0U);
    SAU->RBAR = memory_regions.non_secure_partition_base & SAU_RBAR_BADDR_Msk;
    SAU->RLAR = (memory_regions.non_secure_partition_limit & SAU_RLAR_LADDR_Msk) | SAU_RLAR_ENABLE_Msk;

    /* Configures Non secure data start region */
    SECURE_WRITE_REGISTER(&(SAU->RNR), 1U);
    SECURE_WRITE_REGISTER(&(SAU->RBAR), (NS_DATA_START & SAU_RBAR_BADDR_Msk));
    SECURE_WRITE_REGISTER(&(SAU->RLAR), ((NS_DATA_LIMIT & SAU_RLAR_LADDR_Msk) | SAU_RLAR_ENABLE_Msk));

    /* Configures veneers region to be non-secure callable */
    SECURE_WRITE_REGISTER(&(SAU->RNR), 2U);
    SAU->RBAR = (memory_regions.veneer_base  & SAU_RBAR_BADDR_Msk);
    SAU->RLAR = (memory_regions.veneer_limit & SAU_RLAR_LADDR_Msk) | SAU_RLAR_ENABLE_Msk | SAU_RLAR_NSC_Msk;

    /* Configure the peripherals space */
    SECURE_WRITE_REGISTER(&(SAU->RNR), 3U);
    SECURE_WRITE_REGISTER(&(SAU->RBAR), (PERIPHERALS_BASE_NS_START & SAU_RBAR_BADDR_Msk));
    SECURE_WRITE_REGISTER(&(SAU->RLAR), ((PERIPHERALS_BASE_NS_END & SAU_RLAR_LADDR_Msk) | SAU_RLAR_ENABLE_Msk));

#ifdef BL2
    /* Secondary image partition */
    SECURE_WRITE_REGISTER(&(SAU->RNR), 4U);
    SAU->RBAR = (memory_regions.secondary_partition_base  & SAU_RBAR_BADDR_Msk);
    SAU->RLAR = (memory_regions.secondary_partition_limit & SAU_RLAR_LADDR_Msk) | SAU_RLAR_ENABLE_Msk;
#endif /* BL2 */

#ifdef TFM_PARTITION_WIFI_FLASH_REGION
	/* Wifi Flash region */
    SAU->RNR  = 5U;
    SAU->RBAR = (memory_regions.wifi_flash_region_base & SAU_RBAR_BADDR_Msk);
    SAU->RLAR = (memory_regions.wifi_flash_region_limit & SAU_RLAR_LADDR_Msk) | SAU_RLAR_ENABLE_Msk;
#endif /* TFM_PARTITION_WIFI_FLASH_REGION */

#ifdef TFM_PARTITION_EL2GO_DATA_IMPORT_REGION
    SAU->RNR  = 6U;
    SAU->RBAR = (memory_regions.el2go_data_import_region_base & SAU_RBAR_BADDR_Msk);
    SAU->RLAR = (memory_regions.el2go_data_import_region_limit & SAU_RLAR_LADDR_Msk) | SAU_RLAR_ENABLE_Msk;
#endif
	
#if TARGET_DEBUG_LOG
    SPMLOG_DBGMSG("=== [SAU NS] =======\r\n");
    SPMLOG_DBGMSGVAL("NS ROM starts from : ", memory_regions.non_secure_partition_base);
    SPMLOG_DBGMSGVAL("NS ROM ends at : ",
                     memory_regions.non_secure_partition_base + memory_regions.non_secure_partition_limit);
    SPMLOG_DBGMSGVAL("NS DATA start from : ", NS_DATA_START);
    SPMLOG_DBGMSGVAL("NS DATA ends at : ", NS_DATA_START + NS_DATA_LIMIT);
    SPMLOG_DBGMSGVAL("NSC starts with : ", memory_regions.veneer_base);
    SPMLOG_DBGMSGVAL("NSC ends at : ", memory_regions.veneer_base + memory_regions.veneer_limit);
    SPMLOG_DBGMSGVAL("PERIPHERALS starts with : ", PERIPHERALS_BASE_NS_START);
    SPMLOG_DBGMSGVAL("PERIPHERALS ends at : ", PERIPHERALS_BASE_NS_END);
#endif /* TARGET_DEBUG_LOG */
}

void enable_mem_rule_for_partition(uint32_t memory_region_base, uint32_t memory_region_limit)
{
    uint32_t ns_region_id       = 0;
    uint32_t ns_region_start_id = 0;
    uint32_t ns_region_end_id   = 0;

    ns_region_start_id  = (memory_region_base - NS_ROM_ALIAS_BASE)
                          / FLASH_REGION0_SUBREGION_SIZE;
    ns_region_end_id    = ((memory_region_limit - NS_ROM_ALIAS_BASE)
                          / FLASH_REGION0_SUBREGION_SIZE) + 1;

    /* Set to non-secure and non-privileged user access allowed */
    for (ns_region_id = ns_region_start_id; ns_region_id < ns_region_end_id; ns_region_id++) /* == Region 0 == */
    {
        if (ns_region_id < 8) 
        {
            /* Set regions in the AHB controller for flash memory 0x0800 0000 - 0x080F FFFF */
            AHB_SECURE_CTRL->FLEXSPI_RULES[0].REGION0_MEM_RULE[0] &= ~(0xF << (ns_region_id * 4));
        }
        else if ((ns_region_id >= 8) && (ns_region_id < 16))
        {
            /* Set regions in the AHB controller for flash memory 0x0810 0000 - 0x081F FFFF */
            AHB_SECURE_CTRL->FLEXSPI_RULES[0].REGION0_MEM_RULE[1] &= ~(0xF << ((ns_region_id - 8) * 4));
        }
        else if ((ns_region_id >= 16) && (ns_region_id < 24))
        {
            /* Set regions the AHB controller for flash memory 0x0820 0000 - 0x082 FFFFF */
            AHB_SECURE_CTRL->FLEXSPI_RULES[0].REGION0_MEM_RULE[2] &= ~(0xF << ((ns_region_id - 16) * 4));
        }
        else if ((ns_region_id >= 24) && (ns_region_id < 32))
        {
            /* Set regions the AHB controller for flash memory 0x0830 0000 - 0x083F FFFF */
            AHB_SECURE_CTRL->FLEXSPI_RULES[0].REGION0_MEM_RULE[3] &= ~(0xF << ((ns_region_id - 24) * 4));
        }
        else /* == Region 1 == */
        {
            if (ns_region_start_id > FLASH_REGION0_SUBREGION_NUMBER)
            {
                ns_region_start_id = (memory_region_base
                                      - NS_ROM_ALIAS_BASE
                                      - FLASH_REGION0_SIZE ) / FLASH_REGION1_SUBREGION_SIZE;
            }
            else
            {
                ns_region_start_id = 0;   
            }
            
            ns_region_end_id = ((memory_region_limit
                                - NS_ROM_ALIAS_BASE
                                - FLASH_REGION0_SIZE
                      			) / FLASH_REGION1_SUBREGION_SIZE) + 1;
            
            for (ns_region_id = ns_region_start_id; ns_region_id < ns_region_end_id; ns_region_id++)
            {
                if (ns_region_id < FLASH_REGION1_SUBREGION_NUMBER)
                {
                    /* Set regions in the AHB controller for flash memory 0x0840 0000 - 0x087 FFFFF */
                    AHB_SECURE_CTRL->FLEXSPI_RULES[0].REGION1_MEM_RULE &= ~(0xF << (ns_region_id * 4));
                }
                else /* == Region 2 == */
                {
                    if (ns_region_start_id > FLASH_REGION1_SUBREGION_NUMBER)
                    {
                        ns_region_start_id = (memory_region_base
                                              - NS_ROM_ALIAS_BASE
                                              - (FLASH_REGION0_SIZE + FLASH_REGION1_SIZE))
                                             / FLASH_REGION2_SUBREGION_SIZE;
                    }
                    else
                    {
                        ns_region_start_id = 0;   
                    }
                    
                    ns_region_end_id = ((memory_region_limit
                                        - NS_ROM_ALIAS_BASE
                                        - (FLASH_REGION0_SIZE + FLASH_REGION1_SIZE)
                                        ) / FLASH_REGION2_SUBREGION_SIZE) + 1;
                    
                    for (ns_region_id = ns_region_start_id; ns_region_id < ns_region_end_id; ns_region_id++) 
                    {
                        if (ns_region_id < FLASH_REGION2_SUBREGION_NUMBER)
                        {
                            /* Set regions in the AHB controller for flash memory 0x0880 0000 - 0x8FF FFFF */
                            AHB_SECURE_CTRL->FLEXSPI_RULES[0].REGION2_MEM_RULE &= ~(0xF << (ns_region_id * 4));
                        }
                        else /* == Region 3 == */
                        {
                            if (ns_region_start_id > FLASH_REGION2_SUBREGION_NUMBER)
                            {
                                ns_region_start_id = (memory_region_base
                                                      - NS_ROM_ALIAS_BASE
                                                      - (FLASH_REGION0_SIZE
                                                         + FLASH_REGION1_SIZE
                                                         + FLASH_REGION2_SIZE)) / FLASH_REGION3_SUBREGION_SIZE;
                            }
                            else
                            {
                                ns_region_start_id = 0;   
                            }
                        
                            ns_region_end_id = ((memory_region_limit
                                                - NS_ROM_ALIAS_BASE
                                                - (FLASH_REGION0_SIZE
                                                   + FLASH_REGION1_SIZE
                                                   + FLASH_REGION2_SIZE)
                                                ) / FLASH_REGION3_SUBREGION_SIZE) + 1;

                            for (ns_region_id = ns_region_start_id; ns_region_id < ns_region_end_id; ns_region_id++) 
                            {
                                if (ns_region_id < FLASH_REGION3_SUBREGION_NUMBER)
                                {
                                    /* Set regions in the AHB controller for flash memory 0x0900 0000 - 0x9FF FFFF */
                                    AHB_SECURE_CTRL->FLEXSPI_RULES[0].REGION3_MEM_RULE &= ~(0xF << (ns_region_id * 4));
                                }
                                else /* == Region 4 == */
                                {
                                    if (ns_region_start_id > FLASH_REGION3_SUBREGION_NUMBER)
                                    {
                                        ns_region_start_id = (memory_region_base
                                                              - NS_ROM_ALIAS_BASE
                                                              - (FLASH_REGION0_SIZE
                                                                 + FLASH_REGION1_SIZE
                                                                 + FLASH_REGION2_SIZE
                                                                 + FLASH_REGION3_SIZE)) / FLASH_REGION4_SUBREGION_SIZE;
                                    }
                                    else
                                    {
                                        ns_region_start_id = 0;   
                                    }

                                    ns_region_end_id = ((memory_region_limit
                                                        - NS_ROM_ALIAS_BASE
                                                        - (FLASH_REGION0_SIZE
                                                           + FLASH_REGION1_SIZE
                                                           + FLASH_REGION2_SIZE
                                                           + FLASH_REGION3_SIZE)
                                                        ) / FLASH_REGION4_SUBREGION_SIZE) + 1;

                                    for (ns_region_id = ns_region_start_id;
                                         ns_region_id < ns_region_end_id;
                                         ns_region_id++)
                                    {
                                        if (ns_region_id < FLASH_REGION4_SUBREGION_NUMBER)
                                        {
                                            /* Set regions in the AHB controller for flash memory 0x0A00 0000 - 0xBFF FFFF */
                                            AHB_SECURE_CTRL->FLEXSPI_RULES[0].REGION4_MEM_RULE &= ~(0xF << (ns_region_id * 4));
                                        }
                                        else
                                        {
                                            break;
                                        }
                                    }
                                    break;
                                }
                            }
                            break;
                        }
                    }
                    break;
                }
            }
            break;
        }
    }  	
}

/*------------------- Memory configuration functions -------------------------*/
int32_t mpc_init_cfg(void)
{
	uint32_t* ram_rule_sfr[] = {
	  (uint32_t*)&AHB_SECURE_CTRL->RAM00_RULE[0],
	  (uint32_t*)&AHB_SECURE_CTRL->RAM01_RULE[0],
	  (uint32_t*)&AHB_SECURE_CTRL->RAM02_RULE[0],
	  (uint32_t*)&AHB_SECURE_CTRL->RAM03_RULE[0],
	  (uint32_t*)&AHB_SECURE_CTRL->RAM04_RULE[0],
	  (uint32_t*)&AHB_SECURE_CTRL->RAM05_RULE[0],
	  (uint32_t*)&AHB_SECURE_CTRL->RAM06_RULE[0],
	  (uint32_t*)&AHB_SECURE_CTRL->RAM07_RULE[0],
	  (uint32_t*)&AHB_SECURE_CTRL->RAM08_RULE[0],
	  (uint32_t*)&AHB_SECURE_CTRL->RAM09_RULE[0],
	  (uint32_t*)&AHB_SECURE_CTRL->RAM10_RULE[0],
	  (uint32_t*)&AHB_SECURE_CTRL->RAM11_RULE[0],
	  (uint32_t*)&AHB_SECURE_CTRL->RAM12_RULE[0],
	  (uint32_t*)&AHB_SECURE_CTRL->RAM13_RULE[0],
	  (uint32_t*)&AHB_SECURE_CTRL->RAM14_RULE[0],
	  (uint32_t*)&AHB_SECURE_CTRL->RAM15_RULE[0],
	  (uint32_t*)&AHB_SECURE_CTRL->RAM16_RULE[0],
	  (uint32_t*)&AHB_SECURE_CTRL->RAM17_RULE[0],
	  (uint32_t*)&AHB_SECURE_CTRL->RAM18_RULE[0]
	};
    int i, j;
    uint32_t ns_region_id       = 0;
    uint32_t ns_region_start_id = 0;
    uint32_t ns_region_end_id   = 0;
    uint32_t ram_rule_sfr_index = 0U;
    uint32_t ram_rule_sfr_offset = 0U;
    uint32_t ram_rule_sfr_shift = 0U;

    /* Starts changing actual configuration so issue DMB to ensure every transaction has completed by now */
    __DMB();

    /* Configuration of AHB Secure Controller
     * Possible values for every memory sector or peripheral rule:
     *  0    Non-secure, user access allowed.
     *  1    Non-secure, privileged access allowed.
     *  2    Secure, user access allowed.
     *  3    Secure, privileged access allowed. */

    /* == ROM region == */

    /* Security access rules for boot ROM memory sectors. Each sector is 8 KB. Up to 32 sectors are supported. */
    /* Security control ROM memory configuration (0x3 = all regions set to secure and privileged user access). */
    for (i = 0; i < ARRAY_SIZE(AHB_SECURE_CTRL->BOOTROM0_MEM_RULE); i++)
    {
        AHB_SECURE_CTRL->BOOTROM0_MEM_RULE[i] = 0x33333333U;
    }
    
    /* == Flash region == */

    /* FlexSPI 0x0800 0000 to 0x0BFF FFFF 64 MB
            Region 0: 4 MB (32 * 128 KB)
            Region 1: 4 MB (8 * 512 KB)
            Region 2: 8 MB (4 * 2 MB)
            Region 3: 16 MB (4 * 4 MB)
            Region 4: 32 MB (4 * 8 MB) */

    /* 1) Set FLASH memory security access rule configuration to init value (0x3 = all regions set to secure and
     *    privileged user access).
     */
    /* Region 0 has 32 regions of 128 KB each, totaling 4 MB. */
    for (i = 0; i < ARRAY_SIZE(AHB_SECURE_CTRL->FLEXSPI_RULES[0].REGION0_MEM_RULE); i++)
    {
        AHB_SECURE_CTRL->FLEXSPI_RULES[0].REGION0_MEM_RULE[i] = 0x33333333U;
    }
    /* Region 1 has 8 regions of 512 KB each, totaling 4 MB. */
    AHB_SECURE_CTRL->FLEXSPI_RULES[0].REGION1_MEM_RULE = 0x33333333U;
    /* Region 2 has 4 regions of 2 MB each, totaling 8 MB. */
    AHB_SECURE_CTRL->FLEXSPI_RULES[0].REGION2_MEM_RULE = 0x00003333U;
    /* Region 3 has 4 regions of 4 MB each, totaling 16 MB. */
    AHB_SECURE_CTRL->FLEXSPI_RULES[0].REGION3_MEM_RULE = 0x00003333U;
    /* Region 4 has 4 regions of 8 MB each, totaling 32 MB. */
    AHB_SECURE_CTRL->FLEXSPI_RULES[0].REGION4_MEM_RULE = 0x00003333U;

    /* 2) Set FLASH memory security access rule configuration (set to non-secure and non-privileged user access
     *    allowed).
     */
    /* == Region 0 == */
    /* The regions have to be alligned to FLASH_REGION0_SUBREGION_SIZE to cover the AHB Flash Region. */
    SPM_ASSERT(memory_regions.non_secure_partition_base >= NS_ROM_ALIAS_BASE);
    SPM_ASSERT(((memory_regions.non_secure_partition_base - NS_ROM_ALIAS_BASE) % FLASH_REGION0_SUBREGION_SIZE) == 0);
    SPM_ASSERT(((memory_regions.non_secure_partition_limit - NS_ROM_ALIAS_BASE + 1) % FLASH_REGION0_SUBREGION_SIZE)
               == 0);
	enable_mem_rule_for_partition(memory_regions.non_secure_partition_base, memory_regions.non_secure_partition_limit);

#ifdef TFM_PARTITION_WIFI_FLASH_REGION
	enable_mem_rule_for_partition(memory_regions.wifi_flash_region_base, memory_regions.wifi_flash_region_limit);
#endif /* TFM_PARTITION_WIFI_FLASH_REGION */

#ifdef TFM_PARTITION_EL2GO_DATA_IMPORT_REGION
	enable_mem_rule_for_partition(memory_regions.el2go_data_import_region_base, memory_regions.el2go_data_import_region_limit);
#endif /* TFM_PARTITION_EL2GO_DATA_IMPORT_REGION */

    /* == SRAM region == */
    /* RAM0 to RAM18 ~1 MB, each 64 KB (32 * 2 KB) */

    /* The regions have to be alligned to 2 kB to cover the AHB RAM Region */
    SPM_ASSERT((S_DATA_SIZE % DATA_REGION0_SUBREGION_SIZE) == 0);
    SPM_ASSERT(((S_DATA_SIZE + NS_DATA_SIZE) % DATA_REGION0_SUBREGION_SIZE) == 0);

    /* Security access rules for RAM (0x3 = all regions set to secure and privileged user access) */
    for (i = 0; i < (sizeof(ram_rule_sfr)/sizeof(uint32_t*)); i++)
    {
          for (j = 0; j < ARRAY_SIZE(AHB_SECURE_CTRL->RAM00_RULE); j++)
        {
            *(ram_rule_sfr[i] + j) = 0x33333333U;
        }        
    }

    /* == Region 0 == */
    /* RAM memory configuration (set according to region_defs.h and flash_layout.h) */
    ns_region_start_id  = (NS_DATA_START - NS_RAM_DATA_ALIAS_BASE) / DATA_REGION0_SUBREGION_SIZE; /* NS starts after S */
    ns_region_end_id    = (NS_DATA_START - NS_RAM_DATA_ALIAS_BASE + NS_DATA_SIZE) / DATA_REGION0_SUBREGION_SIZE;

    for (ns_region_id = ns_region_start_id; ns_region_id < ns_region_end_id; ns_region_id++)
    {
        ram_rule_sfr_index = ns_region_id / 32;
        ram_rule_sfr_offset = (ns_region_id / 8) % 4;
        ram_rule_sfr_shift = (ns_region_id % 8) * 4;
        *(ram_rule_sfr[ram_rule_sfr_index] + ram_rule_sfr_offset) &= ~(0xF << ram_rule_sfr_shift);
    }

#if TARGET_DEBUG_LOG
    SPMLOG_DBGMSG("=== [AHB MPC NS] =======\r\n");
    SPMLOG_DBGMSGVAL("NS ROM starts from : ", memory_regions.non_secure_partition_base);
    SPMLOG_DBGMSGVAL("NS ROM ends at : ",
                     memory_regions.non_secure_partition_base + memory_regions.non_secure_partition_limit);
    SPMLOG_DBGMSGVAL("NS DATA start from : ", NS_DATA_START);
    SPMLOG_DBGMSGVAL("NS DATA ends at : ", NS_DATA_START + NS_DATA_LIMIT);
#endif /* TARGET_DEBUG_LOG */

    /* Add barriers to assure the MPC configuration is done before continue the execution. */
    __DSB();
    __ISB();

    return ARM_DRIVER_OK;
}

/*---------------------- PPC configuration functions -------------------------*/
int32_t ppc_init_cfg(void)
{
     /* Configuration of AHB Secure Controller. Grant user access to peripherals.
     * Possible values for every memory sector or peripheral rule:
     *  0    Non-secure, user access allowed.
     *  1    Non-secure, privileged access allowed.
     *  2    Secure, user access allowed.
     *  3    Secure, privileged access allowed. */
    
    /* Write access attributes for AHB_SECURE_CTRL module are tier-4 (secure privileged). */ 
    
    // TODO GG: All rules needs to be checked once more with the documentation are all of them met and set for RW612 --
    /* Security access rules for APB Bridge 0 peripherals. */
    AHB_SECURE_CTRL->APB_GRP0_MEM_RULE0 =
        (0x00300000U) |                                                                       /* Bits have to be set to '1' according to UM.*/
        AHB_SECURE_CTRL_APB_GRP0_MEM_RULE0_RSTCTL0_RULE0(TFM_SEC_ACCESS_LVL_USER_NS) |        /* RSTCTL0*/
        AHB_SECURE_CTRL_APB_GRP0_MEM_RULE0_CLKCTL0_RULE1(TFM_SEC_ACCESS_LVL_USER_NS) |        /* CLKCTL0 */
        AHB_SECURE_CTRL_APB_GRP0_MEM_RULE0_SYSCTL0_RULE2(TFM_SEC_ACCESS_LVL_USER_NS) |        /* SYSCTL0 */
        AHB_SECURE_CTRL_APB_GRP0_MEM_RULE0_SYSCTL2_RULE3(TFM_SEC_ACCESS_LVL_USER_NS) |        /* SYSCTL2 */
        AHB_SECURE_CTRL_APB_GRP0_MEM_RULE0_IOCON_RULE4(TFM_SEC_ACCESS_LVL_USER_NS)   |        /* IOCON */
        AHB_SECURE_CTRL_APB_GRP0_MEM_RULE0_PUFCTRL_RULE6(TFM_SEC_ACCESS_LVL_PRIV_S)  |        /* PUF */
        AHB_SECURE_CTRL_APB_GRP0_MEM_RULE0_ELS_RULE7(TFM_SEC_ACCESS_LVL_PRIV_S);              /* ELS */
                                                                                              
    AHB_SECURE_CTRL->APB_GRP0_MEM_RULE1 =                                                     
        (0x00330000U) |                                                                       /* Bits have to be set to '1' according to UM.*/
        AHB_SECURE_CTRL_APB_GRP0_MEM_RULE1_USIM_RULE8(TFM_SEC_ACCESS_LVL_USER_NS)   |         /* USIM */
        AHB_SECURE_CTRL_APB_GRP0_MEM_RULE1_PKC_RULE9(TFM_SEC_ACCESS_LVL_PRIV_S)     |         /* PKC */
        AHB_SECURE_CTRL_APB_GRP0_MEM_RULE1_OCOTP_RULE10(TFM_SEC_ACCESS_LVL_USER_NS) |         /* OCOTP */
        AHB_SECURE_CTRL_APB_GRP0_MEM_RULE1_OCOTP_ADAP_RULE11(TFM_SEC_ACCESS_LVL_USER_NS) |    /* OCOTP ADAP */
        AHB_SECURE_CTRL_APB_GRP0_MEM_RULE1_WWDT0_RULE14(TFM_SEC_ACCESS_LVL_USER_NS) |         /* Watchdog timer 0 */
        AHB_SECURE_CTRL_APB_GRP0_MEM_RULE1_UTICK_RULE15(TFM_SEC_ACCESS_LVL_USER_NS);          /* U-Tick timer */
                                                                                              
    AHB_SECURE_CTRL->APB_GRP0_MEM_RULE2 =                                                     
        (0x00003333U) |                                                                       /* Bits have to be set to '1' according to UM.*/
        AHB_SECURE_CTRL_APB_GRP0_MEM_RULE2_TRNG_RULE20(TFM_SEC_ACCESS_LVL_USER_NS);           /* TRNG */

    AHB_SECURE_CTRL->APB_GRP0_MEM_RULE3 =
        (0x33300333U) |                                                                             /* Bits have to be set to '1' according to UM.*/
        AHB_SECURE_CTRL_APB_GRP0_MEM_RULE3_C0_DOMAIN_TESTCON_RULE27(TFM_SEC_ACCESS_LVL_USER_NS) |   /* C0 DOMAIN TESTCON */
        AHB_SECURE_CTRL_APB_GRP0_MEM_RULE3_C0AON_DOMAIN_TESTCON_RULE28(TFM_SEC_ACCESS_LVL_USER_NS); /* C0 AON DOMAIN TESTCON */
                                                                                       
    /* Security access rules for APB Bridge 1 peripherals */                           
    AHB_SECURE_CTRL->APB_GRP1_MEM_RULE0 =                                              
        (0x30003000U) |                                                                       /* Bits have to be set to '1' according to UM.*/
        AHB_SECURE_CTRL_APB_GRP1_MEM_RULE0_RSTCTL1_RULE0(TFM_SEC_ACCESS_LVL_USER_NS)       |  /* RSTCTL1 */
        AHB_SECURE_CTRL_APB_GRP1_MEM_RULE0_CLKCTL1_RULE1(TFM_SEC_ACCESS_LVL_USER_NS)       |  /* CLKCTL1 */
        AHB_SECURE_CTRL_APB_GRP1_MEM_RULE0_SYSCTL1_RULE2(TFM_SEC_ACCESS_LVL_USER_NS)       |  /* SYSCTL1 */
        AHB_SECURE_CTRL_APB_GRP1_MEM_RULE0_ITRC_RULE4(TFM_SEC_ACCESS_LVL_PRIV_S)          |  /* ITRC */
        AHB_SECURE_CTRL_APB_GRP1_MEM_RULE0_GPIO_INTR_CTRL_RULE5(TFM_SEC_ACCESS_LVL_USER_NS)|  /* GPIO pin interrupts (PINT) */
        AHB_SECURE_CTRL_APB_GRP1_MEM_RULE0_PERIPH_INPUT_MUX_RULE6(TFM_SEC_ACCESS_LVL_USER_NS);/* Input Muxes */               
                                                                                       
    AHB_SECURE_CTRL->APB_GRP1_MEM_RULE1 =                                              
        (0x03030000U) |                                                                
        AHB_SECURE_CTRL_APB_GRP1_MEM_RULE1_CT32BIT0_RULE0(TFM_SEC_ACCESS_LVL_USER_NS) |       /* CTIMER0 */
        AHB_SECURE_CTRL_APB_GRP1_MEM_RULE1_CT32BIT1_RULE1(TFM_SEC_ACCESS_LVL_USER_NS) |       /* CTIMER1 */
        AHB_SECURE_CTRL_APB_GRP1_MEM_RULE1_CT32BIT2_RULE2(TFM_SEC_ACCESS_LVL_USER_NS) |       /* CTIMER2 */
        AHB_SECURE_CTRL_APB_GRP1_MEM_RULE1_CT32BIT3_RULE3(TFM_SEC_ACCESS_LVL_USER_NS) |       /* CTIMER3 */
        AHB_SECURE_CTRL_APB_GRP1_MEM_RULE1_MRT_RULE5(TFM_SEC_ACCESS_LVL_USER_NS)      |       /* MRT */
        AHB_SECURE_CTRL_APB_GRP1_MEM_RULE1_FREQME_RULE7(TFM_SEC_ACCESS_LVL_USER_NS);          /* Frequency measure */
                                                                                       
    AHB_SECURE_CTRL->APB_GRP1_MEM_RULE2 =
        (0x33300300U) |                                                                       /* Bits have to be set to '1' according to UM.*/
        AHB_SECURE_CTRL_APB_GRP1_MEM_RULE2_RTC_RULE0(TFM_SEC_ACCESS_LVL_USER_NS)          |   /* RTC */
        AHB_SECURE_CTRL_APB_GRP1_MEM_RULE2_PMU_RULE1(TFM_SEC_ACCESS_LVL_USER_NS)          |   /* PMU */
        AHB_SECURE_CTRL_APB_GRP1_MEM_RULE2_FLASH_CACHE0_RULE3(TFM_SEC_ACCESS_LVL_USER_NS) |   /* FLASH CACHE0 */
        AHB_SECURE_CTRL_APB_GRP1_MEM_RULE2_FLASH_CACHE1_RULE4(TFM_SEC_ACCESS_LVL_USER_NS);    /* FLASH CACHE1 */
                                                                                       
    AHB_SECURE_CTRL->APB_GRP1_MEM_RULE3 =                                              
        (0x03330330U) |                                                                       /* Bits have to be set to '1' according to UM.*/
        AHB_SECURE_CTRL_APB_GRP1_MEM_RULE3_GAU_RULE0(TFM_SEC_ACCESS_LVL_USER_NS)      |       /* GAU */
        AHB_SECURE_CTRL_APB_GRP1_MEM_RULE3_RF_SYSCON_RULE3(TFM_SEC_ACCESS_LVL_USER_NS)|       /* RF SYSCON */
        AHB_SECURE_CTRL_APB_GRP1_MEM_RULE3_FREEMRT_RULE7(TFM_SEC_ACCESS_LVL_USER_NS);         /* FREEMRT */
                                                                                       
    /* Security access rules for AHB peripherals */                                    
    AHB_SECURE_CTRL->AHB_PERIPH0_SLAVE_RULE =                                          
        (0x00000000U) |                                                                
        AHB_SECURE_CTRL_AHB_PERIPH0_SLAVE_RULE_HSGPIO_RULE0(TFM_SEC_ACCESS_LVL_USER_NS)    |  /* High-speed GPIO */
        AHB_SECURE_CTRL_AHB_PERIPH0_SLAVE_RULE_DMA0_RULE1(TFM_SEC_ACCESS_LVL_USER_NS)      |  /* DMAC0 */
        AHB_SECURE_CTRL_AHB_PERIPH0_SLAVE_RULE_DMA1_RULE2(TFM_SEC_ACCESS_LVL_USER_NS)      |  /* DMAC1 */
        AHB_SECURE_CTRL_AHB_PERIPH0_SLAVE_RULE_FLEXCOMM0_RULE3(TFM_SEC_ACCESS_LVL_USER_NS) |  /* Flexcomm Interface 0 */
        AHB_SECURE_CTRL_AHB_PERIPH0_SLAVE_RULE_FLEXCOMM1_RULE4(TFM_SEC_ACCESS_LVL_USER_NS) |  /* Flexcomm Interface 1 */
        AHB_SECURE_CTRL_AHB_PERIPH0_SLAVE_RULE_FLEXCOMM2_RULE5(TFM_SEC_ACCESS_LVL_USER_NS) |  /* Flexcomm Interface 2 */
        AHB_SECURE_CTRL_AHB_PERIPH0_SLAVE_RULE_FLEXCOMM3_RULE6(TFM_SEC_ACCESS_LVL_USER_NS) |  /* Flexcomm Interface 3 */
        AHB_SECURE_CTRL_AHB_PERIPH0_SLAVE_RULE_DEBUG_MAILBOX_RULE7(TFM_SEC_ACCESS_LVL_USER_NS); /* Debug mailbox */
                                                                                       
    /* Security access rules for AHB peripherals */
    AHB_SECURE_CTRL->AHB_PERIPH1_SLAVE_RULE =
        (0x30333000U) |                                                                       /* Bits have to be set to '1' according to UM.*/
        AHB_SECURE_CTRL_AHB_PERIPH1_SLAVE_RULE_CRC_RULE0(TFM_SEC_ACCESS_LVL_USER_NS)       |  /* CRC engine */
        AHB_SECURE_CTRL_AHB_PERIPH1_SLAVE_RULE_DMIC_RULE1(TFM_SEC_ACCESS_LVL_USER_NS)      |  /* DMIC and HWVAD */
        AHB_SECURE_CTRL_AHB_PERIPH1_SLAVE_RULE_FLEXCOMM4_RULE2(TFM_SEC_ACCESS_LVL_USER_NS) |  /* Flexcomm Interface 4 */
        AHB_SECURE_CTRL_AHB_PERIPH1_SLAVE_RULE_FLEXCOMM14_RULE6(TFM_SEC_ACCESS_LVL_USER_NS);  /* Flexcomm Interface 14 */
                                                                                       
    /* Security access rules for AIPS peripherals */                                   
    AHB_SECURE_CTRL->AIPS_BRIDGE_MEM_RULE0 =                                           
        (0x33303333U) |                                                                       /* Bits have to be set to '1' according to UM.*/
        AHB_SECURE_CTRL_AIPS_BRIDGE_MEM_RULE0_OSPI_AND_OTFAD_RULE4(TFM_SEC_ACCESS_LVL_USER_NS); /* FlexSPI and OTFAD */
                                                                                       
    AHB_SECURE_CTRL->AIPS_BRIDGE_MEM_RULE0 =                                           
        (0x00300330U) |                                                                       /* Bits have to be set to '1' according to UM.*/
        AHB_SECURE_CTRL_AIPS_BRIDGE_MEM_RULE1_ENET(TFM_SEC_ACCESS_LVL_USER_NS)           |    /* ENET */
        AHB_SECURE_CTRL_AIPS_BRIDGE_MEM_RULE1_OSTIMER_RULE3(TFM_SEC_ACCESS_LVL_USER_NS)  |    /* OSTIMER */
        AHB_SECURE_CTRL_AIPS_BRIDGE_MEM_RULE1_ROM_CTRL_RULE4(TFM_SEC_ACCESS_LVL_USER_NS) |    /* ROM CTRL */
        AHB_SECURE_CTRL_AIPS_BRIDGE_MEM_RULE1_MTR_TEST_RULE6(TFM_SEC_ACCESS_LVL_USER_NS) |    /* MTR */
        AHB_SECURE_CTRL_AIPS_BRIDGE_MEM_RULE1_ATX_TEST_RULE7(TFM_SEC_ACCESS_LVL_USER_NS);     /* ATX */
                                                                                       
    /* Security access rules for AHB peripherals */                                    
    AHB_SECURE_CTRL->AHB_PERIPH2_SLAVE_RULE =                                          
        (0x33000000U) |                                                                       /* Bits have to be set to '1' according to UM.*/
        AHB_SECURE_CTRL_AHB_PERIPH2_SLAVE_RULE_USBOTG(TFM_SEC_ACCESS_LVL_USER_NS) |           /* High Speed USB RAM */
        AHB_SECURE_CTRL_AHB_PERIPH2_SLAVE_RULE_SCT(TFM_SEC_ACCESS_LVL_USER_NS)    |           /* High Speed USB Device registers */
        AHB_SECURE_CTRL_AHB_PERIPH2_SLAVE_RULE_GDMA(TFM_SEC_ACCESS_LVL_USER_NS)   |           /* High Speed USB Host registers */
        AHB_SECURE_CTRL_AHB_PERIPH2_SLAVE_RULE_CDOG(TFM_SEC_ACCESS_LVL_PRIV_S);               /* CDOG */
                                                                                              
    /* Security access rules for memory */                                                    
    AHB_SECURE_CTRL->SECURITY_CTRL_MEM_RULE =                                                 
        (0x33330000U) |                                                                       /* Bits have to be set to '1' according to UM.*/
        AHB_SECURE_CTRL_SECURITY_CTRL_MEM_RULE_RULE0(TFM_SEC_ACCESS_LVL_PRIV_S) |             /* MEM 0 */
        AHB_SECURE_CTRL_SECURITY_CTRL_MEM_RULE_RULE1(TFM_SEC_ACCESS_LVL_PRIV_S) |             /* MEM 1 */
        AHB_SECURE_CTRL_SECURITY_CTRL_MEM_RULE_RULE2(TFM_SEC_ACCESS_LVL_PRIV_S) |             /* MEM 2 */
        AHB_SECURE_CTRL_SECURITY_CTRL_MEM_RULE_RULE3(TFM_SEC_ACCESS_LVL_PRIV_S);              /* MEM 3 */
                                                                                       
    /* Security access rules for AHB peripherals */                                    
    AHB_SECURE_CTRL->AHB_PERIPH3_SLAVE_RULE =                                          
        (0x33300000U) |                                                                         /* Bits have to be set to '1' according to UM.*/
        AHB_SECURE_CTRL_AHB_PERIPH3_SLAVE_RULE_PQ_COPRO_RULE0(TFM_SEC_ACCESS_LVL_USER_NS)    |  /* PowerQuad coprocessor registers */
        AHB_SECURE_CTRL_AHB_PERIPH3_SLAVE_RULE_SECURE_GPIO_RULE1(TFM_SEC_ACCESS_LVL_USER_NS) |  /* Secure GPIO */
        AHB_SECURE_CTRL_AHB_PERIPH3_SLAVE_RULE_SDIO_RULE2(TFM_SEC_ACCESS_LVL_USER_NS)        |  /* SDIO */
        AHB_SECURE_CTRL_AHB_PERIPH3_SLAVE_RULE_HPU_RULE3(TFM_SEC_ACCESS_LVL_USER_NS)         |  /* HPU */
        AHB_SECURE_CTRL_AHB_PERIPH3_SLAVE_RULE_PKC_RULE4(TFM_SEC_ACCESS_LVL_PRIV_S);            /* PKC */
                                                                                       
    /* Security access rules for AON memory */                                         
    AHB_SECURE_CTRL->AON_MEM_RULE =                                                    
        (0x33330000U) |                                                                /* Bits have to be set to '1' according to UM.*/
        AHB_SECURE_CTRL_AON_MEM_RULE_RULE0(TFM_SEC_ACCESS_LVL_USER_NS) |                 /* MEM 0 */
        AHB_SECURE_CTRL_AON_MEM_RULE_RULE1(TFM_SEC_ACCESS_LVL_USER_NS) |                 /* MEM 1 */
        AHB_SECURE_CTRL_AON_MEM_RULE_RULE2(TFM_SEC_ACCESS_LVL_USER_NS) |                 /* MEM 2 */
        AHB_SECURE_CTRL_AON_MEM_RULE_RULE3(TFM_SEC_ACCESS_LVL_USER_NS);                  /* MEM 3 */
                                                                                       
    /* Security access rules for WLAN Slave */                                         
    AHB_SECURE_CTRL->WLAN_S0_SLAVE_RULE =                                              
        (0x33333330U) |                                                                /* Bits have to be set to '1' according to UM.*/
        AHB_SECURE_CTRL_WLAN_S0_SLAVE_RULE_RULE0(TFM_SEC_ACCESS_LVL_USER_NS);            /* WLAN S0 Slave */
                                                                                       
    /* Security access rules for WLAN Memory */                                        
    for (uint8_t i = 0; i < ARRAY_SIZE(AHB_SECURE_CTRL->WLAN_S1_MEM_RULE); i++)        
    {                                                                                  
        AHB_SECURE_CTRL->WLAN_S1_MEM_RULE[i] =                                         
        (0x00000000U) |                                                                /* Bits have to be set to '1' according to UM.*/
        AHB_SECURE_CTRL_WLAN_S1_MEM_RULE_RULE0(TFM_SEC_ACCESS_LVL_USER_NS) |             /* WLAN S1 MEM 0 */
        AHB_SECURE_CTRL_WLAN_S1_MEM_RULE_RULE1(TFM_SEC_ACCESS_LVL_USER_NS) |             /* WLAN S1 MEM 1 */
        AHB_SECURE_CTRL_WLAN_S1_MEM_RULE_RULE2(TFM_SEC_ACCESS_LVL_USER_NS) |             /* WLAN S1 MEM 2 */
        AHB_SECURE_CTRL_WLAN_S1_MEM_RULE_RULE3(TFM_SEC_ACCESS_LVL_USER_NS) |             /* WLAN S1 MEM 3 */
        AHB_SECURE_CTRL_WLAN_S1_MEM_RULE_RULE4(TFM_SEC_ACCESS_LVL_USER_NS) |             /* WLAN S1 MEM 4 */
        AHB_SECURE_CTRL_WLAN_S1_MEM_RULE_RULE5(TFM_SEC_ACCESS_LVL_USER_NS) |             /* WLAN S1 MEM 5 */
        AHB_SECURE_CTRL_WLAN_S1_MEM_RULE_RULE6(TFM_SEC_ACCESS_LVL_USER_NS) |             /* WLAN S1 MEM 6 */
        AHB_SECURE_CTRL_WLAN_S1_MEM_RULE_RULE7(TFM_SEC_ACCESS_LVL_USER_NS);              /* WLAN S1 MEM 7 */
    }

    /* Security access rules for BLE Slave */
    AHB_SECURE_CTRL->BLE_S0_SLAVE_RULE =
        (0x33333330U) |                                                                /* Bits have to be set to '1' according to UM.*/
        AHB_SECURE_CTRL_BLE_S0_SLAVE_RULE_RULE0(TFM_SEC_ACCESS_LVL_USER_NS);             /* BLE S0 Slave */
                                                                                       
    /* Security access rules for BLE Memory */                                         
    for (uint8_t i = 0; i < ARRAY_SIZE(AHB_SECURE_CTRL->BLE_S1_MEM_RULE); i++)         
    {                                                                                  
        AHB_SECURE_CTRL->BLE_S1_MEM_RULE[i] =                                          
        (0x00000000U) |                                                                /* Bits have to be set to '1' according to UM.*/
        AHB_SECURE_CTRL_BLE_S1_MEM_RULE_RULE0(TFM_SEC_ACCESS_LVL_USER_NS) |              /* BLE S1 MEM 0 */
        AHB_SECURE_CTRL_BLE_S1_MEM_RULE_RULE1(TFM_SEC_ACCESS_LVL_USER_NS) |              /* BLE S1 MEM 1 */
        AHB_SECURE_CTRL_BLE_S1_MEM_RULE_RULE2(TFM_SEC_ACCESS_LVL_USER_NS) |              /* BLE S1 MEM 2 */
        AHB_SECURE_CTRL_BLE_S1_MEM_RULE_RULE3(TFM_SEC_ACCESS_LVL_USER_NS) |              /* BLE S1 MEM 3 */
        AHB_SECURE_CTRL_BLE_S1_MEM_RULE_RULE4(TFM_SEC_ACCESS_LVL_USER_NS) |              /* BLE S1 MEM 4 */
        AHB_SECURE_CTRL_BLE_S1_MEM_RULE_RULE5(TFM_SEC_ACCESS_LVL_USER_NS) |              /* BLE S1 MEM 5 */
        AHB_SECURE_CTRL_BLE_S1_MEM_RULE_RULE6(TFM_SEC_ACCESS_LVL_USER_NS) |              /* BLE S1 MEM 6 */
        AHB_SECURE_CTRL_BLE_S1_MEM_RULE_RULE7(TFM_SEC_ACCESS_LVL_USER_NS);               /* BLE S1 MEM 7 */
    }                                                                                  
                                                                                       
    /* Security access rules for SoC TOP Memory */                                     
    for (uint8_t i = 0; i < ARRAY_SIZE(AHB_SECURE_CTRL->SOC_TOP_MEM_RULE); i++)        
    {                                                                                  
        AHB_SECURE_CTRL->SOC_TOP_MEM_RULE[i] =                                         
        (0x00000000U) |                                                                /* Bits have to be set to '1' according to UM.*/
        AHB_SECURE_CTRL_SOC_TOP_MEM_RULE_RULE0(TFM_SEC_ACCESS_LVL_USER_NS) |             /* SOC TOP MEM 0 */
        AHB_SECURE_CTRL_SOC_TOP_MEM_RULE_RULE1(TFM_SEC_ACCESS_LVL_USER_NS) |             /* SOC TOP MEM 1 */
        AHB_SECURE_CTRL_SOC_TOP_MEM_RULE_RULE2(TFM_SEC_ACCESS_LVL_USER_NS) |             /* SOC TOP MEM 2 */
        AHB_SECURE_CTRL_SOC_TOP_MEM_RULE_RULE3(TFM_SEC_ACCESS_LVL_USER_NS) |             /* SOC TOP MEM 3 */
        AHB_SECURE_CTRL_SOC_TOP_MEM_RULE_RULE4(TFM_SEC_ACCESS_LVL_USER_NS) |             /* SOC TOP MEM 4 */
        AHB_SECURE_CTRL_SOC_TOP_MEM_RULE_RULE5(TFM_SEC_ACCESS_LVL_USER_NS) |             /* SOC TOP MEM 5 */
        AHB_SECURE_CTRL_SOC_TOP_MEM_RULE_RULE6(TFM_SEC_ACCESS_LVL_USER_NS) |             /* SOC TOP MEM 6 */
        AHB_SECURE_CTRL_SOC_TOP_MEM_RULE_RULE7(TFM_SEC_ACCESS_LVL_USER_NS);              /* SOC TOP MEM 7 */
    }

    /* Secure GPIO mask for pins. 
     * This register is used to block leakage of Secure interface (GPIOs, I2C, UART configured as secure peripherals)
     * pin states to non-secure world. 
     * 0: GPIO can't read PIOn_PIN,
     * 1: GPIO can read PIOn_PIN 0x1
     */
    AHB_SECURE_CTRL->SEC_GPIO_MASK0 = 0xFFFFFFFFU; /* Reset value */
    AHB_SECURE_CTRL->SEC_GPIO_MASK1 = 0xFFFFFFFFU;
    
    /* m33 lock control register (0x2: CM33 Non-secure VTOR is not locked.) */
    AHB_SECURE_CTRL->CM33_LOCK_REG = 0x800002AAU; /* Reset value */
    
    /* Set Master Security Level of PKC and ELS Security Level to secure and privileged master, and lock it. */
    SECURE_READ_MODIFY_WRITE_REGISTER(&(AHB_SECURE_CTRL->MASTER_SEC_LEVEL),
        (AHB_SECURE_CTRL_MASTER_SEC_LEVEL_MASTER_SEC_LEVEL_LOCK_MASK |
        AHB_SECURE_CTRL_MASTER_SEC_LEVEL_ENET_MASK |
        AHB_SECURE_CTRL_MASTER_SEC_LEVEL_SDIO_MASK |
        AHB_SECURE_CTRL_MASTER_SEC_LEVEL_PKC_MASK  |
        AHB_SECURE_CTRL_MASTER_SEC_LEVEL_USB_MASK  |
        AHB_SECURE_CTRL_MASTER_SEC_LEVEL_ELS_MASK  |
        AHB_SECURE_CTRL_MASTER_SEC_LEVEL_DMA1_MASK |
        AHB_SECURE_CTRL_MASTER_SEC_LEVEL_DMA0_MASK |
        AHB_SECURE_CTRL_MASTER_SEC_LEVEL_POWERQUAD_MASK),
        (AHB_SECURE_CTRL_MASTER_SEC_LEVEL_MASTER_SEC_LEVEL_LOCK(0x1U)     |        /* MASTER SEC LEVEL LOCK Setting */
        AHB_SECURE_CTRL_MASTER_SEC_LEVEL_ENET(TFM_SEC_ACCESS_LVL_USER_NS) |        /* MASTER SEC LEVEL ENET */
        AHB_SECURE_CTRL_MASTER_SEC_LEVEL_SDIO(TFM_SEC_ACCESS_LVL_USER_NS) |        /* MASTER SEC LEVEL SDIO */
        AHB_SECURE_CTRL_MASTER_SEC_LEVEL_PKC(TFM_SEC_ACCESS_LVL_PRIV_S)   |        /* MASTER SEC LEVEL PKC  */
        AHB_SECURE_CTRL_MASTER_SEC_LEVEL_USB(TFM_SEC_ACCESS_LVL_USER_NS)  |        /* MASTER SEC LEVEL USB  */
        AHB_SECURE_CTRL_MASTER_SEC_LEVEL_ELS(TFM_SEC_ACCESS_LVL_PRIV_S)   |        /* MASTER SEC LEVEL ELS  */
        AHB_SECURE_CTRL_MASTER_SEC_LEVEL_DMA1(TFM_SEC_ACCESS_LVL_USER_NS) |        /* MASTER SEC LEVEL DMA1 */
        AHB_SECURE_CTRL_MASTER_SEC_LEVEL_DMA0(TFM_SEC_ACCESS_LVL_USER_NS) |        /* MASTER SEC LEVEL DMA0 */
        AHB_SECURE_CTRL_MASTER_SEC_LEVEL_POWERQUAD(TFM_SEC_ACCESS_LVL_USER_NS)));  /* MASTER SEC LEVEL PowerQuad */

    /* Set the corresponding ANTI POL register */
    SECURE_READ_MODIFY_WRITE_REGISTER(&(AHB_SECURE_CTRL->MASTER_SEC_LEVEL_ANTI_POL),
        ~(AHB_SECURE_CTRL_MASTER_SEC_LEVEL_ANTI_POL_MASTER_SEC_LEVEL_ANTIPOL_LOCK_MASK |
        AHB_SECURE_CTRL_MASTER_SEC_LEVEL_ANTI_POL_ENET_MASK |
        AHB_SECURE_CTRL_MASTER_SEC_LEVEL_ANTI_POL_SDIO_MASK |
        AHB_SECURE_CTRL_MASTER_SEC_LEVEL_ANTI_POL_PKC_MASK  |
        AHB_SECURE_CTRL_MASTER_SEC_LEVEL_ANTI_POL_USB_MASK  |
        AHB_SECURE_CTRL_MASTER_SEC_LEVEL_ANTI_POL_ELS_MASK  |
        AHB_SECURE_CTRL_MASTER_SEC_LEVEL_ANTI_POL_DMA1_MASK |
        AHB_SECURE_CTRL_MASTER_SEC_LEVEL_ANTI_POL_DMA0_MASK |
        AHB_SECURE_CTRL_MASTER_SEC_LEVEL_ANTI_POL_POWERQUAD_MASK),
        ~(AHB_SECURE_CTRL_MASTER_SEC_LEVEL_ANTI_POL_MASTER_SEC_LEVEL_ANTIPOL_LOCK(0x1U) |   /* MASTER SEC LEVEL LOCK Setting */
        AHB_SECURE_CTRL_MASTER_SEC_LEVEL_ANTI_POL_ENET(TFM_SEC_ACCESS_LVL_USER_NS) |        /* MASTER SEC LEVEL ENET */
        AHB_SECURE_CTRL_MASTER_SEC_LEVEL_ANTI_POL_SDIO(TFM_SEC_ACCESS_LVL_USER_NS) |        /* MASTER SEC LEVEL SDIO */
        AHB_SECURE_CTRL_MASTER_SEC_LEVEL_ANTI_POL_PKC(TFM_SEC_ACCESS_LVL_PRIV_S)   |        /* MASTER SEC LEVEL PKC  */
        AHB_SECURE_CTRL_MASTER_SEC_LEVEL_ANTI_POL_USB(TFM_SEC_ACCESS_LVL_USER_NS)  |        /* MASTER SEC LEVEL USB  */
        AHB_SECURE_CTRL_MASTER_SEC_LEVEL_ANTI_POL_ELS(TFM_SEC_ACCESS_LVL_PRIV_S)   |        /* MASTER SEC LEVEL ELS  */
        AHB_SECURE_CTRL_MASTER_SEC_LEVEL_ANTI_POL_DMA1(TFM_SEC_ACCESS_LVL_USER_NS) |        /* MASTER SEC LEVEL DMA1 */
        AHB_SECURE_CTRL_MASTER_SEC_LEVEL_ANTI_POL_DMA0(TFM_SEC_ACCESS_LVL_USER_NS) |        /* MASTER SEC LEVEL DMA0 */
        AHB_SECURE_CTRL_MASTER_SEC_LEVEL_ANTI_POL_POWERQUAD(TFM_SEC_ACCESS_LVL_USER_NS)));  /* MASTER SEC LEVEL PowerQuad */

    /* Update AHB Secure control register */
    SECURE_READ_MODIFY_WRITE_REGISTER(&(AHB_SECURE_CTRL->MISC_CTRL_REG),
        ~(AHB_SECURE_CTRL_MISC_CTRL_REG_WRITE_LOCK_MASK                |
          AHB_SECURE_CTRL_MISC_CTRL_REG_ENABLE_SECURE_CHECKING_MASK    |
          AHB_SECURE_CTRL_MISC_CTRL_REG_DISABLE_STRICT_MODE_MASK       |
          AHB_SECURE_CTRL_MISC_CTRL_REG_DISABLE_VIOLATION_ABORT_MASK   |
          AHB_SECURE_CTRL_MISC_CTRL_REG_IDAU_ALL_NS_MASK               ),
         (AHB_SECURE_CTRL_MISC_CTRL_REG_WRITE_LOCK              (0x2U) |         /* 2 = Writes to this register and to the Memory and Peripheral RULE registers are allowed */
          AHB_SECURE_CTRL_MISC_CTRL_REG_ENABLE_SECURE_CHECKING  (0x1U) |         /* 1 = Enable Secure Checking (restrictive mode) */
          AHB_SECURE_CTRL_MISC_CTRL_REG_ENABLE_S_PRIV_CHECK     (0x2U) |         /* 2 = Disabled Secure Privilege Checking */
          AHB_SECURE_CTRL_MISC_CTRL_REG_ENABLE_NS_PRIV_CHECK    (0x2U) |         /* 2 = Disabled Non-Secure Privilege Checking */
          AHB_SECURE_CTRL_MISC_CTRL_REG_DISABLE_VIOLATION_ABORT (0x2U) |         /* 2 = The violation detected by the secure checker will cause an abort. */
          AHB_SECURE_CTRL_MISC_CTRL_REG_DISABLE_STRICT_MODE     (0x1U) |         /* 1 = AHB master in tier mode. Can read and write to memories at same or below level. */
          AHB_SECURE_CTRL_MISC_CTRL_REG_IDAU_ALL_NS             (0x2U)));        /* 2 = IDAU is enabled (restrictive mode) */

    /* Secure control duplicate register */
    SECURE_READ_MODIFY_WRITE_REGISTER(&(AHB_SECURE_CTRL->MISC_CTRL_DP_REG),
        ~(AHB_SECURE_CTRL_MISC_CTRL_DP_REG_WRITE_LOCK_MASK                |
          AHB_SECURE_CTRL_MISC_CTRL_DP_REG_ENABLE_SECURE_CHECKING_MASK    |
          AHB_SECURE_CTRL_MISC_CTRL_DP_REG_DISABLE_STRICT_MODE_MASK       |
          AHB_SECURE_CTRL_MISC_CTRL_DP_REG_DISABLE_VIOLATION_ABORT_MASK   |
          AHB_SECURE_CTRL_MISC_CTRL_DP_REG_IDAU_ALL_NS_MASK               ),
         (AHB_SECURE_CTRL_MISC_CTRL_DP_REG_WRITE_LOCK              (0x2U) |      /* 2 = Writes to this register and to the Memory and Peripheral RULE registers are allowed */
          AHB_SECURE_CTRL_MISC_CTRL_DP_REG_ENABLE_SECURE_CHECKING  (0x1U) |      /* 1 = Enable Secure Checking (restrictive mode) */
          AHB_SECURE_CTRL_MISC_CTRL_DP_REG_ENABLE_S_PRIV_CHECK     (0x2U) |      /* 2 = Disabled Secure Privilege Checking */
          AHB_SECURE_CTRL_MISC_CTRL_DP_REG_ENABLE_NS_PRIV_CHECK    (0x2U) |      /* 2 = Disabled Non-Secure Privilege Checking */
          AHB_SECURE_CTRL_MISC_CTRL_DP_REG_DISABLE_VIOLATION_ABORT (0x2U) |      /* 2 = The violation detected by the secure checker will cause an abort. */
          AHB_SECURE_CTRL_MISC_CTRL_DP_REG_DISABLE_STRICT_MODE     (0x1U) |      /* 1 = AHB master in tier mode. Can read and write to memories at same or below level. */
          AHB_SECURE_CTRL_MISC_CTRL_DP_REG_IDAU_ALL_NS             (0x2U)));     /* 2 = IDAU is enabled (restrictive mode) */

    return ARM_DRIVER_OK;
}

void ppc_configure_to_secure(volatile uint32_t *bank, uint32_t pos, bool privileged)
{
    /* Clear NS flag for peripheral to prevent NS access */
    if (bank)
    {
        /*  0b00..Non-secure and Non-priviledge user access allowed.
         *  0b01..Non-secure and Privilege access allowed.
         *  0b10..Secure and Non-priviledge user access allowed.
         *  0b11..Secure and Priviledge/Non-priviledge user access allowed.
         */
        /* Set to secure and privileged user access 0x3. */
        *bank = (*bank) | (((privileged == true)?0x3:0x2) << (pos));
    }
}

/* Secure Violation IRQ */
void SECUREVIOLATION_DriverIRQHandler(void)
{
    SPMLOG_ERRMSG("Oops... Secure Violation!!!\n");
    
    tfm_core_panic();
}

