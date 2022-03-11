/*
 * Copyright (c) 2019-2022 Arm Limited
 *
 * Licensed under the Apache License Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing software
 * distributed under the License is distributed on an "AS IS" BASIS
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * \file platform_base_address.h
 * \brief This file defines all the peripheral base addresses for RSS platform.
 */

#ifndef __PLATFORM_BASE_ADDRESS_H__
#define __PLATFORM_BASE_ADDRESS_H__

/* ======= Defines peripherals memory map addresses ======= */
/* Non-secure memory map addresses */
#define ITCM_BASE_NS                     0x00000000 /* Instruction TCM Non-Secure base address */
#define DTCM_BASE_NS                     0x20000000 /* Data TCM Non-Secure base address */
#define VM0_BASE_NS                      0x21000000 /* Volatile Memory 0 Non-Secure base address */
#define VM1_BASE_NS                      0x21800000 /* Volatile Memory 1 Non-Secure base address */
/* Non-Secure Private CPU region */
#define CPU0_PWRCTRL_BASE_NS             0x40012000 /* CPU 0 Power Control Block Non-Secure base address */
#define CPU0_IDENTITY_BASE_NS            0x4001F000 /* CPU 0 Identity Block Non-Secure base address */
/* Non-Secure Peripheral region */
#define DMA_0_BASE_NS                    0x40002000 /* DMA 0 Non-Secure base address */
#define RSS_NSACFG_BASE_NS               0x40080000 /* RSS Non-Secure Access Configuration Register Block Non-Secure base address */
#define GPIO0_CMSDK_BASE_NS              0x40100000 /* GPIO 0 Non-Secure base address */
#define GPIO1_CMSDK_BASE_NS              0x40101000 /* GPIO 1 Non-Secure base address */
#define MHU0_SENDER_BASE_NS              0x40160000 /* Combined MHU 0 Sender Non-Secure base address */
#define MHU0_RECEIVER_BASE_NS            0x40170000 /* Combined MHU 0 Receiver Non-Secure base address */
#define MHU1_SENDER_BASE_NS              0x40180000 /* Combined MHU 1 Sender Non-Secure base address */
#define MHU1_RECEIVER_BASE_NS            0x40190000 /* Combined MHU 1 Receiver Non-Secure base address */
#define MHU2_SENDER_BASE_NS              0x401A0000 /* Combined MHU 2 Sender Non-Secure base address */
#define MHU2_RECEIVER_BASE_NS            0x401B0000 /* Combined MHU 2 Receiver Non-Secure base address */
#define MHU3_SENDER_BASE_NS              0x401C0000 /* Combined MHU 3 Sender Non-Secure base address */
#define MHU3_RECEIVER_BASE_NS            0x401D0000 /* Combined MHU 3 Receiver Non-Secure base address */
#define MHU4_SENDER_BASE_NS              0x401E0000 /* Combined MHU 4 Sender Non-Secure base address */
#define MHU4_RECEIVER_BASE_NS            0x401F0000 /* Combined MHU 4 Receiver Non-Secure base address */
#define MHU5_SENDER_BASE_NS              0x40200000 /* Combined MHU 5 Sender Non-Secure base address */
#define MHU5_RECEIVER_BASE_NS            0x40210000 /* Combined MHU 5 Receiver Non-Secure base address */
#define MHU6_SENDER_BASE_NS              0x40220000 /* Combined MHU 6 Sender Non-Secure base address */
#define MHU6_RECEIVER_BASE_NS            0x40230000 /* Combined MHU 6 Receiver Non-Secure base address */
#define MHU7_SENDER_BASE_NS              0x40240000 /* Combined MHU 7 Sender Non-Secure base address */
#define MHU7_RECEIVER_BASE_NS            0x40250000 /* Combined MHU 7 Receiver Non-Secure base address */
#define MHU8_SENDER_BASE_NS              0x40260000 /* Combined MHU 8 Sender Non-Secure base address */
#define MHU8_RECEIVER_BASE_NS            0x40270000 /* Combined MHU 8 Receiver Non-Secure base address */
#define SYSTIMER0_ARMV8_M_BASE_NS        0x48000000 /* System Timer 0 Non-Secure base address */
#define SYSTIMER1_ARMV8_M_BASE_NS        0x48001000 /* System Timer 1 Non-Secure base address */
#define SYSTIMER2_ARMV8_M_BASE_NS        0x48002000 /* System Timer 2 Non-Secure base address */
#define SYSTIMER3_ARMV8_M_BASE_NS        0x48003000 /* System Timer 3 Non-Secure base address */
#define RSS_SYSINFO_BASE_NS              0x48020000 /* RSS System info Block Non-Secure base address */
#define SLOWCLK_TIMER_CMSDK_BASE_NS      0x4802F000 /* CMSDK based SLOWCLK Timer Non-Secure base address */
#define SYSWDOG_ARMV8_M_CNTRL_BASE_NS    0x48040000 /* Non-Secure Watchdog Timer control frame Non-Secure base address */
#define SYSWDOG_ARMV8_M_REFRESH_BASE_NS  0x48041000 /* Non-Secure Watchdog Timer refresh frame Non-Secure base address */
/* Non-Secure Host region */
#define HOST_ACCESS_BASE_NS              0x60000000 /* Can access the Host region based on ATU config */
#define HOST_ACCESS_LIMIT_NS             (HOST_ACCESS_BASE_NS + HOST_ACCESS_SIZE - 1)
#define UART0_BASE_NS                    (HOST_ACCESS_BASE_NS + 0x0A400000) /* UART 0 Non-Secure base address */

/* Secure memory map addresses */
#define ITCM_BASE_S                      0x10000000 /* Instruction TCM Secure base address */
#define ROM_BASE_S                       0x11000000 /* CODE ROM Secure base address. No NS alias for ROM */
#define DTCM_BASE_S                      0x30000000 /* Data TCM Secure base address */
#define VM0_BASE_S                       0x31000000 /* Volatile Memory 0 Secure base address */
#define VM1_BASE_S                       0x31800000 /* Volatile Memory 1 Secure base address */
/* Secure Private CPU region */
#define CPU0_SECCTRL_BASE_S              0x50011000 /* CPU 0 Local Security Control Block Secure base address */
#define CPU0_PWRCTRL_BASE_S              0x50012000 /* CPU 0 Power Control Block Secure base address */
#define CPU0_IDENTITY_BASE_S             0x5001F000 /* CPU 0 Identity Block Secure base address */
/* Secure Peripheral region */
#define DMA_0_BASE_S                     0x50002000 /* DMA 0 Secure base address */
#define RSS_SACFG_BASE_S                 0x50080000 /* RSS Secure Access Configuration Register Secure base address */
#define MPC_VM0_BASE_S                   0x50083000 /* VM0 Memory Protection Controller Secure base address */
#define MPC_VM1_BASE_S                   0x50084000 /* VM1 Memory Protection Controller Secure base address */
#define GPIO0_CMSDK_BASE_S               0x50100000 /* GPIO 0 Secure base address */
#define GPIO1_CMSDK_BASE_S               0x50101000 /* GPIO 1 Secure base address */
#define ATU_BASE_S                       0x50150000 /* ATU Secure base address */
#define SYSCNTR_CNTRL_BASE_S             0x5015A000 /* System Counter Control Secure base address */
#define SYSCNTR_READ_BASE_S              0x5015B000 /* System Counter Read Secure base address */
#define MHU0_SENDER_BASE_S               0x50160000 /* Combined MHU 0 Sender Secure base address */
#define MHU0_RECEIVER_BASE_S             0x50170000 /* Combined MHU 0 Receiver Secure base address */
#define MHU1_SENDER_BASE_S               0x50180000 /* Combined MHU 1 Sender Secure base address */
#define MHU1_RECEIVER_BASE_S             0x50190000 /* Combined MHU 1 Receiver Secure base address */
#define MHU2_SENDER_BASE_S               0x501A0000 /* Combined MHU 2 Sender Secure base address */
#define MHU2_RECEIVER_BASE_S             0x501B0000 /* Combined MHU 2 Receiver Secure base address */
#define MHU3_SENDER_BASE_S               0x501C0000 /* Combined MHU 3 Sender Secure base address */
#define MHU3_RECEIVER_BASE_S             0x501D0000 /* Combined MHU 3 Receiver Secure base address */
#define MHU4_SENDER_BASE_S               0x501E0000 /* Combined MHU 4 Sender Secure base address */
#define MHU4_RECEIVER_BASE_S             0x501F0000 /* Combined MHU 4 Receiver Secure base address */
#define MHU5_SENDER_BASE_S               0x50200000 /* Combined MHU 5 Sender Secure base address */
#define MHU5_RECEIVER_BASE_S             0x50210000 /* Combined MHU 5 Receiver Secure base address */
#define MHU6_SENDER_BASE_S               0x50220000 /* Combined MHU 6 Sender Secure base address */
#define MHU6_RECEIVER_BASE_S             0x50230000 /* Combined MHU 6 Receiver Secure base address */
#define MHU7_SENDER_BASE_S               0x50240000 /* Combined MHU 7 Sender Secure base address */
#define MHU7_RECEIVER_BASE_S             0x50250000 /* Combined MHU 7 Receiver Secure base address */
#define MHU8_SENDER_BASE_S               0x50260000 /* Combined MHU 8 Sender Secure base address */
#define MHU8_RECEIVER_BASE_S             0x50270000 /* Combined MHU 8 Receiver Secure base address */
#define SYSTIMER0_ARMV8_M_BASE_S         0x58000000 /* System Timer 0 Secure base address */
#define SYSTIMER1_ARMV8_M_BASE_S         0x58001000 /* System Timer 1 Secure base address */
#define SYSTIMER2_ARMV8_M_BASE_S         0x58002000 /* System Timer 2 Secure base address */
#define SYSTIMER3_ARMV8_M_BASE_S         0x58003000 /* System Timer 3 Secure base address */
#define RSS_SYSINFO_BASE_S               0x58020000 /* RSS System info Block Secure base address */
#define RSS_SYSCTRL_BASE_S               0x58021000 /* RSS System control Block Secure base address */
#define RSS_SYSPPU_BASE_S                0x58022000 /* RSS System Power Policy Unit Secure base address */
#define RSS_CPU0PPU_BASE_S               0x58023000 /* RSS CPU 0 Power Policy Unit Secure base address */
#define RSS_MGMTPPU_BASE_S               0x58028000 /* RSS Management Power Policy Unit Secure base address */
#define RSS_DBGPPU_BASE_S                0x58029000 /* RSS Debug Power Policy Unit Secure base address */
#define SLOWCLK_WDOG_CMSDK_BASE_S        0x5802E000 /* CMSDK based SLOWCLK Watchdog Secure base address */
#define SLOWCLK_TIMER_CMSDK_BASE_S       0x5802F000 /* CMSDK based SLOWCLK Timer Secure base address */
#define SYSWDOG_ARMV8_M_CNTRL_BASE_S     0x58040000 /* Secure Watchdog Timer control frame Secure base address */
#define SYSWDOG_ARMV8_M_REFRESH_BASE_S   0x58041000 /* Secure Watchdog Timer refresh frame Secure base address */
/* Secure Host region */
#define HOST_ACCESS_BASE_S               0x70000000 /* Can access the Host region based on ATU config */
#define HOST_ACCESS_LIMIT_S              (HOST_ACCESS_BASE_S + HOST_ACCESS_SIZE - 1)
#define UART0_BASE_S                     (HOST_ACCESS_BASE_S + 0x0A400000) /* UART 0 Secure base address */

/* Memory map addresses exempt from memory attribution by both the SAU and IDAU */
#define RSS_EWIC_BASE                    0xE0047000 /* External Wakeup Interrupt Controller
                                                     * Access from Non-secure software is only allowed
                                                     * if AIRCR.BFHFNMINS is set to 1 */

/* Memory size definitions */
#define ITCM_SIZE                        0x00008000 /* 32 kB */
#define ROM_SIZE                         0x00020000 /* 128 kB */
#define DTCM_SIZE                        0x00008000 /* 32 kB */
#define VM0_SIZE                         0x00800000 /* 8 MB */
#define VM1_SIZE                         0x00800000 /* 8 MB */
#define HOST_ACCESS_SIZE                 0x10000000 /* 256 MB */

/* Defines for Driver MPC's */
/* VM0 -- 8 MB */
#define MPC_VM0_RANGE_BASE_NS            (VM0_BASE_NS)
#define MPC_VM0_RANGE_LIMIT_NS           (VM0_BASE_NS + VM0_SIZE-1)
#define MPC_VM0_RANGE_OFFSET_NS          (0x0)
#define MPC_VM0_RANGE_BASE_S             (VM0_BASE_S)
#define MPC_VM0_RANGE_LIMIT_S            (VM0_BASE_S + VM0_SIZE-1)
#define MPC_VM0_RANGE_OFFSET_S           (0x0)

/* VM1 -- 8 MB */
#define MPC_VM1_RANGE_BASE_NS            (VM1_BASE_NS)
#define MPC_VM1_RANGE_LIMIT_NS           (VM1_BASE_NS + VM1_SIZE-1)
#define MPC_VM1_RANGE_OFFSET_NS          (0x0)
#define MPC_VM1_RANGE_BASE_S             (VM1_BASE_S)
#define MPC_VM1_RANGE_LIMIT_S            (VM1_BASE_S + VM1_SIZE-1)
#define MPC_VM1_RANGE_OFFSET_S           (0x0)

#endif  /* __PLATFORM_BASE_ADDRESS_H__ */
