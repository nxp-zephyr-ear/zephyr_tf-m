/*
 * Copyright (c) 2022 Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * This file is derivative of CMSIS V5.9.0 startup_ARMCM33.c
 * Git SHA: 2b7495b8535bdcb306dac29b9ded4cfb679d7e5c
 */

/* NS linker scripts using the default CMSIS style naming conventions, while the
 * secure and bl2 linker scripts remain untouched (region.h compatibility).
 * To be compatible with the untouched files (which using ARMCLANG naming style),
 * we have to override __INITIAL_SP and __STACK_LIMIT labels. */
#if defined (__ARM_FEATURE_CMSE) && (__ARM_FEATURE_CMSE == 3U) 
#include "cmsis_override.h"
#endif

#include "cmsis.h"

/*----------------------------------------------------------------------------
  External References
 *----------------------------------------------------------------------------*/
extern uint32_t __INITIAL_SP;
extern uint32_t __STACK_LIMIT;
#if defined (__ARM_FEATURE_CMSE) && (__ARM_FEATURE_CMSE == 3U)
extern uint64_t __STACK_SEAL;
#endif

typedef void(*VECTOR_TABLE_Type)(void);

extern void __PROGRAM_START(void) __NO_RETURN;

/*----------------------------------------------------------------------------
  Internal References
 *----------------------------------------------------------------------------*/
void Reset_Handler  (void) __NO_RETURN;

/*----------------------------------------------------------------------------
  Exception / Interrupt Handler
 *----------------------------------------------------------------------------*/
#define DEFAULT_IRQ_HANDLER(handler_name)  \
void __WEAK handler_name(void) __NO_RETURN; \
void handler_name(void) { \
    while(1); \
}

/* Exceptions */
DEFAULT_IRQ_HANDLER(NMI_Handler)
DEFAULT_IRQ_HANDLER(HardFault_Handler)
DEFAULT_IRQ_HANDLER(MemManage_Handler)
DEFAULT_IRQ_HANDLER(BusFault_Handler)
DEFAULT_IRQ_HANDLER(UsageFault_Handler)
DEFAULT_IRQ_HANDLER(SecureFault_Handler)
DEFAULT_IRQ_HANDLER(SVC_Handler)
DEFAULT_IRQ_HANDLER(DebugMon_Handler)
DEFAULT_IRQ_HANDLER(PendSV_Handler)
DEFAULT_IRQ_HANDLER(SysTick_Handler)

DEFAULT_IRQ_HANDLER(WDT0_IRQHandler)
DEFAULT_IRQ_HANDLER(DMA0_IRQHandler)
DEFAULT_IRQ_HANDLER(GPIO_INTA_IRQHandler)
DEFAULT_IRQ_HANDLER(GPIO_INTB_IRQHandler)
DEFAULT_IRQ_HANDLER(PIN_INT0_IRQHandler)
DEFAULT_IRQ_HANDLER(PIN_INT1_IRQHandler)
DEFAULT_IRQ_HANDLER(PIN_INT2_IRQHandler)
DEFAULT_IRQ_HANDLER(PIN_INT3_IRQHandler)
DEFAULT_IRQ_HANDLER(UTICK_IRQHandler)
DEFAULT_IRQ_HANDLER(MRT0_IRQHandler)
DEFAULT_IRQ_HANDLER(CTIMER0_IRQHandler)
DEFAULT_IRQ_HANDLER(CTIMER1_IRQHandler)
DEFAULT_IRQ_HANDLER(SCT0_IRQHandler)
DEFAULT_IRQ_HANDLER(CTIMER3_IRQHandler)
DEFAULT_IRQ_HANDLER(FLEXCOMM0_IRQHandler)
DEFAULT_IRQ_HANDLER(FLEXCOMM1_IRQHandler)
DEFAULT_IRQ_HANDLER(FLEXCOMM2_IRQHandler)
DEFAULT_IRQ_HANDLER(FLEXCOMM3_IRQHandler)
DEFAULT_IRQ_HANDLER(Reserved34_IRQHandler)
DEFAULT_IRQ_HANDLER(Reserved35_IRQHandler)
DEFAULT_IRQ_HANDLER(FLEXCOMM14_IRQHandler)
DEFAULT_IRQ_HANDLER(Reserved37_IRQHandler)
DEFAULT_IRQ_HANDLER(Reserved38_IRQHandler)
DEFAULT_IRQ_HANDLER(MRT1_IRQHandler)
DEFAULT_IRQ_HANDLER(Reserved40_IRQHandler)
DEFAULT_IRQ_HANDLER(DMIC0_IRQHandler)
DEFAULT_IRQ_HANDLER(WFD_IRQHandler)
DEFAULT_IRQ_HANDLER(HYPERVISOR_IRQHandler)
DEFAULT_IRQ_HANDLER(SECUREVIOLATION_IRQHandler)
DEFAULT_IRQ_HANDLER(HWVAD0_IRQHandler)
DEFAULT_IRQ_HANDLER(Reserved46_IRQHandler)
DEFAULT_IRQ_HANDLER(Reserved47_IRQHandler)
DEFAULT_IRQ_HANDLER(RTC_IRQHandler)
DEFAULT_IRQ_HANDLER(Reserved49_IRQHandler)
DEFAULT_IRQ_HANDLER(Reserved50_IRQHandler)
DEFAULT_IRQ_HANDLER(PIN_INT4_IRQHandler)
DEFAULT_IRQ_HANDLER(PIN_INT5_IRQHandler)
DEFAULT_IRQ_HANDLER(PIN_INT6_IRQHandler)
DEFAULT_IRQ_HANDLER(PIN_INT7_IRQHandler)
DEFAULT_IRQ_HANDLER(CTIMER2_IRQHandler)
DEFAULT_IRQ_HANDLER(CTIMER4_IRQHandler)
DEFAULT_IRQ_HANDLER(OS_EVENT_IRQHandler)
DEFAULT_IRQ_HANDLER(FLEXSPI_IRQHandler)
DEFAULT_IRQ_HANDLER(Reserved59_IRQHandler)
DEFAULT_IRQ_HANDLER(Reserved60_IRQHandler)
DEFAULT_IRQ_HANDLER(Reserved61_IRQHandler)
DEFAULT_IRQ_HANDLER(SDU_IRQHandler)
DEFAULT_IRQ_HANDLER(SGPIO_INTA_IRQHandler)
DEFAULT_IRQ_HANDLER(SGPIO_INTB_IRQHandler)
DEFAULT_IRQ_HANDLER(Reserved65_IRQHandler)
DEFAULT_IRQ_HANDLER(USB_IRQHandler)
DEFAULT_IRQ_HANDLER(Reserved67_IRQHandler)
DEFAULT_IRQ_HANDLER(Reserved68_IRQHandler)
DEFAULT_IRQ_HANDLER(Reserved69_IRQHandler)
DEFAULT_IRQ_HANDLER(DMA1_IRQHandler)
DEFAULT_IRQ_HANDLER(PUF_IRQHandler)
DEFAULT_IRQ_HANDLER(POWERQUAD_IRQHandler)
DEFAULT_IRQ_HANDLER(Reserved73_IRQHandler)
DEFAULT_IRQ_HANDLER(Reserved74_IRQHandler)
DEFAULT_IRQ_HANDLER(Reserved75_IRQHandler)
DEFAULT_IRQ_HANDLER(Reserved76_IRQHandler)
DEFAULT_IRQ_HANDLER(LCDIC_IRQHandler)
DEFAULT_IRQ_HANDLER(CAPT_PULSE_IRQHandler)
DEFAULT_IRQ_HANDLER(Reserved79_IRQHandler)
DEFAULT_IRQ_HANDLER(WL_MCI_WAKEUP_DONE0_IRQHandler)
DEFAULT_IRQ_HANDLER(WL_MCI_WAKEUP_DONE1_IRQHandler)
DEFAULT_IRQ_HANDLER(WL_MCI_WAKEUP_DONE2_IRQHandler)
DEFAULT_IRQ_HANDLER(WL_MCI_WAKEUP_DONE3_IRQHandler)
DEFAULT_IRQ_HANDLER(WL_MCI_WAKEUP_DONE4_IRQHandler)
DEFAULT_IRQ_HANDLER(WL_MCI_WAKEUP_DONE5_IRQHandler)
DEFAULT_IRQ_HANDLER(WL_MCI_WAKEUP_DONE6_IRQHandler)
DEFAULT_IRQ_HANDLER(WL_MCI_WAKEUP_DONE7_IRQHandler)
DEFAULT_IRQ_HANDLER(WL_MCI_WAKEUP0_IRQHandler)
DEFAULT_IRQ_HANDLER(WL_MCI_WAKEUP1_IRQHandler)
DEFAULT_IRQ_HANDLER(WL_MCI_INT0_IRQHandler)
DEFAULT_IRQ_HANDLER(WL_MCI_INT1_IRQHandler)
DEFAULT_IRQ_HANDLER(WL_MCI_INT2_IRQHandler)
DEFAULT_IRQ_HANDLER(WL_MCI_INT3_IRQHandler)
DEFAULT_IRQ_HANDLER(WL_MCI_INT4_IRQHandler)
DEFAULT_IRQ_HANDLER(WL_MCI_INT5_IRQHandler)
DEFAULT_IRQ_HANDLER(WL_MCI_INT6_IRQHandler)
DEFAULT_IRQ_HANDLER(WL_MCI_INT7_IRQHandler)
DEFAULT_IRQ_HANDLER(BLE_MCI_WAKEUP_DONE0_IRQHandler)
DEFAULT_IRQ_HANDLER(BLE_MCI_WAKEUP_DONE1_IRQHandler)
DEFAULT_IRQ_HANDLER(BLE_MCI_WAKEUP_DONE2_IRQHandler)
DEFAULT_IRQ_HANDLER(BLE_MCI_WAKEUP_DONE3_IRQHandler)
DEFAULT_IRQ_HANDLER(BLE_MCI_WAKEUP_DONE4_IRQHandler)
DEFAULT_IRQ_HANDLER(BLE_MCI_WAKEUP_DONE5_IRQHandler)
DEFAULT_IRQ_HANDLER(BLE_MCI_WAKEUP_DONE6_IRQHandler)
DEFAULT_IRQ_HANDLER(BLE_MCI_WAKEUP_DONE7_IRQHandler)
DEFAULT_IRQ_HANDLER(BLE_MCI_WAKEUP0_IRQHandler)
DEFAULT_IRQ_HANDLER(BLE_MCI_WAKEUP1_IRQHandler)
DEFAULT_IRQ_HANDLER(BLE_MCI_INT0_IRQHandler)
DEFAULT_IRQ_HANDLER(BLE_MCI_INT1_IRQHandler)
DEFAULT_IRQ_HANDLER(BLE_MCI_INT2_IRQHandler)
DEFAULT_IRQ_HANDLER(BLE_MCI_INT3_IRQHandler)
DEFAULT_IRQ_HANDLER(BLE_MCI_INT4_IRQHandler)
DEFAULT_IRQ_HANDLER(BLE_MCI_INT5_IRQHandler)
DEFAULT_IRQ_HANDLER(BLE_MCI_INT6_IRQHandler)
DEFAULT_IRQ_HANDLER(BLE_MCI_INT7_IRQHandler)
DEFAULT_IRQ_HANDLER(PIN0_INT_IRQHandler)
DEFAULT_IRQ_HANDLER(PIN1_INT_IRQHandler)
DEFAULT_IRQ_HANDLER(CSS_IRQHandler)
DEFAULT_IRQ_HANDLER(CSS_GDET_IRQ_IRQHandler)
DEFAULT_IRQ_HANDLER(CSS_GDET_ERR_IRQHandler)
DEFAULT_IRQ_HANDLER(PKC_IRQHandler)
DEFAULT_IRQ_HANDLER(PKC_ERR_IRQHandler)
DEFAULT_IRQ_HANDLER(CDOG_IRQHandler)
DEFAULT_IRQ_HANDLER(GAU_GPDAC_INT_FUNC11_IRQHandler)
DEFAULT_IRQ_HANDLER(GAU_ACOMP_INT_WKUP11_IRQHandler)
DEFAULT_IRQ_HANDLER(GAU_ACOMP_INT_FUNC11_IRQHandler)
DEFAULT_IRQ_HANDLER(GAU_GPADC1_INT_FUNC11_IRQHandler)
DEFAULT_IRQ_HANDLER(GAU_GPADC0_INT_FUNC11_IRQHandler)
DEFAULT_IRQ_HANDLER(USIM_IRQHandler)
DEFAULT_IRQ_HANDLER(OCOTP_IRQHandler)
DEFAULT_IRQ_HANDLER(ENET_IRQHandler)
DEFAULT_IRQ_HANDLER(ENET_TIMER_IRQHandler)
DEFAULT_IRQ_HANDLER(BOD_1_85_INT_IRQHandler)
DEFAULT_IRQ_HANDLER(BOD_1_85_NEG_IRQHandler)
DEFAULT_IRQ_HANDLER(ITRC_IRQHandler)
DEFAULT_IRQ_HANDLER(BTU_HOST_TRIGGER0_IRQHandler)
DEFAULT_IRQ_HANDLER(BTU_HOST_TRIGGER1_IRQHandler)
DEFAULT_IRQ_HANDLER(BTU_HOST_TRIGGER2_IRQHandler)
DEFAULT_IRQ_HANDLER(TRNG_IRQHandler)
DEFAULT_IRQ_HANDLER(AHB_MEM_ACC_CHECKER_VIO_INT_C_OR_IRQHandler)
DEFAULT_IRQ_HANDLER(AHB_MEM_ACC_CHECKER_VIO_INT_S_OR_IRQHandler)
DEFAULT_IRQ_HANDLER(WL_ACC_INT_IRQHandler)
DEFAULT_IRQ_HANDLER(BLE_ACC_INT_IRQHandler)
DEFAULT_IRQ_HANDLER(GDMA_IRQHandler)

/*----------------------------------------------------------------------------
  Exception / Interrupt Vector table
 *----------------------------------------------------------------------------*/

#if defined ( __GNUC__ )
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#endif

extern const VECTOR_TABLE_Type __VECTOR_TABLE[];
       const VECTOR_TABLE_Type __VECTOR_TABLE[] __VECTOR_TABLE_ATTRIBUTE = {
  (VECTOR_TABLE_Type)(&__INITIAL_SP),            /* Initial Stack Pointer */
  Reset_Handler,                                 /* Reset Handler */
  NMI_Handler,                                   /* NMI Handler*/
  HardFault_Handler,                             /* Hard Fault Handler*/
  MemManage_Handler,                             /* MPU Fault Handler*/
  BusFault_Handler,                              /* Bus Fault Handler*/
  UsageFault_Handler,                            /* Usage Fault Handler*/
  SecureFault_Handler,                           /* Secure Fault Handler */
  0,                                             /* Reserved*/
  0,                                             /* Reserved*/
  0,                                             /* Reserved*/
  SVC_Handler,                                   /* SVCall Handler*/
  DebugMon_Handler,                              /* Debug Monitor Handler*/
  0,                                             /* Reserved*/
  PendSV_Handler,                                /* PendSV Handler*/
  SysTick_Handler,                               /* SysTick Handler*/


  /* External Interrupts */
  WDT0_IRQHandler,                                /* Windowed watchdog timer 0 (CM33 watchdog) */
  DMA0_IRQHandler,                                /* DMA controller 0 (secure or CM33 DMA) */
  GPIO_INTA_IRQHandler,                           /* GPIO interrupt A */
  GPIO_INTB_IRQHandler,                           /* GPIO interrupt B */
  PIN_INT0_IRQHandler,                            /* Pin interrupt 0 or pattern match engine slice 0 int */
  PIN_INT1_IRQHandler,                            /* Pin interrupt 1 or pattern match engine slice 1 int */
  PIN_INT2_IRQHandler,                            /* Pin interrupt 2 or pattern match engine slice 2 int */
  PIN_INT3_IRQHandler,                            /* Pin interrupt 3 or pattern match engine slice 3 int */
  UTICK_IRQHandler,                               /* Micro-tick Timer */
  MRT0_IRQHandler,                                /* Multi-Rate Timer. Global MRT interrupts */
  CTIMER0_IRQHandler,                             /* Standard counter/timer CTIMER0 */
  CTIMER1_IRQHandler,                             /* Standard counter/timer CTIMER1 */
  SCT0_IRQHandler,                                /* SCTimer/PWM */
  CTIMER3_IRQHandler,                             /* Standard counter/timer CTIMER3 */
  FLEXCOMM0_IRQHandler,                           /* Flexcomm Interface 0 (USART, SPI, I2C, I2S) */
  FLEXCOMM1_IRQHandler,                           /* Flexcomm Interface 1 (USART, SPI, I2C, I2S) */
  FLEXCOMM2_IRQHandler,                           /* Flexcomm Interface 2 (USART, SPI, I2C, I2S) */
  FLEXCOMM3_IRQHandler,                           /* Flexcomm Interface 3 (USART, SPI, I2C, I2S) */
  Reserved34_IRQHandler,                          /* xxx Interrupt 34 */
  Reserved35_IRQHandler,                          /* xxx Interrupt 35 */
  FLEXCOMM14_IRQHandler,                          /* Flexcomm Interface 14 (USART, SPI, I2C, I2S) */
  Reserved37_IRQHandler,                          /* xxx Interrupt 37 */
  Reserved38_IRQHandler,                          /* xxx Interrupt 38 */
  MRT1_IRQHandler,                                /* Free Multi-rate timer. Global MRT interrupts */
  Reserved40_IRQHandler,                          /* xxx Interrupt 40 */
  DMIC0_IRQHandler,                               /* Digital microphone and DMIC subsystem */
  WFD_IRQHandler,                                 /* Wakeup From Deepsleep */
  HYPERVISOR_IRQHandler,                          /* Hypervisor service software interrupt */
  SECUREVIOLATION_IRQHandler,                     /* Secure violation */
  HWVAD0_IRQHandler,                              /* Hardware Voice Activity Detector */
  Reserved46_IRQHandler,                          /* xxx Interrupt 46 */
  Reserved47_IRQHandler,                          /* xxx Interrupt 47 */
  RTC_IRQHandler,                                 /* RTC alarm and wake-up */
  Reserved49_IRQHandler,                          /* xxx Interrupt 49 */
  Reserved50_IRQHandler,                          /* xxx Interrupt 50 */
  PIN_INT4_IRQHandler,                            /* Pin interrupt 4 or pattern match engine slice 4 int */
  PIN_INT5_IRQHandler,                            /* Pin interrupt 5 or pattern match engine slice 5 int */
  PIN_INT6_IRQHandler,                            /* Pin interrupt 6 or pattern match engine slice 6 int */
  PIN_INT7_IRQHandler,                            /* Pin interrupt 7 or pattern match engine slice 7 int */
  CTIMER2_IRQHandler,                             /* Standard counter/timer CTIMER2 */
  CTIMER4_IRQHandler,                             /* Standard counter/timer CTIMER4 */
  OS_EVENT_IRQHandler,                            /* OS event timer */
  FLEXSPI_IRQHandler,                             /* FLEXSPI interface */
  Reserved59_IRQHandler,                          /* xxx Interrupt 59 */
  Reserved60_IRQHandler,                          /* xxx Interrupt 60 */
  Reserved61_IRQHandler,                          /* xxx Interrupt 61 */
  SDU_IRQHandler,                                 /* SDIO */
  SGPIO_INTA_IRQHandler,                          /* Secure GPIO interrupt A */
  SGPIO_INTB_IRQHandler,                          /* Secure GPIO interrupt B */
  Reserved65_IRQHandler,                          /* xxx Interrupt 65 */
  USB_IRQHandler,                                 /* High-speed USB device/host */
  Reserved67_IRQHandler,                          /* xxx Interrupt 67 */
  Reserved68_IRQHandler,                          /* xxx Interrupt 68 */
  Reserved69_IRQHandler,                          /* xxx Interrupt 69 */
  DMA1_IRQHandler,                                /* DMA controller 1 (non-secure or HiFi 4 DMA) */
  PUF_IRQHandler,                                 /* Physical Unclonable Function */
  POWERQUAD_IRQHandler,                           /* PowerQuad math coprocessor */
  Reserved73_IRQHandler,                          /* xxx Interrupt 73 */
  Reserved74_IRQHandler,                          /* xxx Interrupt 74 */
  Reserved75_IRQHandler,                          /* xxx Interrupt 75 */
  Reserved76_IRQHandler,                          /* xxx Interrupt 76 */
  LCDIC_IRQHandler,                               /* LCDIC */
  CAPT_PULSE_IRQHandler,                          /* Capture timer */
  Reserved79_IRQHandler,                          /* xxx Interrupt 79 */
  WL_MCI_WAKEUP_DONE0_IRQHandler,                 /* WL to MCI, Wakeup done 0 */
  WL_MCI_WAKEUP_DONE1_IRQHandler,                 /* WL to MCI, Wakeup done 1 */
  WL_MCI_WAKEUP_DONE2_IRQHandler,                 /* WL to MCI, Wakeup done 2 */
  WL_MCI_WAKEUP_DONE3_IRQHandler,                 /* WL to MCI, Wakeup done 3 */
  WL_MCI_WAKEUP_DONE4_IRQHandler,                 /* WL to MCI, Wakeup done 4 */
  WL_MCI_WAKEUP_DONE5_IRQHandler,                 /* WL to MCI, Wakeup done 5 */
  WL_MCI_WAKEUP_DONE6_IRQHandler,                 /* WL to MCI, Wakeup done 6 */
  WL_MCI_WAKEUP_DONE7_IRQHandler,                 /* WL to MCI, Wakeup done 7 */
  WL_MCI_WAKEUP0_IRQHandler,                      /* IMU_INT0: Cpu1_to_cpu3_msg_rdy_imu wl_mci_wakeup[0] */
  WL_MCI_WAKEUP1_IRQHandler,                      /* GP_INT from WL */
  WL_MCI_INT0_IRQHandler,                         /* IMU_INT: Imu13_cpu3_msg_space_avail */
  WL_MCI_INT1_IRQHandler,                         /* reserved */
  WL_MCI_INT2_IRQHandler,                         /* reserved */
  WL_MCI_INT3_IRQHandler,                         /* reserved */
  WL_MCI_INT4_IRQHandler,                         /* reserved */
  WL_MCI_INT5_IRQHandler,                         /* reserved */
  WL_MCI_INT6_IRQHandler,                         /* reserved */
  WL_MCI_INT7_IRQHandler,                         /* reserved */
  BLE_MCI_WAKEUP_DONE0_IRQHandler,                /* BLE to MCI, Wakeup done 0 */
  BLE_MCI_WAKEUP_DONE1_IRQHandler,                /* BLE to MCI, Wakeup done 1 */
  BLE_MCI_WAKEUP_DONE2_IRQHandler,                /* BLE to MCI, Wakeup done 2 */
  BLE_MCI_WAKEUP_DONE3_IRQHandler,                /* BLE to MCI, Wakeup done 3 */
  BLE_MCI_WAKEUP_DONE4_IRQHandler,                /* BLE to MCI, Wakeup done 4 */
  BLE_MCI_WAKEUP_DONE5_IRQHandler,                /* BLE to MCI, Wakeup done 5 */
  BLE_MCI_WAKEUP_DONE6_IRQHandler,                /* BLE to MCI, Wakeup done 6 */
  BLE_MCI_WAKEUP_DONE7_IRQHandler,                /* BLE to MCI, Wakeup done 7 */
  BLE_MCI_WAKEUP0_IRQHandler,                     /* IMU_INT0: Cpu2_to_cpu3_msg_rdy_imu wl_mci_wakeup[0] */
  BLE_MCI_WAKEUP1_IRQHandler,                     /* GP_INT from BLE */
  BLE_MCI_INT0_IRQHandler,                        /* IMU_INT: Imu13_cpu3_msg_space_avail */
  BLE_MCI_INT1_IRQHandler,                        /* reserved */
  BLE_MCI_INT2_IRQHandler,                        /* reserved */
  BLE_MCI_INT3_IRQHandler,                        /* reserved */
  BLE_MCI_INT4_IRQHandler,                        /* reserved */
  BLE_MCI_INT5_IRQHandler,                        /* reserved */
  BLE_MCI_INT6_IRQHandler,                        /* reserved */
  BLE_MCI_INT7_IRQHandler,                        /* reserved */
  PIN0_INT_IRQHandler,                            /* From AON GPIO */
  PIN1_INT_IRQHandler,                            /* From AON GPIO */
  CSS_IRQHandler,                                 /* CSS */
  CSS_GDET_IRQ_IRQHandler,                        /* CSS IRQ line for GDET error */
  CSS_GDET_ERR_IRQHandler,                        /* CSS Ungated latched error */
  PKC_IRQHandler,                                 /* PKC interrupt */
  PKC_ERR_IRQHandler,                             /* PKC error */
  CDOG_IRQHandler,                                /* Code watch dog timmer */
  GAU_GPDAC_INT_FUNC11_IRQHandler,                /* GAU */
  GAU_ACOMP_INT_WKUP11_IRQHandler,                /* GAU */
  GAU_ACOMP_INT_FUNC11_IRQHandler,                /* GAU */
  GAU_GPADC1_INT_FUNC11_IRQHandler,               /* GAU */
  GAU_GPADC0_INT_FUNC11_IRQHandler,               /* GAU */
  USIM_IRQHandler,                                /* USIM */
  OCOTP_IRQHandler,                               /* OTP */
  ENET_IRQHandler,                                /* ENET */
  ENET_TIMER_IRQHandler,                          /* ENET */
  BOD_1_85_INT_IRQHandler,                        /* PMIP */
  BOD_1_85_NEG_IRQHandler,                        /* Bod_1_85_int negedge */
  ITRC_IRQHandler,                                /* ITRC */
  BTU_HOST_TRIGGER0_IRQHandler,                   /* Btu host trigger0 */
  BTU_HOST_TRIGGER1_IRQHandler,                   /* Btu host trigger1 */
  BTU_HOST_TRIGGER2_IRQHandler,                   /* Btu host trigger2 */
  TRNG_IRQHandler,                                /* TRNG */
  AHB_MEM_ACC_CHECKER_VIO_INT_C_OR_IRQHandler,    /* ahb memory access checker - CM33 code bus */
  AHB_MEM_ACC_CHECKER_VIO_INT_S_OR_IRQHandler,    /* ahb memory access checker - CM33 sys bus */
  WL_ACC_INT_IRQHandler,                          /* Cpu access wlan when wlan is powered off */
  BLE_ACC_INT_IRQHandler,                         /* Cpu access wlan when ble is powered off */
  GDMA_IRQHandler,                                /* GDMA */
};

#if defined(__ICCARM__)
extern typeof(__vector_table) __attribute__ ((alias ("__vector_table"))) __Vectors;
#endif

#if defined ( __GNUC__ )
#pragma GCC diagnostic pop
#endif

/*----------------------------------------------------------------------------
  Reset Handler called on controller reset
 *----------------------------------------------------------------------------*/
void Reset_Handler(void)
{

#if defined (__ARM_FEATURE_CMSE) && (__ARM_FEATURE_CMSE == 3U)
    __disable_irq();
#endif
    __set_PSP((uint32_t)(&__INITIAL_SP));

    __set_MSPLIM((uint32_t)(&__STACK_LIMIT));
    __set_PSPLIM((uint32_t)(&__STACK_LIMIT));

#if defined (__ARM_FEATURE_CMSE) && (__ARM_FEATURE_CMSE == 3U)
    __TZ_set_STACKSEAL_S((uint32_t *)(&__STACK_SEAL));
#endif

    SystemInit();                             /* CMSIS System Initialization */
    __PROGRAM_START();                        /* Enter PreMain (C library entry point) */
}
