/*
 * Copyright (c) 2018-2021, Arm Limited. All rights reserved.
 * Copyright 2019-2020, 2022 NXP. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __TFM_PERIPHERALS_DEF_H__
#define __TFM_PERIPHERALS_DEF_H__

#include "fsl_clock.h"

#ifdef __cplusplus
extern "C" {
#endif
  
/*
 * Quantized default IRQ priority, the value is:
 * (Number of configurable priority) / 4: (1UL << __NVIC_PRIO_BITS) / 4
 */
#define DEFAULT_IRQ_PRIORITY    (1UL << (__NVIC_PRIO_BITS - 2))
  
#define CTIMER                  (CTIMER2)                       /* Timer 2 */
#define CTIMER_CLK_FREQ         (CLOCK_GetCTimerClkFreq(2U))
#define CTIMER_CLK_ATTACH       (kSFRO_to_CTIMER2)              /* Use 16 MHz clock */
#define CTIMER_IRQ_HANDLER      (CTIMER2_IRQHandler)
#define TFM_TIMER0_IRQ          (CTIMER2_IRQn)                  /* (tfm_core_irq_signal_data_t->irq_line) */

#define CTIMER_NS               (CTIMER3)                       /* Timer 3 */
#define CTIMER_NS_CLK_FREQ      (CLOCK_GetCTimerClkFreq(3U))
#define CTIMER_NS_CLK_ATTACH    (kSFRO_to_CTIMER3)              /* Use 16 MHz clock */
#define CTIMER_NS_IRQ_HANDLER   (CTIMER3_IRQHandler)
#define TFM_TIMER1_IRQ          (CTIMER3_IRQn)                  /* use by tfm_core_test_irq() */

struct platform_data_t;

extern struct platform_data_t tfm_peripheral_std_uart;
extern struct platform_data_t tfm_peripheral_timer0;

#define TFM_PERIPHERAL_STD_UART     (&tfm_peripheral_std_uart)
#define TFM_PERIPHERAL_TIMER0       (&tfm_peripheral_timer0)

#ifdef __cplusplus
}
#endif

#endif /* __TFM_PERIPHERALS_DEF_H__ */