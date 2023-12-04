/*
 * Copyright 2023 NXP.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "fsl_common.h"
#include <stdint.h>
#include "fsl_trng.h"

int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen)
{
    status_t result = kStatus_Success;

    result = TRNG_GetRandomData(TRNG, output, len);

    if (result != kStatus_Success)
    {
        return result;
    }

    *olen = len;
    return 0;
}
