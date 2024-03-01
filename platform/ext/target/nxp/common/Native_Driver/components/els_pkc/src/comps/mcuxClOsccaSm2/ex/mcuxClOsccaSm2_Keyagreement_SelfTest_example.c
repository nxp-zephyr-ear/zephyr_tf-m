/*--------------------------------------------------------------------------*/
/* Copyright 2023 NXP                                                       */
/*                                                                          */
/* NXP Confidential. This software is owned or controlled by NXP and may    */
/* only be used strictly in accordance with the applicable license terms.   */
/* By expressly accepting such terms or by downloading, installing,         */
/* activating and/or otherwise using the software, you are agreeing that    */
/* you have read, and that you agree to comply with and are bound by, such  */
/* license terms. If you do not agree to be bound by the applicable license */
/* terms, then you may not retain, install, activate or otherwise use the   */
/* software.                                                                */
/*--------------------------------------------------------------------------*/

/**
 * @file:   mcuxClOsccaSm2_Keyagreement_SelfTest_example.c
 * @brief:  Example OSCCA SM2 key agreement selftest
 */

/******************************************************************************
 * Includes
 ******************************************************************************/
#include <mcuxClSession.h>
#include <mcuxClRandom.h>
#include <mcuxClKey.h>
#include <mcuxClOsccaSm2.h>
#include <mcuxClOsccaSm2_CommonParams.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClOscca_FunctionIdentifiers.h>
#include <mcuxClExample_Session_Helper.h>
#include <mcuxClExample_ELS_Helper.h>
#include <mcuxClCore_Examples.h>
#if MCUXCL_FEATURE_RANDOMMODES_OSCCA_TRNG == 1
#include <mcuxClOsccaRandomModes.h>
#else
#include <mcuxClRandomModes.h>
#include <mcuxClMemory.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#endif

/******************************************************************************
 * External variables
 ******************************************************************************/
/* none */

/******************************************************************************
 * Local variables
 ******************************************************************************/
/* none */

/******************************************************************************
 * Local and global function declarations
 ******************************************************************************/
/**
 * @brief:  Example OSCCA SM2 key agreement selftest
 *
 * @return
 *    - true if selected algorithm processed successfully
 *    - false if selected algorithm caused an error
 *
 * @pre
 *  none
 *
 * @post
 *   the mcuxClOsccaSm2_Keyagreement_SelfTest_example function will be triggered
 *
 * @note
 *   none
 *
 * @warning
 *   none
 */
bool mcuxClOsccaSm2_Keyagreement_SelfTest_example(void)
{
    /**************************************************************************/
    /* Preparation: RNG initialization, CPU and PKC workarea allocation       */
    /**************************************************************************/

    /* Initialize ELS, Enable the ELS */
    if(!mcuxClExample_Els_Init(MCUXCLELS_RESET_DO_NOT_CANCEL))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /* Setup one session to be used by all functions called */
    mcuxClSession_Descriptor_t session;
    /* Allocate and initialize session with pkcWA on the beginning of PKC RAM */
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(&session, MCUXCLOSCCASM2_KEYAGREEMENT_SELFTEST_SIZEOF_WA_CPU,
                        MCUXCLOSCCASM2_KEYAGREEMENT_SELFTEST_SIZEOF_WA_PKC);

#if MCUXCL_FEATURE_RANDOMMODES_OSCCA_TRNG == 1
    /* Initialize the RNG context */
    /* We need a context for OSCCA Rng. */
    uint32_t rngCtx[MCUXCLOSCCARANDOMMODES_OSCCARNG_CONTEXT_SIZE_IN_WORDS];
    mcuxClRandom_Context_t pRngCtx = (mcuxClRandom_Context_t)rngCtx;
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(randomInit_result, randomInit_token, mcuxClRandom_init(&session,
                                                               pRngCtx,
                                                               mcuxClOsccaRandomModes_Mode_TRNG));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_init) != randomInit_token) || (MCUXCLRANDOM_STATUS_OK != randomInit_result))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
#else
    /* Fill mode descriptor with the relevant data */
    uint32_t customModeDescBytes[(MCUXCLRANDOMMODES_PATCHMODE_DESCRIPTOR_SIZE + sizeof(uint32_t) - 1U)/sizeof(uint32_t)];
    mcuxClRandom_ModeDescriptor_t *mcuxClRandomModes_Mode_Custom = (mcuxClRandom_ModeDescriptor_t *) customModeDescBytes;

    /**************************************************************************/
    /* RANDOM Patch Mode creation                                             */
    /**************************************************************************/
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(randomPatch_result, randomPatch_token, mcuxClRandomModes_createPatchMode(mcuxClRandomModes_Mode_Custom,
                                        (mcuxClRandomModes_CustomGenerateAlgorithm_t)RNG_Patch_function,
                                        NULL,
                                        256U));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandomModes_createPatchMode) != randomPatch_token) || (MCUXCLRANDOM_STATUS_OK != randomPatch_result))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
    /**************************************************************************/
    /* patch mode initialization                                              */
    /**************************************************************************/
    uint32_t* rngContextPatched = NULL;
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(randomInit_result, randomInit_token, mcuxClRandom_init(&session, (mcuxClRandom_Context_t)rngContextPatched, mcuxClRandomModes_Mode_Custom));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_init) != randomInit_token) || (MCUXCLRANDOM_STATUS_OK != randomInit_result))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
#endif

    /* Initialize the PRNG */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(prngInit_result, prngInit_token, mcuxClRandom_ncInit(&session));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClRandom_ncInit) != prngInit_token) || (MCUXCLRANDOM_STATUS_OK != prngInit_result))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /****************************************************************/
    /* OSCCA SM2 key exchange selftest                              */
    /****************************************************************/
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(keyTestRet, keyTestToken, mcuxClKey_agreement_selftest(
      /* mcuxClSession_Handle_t session:   */ &session,
      /* mcuxClKey_Agreement_t agreement:  */ mcuxClOsccaSm2_Agreement_Initiator,
      /* mcuxClKey_Test_t test:            */ mcuxClKey_Test_SM2_Agreement
    ));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_agreement_selftest) != keyTestToken) || (MCUXCLKEY_STATUS_OK != keyTestRet))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /** Destroy Session and cleanup Session **/
    if(!mcuxClExample_Session_Clean(&session))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /* Disable the ELS */
    if(!mcuxClExample_Els_Disable())
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    return MCUXCLEXAMPLE_STATUS_OK;
}
