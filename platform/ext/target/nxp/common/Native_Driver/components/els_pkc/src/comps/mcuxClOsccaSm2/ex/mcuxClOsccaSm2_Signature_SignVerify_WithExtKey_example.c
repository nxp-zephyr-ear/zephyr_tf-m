/*--------------------------------------------------------------------------*/
/* Copyright 2023-2024 NXP                                                  */
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
 * @file:   mcuxClOsccaSm2_Signature_SignVerify_WithExtKey_example.c
 * @brief:  Example OSCCA SM2 signature, including signature generation and signature
 *          verification with extend key
 */

/******************************************************************************
 * Includes
 ******************************************************************************/
#include <mcuxClSession.h>
#include <mcuxClRandom.h>
#include <mcuxClKey.h>
#include <mcuxClOsccaSm2.h>
#include <mcuxClOsccaSm3.h>
#include <mcuxClSignature.h>
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
 * Defines
 ******************************************************************************/
/**
 * @brief Maximum of the CPU workarea
 */
#define SIZE_WA_CPU  MCUXCLCORE_MAX(\
    MCUXCLOSCCASM2_SIGN_SIZEOF_WA_CPU(MCUXCLOSCCASM2_SM2P256_SIZE_BASEPOINTORDER), \
    MCUXCLOSCCASM2_VERIFY_SIZEOF_WA_CPU)
/**
 * @def SIZE_WA_PKC
 * @brief Maximum of the pkc workarea
 */
#define SIZE_WA_PKC  MCUXCLCORE_MAX(\
    MCUXCLOSCCASM2_SIGN_SIZEOF_WA_PKC_256(),   \
    MCUXCLOSCCASM2_VERIFY_SIZEOF_WA_PKC_256())

/******************************************************************************
 * External variables
 ******************************************************************************/
/* none */

/**
 * @def pMessage Digest
 */
static const uint8_t pDigest[MCUXCLOSCCASM3_OUTPUT_SIZE_SM3] =
{
    //B524F552 CD82B8B0 28476E00 5C377FB1 9A87E6FC 682D48BB 5D42E3D9 B9EFFE76
    0xB5u, 0x24u, 0xF5u, 0x52u, 0xCDu, 0x82u, 0xB8u, 0xB0u,
    0x28u, 0x47u, 0x6Eu, 0x00u, 0x5Cu, 0x37u, 0x7Fu, 0xB1u,
    0x9Au, 0x87u, 0xE6u, 0xFCu, 0x68u, 0x2Du, 0x48u, 0xBBu,
    0x5Du, 0x42u, 0xE3u, 0xD9u, 0xB9u, 0xEFu, 0xFEu, 0x76u
};

/******************************************************************************
 * Local variables
 ******************************************************************************/
/* none */

/******************************************************************************
 * Local and global function declarations
 ******************************************************************************/
/**
 * @brief:  Example OSCCA SM2 signature, including
 *          signature generation and signature verification
 *
 * @return
 *    - true if selected algorithm processed successfully
 *    - false if selected algorithm caused an error
 *
 * @pre
 *  none
 *
 * @post
 *   the mcuxClOsccaSm2_Signature_SignVerify_WithExtKey_example function will be triggered
 *
 * @note
 *   none
 *
 * @warning
 *   none
 */
bool mcuxClOsccaSm2_Signature_SignVerify_WithExtKey_example(void)
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
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(&session, SIZE_WA_CPU, SIZE_WA_PKC);
    /* Initialize the RNG context */
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
    /* Preparation: setup SM2 key                                   */
    /****************************************************************/
    /* Initialize SM2 private key */
    uint32_t privKeyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
    mcuxClKey_Handle_t privKey = (mcuxClKey_Handle_t) &privKeyDesc;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ki_priv_result, ki_priv_token, mcuxClKey_init(
      /* mcuxClSession_Handle_t session         */ &session,
      /* mcuxClKey_Handle_t key                 */ privKey,
      /* mcuxClKey_Type_t type                  */ mcuxClKey_Type_SM2P256_Ext_Private,
      /* const uint8_t * pKeyData              */ privateKey,
      /* uint32_t keyDataLength                */ sizeof(privateKey)
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != ki_priv_token) || (MCUXCLKEY_STATUS_OK != ki_priv_result))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Initialize SM2 public key */
    uint32_t pubKeyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
    mcuxClKey_Handle_t pubKey = (mcuxClKey_Handle_t) &pubKeyDesc;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ki_pub_result, ki_pub_token, mcuxClKey_init(
      /* mcuxClSession_Handle_t session         */ &session,
      /* mcuxClKey_Handle_t key                 */ pubKey,
      /* mcuxClKey_Type_t type                  */ mcuxClKey_Type_SM2P256_Ext_Public,
      /* const uint8_t * pKeyData              */ publicKey,
      /* uint32_t keyDataLength                */ sizeof(publicKey)
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != ki_pub_token) || (MCUXCLKEY_STATUS_OK != ki_pub_result))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /****************************************************************/
    /* OSCCA SM2 signature generation                               */
    /****************************************************************/
    uint8_t signature[MCUXCLOSCCASM2_SM2P256_SIZE_SIGNATURE];
    uint32_t signatureSize = 0;
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(ss_result, ss_token, mcuxClSignature_sign(
      /* mcuxClSession_Handle_t session:   */ &session,
      /* mcuxClKey_Handle_t key:           */ privKey,
      /* mcuxClSignature_Mode_t mode:      */ mcuxClSignature_Mode_SM2,
      /* mcuxCl_InputBuffer_t pIn:         */ pDigest,
      /* uint32_t inSize:                 */ sizeof(pDigest),
      /* mcuxCl_Buffer_t pSignature:       */ signature,
      /* uint32_t * const pSignatureSize: */ &signatureSize
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSignature_sign) != ss_token) || (MCUXCLSIGNATURE_STATUS_OK != ss_result))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /****************************************************************/
    /* OSCCA SM2 signature verification                             */
    /****************************************************************/
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(sv_result, sv_token, mcuxClSignature_verify(
      /* mcuxClSession_Handle_t session:  */ &session,
      /* mcuxClKey_Handle_t key:          */ pubKey,
      /* mcuxClSignature_Mode_t mode:     */ mcuxClSignature_Mode_SM2,
      /* mcuxCl_InputBuffer_t pIn:        */ pDigest,
      /* uint32_t inSize:                */ sizeof(pDigest),
      /* mcuxCl_InputBuffer_t pSignature: */ signature,
      /* uint32_t signatureSize:         */ signatureSize
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSignature_verify) != sv_token) || (MCUXCLSIGNATURE_STATUS_OK != sv_result))
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
