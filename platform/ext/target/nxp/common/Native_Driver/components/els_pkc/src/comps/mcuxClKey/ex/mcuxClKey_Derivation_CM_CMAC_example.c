/*--------------------------------------------------------------------------*/
/* Copyright 2022-2024 NXP                                                  */
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
 * @file  mcuxClKey_Derivation_CM_CMAC_example.c
 * @brief Example for the mcuxClKey component, showing a KDF according to the
 *        NIST SP108-800 Standard in Counter Mode using CMAC (AES256)
 */

#include <mcuxClKey.h>
#include <mcuxClMac.h>
#include <mcuxClMacModes.h>
#include <mcuxClCore_Examples.h>
#include <mcuxClSession.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection
#include <stdbool.h>  // bool type for the example's return code
#include <mcuxClAes.h>
#include <mcuxClExample_Session_Helper.h>
#include <mcuxClExample_RNG_Helper.h>
#include <mcuxClEls.h>
#include <mcuxClExample_ELS_Helper.h>
#include <mcuxClExample_Key_Helper.h>

/* Example AES-256 key. */
static const uint8_t inputKey[MCUXCLAES_AES256_KEY_SIZE] = {
    0x54u, 0x02u, 0xc9u, 0x78u, 0x95u, 0x51u, 0x28u, 0x55u,
    0x87u, 0x89u, 0xbeu, 0xe7u, 0xb5u, 0x71u, 0x46u, 0x51u,
    0x74u, 0xa6u, 0x05u, 0x82u, 0xa7u, 0x64u, 0x00u, 0x37u,
    0x38u, 0x7fu, 0x99u, 0xacu, 0x16u, 0x68u, 0x31u, 0x73u
};

static const uint8_t label[8] = { 0x25u, 0x5au, 0x53u, 0x35u, 0xcau, 0xc9u, 0x18u, 0x5bu };
static const uint8_t context[8] = { 0xb6u, 0x9du, 0xecu, 0xa7u, 0x35u, 0xb2u, 0x37u, 0x67u };

/* CMAC(inputKey, "01255a5335cac9185b00b69deca735b2376700000100") || CMAC(inputKey, "02255a5335cac9185b00b69deca735b2376700000100") */
static const uint8_t expectedDerivedKey[MCUXCLAES_AES256_KEY_SIZE] = {
    0x77u, 0x7cu, 0x89u, 0x27u, 0xd8u, 0x26u, 0x4du, 0xfau,
    0x48u, 0xd4u, 0x02u, 0x27u, 0xd7u, 0x7bu, 0x31u, 0x05u,
    0x48u, 0x24u, 0xb3u, 0xf0u, 0x1au, 0x63u, 0x4eu, 0x0fu,
    0x7eu, 0xf9u, 0xbfu, 0x74u, 0xe5u, 0x2du, 0xb6u, 0x37u
};

/** Performs an example key derivation using the mcuxClKey component.
 * @retval MCUXCLEXAMPLE_STATUS_OK    The example code completed successfully
 * @retval MCUXCLEXAMPLE_STATUS_ERROR The example code failed */
MCUXCLEXAMPLE_FUNCTION(mcuxClKey_Derivation_CM_CMAC_example)
{
    /**************************************************************************/
    /* Preparation                                                            */
    /**************************************************************************/
    /** Initialize ELS, Enable the ELS **/
    if(!mcuxClExample_Els_Init(MCUXCLELS_RESET_DO_NOT_CANCEL))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /* Initialize session */
    mcuxClSession_Descriptor_t sessionDesc;
    mcuxClSession_Handle_t session = &sessionDesc;

    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session, MCUXCLEXAMPLE_MAX_WA(MCUXCLKEY_DERIVATION_CPU_WA_SIZE, MCUXCLRANDOMMODES_NCINIT_WACPU_SIZE), 0u);
    /* Initialize the PRNG */
    MCUXCLEXAMPLE_INITIALIZE_PRNG(session);

    /**************************************************************************/
    /* Key setup                                                              */
    /**************************************************************************/

    /* Create and initialize key descriptor structure. */
    uint32_t keyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
    mcuxClKey_Handle_t key = (mcuxClKey_Handle_t) &keyDesc;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(resultKeyInit1, tokenKeyInit1, mcuxClKey_init(
      /* mcuxClSession_Handle_t session         */ session,
      /* mcuxClKey_Handle_t key                 */ key,
      /* mcuxClKey_Type_t type                  */ mcuxClKey_Type_Aes256,
      /* uint8_t * pKeyData                    */ (uint8_t *) inputKey,
      /* uint32_t keyDataLength                */ sizeof(inputKey)
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != tokenKeyInit1) || (MCUXCLKEY_STATUS_OK != resultKeyInit1))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Key buffer for the key in memory. */
    uint32_t key_buffer[MCUXCLAES_AES256_KEY_SIZE_IN_WORDS];

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(resultKeyLoad, tokenKeyLoad, mcuxClKey_loadMemory(
      /* mcuxClSession_Handle_t session         */ session,
      /* mcuxClKey_Handle_t key                 */ key,
      /* mcuxCl_Buffer_t pKeyData               */ key_buffer
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_loadMemory) != tokenKeyLoad) || (MCUXCLKEY_STATUS_OK != resultKeyLoad))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();


    /**************************************************************************/
    /* Key Derivation                                                         */
    /**************************************************************************/

    /* Set up input parameter structures. */
    MCUXCLBUFFER_INIT_RO(labelBuf, session, label, sizeof(label));
    MCUXCLBUFFER_INIT_RO(contextBuf, session, context, sizeof(context));
    struct mcuxClKey_DerivationInput inputLabel = {.input=labelBuf, .size=sizeof(label)};
    struct mcuxClKey_DerivationInput inputContext = {.input=contextBuf, .size=sizeof(context)};


    mcuxClKey_DerivationInput_t inputs[] = {inputLabel, inputContext};

    /* Set up output structure. */
    uint8_t derivedKeyBuf[MCUXCLAES_AES256_KEY_SIZE];

    /* Create and initialize derivedKey descriptor structure. */
    uint32_t derivedKeyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
    mcuxClKey_Handle_t derivedKey = (mcuxClKey_Handle_t) &derivedKeyDesc;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(resultKeyInit2, tokenKeyInit2, mcuxClKey_init(
      /* mcuxClSession_Handle_t session         */ session,
      /* mcuxClKey_Handle_t key                 */ derivedKey,
      /* mcuxClKey_Type_t type                  */ mcuxClKey_Type_Aes256,
      /* uint8_t * pKeyData                    */ derivedKeyBuf,
      /* uint32_t keyDataLength                */ sizeof(derivedKeyBuf)
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != tokenKeyInit2) || (MCUXCLKEY_STATUS_OK != resultKeyInit2))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Call key derivation function. */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(resultDeriv, tokenDeriv, mcuxClKey_derivation(
      /* mcuxClSession_Handle_t pSession         */ session,
      /* mcuxClKey_Derivation_t derivationMode   */ mcuxClKey_Derivation_SP800_108_CM_CMAC,
      /* mcuxClKey_Handle_t derivationKey        */ key,
      /* mcuxClKey_DerivationInput_t inputs[]    */ inputs,
      /* uint32_t numberOfInputs                */ 2u,
      /* mcuxClKey_Handle_t derivedKey           */ derivedKey
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_derivation) != tokenDeriv) || (MCUXCLKEY_STATUS_OK != resultDeriv))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();


    /**************************************************************************/
    /* The derivedKey could now be used for a cryptographic operation.        */
    /**************************************************************************/


    /**************************************************************************/
    /* Verification                                                           */
    /**************************************************************************/

    /* Compare the derived key to the reference value. */
    if(!mcuxClCore_assertEqual(derivedKeyBuf, expectedDerivedKey, sizeof(expectedDerivedKey)))
    {
        return MCUXCLEXAMPLE_STATUS_FAILURE;
    }

    /**************************************************************************/
    /* Cleanup                                                                */
    /**************************************************************************/

    /* Flush the key. */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(resultFlush, tokenFlush, mcuxClKey_flush(session, key));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_flush) != tokenFlush) || (MCUXCLKEY_STATUS_OK != resultFlush))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /** Destroy Session and cleanup Session **/
    if(!mcuxClExample_Session_Clean(session))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    if(!mcuxClExample_Els_Disable())
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    return MCUXCLEXAMPLE_STATUS_OK;
}
