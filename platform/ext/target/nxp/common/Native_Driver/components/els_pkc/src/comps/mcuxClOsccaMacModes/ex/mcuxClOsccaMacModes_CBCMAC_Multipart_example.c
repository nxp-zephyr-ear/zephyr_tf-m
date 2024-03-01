/*--------------------------------------------------------------------------*/
/* Copyright 2022-2023 NXP                                                  */
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

#include <mcuxClMac.h> // Interface to the entire mcuxClMac component
#include <mcuxClOsccaMacModes.h> // Interface to the entire mcuxClOsccaMacModes component
#include <mcuxClSession.h> // Interface to the entire mcuxClSession component
#include <mcuxClKey.h> // Interface to the entire mcuxClKey component
#include <mcuxClOsccaSm4.h>
#include <mcuxCsslFlowProtection.h> // Code flow protection
#include <mcuxClOscca_FunctionIdentifiers.h>
#include <mcuxClToolchain.h> // memory segment definitions
#include <stdbool.h>  // bool type for the example's return code
#include <mcuxClExample_Session_Helper.h>
#include <mcuxClExample_ELS_Helper.h>
#include <mcuxClCore_Examples.h>

/**
 * @brief Cryptographic Keys
 */
static const uint8_t sm4CbcMacKey[] = { 0xC2, 0x0A, 0x2B, 0xBC, 0x2F, 0x40, 0x92, 0xC1,
                                        0x3F, 0xFF, 0x8E, 0xC6, 0x55, 0xB4, 0xC5, 0x72 };
/**
 * @brief Plaintext
 */
static const uint8_t sm4CbcMacPtxt[] = { 0x0D, 0x43, 0x46, 0x88, 0x01, 0x80, 0x84, 0x08,
                                         0x20, 0x52, 0x3B, 0x87, 0x2A, 0x9E, 0x2F, 0x30,
                                         0x79, 0xFD, 0xF8, 0x0B, 0x4C, 0xCC, 0x02, 0x7A,
                                         0x60, 0xC4, 0xB8, 0xC9, 0x42, 0x8B, 0x97, 0x7C };
/**
 * @brief Expected result
 */
static const uint8_t sm4CbcMacResult[] = { 0xF1, 0x33, 0x9F, 0x63, 0x93, 0x4E, 0x72, 0xE4,
                                           0xA7, 0x8F, 0x04, 0x7D, 0x9A, 0x9E, 0x7C, 0xCA };

bool mcuxClOsccaMacModes_CBCMAC_Multipart_example(void)
{
    /**************************************************************************/
    /* Preparation                                                            */
    /**************************************************************************/

    /* Initialize ELS, Enable the ELS */
    if(!mcuxClExample_Els_Init(MCUXCLELS_RESET_DO_NOT_CANCEL))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /* Initialize session */
    mcuxClSession_Descriptor_t sessionDesc;
    mcuxClSession_Handle_t session = &sessionDesc;
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session, MCUXCLOSCCAMACMODES_SM4_MAX_CPU_WA_BUFFER_SIZE, 0u);

    /* Initialize key */
    uint32_t keyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
    mcuxClKey_Handle_t key = (mcuxClKey_Handle_t) keyDesc;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result_ki, token_ki, mcuxClKey_init(
      /* mcuxClSession_Handle_t session         */ session,
      /* mcuxClKey_Handle_t key                 */ key,
      /* mcuxClKey_Type_t type                  */ mcuxClKey_Type_SM4,
      /* const uint8_t * pKeyData              */ sm4CbcMacKey,
      /* uint32_t keyDataLength                */ sizeof(sm4CbcMacKey)
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != token_ki) || (MCUXCLKEY_STATUS_OK != result_ki))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Create a buffer for the context */
    uint32_t ctxBuf[0x6D]; //MCUXCLOSCCAMACMODES_CTX_SIZE_IN_WORDS
    mcuxClMac_Context_t * const pCtx = (mcuxClMac_Context_t *) ctxBuf;

    /* Declare message buffer and size. */
    uint8_t cbcmacData[sizeof(sm4CbcMacResult)];
    uint32_t cbcmac_data_size = 0u;

    /**************************************************************************/
    /* Init                                                                   */
    /**************************************************************************/

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result_init, token_init, mcuxClMac_init(
    /* mcuxClSession_Handle_t session,          */ session,
    /* mcuxClMac_Context_t * const pContext,    */ pCtx,
    /* mcuxClKey_Handle_t key,                  */ key,
    /* mcuxClMac_Mode_t mode,                   */ mcuxClOsccaMac_Mode_CBCMAC_NoPadding
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMac_init) != token_init) || (MCUXCLMAC_STATUS_OK != result_init))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();


    /**************************************************************************/
    /* Process                                                                */
    /**************************************************************************/

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result_proc, token_proc, mcuxClMac_process(
    /* mcuxClSession_Handle_t session,         */ session,
    /* mcuxClCipher_Context_t * const pContext */ pCtx,
    /* const uint8_t * const pIn,             */ sm4CbcMacPtxt,
    /* uint32_t inLength,                     */ 5u
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMac_process) != token_proc) || (MCUXCLMAC_STATUS_OK != result_proc))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();


    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result_proc2, token_proc2, mcuxClMac_process(
    /* mcuxClSession_Handle_t session,         */ session,
    /* mcuxClCipher_Context_t * const pContext */ pCtx,
    /* const uint8_t * const pIn,             */ &sm4CbcMacPtxt[5u],
    /* uint32_t inLength,                     */ sizeof(sm4CbcMacPtxt) - 5u
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMac_process) != token_proc2) || (MCUXCLMAC_STATUS_OK != result_proc2))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /**************************************************************************/
    /* Finish                                                                 */
    /**************************************************************************/

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result_fin, token_fin, mcuxClMac_finish(
    /* mcuxClSession_Handle_t session,         */ session,
    /* mcuxClCipher_Context_t * const pContext */ pCtx,
    /* uint8_t * const pOut,                  */ cbcmacData,
    /* uint32_t * const pOutLength            */ &cbcmac_data_size
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClMac_finish) != token_fin) || (MCUXCLMAC_STATUS_OK != result_fin))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    // Expect that the resulting encrypted msg matches our expected initial message
    if (!mcuxClCore_assertEqual(cbcmacData, sm4CbcMacResult, cbcmac_data_size))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /**************************************************************************/
    /* Cleanup                                                                */
    /**************************************************************************/

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(cleanup_result, cleanup_token, mcuxClSession_cleanup(session));

    if(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_cleanup) != cleanup_token || MCUXCLSESSION_STATUS_OK != cleanup_result)
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(destroy_result, destroy_token, mcuxClSession_destroy(session));

    if(MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClSession_destroy) != destroy_token || MCUXCLSESSION_STATUS_OK != destroy_result)
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /* Disable the ELS */
    if(!mcuxClExample_Els_Disable())
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    return MCUXCLEXAMPLE_STATUS_OK;
}
