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

#include <mcuxClExample_Session_Helper.h>
#include <mcuxClExample_ELS_Helper.h>
#include <mcuxClSession.h> // Interface to the entire mcuxClSession component
#include <mcuxClKey.h> // Interface to the entire mcuxClKey component
#include <mcuxClAead.h> // Interface to the entire mcuxClAead component
#include <mcuxClOsccaAeadModes.h> // Interface to the entire mcuxClOsccaAeadModes component
#include <mcuxClOsccaSm4.h>
#include <mcuxCsslFlowProtection.h>
#include <mcuxClOscca_FunctionIdentifiers.h> // Code flow protection
#include <mcuxClToolchain.h> // memory segment definitions
#include <stdbool.h>  // bool type for the example's return code
#include <mcuxClCore_Examples.h>

/**
 * @brief Cryptographic Keys
 */
static const uint8_t sm4CcmKey[] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                                     0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 };
/**
 * @brief Plaintext
 */
static const uint8_t sm4CcmPtxt[] = { 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                                      0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
                                      0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
                                      0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD,
                                      0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE,
                                      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                      0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE,
                                      0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA};

/**
 * @brief Cryptographic IV
 */
static const uint8_t sm4CcmIv[] = { 0x00, 0x00, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00,
                                    0x00, 0x00, 0xAB, 0xCD};

/**
 * @brief Cryptographic AAD
 */
static const uint8_t sm4CcmAad[] = { 0xFE, 0xED, 0xFA, 0xCE, 0xDE, 0xAD, 0xBE, 0xEF,
                                     0xFE, 0xED, 0xFA, 0xCE, 0xDE, 0xAD, 0xBE, 0xEF,
                                     0xAB, 0xAD, 0xDA, 0xD2};
/**
 * @brief Expected cipher
 */

static const uint8_t sm4CcmCipher[] = { 0x48, 0xAF, 0x93, 0x50, 0x1F, 0xA6, 0x2A, 0xDB,
                                        0xCD, 0x41, 0x4C, 0xCE, 0x60, 0x34, 0xD8, 0x95,
                                        0xDD, 0xA1, 0xBF, 0x8F, 0x13, 0x2F, 0x04, 0x20,
                                        0x98, 0x66, 0x15, 0x72, 0xE7, 0x48, 0x30, 0x94,
                                        0xFD, 0x12, 0xE5, 0x18, 0xCE, 0x06, 0x2C, 0x98,
                                        0xAC, 0xEE, 0x28, 0xD9, 0x5D, 0xF4, 0x41, 0x6B,
                                        0xED, 0x31, 0xA2, 0xF0, 0x44, 0x76, 0xC1, 0x8B,
                                        0xB4, 0x0C, 0x84, 0xA7, 0x4B, 0x97, 0xDC, 0x5B};

/**
 * @brief Expected tag
 */

static const uint8_t sm4CcmTag[] = { 0x16, 0x84, 0x2D, 0x4F, 0xA1, 0x86, 0xF5, 0x6A,
                                     0xB3, 0x32, 0x56, 0x97, 0x1F, 0xA1, 0x10, 0xF4};

bool mcuxClOsccaAeadModes_CCM_Crypt_Multipart_example(void)
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

    //Allocate and initialize session
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session, MCUXCLOSCCAAEADMODES_WA_MAX_SIZE, 0u);

    /* Initialize key */
    uint32_t keyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
    mcuxClKey_Handle_t key = (mcuxClKey_Handle_t) keyDesc;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result_ki, token_ki, mcuxClKey_init(
      /* mcuxClSession_Handle_t session         */ session,
      /* mcuxClKey_Handle_t key                 */ key,
      /* mcuxClKey_Type_t type                  */ mcuxClKey_Type_SM4,
      /* const uint8_t * pKeyData              */ sm4CcmKey,
      /* uint32_t keyDataLength                */ sizeof(sm4CcmKey)
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_init) != token_ki) || (MCUXCLKEY_STATUS_OK != result_ki))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /**************************************************************************/
    /* Encryption                                                             */
    /**************************************************************************/

    uint8_t msg_enc[sizeof(sm4CcmCipher)] = {0u};
    uint32_t msg_enc_size = 0u;

    uint8_t msg_tag[sizeof(sm4CcmTag)];

    uint32_t ctxBufEnc[MCUXCLOSCCAAEADMODES_CTX_SIZE_IN_WORDS];
    mcuxClAead_Context_t * ctxEnc = (mcuxClAead_Context_t *) ctxBufEnc;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result_init, token_init, mcuxClAead_init(
    /* mcuxClSession_Handle_t session, */ session,
    /* mcuxClAead_Context_t pContext,  */ ctxEnc,
    /* mcuxClKey_Handle_t key,         */ key,
    /* mcuxClAead_Mode_t mode,         */ mcuxClOsccaAead_Mode_CCM_ENC,
    /* mcuxCl_InputBuffer_t pNonce,    */ sm4CcmIv,
    /* uint32_t nonceSize,            */ sizeof(sm4CcmIv),
    /* uint32_t inSize,               */ sizeof(sm4CcmPtxt),
    /* uint32_t adataSize,            */ sizeof(sm4CcmAad),
    /* uint32_t tagSize               */ sizeof(sm4CcmTag)
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAead_init) != token_init) || (MCUXCLAEAD_STATUS_OK != result_init))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

  /*
   * mcuxClAead_process_adata() processes the header data. This needs to be completed
   * before other data can be processed. Therefore all calls to mcuxClAead_process_adata()
   * need to be made before calls to mcuxClAead_process().
   */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result_aad, token_aad, mcuxClAead_process_adata(
    /* mcuxClSession_Handle_t session, */ session,
    /* mcuxClAead_Context_t pContext,  */ ctxEnc,
    /* mcuxCl_InputBuffer_t pAdata,    */ sm4CcmAad,
    /* uint32_t adataSize,            */ sizeof(sm4CcmAad)
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAead_process_adata) != token_aad) || (MCUXCLAEAD_STATUS_OK != result_aad))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result_indata, token_indata, mcuxClAead_process(
    /* mcuxClSession_Handle_t session, */ session,
    /* mcuxClAead_Context_t pContext,  */ ctxEnc,
    /* mcuxCl_InputBuffer_t pIn,       */ sm4CcmPtxt,
    /* uint32_t inSize,               */ sizeof(sm4CcmPtxt),
    /* mcuxCl_Buffer_t pOut,           */ msg_enc,
    /* uint32_t * const pOutSize      */ &msg_enc_size
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAead_process) != token_indata) || (MCUXCLAEAD_STATUS_OK != result_indata))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result_final, token_final, mcuxClAead_finish(
    /* mcuxClSession_Handle_t session, */ session,
    /* mcuxClAead_Context_t pContext,  */ ctxEnc,
    /* mcuxCl_Buffer_t pOut,           */ &msg_enc[msg_enc_size],
    /* uint32_t * const pOutSize      */ &msg_enc_size,
    /* mcuxCl_Buffer_t pTag,           */ msg_tag
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAead_finish) != token_final) || (MCUXCLAEAD_STATUS_OK != result_final))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    // Expect that the resulting encrypted msg matches our expected output
    if (!mcuxClCore_assertEqual(msg_enc, sm4CcmCipher, sizeof(msg_enc)))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    // TODO: change to MCUXCLELS_AEAD_TAG_SIZE
    // Expect that the resulting authentication tag matches our expected output
    if (!mcuxClCore_assertEqual(msg_tag, sm4CcmTag, sizeof(sm4CcmTag)))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /**************************************************************************/
    /* Decryption                                                             */
    /**************************************************************************/

    uint8_t msg_dec[sizeof(sm4CcmPtxt)] = {0u};
    uint32_t msg_dec_size = 0u;

    uint32_t ctxBufDec[32u]; //MCUXCLOSCCAAEADMODES_CTX_SIZE_IN_WORDS
    mcuxClAead_Context_t * ctxDec = (mcuxClAead_Context_t *) ctxBufDec;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result_init2, token_init2, mcuxClAead_init(
    /* mcuxClSession_Handle_t session, */ session,
    /* mcuxClAead_Context_t pContext,  */ ctxDec,
    /* mcuxClKey_Handle_t key,         */ key,
    /* mcuxClAead_Mode_t mode,         */ mcuxClOsccaAead_Mode_CCM_DEC,
    /* mcuxCl_InputBuffer_t pNonce,    */ sm4CcmIv,
    /* uint32_t nonceSize,            */ sizeof(sm4CcmIv),
    /* uint32_t inSize,               */ sizeof(sm4CcmPtxt),
    /* uint32_t adataSize,            */ sizeof(sm4CcmAad),
    /* uint32_t tagSize               */ sizeof(sm4CcmTag)
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAead_init) != token_init2) || (MCUXCLAEAD_STATUS_OK != result_init2))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

  /*
   * mcuxClAead_process_adata() processes the header data. This needs to be completed
   * before other data can be processed. Therefore all calls to mcuxClAead_process_adata()
   * need to be made before calls to mcuxClAead_process().
   */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result_aad2, token_aad2, mcuxClAead_process_adata(
    /* mcuxClSession_Handle_t session, */ session,
    /* mcuxClAead_Context_t pContext,  */ ctxDec,
    /* mcuxCl_InputBuffer_t pAdata,    */ sm4CcmAad,
    /* uint32_t adataSize,            */ sizeof(sm4CcmAad)
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAead_process_adata) != token_aad2) || (MCUXCLAEAD_STATUS_OK != result_aad2))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result_indata2, token_indata2, mcuxClAead_process(
    /* mcuxClSession_Handle_t session, */ session,
    /* mcuxClAead_Context_t pContext,  */ ctxDec,
    /* mcuxCl_InputBuffer_t pIn,       */ msg_enc,
    /* uint32_t inSize,               */ msg_enc_size,
    /* mcuxCl_Buffer_t pOut,           */ msg_dec,
    /* uint32_t * const pOutSize      */ &msg_dec_size
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAead_process) != token_indata2) || (MCUXCLAEAD_STATUS_OK != result_indata2))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result_verify2, token_verify2, mcuxClAead_verify(
    /* mcuxClSession_Handle_t session, */ session,
    /* mcuxClAead_Context_t pContext,  */ ctxDec,
    /* mcuxCl_Buffer_t pTag,           */ msg_tag,
    /* mcuxCl_Buffer_t pOut,           */ &msg_dec[msg_dec_size],
    /* uint32_t * const pOutSize      */ &msg_dec_size
    ));
    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClAead_verify) != token_verify2) || (MCUXCLAEAD_STATUS_OK != result_verify2))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /**************************************************************************/
    /* Cleanup                                                                */
    /**************************************************************************/

    /** Destroy Session and cleanup Session **/
    if(!mcuxClExample_Session_Clean(session))
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
