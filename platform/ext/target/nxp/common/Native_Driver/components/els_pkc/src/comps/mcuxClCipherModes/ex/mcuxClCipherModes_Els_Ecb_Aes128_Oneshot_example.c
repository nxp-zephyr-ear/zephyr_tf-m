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

#include <mcuxClToolchain.h>
#include <mcuxClCore_Examples.h> // Defines and assertions for examples
#include <mcuxClExample_ELS_Helper.h>
#include <mcuxClExample_Session_Helper.h>
#include <mcuxClExample_Key_Helper.h>
#include <mcuxClEls.h> // Interface to the entire mcuxClEls component
#include <mcuxClSession.h> // Interface to the entire mcuxClSession component
#include <mcuxClKey.h> // Interface to the entire mcuxClKey component
#include <mcuxCsslFlowProtection.h>
#include <mcuxClCore_FunctionIdentifiers.h> // Code flow protection
#include <mcuxClToolchain.h> // memory segment definitions
#include <mcuxClAes.h> // Interface to AES-related definitions and types
#include <mcuxClCipher.h> // Interface to the entire mcuxClCipher component
#include <mcuxClCipherModes.h> // Interface to the entire mcuxClCipherModes component
#include <mcuxClExample_RNG_Helper.h>

/** Key for the AES encryption. */
static ALIGNED uint8_t aes128_key[MCUXCLAES_BLOCK_SIZE] = {
    0x2Bu, 0x7Eu, 0x15u, 0x16u,
    0x28u, 0xAEu, 0xD2u, 0xA6u,
    0xABu, 0xF7u, 0x15u, 0x88u,
    0x09u, 0xCFu, 0x4Fu, 0x3Cu
};

/** Plaintext input for the AES encryption. */
static ALIGNED uint8_t const msg_plain[3u * MCUXCLAES_BLOCK_SIZE] = {
    0xC8u, 0xC6u, 0x6Au, 0xB4u, 0x25u, 0x81u, 0x91u, 0xFDu,
    0x2Eu, 0x5Cu, 0x24u, 0x1Eu, 0xA8u, 0xCBu, 0x73u, 0xF7u,
    0x74u, 0x24u, 0xEAu, 0xD8u, 0x77u, 0x59u, 0x75u, 0x73u,
    0x17u, 0xC3u, 0x4Eu, 0x6Bu, 0xD5u, 0x8Du, 0xF8u, 0xDFu,
    0xA2u, 0x3Fu, 0xCFu, 0x2Au, 0x16u, 0xBEu, 0x30u, 0x55u,
    0x6Fu, 0xA8u, 0xF8u, 0xC6u, 0x6Eu, 0x47u, 0x2Bu, 0xE4u
};

/** Expected ciphertext output of the AES encryption. */
static ALIGNED uint8_t const msg_enc_expected[3u * MCUXCLAES_BLOCK_SIZE] = {
    0x57u, 0xF5u, 0xD5u, 0xBEu, 0x68u, 0xFFu, 0xF9u, 0x06u,
    0xE8u, 0x61u, 0xF4u, 0x30u, 0x99u, 0x20u, 0x3Au, 0xFFu,
    0x3Du, 0x56u, 0xDBu, 0x42u, 0x07u, 0xB3u, 0xBBu, 0xBDu,
    0x66u, 0xE4u, 0xAFu, 0x0Au, 0x1Eu, 0xDBu, 0xB0u, 0x93u,
    0xA6u, 0x9Bu, 0xC1u, 0x11u, 0x42u, 0x6Eu, 0xB1u, 0x6Du,
    0x06u, 0xFDu, 0xD7u, 0xE9u, 0x60u, 0x91u, 0x78u, 0x84u

};

MCUXCLEXAMPLE_FUNCTION(mcuxClCipherModes_Els_Ecb_Aes128_Oneshot_example)
{
    /**************************************************************************/
    /* Preparation                                                            */
    /**************************************************************************/

    /** Initialize ELS, MCUXCLELS_RESET_DO_NOT_CANCEL **/
    if(!mcuxClExample_Els_Init(MCUXCLELS_RESET_DO_NOT_CANCEL))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }


    /* Initialize session */
    mcuxClSession_Descriptor_t sessionDesc;
    mcuxClSession_Handle_t session = &sessionDesc;

    /* Allocate and initialize session */
    MCUXCLEXAMPLE_ALLOCATE_AND_INITIALIZE_SESSION(session, MCUXCLEXAMPLE_MAX_WA(MCUXCLCIPHER_MAX_AES_CPU_WA_BUFFER_SIZE, MCUXCLRANDOMMODES_NCINIT_WACPU_SIZE), 0u);

    /* Initialize the PRNG */
    MCUXCLEXAMPLE_INITIALIZE_PRNG(session);

    /* Initialize key */
    uint32_t keyDesc[MCUXCLKEY_DESCRIPTOR_SIZE_IN_WORDS];
    mcuxClKey_Handle_t key = (mcuxClKey_Handle_t) &keyDesc;

    /* Set key properties. */
    mcuxClEls_KeyProp_t key_properties;

    key_properties.word.value = 0u;
    key_properties.bits.ksize = MCUXCLELS_KEYPROPERTY_KEY_SIZE_128;
    key_properties.bits.kactv = MCUXCLELS_KEYPROPERTY_ACTIVE_TRUE;

    /* Load key. */
    uint32_t dstData[8];
    //Initializes a key handle, Set key properties and Load key.
    if(!mcuxClExample_Key_Init_And_Load(session,
                                       key,
                                       mcuxClKey_Type_Aes128,
                                       (uint8_t *) aes128_key,
                                       sizeof(aes128_key),
                                       &key_properties,
                                       dstData, MCUXCLEXAMPLE_CONST_EXTERNAL_KEY))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /**************************************************************************/
    /* Encryption                                                             */
    /**************************************************************************/

    ALIGNED uint8_t msg_enc[3u * MCUXCLAES_BLOCK_SIZE];
    uint32_t msg_enc_size = 0u;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result_enc, token_enc, mcuxClCipher_crypt(
    /* mcuxClSession_Handle_t session: */ session,
    /* mcuxClKey_Handle_t key:         */ key,
    /* mcuxClCipher_Mode_t mode:       */ mcuxClCipher_Mode_AES_ECB_Enc_NoPadding,
    /* mcuxCl_InputBuffer_t pIv:       */ NULL,
    /* uint32_t ivLength:             */ 0u,
    /* mcuxCl_InputBuffer_t pIn:       */ msg_plain,
    /* uint32_t inLength:             */ sizeof(msg_plain),
    /* mcuxCl_Buffer_t pOut:           */ msg_enc,
    /* uint32_t * const pOutLength:   */ &msg_enc_size
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipher_crypt) != token_enc) || (MCUXCLCIPHER_STATUS_OK != result_enc))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    if(msg_enc_size != sizeof(msg_enc_expected))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /* Check the result of the encryption, compare it against the reference */
    if(!mcuxClCore_assertEqual(msg_enc, msg_enc_expected, msg_enc_size))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /**************************************************************************/
    /* Decryption                                                             */
    /**************************************************************************/

    ALIGNED uint8_t msg_dec[3u * MCUXCLAES_BLOCK_SIZE];
    uint32_t msg_dec_size = 0u;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result_dec, token_dec, mcuxClCipher_crypt(
    /* mcuxClSession_Handle_t session: */ session,
    /* mcuxClKey_Handle_t key:         */ key,
    /* mcuxClCipher_Mode_t mode:       */ mcuxClCipher_Mode_AES_ECB_Dec_NoPadding,
    /* mcuxCl_InputBuffer_t pIv:       */ NULL,
    /* uint32_t ivLength:             */ 0u,
    /* mcuxCl_InputBuffer_t pIn:       */ msg_enc,
    /* uint32_t inLength:             */ msg_enc_size,
    /* mcuxCl_Buffer_t pOut:           */ msg_dec,
    /* uint32_t * const pOutLength:   */ &msg_dec_size
    ));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCipher_crypt) != token_dec) || (MCUXCLCIPHER_STATUS_OK != result_dec))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    if(msg_dec_size != sizeof(msg_plain))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /* Check the result of the decryption, compare it against the plain message */
    if(!mcuxClCore_assertEqual(msg_dec, msg_plain, msg_dec_size))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /**************************************************************************/
    /* Cleanup                                                                */
    /**************************************************************************/

    /* Flush the key. */
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClKey_flush(session, key));

    if((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClKey_flush) != token) || (MCUXCLKEY_STATUS_OK != result))
    {
        return MCUXCLEXAMPLE_STATUS_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    /** Destroy Session and cleanup Session **/
    if(!mcuxClExample_Session_Clean(session))
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    /** Disable the ELS **/
    if(!mcuxClExample_Els_Disable())
    {
        return MCUXCLEXAMPLE_STATUS_ERROR;
    }

    return MCUXCLEXAMPLE_STATUS_OK;
}
