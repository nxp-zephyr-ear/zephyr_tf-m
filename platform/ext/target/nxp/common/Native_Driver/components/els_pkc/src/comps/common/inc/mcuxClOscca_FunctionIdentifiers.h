/*--------------------------------------------------------------------------*/
/* Copyright 2020-2024 NXP                                                  */
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
 * @file  mcuxClOscca_FunctionIdentifiers.h
 * @brief Definition of function identifiers for the flow protection mechanism.
 *
 * @note This file might be post-processed to update the identifier values to
 * proper/secure values.
 */

#ifndef MCUX_OSCCACL_FLOW_PROTECTION_FUNCTION_IDENTIFIERS_H_
#define MCUX_OSCCACL_FLOW_PROTECTION_FUNCTION_IDENTIFIERS_H_

#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_Cipher_init_encrypt                 (0x1766u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaCipherModes_finish_internal_encrypt_Sm4 (0x5AE4u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaCipherModes_finish_internal_decrypt_Sm4 (0x7C26u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_Signature_OnlyVerify_SelfTest       (0x1F43u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_Signature_SignVerify_SelfTest       (0x3BE0u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_Cipher_EncDec_selftest              (0x3A2Bu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_KeyExchange_SelfTest                (0x3A8Eu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaMacModes_finish                         (0x1E63u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaMacModes_process                        (0x1B8Du)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaMacModes_compute                        (0x5A87u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaMacModes_init                           (0x2E4Bu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaMacModes_SM4_Gen_K1K2                   (0x413Fu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaMacModes_Engine_CBCMAC_Finalize         (0x52D9u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaMacModes_Engine_CMAC_Finalize           (0x14EDu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaMacModes_Engine_CBCMAC_Update           (0x7247u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaMacModes_Engine_CMAC_Update             (0x14B7u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaMacModes_Engine_CBCMAC_Init             (0x06F5u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaMacModes_Engine_CMAC_Init               (0x489Fu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaMacModes_Engine_CBCMAC_Oneshot          (0x3BA2u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaMacModes_Engine_CMAC_Oneshot            (0x11BDu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaRandomModes_ROtrng_reseed               (0x49DCu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaCipherModes_finish_Sm4                  (0x724Eu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaCipherModes_process_Sm4                 (0x68AEu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaCipherModes_init_decrypt_Sm4            (0x7D0Au)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaCipherModes_init_encrypt_Sm4            (0x54C7u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaCipherModes_decrypt_Sm4                 (0x39ACu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaCipherModes_encrypt_Sm4                 (0x21DEu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_FastSecureXor                          (0x6C35u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_switch_endianness                      (0x2C1Fu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm3_sw_finish_sm3                       (0x60EDu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm3_sw_process_sm3                      (0x519Du)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm3_sw_oneShotSkeleton_sm3              (0x5572u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm3_sm3_finishSkeleton                  (0x70A7u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm3_sm3_processSkeleton                 (0x06EBu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm3_sm3_oneShotSkeleton                 (0x574Au)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaRandomModes_ROtrng_selftest             (0x5335u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaRandomModes_ROtrng_PowerOnTest          (0x155Eu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaRandomModes_ROtrng_DeliverySimpleTest   (0x6E49u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaRandomModes_ROtrng_PokerTest            (0x31ABu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaRandomModes_ROtrng_generate             (0x563Cu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaRandomModes_ROtrng_init                 (0x7BC0u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaAeadModes_SkeletonCcm                   (0x30BEu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaPkc_CalcMontInverse                     (0x6B2Cu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaAeadModes_EngineCcm                     (0x2E47u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaAeadModes_SM4_Crypt_Internal_Ctr        (0x457Cu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaPkc_ComputeModInv                       (0x2BB1u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaPkc_LeadingZeros                        (0x496Eu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaPkc_MultipleShiftRotate_Index           (0x52F8u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaPkc_GeneratePointerTable                (0x6D54u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaPkc_ComputeQSquared                     (0x1A57u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaPkc_ComputeNDash                        (0x3B61u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaPkc_StartFupProgram                     (0x161Fu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaPkc_Op                                  (0x5A6Cu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaPkc_SetFupTable                         (0x339Au)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaPkc_WaitforFinish                       (0x156Du)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaPkc_GetWordSize                         (0x1E4Du)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaPkc_SetWordSize                         (0x6798u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaPkc_Init                                (0x16ABu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaPkc_Reset                               (0x4C73u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaAeadModes_init                          (0x61CBu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaAeadModes_init_encrypt                  (0x168Fu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaAeadModes_init_decrypt                  (0x6F82u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaAeadModes_process                       (0x2BD1u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaAeadModes_process_adata                 (0x0B2Fu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaAeadModes_finish                        (0x1D8Bu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaAeadModes_verify                        (0x4B87u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaAeadModes_crypt                         (0x4BD4u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaAeadModes_encrypt                       (0x5CA9u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaAeadModes_decrypt                       (0x6A5Au)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaMacModes_prepareHMACKey                 (0x469Bu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaMacModes_Engine_HMAC_Init               (0x2787u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm4_Tprime                              (0x3B43u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm4_Lprime                              (0x2CBAu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm4_T                                   (0x6D45u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm4_L                                   (0x743Cu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaMacModes_Engine_HMAC_Finalize           (0x45B5u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaMacModes_Engine_HMAC_Oneshot            (0x2BA3u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm4_Tau                                 (0x383Du)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaMacModes_Engine_HMAC_Update             (0x5C0Fu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_Cipher_SkeletonSM2                  (0x41F6u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_Cipher_finish                       (0x3F11u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_Cipher_process                      (0x5A5Cu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_Cipher_init_decrypt                 (0x1C5Du)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_GenerateKeyPair                     (0x392Bu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm3_Safo_Hash_PreLoad                   (0x0DAEu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm3_Safo_Hash_Auto                      (0x1CC7u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm3_Safo_Hash_Norm                      (0x39E2u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm3_SetMessagePreLoadIV_Sgi             (0x5F24u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm3_ProcessMessageBlock_Sgi             (0x4D17u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_RobustCompareToZero                 (0x50FAu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_RobustCompareBoolean                (0x5D62u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_SignVerify_SelfTest                 (0x6437u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_EncDec_SelfTest                     (0x21CFu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_KeyExchange                         (0x52ABu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_Decrypt                             (0x6E38u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_Encrypt                             (0x4D0Fu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_ComputePrehash                      (0x60F6u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_InvertPrivateKey                    (0x5EB0u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_Verify                              (0x48F9u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_Sign                                (0x3947u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_Export                              (0x5933u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_Import                              (0x1B4Bu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_EccPointCheckCoordinate             (0x4B71u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_EccPointAddOrDouble                 (0x4A7Au)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_EccTransAffinePoint2Jac             (0x09E7u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_EccGenRandomBytes                   (0x5E62u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_EccPointMultMontgomery              (0x5C63u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_EccPointAdd                         (0x0D6Eu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_EccPointDouble                      (0x0D9Du)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_EccPointConvert2Affine              (0x4973u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_EccJacPointCheck                    (0x2A97u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_EccImportInputPointYNegNoInit       (0x2E78u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_EccImportInputPointWithInit         (0x2F62u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_EccGenerateZ                        (0x4B55u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_EccPrepareParameters                (0x722Eu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_EccInit                             (0x11E7u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_WrapHash                            (0x6E58u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_ValidateEncDecCtx                   (0x7496u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_EncDec_UpdatePhase                  (0x7345u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_SecondPartOfInitPhase               (0x7670u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_KDF                                 (0x63B4u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_Cipher_decrypt                      (0x16B3u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_Cipher_encrypt                      (0x293Du)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm4_ScheduleSM4Key                      (0x58B9u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaCipherModes_SkeletonSM4                 (0x65CAu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_key_agreement                       (0x362Eu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaMacModes_compare                        (0x3D94u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaMacModes_verify                         (0x532Eu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_Signature_Init                      (0x43A7u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_Signature_Finish                    (0x387Cu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_Signature_PreHash                   (0x22D7u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_KeyAgreement_SelfTest               (0x70F2u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_Signature_PrepareDigest             (0x1DF0u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaAeadModes_SM4_Crypt_IncCounter          (0x2BACu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaPkc_CountLeadingZerosWord               (0x7741u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm3_core_sm3_processMessageBlock        (0x4B74u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm4_Engine                              (0x153Eu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm4_ScheduleKey                         (0x1774u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_EccSecurePointMult                  (0x398Eu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_EccPointMultSplitScalar             (0x70C7u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_SecureExport                        (0x3D51u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_SecureImport                        (0x09FCu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_Signature_Internal_Init             (0x31B9u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_Signature_Internal_Finish           (0x25DCu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaCipherModes_Sm4Ecb_EncDec_SelfTest      (0x1747u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaCipherModes_Sm4Cbc_EncDec_SelfTest      (0x06E7u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaMacModes_Sm4Cmac_SelfTest               (0x29BAu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaMacModes_Sm4CbcMac_SelfTest             (0x53D8u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaAeadModes_Sm4Ccm_EncDec_SelfTest        (0x2D0Fu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm3_selftest                            (0x7474u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaAeadModes_Ccm_Internal_Init             (0x13F1u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaAeadModes_Ccm_Internal_ProcessAad       (0x5D15u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaAeadModes_Ccm_Internal_Process          (0x3DB0u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaAeadModes_Ccm_Internal_Finish           (0x472Du)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaCipherModes_SkeletonSM4_Init            (0x7E18u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaCipherModes_SkeletonSM4_Process         (0x1576u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaCipherModes_SkeletonSM4_Finish          (0x5C36u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaCipherModes_SM4_Crypt_IncCounter        (0x3A65u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaCipherModes_SkeletonSM4_Pre             (0x0B73u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaCipherModes_SkeletonSM4_OneShot         (0x29ABu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaCipherModes_SkeletonSM4Ctr_LastBlockPro (0x6D85u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaCipherModes_SkeletonSM4NoCtr_LastBlockPro (0x4F83u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaCipherModes_SkeletonSM4NoCtr_BlockPro   (0x09BDu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaCipherModes_SkeletonSM4Ctr_BlockPro     (0x6167u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_EncDec_UpdatePhase_Common           (0x6A2Du)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_EncDec_UpdatePhase_Pre              (0x1BD4u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_Encrypt_Internal_Init               (0x554Du)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_Encrypt_Internal_Final              (0x6F60u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_Decrypt_Internal_Init               (0x46A7u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_Decrypt_Internal_Final              (0x1BE1u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_HandleKeyConfirmation               (0x4EA9u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_ComputeKeyConfirmation_Init         (0x59ACu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_KeyExchange_Init                    (0x7A89u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_InvertPrivateKey_EccInit            (0x7691u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_PrivateKey_Check                    (0x2277u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_Encrypt_Internal_PointMult          (0x6EA2u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_Decrypt_Internal_Init_EccPrepare    (0x3F14u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_Decrypt_Internal_Init_PointMult     (0x164Fu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_Verify_Init                         (0x3D0Eu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_Signature_Internal_Finish_ComputeS  (0x0D7Au)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_Cipher_SkeletonSM2_Core             (0x13B3u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_Cipher_SkeletonSM2_Encrypt          (0x60E7u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_Cipher_SkeletonSM2_Decrypt          (0x6794u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaSm2_Cipher_SkeletonSM2_Decrypt_Process  (0x127Du)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaRandomModes_ROtrng_generate_words       (0x255Eu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaRandomModes_ROtrng_generate_tail        (0x583Eu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOsccaRandomModes_ROtrng_generate_head        (0x235Du)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_54                                     (0x4793u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_55                                     (0x4A79u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_56                                     (0x7E06u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_57                                     (0x4E74u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_58                                     (0x2CA7u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_59                                     (0x65AAu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_60                                     (0x553Cu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_61                                     (0x4DA3u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_62                                     (0x179Cu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_63                                     (0x36A6u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_64                                     (0x16DAu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_65                                     (0x661Du)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_66                                     (0x0FA5u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_67                                     (0x49CEu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_68                                     (0x0B3Du)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_69                                     (0x7E22u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_70                                     (0x52E5u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_71                                     (0x133Du)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_72                                     (0x3B91u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_73                                     (0x5C55u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_74                                     (0x2C5Bu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_75                                     (0x31E6u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_76                                     (0x16F8u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_77                                     (0x21F5u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_78                                     (0x7B14u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_79                                     (0x6F42u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_80                                     (0x36A5u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_81                                     (0x3565u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_82                                     (0x6715u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_83                                     (0x4D4Eu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_84                                     (0x21FAu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_85                                     (0x1D8Eu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_86                                     (0x0E9Eu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_87                                     (0x4E39u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_88                                     (0x12EBu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_89                                     (0x431Fu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_90                                     (0x12EDu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_91                                     (0x3333u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_92                                     (0x5E8Cu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_93                                     (0x56CAu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_94                                     (0x5566u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_95                                     (0x151Fu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_96                                     (0x5BA2u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_97                                     (0x4F25u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_98                                     (0x5077u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_99                                     (0x59A6u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_100                                    (0x354Du)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_101                                    (0x2EB1u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_102                                    (0x3762u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_103                                    (0x5764u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_104                                    (0x651Du)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_105                                    (0x0F2Bu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_106                                    (0x23BAu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_107                                    (0x65C9u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_108                                    (0x393Au)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_109                                    (0x5273u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_110                                    (0x239Eu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_111                                    (0x6876u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_112                                    (0x37C4u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_113                                    (0x5CA3u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_114                                    (0x792Cu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_115                                    (0x4C5Bu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_116                                    (0x5E8Au)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_117                                    (0x27E2u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_118                                    (0x3EA1u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_119                                    (0x6DC4u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_120                                    (0x09F6u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_121                                    (0x5656u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_122                                    (0x59B1u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_123                                    (0x4D71u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_124                                    (0x7265u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_125                                    (0x78D8u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_126                                    (0x0E57u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_127                                    (0x217Bu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_128                                    (0x525Du)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_129                                    (0x3873u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_130                                    (0x4C7Au)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_131                                    (0x0F4Du)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_132                                    (0x364Eu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_133                                    (0x1AEAu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_134                                    (0x3E85u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_135                                    (0x2C37u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_136                                    (0x2A6Du)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_137                                    (0x38D6u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_138                                    (0x6707u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_139                                    (0x51CDu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_140                                    (0x7859u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_141                                    (0x3713u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_142                                    (0x45F2u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_143                                    (0x29B3u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_144                                    (0x51F2u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_145                                    (0x5671u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_146                                    (0x435Bu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_147                                    (0x18DBu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_148                                    (0x1B71u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_149                                    (0x45B9u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_150                                    (0x46DAu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_151                                    (0x233Du)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_152                                    (0x689Bu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_153                                    (0x2E8Eu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_154                                    (0x2E93u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_155                                    (0x7B28u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_156                                    (0x469Eu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_157                                    (0x3A2Du)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_158                                    (0x714Bu)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_159                                    (0x7AA1u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_160                                    (0x2C9Du)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_161                                    (0x19D9u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_162                                    (0x5E16u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_163                                    (0x0BD5u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_164                                    (0x6517u)
#define MCUX_CSSL_FP_FUNCID_mcuxClOscca_165                                    (0x433Eu)
#endif /* MCUX_OSCCACL_FLOW_PROTECTION_FUNCTION_IDENTIFIERS_H_ */
