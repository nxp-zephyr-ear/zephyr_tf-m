/*--------------------------------------------------------------------------*/
/* Copyright 2021-2023 NXP                                                  */
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

#include <mcuxCsslAnalysis.h>
#include <mcuxClCore_Platform.h>

#include <mcuxClHashModes_Constants.h> // hash output sizes
#include <internal/mcuxClHash_Internal.h>
#include <internal/mcuxClHashModes_Internal_Memory.h>


MCUX_CSSL_ANALYSIS_START_PATTERN_OBJ_SIZES()
MCUX_CSSL_ANALYSIS_START_PATTERN_DESCRIPTIVE_IDENTIFIER()

/* Hash Cpu Workarea size generation */
volatile uint8_t mcuxClHash_compute_WaCpuMd5 [MCUXCLHASH_INTERNAL_WACPU_SIZE_MD5];
volatile uint8_t mcuxClHash_compute_WaCpuSha1 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA1];
volatile uint8_t mcuxClHash_compute_WaCpuSha2_224 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_224];
volatile uint8_t mcuxClHash_compute_nonblocking_WaCpuSha2_224 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_224_NONBLOCKING];
volatile uint8_t mcuxClHash_compute_WaCpuSha2_256 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_256];
volatile uint8_t mcuxClHash_compute_nonblocking_WaCpuSha2_256 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_256_NONBLOCKING];
volatile uint8_t mcuxClHash_compute_WaCpuSha2_384 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_384];
volatile uint8_t mcuxClHash_compute_nonblocking_WaCpuSha2_384 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_384_NONBLOCKING];
volatile uint8_t mcuxClHash_compute_WaCpuSha2_512 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_512];
volatile uint8_t mcuxClHash_compute_nonblocking_WaCpuSha2_512 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_512_NONBLOCKING];
volatile uint8_t mcuxClHash_compute_WaCpuSha3 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA3];
volatile uint8_t mcuxClHash_compute_nonblocking_WaCpuSha3 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA3_NONBLOCKING];
volatile uint8_t mcuxClHash_compute_WaCpuSecSha1 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SECSHA_1];
volatile uint8_t mcuxClHash_compute_WaCpuSecSha2_224 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SECSHA2_224];
volatile uint8_t mcuxClHash_compute_WaCpuSecSha2_256 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SECSHA2_256];
volatile uint8_t mcuxClHash_compute_WaCpuSecSha2_384 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SECSHA2_384];
volatile uint8_t mcuxClHash_compute_WaCpuSecSha2_512 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SECSHA2_512];
volatile uint8_t mcuxClHash_compute_WaCpuSecSha3 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SECSHA3];

volatile uint8_t mcuxClHash_compare_WaCpuMd5 [MCUXCLHASH_INTERNAL_WACPU_SIZE_MD5 + 2u * MCUXCLHASH_BLOCK_SIZE_MD5];
volatile uint8_t mcuxClHash_compare_WaCpuSha1 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA1 + 2u * MCUXCLHASH_BLOCK_SIZE_SHA_1];
volatile uint8_t mcuxClHash_compare_WaCpuSha2_224 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_224 + 2u * MCUXCLHASH_BLOCK_SIZE_SHA_224];
volatile uint8_t mcuxClHash_compare_nonblocking_WaCpuSha2_224 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_224_NONBLOCKING + 2u * MCUXCLHASH_OUTPUT_SIZE_SHA_224];
volatile uint8_t mcuxClHash_compare_WaCpuSha2_256 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_256 + 2u * MCUXCLHASH_BLOCK_SIZE_SHA_256];
volatile uint8_t mcuxClHash_compare_nonblocking_WaCpuSha2_256 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_256_NONBLOCKING + 2u * MCUXCLHASH_BLOCK_SIZE_SHA_256];
volatile uint8_t mcuxClHash_compare_WaCpuSha2_384 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_384 + 2u * MCUXCLHASH_OUTPUT_SIZE_SHA_384];
volatile uint8_t mcuxClHash_compare_nonblocking_WaCpuSha2_384 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_384_NONBLOCKING + 2u * MCUXCLHASH_OUTPUT_SIZE_SHA_384];
volatile uint8_t mcuxClHash_compare_WaCpuSha2_512 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_512 + 2u * MCUXCLHASH_OUTPUT_SIZE_SHA_512];
volatile uint8_t mcuxClHash_compare_WaCpuSha2_512_224 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_512 + 2u * MCUXCLHASH_OUTPUT_SIZE_SHA_512_224];
volatile uint8_t mcuxClHash_compare_WaCpuSha2_512_256 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_512 + 2u * MCUXCLHASH_OUTPUT_SIZE_SHA_512_256];
volatile uint8_t mcuxClHash_compare_nonblocking_WaCpuSha2_512 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_512_NONBLOCKING + 2u * MCUXCLHASH_OUTPUT_SIZE_SHA_512];
volatile uint8_t mcuxClHash_compare_nonblocking_WaCpuSha2_512_224 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_512_NONBLOCKING + 2u * MCUXCLHASH_OUTPUT_SIZE_SHA_512_224];
volatile uint8_t mcuxClHash_compare_nonblocking_WaCpuSha2_512_256 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_512_NONBLOCKING + 2u * MCUXCLHASH_OUTPUT_SIZE_SHA_512_256];
volatile uint8_t mcuxClHash_compare_WaCpuSha3 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA3 + 2u * MCUXCLHASH_OUTPUT_SIZE_SHA3_512];
volatile uint8_t mcuxClHash_compare_nonblocking_WaCpuSha3 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA3_NONBLOCKING + 2u * MCUXCLHASH_OUTPUT_SIZE_SHA3_512];
volatile uint8_t mcuxClHash_compare_WaCpuSecSha1 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SECSHA_1 + 2u * MCUXCLHASH_OUTPUT_SIZE_SHA_1];
volatile uint8_t mcuxClHash_compare_WaCpuSecSha2_224 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SECSHA2_224 + 2u * MCUXCLHASH_OUTPUT_SIZE_SHA_224];
volatile uint8_t mcuxClHash_compare_WaCpuSecSha2_256 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SECSHA2_256 + 2u * MCUXCLHASH_OUTPUT_SIZE_SHA_256];
volatile uint8_t mcuxClHash_compare_WaCpuSecSha2_384 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SECSHA2_384 + 2u * MCUXCLHASH_OUTPUT_SIZE_SHA_384];
volatile uint8_t mcuxClHash_compare_WaCpuSecSha2_512 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SECSHA2_512 + 2u * MCUXCLHASH_OUTPUT_SIZE_SHA_512];
volatile uint8_t mcuxClHash_compare_WaCpuSecSha2_512_224 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SECSHA2_512 + 2u * MCUXCLHASH_OUTPUT_SIZE_SHA_512_224];
volatile uint8_t mcuxClHash_compare_WaCpuSecSha2_512_256 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SECSHA2_512 + 2u * MCUXCLHASH_OUTPUT_SIZE_SHA_512_256];
volatile uint8_t mcuxClHash_compare_WaCpuSecSha3 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SECSHA3 + 2u * MCUXCLHASH_OUTPUT_SIZE_SHA3_512];

volatile uint8_t mcuxClHash_finish_WaCpuMd5 [4u];
volatile uint8_t mcuxClHash_finish_WaCpuSha1 [4u];
volatile uint8_t mcuxClHash_finish_WaCpuSha2_224 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_224];
volatile uint8_t mcuxClHash_finish_WaCpuSha2_256 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_256];
volatile uint8_t mcuxClHash_finish_WaCpuSha2_384 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_384];
volatile uint8_t mcuxClHash_finish_WaCpuSha2_512 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_512];
volatile uint8_t mcuxClHash_finish_WaCpuSha3 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA3];
volatile uint8_t mcuxClHash_finish_nonblocking_WaCpuSha3 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA3_NONBLOCKING];
volatile uint8_t mcuxClHash_finish_WaCpuSecSha1 [4u];
volatile uint8_t mcuxClHash_finish_WaCpuSecSha2_224 [4u]; /* Not needed */
volatile uint8_t mcuxClHash_finish_WaCpuSecSha2_256 [4u];
volatile uint8_t mcuxClHash_finish_WaCpuSecSha2_384 [4u];
volatile uint8_t mcuxClHash_finish_WaCpuSecSha2_512 [4u];
volatile uint8_t mcuxClHash_finish_WaCpuSecSha3 [8u]; /* Not needed */

volatile uint8_t mcuxClHash_verify_WaCpuMd5 [MCUXCLHASH_INTERNAL_WACPU_SIZE_MD5 + 2u * MCUXCLHASH_BLOCK_SIZE_MD5];
volatile uint8_t mcuxClHash_verify_WaCpuSha1 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA1 + 2u * MCUXCLHASH_BLOCK_SIZE_SHA_1];
volatile uint8_t mcuxClHash_verify_WaCpuSha2_224 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_224 + 2u * MCUXCLHASH_BLOCK_SIZE_SHA_224];
volatile uint8_t mcuxClHash_verify_nonblocking_WaCpuSha2_224 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_224_NONBLOCKING + 2u * MCUXCLHASH_OUTPUT_SIZE_SHA_224];
volatile uint8_t mcuxClHash_verify_WaCpuSha2_256 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_256 + 2u * MCUXCLHASH_BLOCK_SIZE_SHA_256];
volatile uint8_t mcuxClHash_verify_nonblocking_WaCpuSha2_256 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_256_NONBLOCKING + 2u * MCUXCLHASH_BLOCK_SIZE_SHA_256];
volatile uint8_t mcuxClHash_verify_WaCpuSha2_384 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_384 + 2u * MCUXCLHASH_OUTPUT_SIZE_SHA_384];
volatile uint8_t mcuxClHash_verify_nonblocking_WaCpuSha2_384 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_384_NONBLOCKING + 2u * MCUXCLHASH_OUTPUT_SIZE_SHA_384];
volatile uint8_t mcuxClHash_verify_WaCpuSha2_512 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_512 + 2u * MCUXCLHASH_OUTPUT_SIZE_SHA_512];
volatile uint8_t mcuxClHash_verify_WaCpuSha2_512_224 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_512 + 2u * MCUXCLHASH_OUTPUT_SIZE_SHA_512_224];
volatile uint8_t mcuxClHash_verify_WaCpuSha2_512_256 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_512 + 2u * MCUXCLHASH_OUTPUT_SIZE_SHA_512_256];
volatile uint8_t mcuxClHash_verify_nonblocking_WaCpuSha2_512 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_512_NONBLOCKING + 2u * MCUXCLHASH_OUTPUT_SIZE_SHA_512];
volatile uint8_t mcuxClHash_verify_nonblocking_WaCpuSha2_512_224 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_512_NONBLOCKING + 2u * MCUXCLHASH_OUTPUT_SIZE_SHA_512_224];
volatile uint8_t mcuxClHash_verify_nonblocking_WaCpuSha2_512_256 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA2_512_NONBLOCKING + 2u * MCUXCLHASH_OUTPUT_SIZE_SHA_512_256];
volatile uint8_t mcuxClHash_verify_WaCpuSha3 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA3 + 2u * MCUXCLHASH_OUTPUT_SIZE_SHA3_512];
volatile uint8_t mcuxClHash_verify_nonblocking_WaCpuSha3 [MCUXCLHASH_INTERNAL_WACPU_SIZE_SHA3_NONBLOCKING + 2u * MCUXCLHASH_OUTPUT_SIZE_SHA3_512];
volatile uint8_t mcuxClHash_verify_WaCpuSecSha1 [2u * MCUXCLHASH_OUTPUT_SIZE_SHA_1];
volatile uint8_t mcuxClHash_verify_WaCpuSecSha2_224 [2u * MCUXCLHASH_OUTPUT_SIZE_SHA_224];
volatile uint8_t mcuxClHash_verify_WaCpuSecSha2_256 [2u * MCUXCLHASH_OUTPUT_SIZE_SHA_256];
volatile uint8_t mcuxClHash_verify_WaCpuSecSha2_384 [2u * MCUXCLHASH_OUTPUT_SIZE_SHA_384];
volatile uint8_t mcuxClHash_verify_WaCpuSecSha2_512 [2u * MCUXCLHASH_OUTPUT_SIZE_SHA_512];
volatile uint8_t mcuxClHash_verify_WaCpuSecSha2_512_224 [2u * MCUXCLHASH_OUTPUT_SIZE_SHA_512_224];
volatile uint8_t mcuxClHash_verify_WaCpuSecSha2_512_256 [2u * MCUXCLHASH_OUTPUT_SIZE_SHA_512_256];
volatile uint8_t mcuxClHash_verify_WaCpuSecSha3 [2u * MCUXCLHASH_OUTPUT_SIZE_SHA3_512];

/* Hash multipart context size generation */
/* State and unprocessed buffers are stored behind context struct. 
 * Start of state is potentially shifted to ensure 64 Bit alignment. Maximum shift: MCUXCLHASH_CONTEXT_MAX_ALIGNMENT_OFFSET.
 * Subsequent buffers are not shifted as state and block sizes guarantee 64 Bit alignment for all algorithms that need it,
 * and 32 Bit alginment for all algorithms.
 * The resulting size is aligned to 32 Bit to allow easy conversion to word size in public memory header. */
volatile uint8_t mcuxClHash_Ctx_size_md5 [MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(sizeof(mcuxClHash_ContextDescriptor_t)      + MCUXCLHASH_CONTEXT_MAX_ALIGNMENT_OFFSET + MCUXCLHASH_BLOCK_SIZE_MD5       + MCUXCLHASH_STATE_SIZE_MD5)];
volatile uint8_t mcuxClHash_Ctx_size_sha_1 [MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(sizeof(mcuxClHash_ContextDescriptor_t)    + MCUXCLHASH_CONTEXT_MAX_ALIGNMENT_OFFSET + MCUXCLHASH_BLOCK_SIZE_SHA_1     + MCUXCLHASH_STATE_SIZE_SHA_1)];
volatile uint8_t mcuxClHash_Ctx_size_sha_256 [MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(sizeof(mcuxClHash_ContextDescriptor_t)  + MCUXCLHASH_CONTEXT_MAX_ALIGNMENT_OFFSET + MCUXCLHASH_BLOCK_SIZE_SHA_256   + MCUXCLHASH_STATE_SIZE_SHA_256)];
volatile uint8_t mcuxClHash_Ctx_size_sha_512 [MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(sizeof(mcuxClHash_ContextDescriptor_t)  + MCUXCLHASH_CONTEXT_MAX_ALIGNMENT_OFFSET + MCUXCLHASH_BLOCK_SIZE_SHA_512   + MCUXCLHASH_STATE_SIZE_SHA_512)];
volatile uint8_t mcuxClHash_Ctx_size_sha3_224 [MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(sizeof(mcuxClHash_ContextDescriptor_t) + MCUXCLHASH_CONTEXT_MAX_ALIGNMENT_OFFSET + MCUXCLHASH_BLOCK_SIZE_SHA3_224  + MCUXCLHASH_STATE_SIZE_SHA3)];
volatile uint8_t mcuxClHash_Ctx_size_sha3_256 [MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(sizeof(mcuxClHash_ContextDescriptor_t) + MCUXCLHASH_CONTEXT_MAX_ALIGNMENT_OFFSET + MCUXCLHASH_BLOCK_SIZE_SHA3_256  + MCUXCLHASH_STATE_SIZE_SHA3)];
volatile uint8_t mcuxClHash_Ctx_size_sha3_384 [MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(sizeof(mcuxClHash_ContextDescriptor_t) + MCUXCLHASH_CONTEXT_MAX_ALIGNMENT_OFFSET + MCUXCLHASH_BLOCK_SIZE_SHA3_384  + MCUXCLHASH_STATE_SIZE_SHA3)];
volatile uint8_t mcuxClHash_Ctx_size_sha3_512 [MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(sizeof(mcuxClHash_ContextDescriptor_t) + MCUXCLHASH_CONTEXT_MAX_ALIGNMENT_OFFSET + MCUXCLHASH_BLOCK_SIZE_SHA3_512  + MCUXCLHASH_STATE_SIZE_SHA3)];
volatile uint8_t mcuxClHash_Ctx_size_sha3_shake_128 [MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(sizeof(mcuxClHash_ContextDescriptor_t) + MCUXCLHASH_CONTEXT_MAX_ALIGNMENT_OFFSET + MCUXCLHASH_BLOCK_SIZE_SHA3_SHAKE_128 + MCUXCLHASH_STATE_SIZE_SHA3)];
volatile uint8_t mcuxClHash_Ctx_size_sha3_shake_256 [MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(sizeof(mcuxClHash_ContextDescriptor_t) + MCUXCLHASH_CONTEXT_MAX_ALIGNMENT_OFFSET + MCUXCLHASH_BLOCK_SIZE_SHA3_SHAKE_256 + MCUXCLHASH_STATE_SIZE_SHA3)];
/* SecSha1 and SecSha2 use additional buffers for stateMask and unprocessedMask. Raw state sizes account for both buffer and mask buffer. */
volatile uint8_t mcuxClHash_Ctx_size_secsha_1 [MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(sizeof(mcuxClHash_ContextDescriptor_t)   + MCUXCLHASH_CONTEXT_MAX_ALIGNMENT_OFFSET + (2u * MCUXCLHASH_BLOCK_SIZE_SHA_1)   + MCUXCLHASH_STATE_SIZE_SECSHA_1)];
volatile uint8_t mcuxClHash_Ctx_size_secsha_256 [MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(sizeof(mcuxClHash_ContextDescriptor_t) + MCUXCLHASH_CONTEXT_MAX_ALIGNMENT_OFFSET + (2u * MCUXCLHASH_BLOCK_SIZE_SHA_256) + MCUXCLHASH_STATE_SIZE_SECSHA_256)];
volatile uint8_t mcuxClHash_Ctx_size_secsha_512 [MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(sizeof(mcuxClHash_ContextDescriptor_t) + MCUXCLHASH_CONTEXT_MAX_ALIGNMENT_OFFSET + (2u * MCUXCLHASH_BLOCK_SIZE_SHA_512) + MCUXCLHASH_STATE_SIZE_SECSHA_512)];
/* SecSha3 does not use an unprocessed mask buffer. */
volatile uint8_t mcuxClHash_Ctx_size_secsha3_224 [MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(sizeof(mcuxClHash_ContextDescriptor_t) + MCUXCLHASH_CONTEXT_MAX_ALIGNMENT_OFFSET + MCUXCLHASH_BLOCK_SIZE_SHA3_224 + MCUXCLHASH_STATE_SIZE_SECSHA3)];
volatile uint8_t mcuxClHash_Ctx_size_secsha3_256 [MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(sizeof(mcuxClHash_ContextDescriptor_t) + MCUXCLHASH_CONTEXT_MAX_ALIGNMENT_OFFSET + MCUXCLHASH_BLOCK_SIZE_SHA3_256 + MCUXCLHASH_STATE_SIZE_SECSHA3)];
volatile uint8_t mcuxClHash_Ctx_size_secsha3_384 [MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(sizeof(mcuxClHash_ContextDescriptor_t) + MCUXCLHASH_CONTEXT_MAX_ALIGNMENT_OFFSET + MCUXCLHASH_BLOCK_SIZE_SHA3_384 + MCUXCLHASH_STATE_SIZE_SECSHA3)];
volatile uint8_t mcuxClHash_Ctx_size_secsha3_512 [MCUXCLCORE_ALIGN_TO_CPU_WORDSIZE(sizeof(mcuxClHash_ContextDescriptor_t) + MCUXCLHASH_CONTEXT_MAX_ALIGNMENT_OFFSET + MCUXCLHASH_BLOCK_SIZE_SHA3_512 + MCUXCLHASH_STATE_SIZE_SECSHA3)];

/* Hash multipart state export size generation */
volatile uint8_t mcuxClHash_export_import_size_md5 [MCUXCLHASH_STATE_SIZE_MD5 + MCUXCLHASH_COUNTER_SIZE_MD5];
volatile uint8_t mcuxClHash_export_import_size_sha_1 [MCUXCLHASH_STATE_SIZE_SHA_1 + MCUXCLHASH_COUNTER_SIZE_SHA_1];
volatile uint8_t mcuxClHash_export_import_size_sha_256 [MCUXCLHASH_STATE_SIZE_SHA_256 + MCUXCLHASH_COUNTER_SIZE_SHA_256];
volatile uint8_t mcuxClHash_export_import_size_sha_512 [MCUXCLHASH_STATE_SIZE_SHA_512 + MCUXCLHASH_COUNTER_SIZE_SHA_512];
volatile uint8_t mcuxClHash_export_import_size_sha3 [MCUXCLHASH_STATE_SIZE_SHA3 + MCUXCLHASH_COUNTER_SIZE_SHA3];
volatile uint8_t mcuxClHash_export_import_size_secsha_1 [MCUXCLHASH_STATE_SIZE_SECSHA_1 + MCUXCLHASH_COUNTER_SIZE_SHA_1];
volatile uint8_t mcuxClHash_export_import_size_secsha_256 [MCUXCLHASH_STATE_SIZE_SECSHA_256 + MCUXCLHASH_COUNTER_SIZE_SHA_256];
volatile uint8_t mcuxClHash_export_import_size_secsha_512 [MCUXCLHASH_STATE_SIZE_SECSHA_512 + MCUXCLHASH_COUNTER_SIZE_SHA_512];
volatile uint8_t mcuxClHash_export_import_size_secsha3 [MCUXCLHASH_STATE_SIZE_SECSHA3 + MCUXCLHASH_COUNTER_SIZE_SHA3];



MCUX_CSSL_ANALYSIS_STOP_PATTERN_DESCRIPTIVE_IDENTIFIER()
MCUX_CSSL_ANALYSIS_STOP_PATTERN_OBJ_SIZES()
