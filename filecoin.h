/* filecoin Header */

#ifdef __cplusplus
extern "C" {
#endif


#ifndef FILECOIN_H
#define FILECOIN_H

/* Generated with cbindgen:0.10.0 */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define DIGEST_BYTES 96

#define PRIVATE_KEY_BYTES 32

#define PUBLIC_KEY_BYTES 48

#define SIGNATURE_BYTES 96

typedef enum {
  FCPResponseStatus_FCPNoError = 0,
  FCPResponseStatus_FCPUnclassifiedError = 1,
  FCPResponseStatus_FCPCallerError = 2,
  FCPResponseStatus_FCPReceiverError = 3,
} FCPResponseStatus;

typedef enum {
  FFIRegisteredPoStProof_StackedDrg2KiBV1,
  FFIRegisteredPoStProof_StackedDrg8MiBV1,
  FFIRegisteredPoStProof_StackedDrg512MiBV1,
  FFIRegisteredPoStProof_StackedDrg32GiBV1,
} FFIRegisteredPoStProof;

typedef enum {
  FFIRegisteredSealProof_StackedDrg2KiBV1,
  FFIRegisteredSealProof_StackedDrg8MiBV1,
  FFIRegisteredSealProof_StackedDrg512MiBV1,
  FFIRegisteredSealProof_StackedDrg32GiBV1,
} FFIRegisteredSealProof;

typedef uint8_t BLSSignature[SIGNATURE_BYTES];

/**
 * AggregateResponse
 */
typedef struct {
  BLSSignature signature;
} AggregateResponse;

typedef struct {
  const char *error_msg;
  FCPResponseStatus status_code;
} ClearCacheResponse;

typedef struct {
  FCPResponseStatus status_code;
  const char *error_msg;
  uint8_t ticket[32];
} FinalizeTicketResponse;

typedef struct {
  uint64_t sector_id;
  uint8_t partial_ticket[32];
  uint8_t ticket[32];
  uint64_t sector_challenge_index;
} FFICandidate;

typedef struct {
  const char *error_msg;
  FCPResponseStatus status_code;
  const FFICandidate *candidates_ptr;
  size_t candidates_len;
} GenerateCandidatesResponse;

typedef struct {
  FCPResponseStatus status_code;
  const char *error_msg;
  uint8_t comm_d[32];
} GenerateDataCommitmentResponse;

typedef struct {
  FCPResponseStatus status_code;
  const char *error_msg;
  uint8_t comm_p[32];
  /**
   * The number of unpadded bytes in the original piece plus any (unpadded)
   * alignment bytes added to create a whole merkle tree.
   */
  uint64_t num_bytes_aligned;
} GeneratePieceCommitmentResponse;

typedef struct {
  FFIRegisteredPoStProof registered_proof;
  size_t proof_len;
  const uint8_t *proof_ptr;
} FFIPoStProof;

typedef struct {
  const char *error_msg;
  size_t proofs_len;
  const FFIPoStProof *proofs_ptr;
  FCPResponseStatus status_code;
} GeneratePoStResponse;

typedef struct {
  FCPResponseStatus status_code;
  const char *error_msg;
  size_t devices_len;
  const char *const *devices_ptr;
} GpuDeviceResponse;

typedef uint8_t BLSDigest[DIGEST_BYTES];

/**
 * HashResponse
 */
typedef struct {
  BLSDigest digest;
} HashResponse;

typedef uint8_t BLSPrivateKey[PRIVATE_KEY_BYTES];

/**
 * PrivateKeyGenerateResponse
 */
typedef struct {
  BLSPrivateKey private_key;
} PrivateKeyGenerateResponse;

typedef uint8_t BLSPublicKey[PUBLIC_KEY_BYTES];

/**
 * PrivateKeyPublicKeyResponse
 */
typedef struct {
  BLSPublicKey public_key;
} PrivateKeyPublicKeyResponse;

/**
 * PrivateKeySignResponse
 */
typedef struct {
  BLSSignature signature;
} PrivateKeySignResponse;

typedef struct {
  FCPResponseStatus status_code;
  const char *error_msg;
  const uint8_t *seal_commit_phase1_output_ptr;
  size_t seal_commit_phase1_output_len;
} SealCommitPhase1Response;

typedef struct {
  FCPResponseStatus status_code;
  const char *error_msg;
  const uint8_t *proof_ptr;
  size_t proof_len;
} SealCommitPhase2Response;

typedef struct {
  const char *error_msg;
  FCPResponseStatus status_code;
  const uint8_t *seal_pre_commit_phase1_output_ptr;
  size_t seal_pre_commit_phase1_output_len;
} SealPreCommitPhase1Response;

typedef struct {
  const char *error_msg;
  FCPResponseStatus status_code;
  FFIRegisteredSealProof registered_proof;
  uint8_t comm_d[32];
  uint8_t comm_r[32];
} SealPreCommitPhase2Response;

/**
 *
 */
typedef struct {
  FCPResponseStatus status_code;
  const char *error_msg;
  const char *string_val;
} StringResponse;

typedef struct {
  FCPResponseStatus status_code;
  const char *error_msg;
} UnsealRangeResponse;

typedef struct {
  FCPResponseStatus status_code;
  const char *error_msg;
} UnsealResponse;

typedef struct {
  FCPResponseStatus status_code;
  const char *error_msg;
  bool is_valid;
} VerifyPoStResponse;

typedef struct {
  FCPResponseStatus status_code;
  const char *error_msg;
  bool is_valid;
} VerifySealResponse;

typedef struct {
  uint8_t comm_p[32];
  const char *error_msg;
  uint64_t left_alignment_unpadded;
  FCPResponseStatus status_code;
  uint64_t total_write_unpadded;
} WriteWithAlignmentResponse;

typedef struct {
  uint8_t comm_p[32];
  const char *error_msg;
  FCPResponseStatus status_code;
  uint64_t total_write_unpadded;
} WriteWithoutAlignmentResponse;

typedef struct {
  FFIRegisteredPoStProof registered_proof;
  const char *cache_dir_path;
  uint8_t comm_r[32];
  const char *replica_path;
  uint64_t sector_id;
} FFIPrivateReplicaInfo;

typedef struct {
  uint64_t num_bytes;
  uint8_t comm_p[32];
} FFIPublicPieceInfo;

typedef struct {
  FFIRegisteredPoStProof registered_proof;
  uint8_t comm_r[32];
  uint64_t sector_id;
} FFIPublicReplicaInfo;

/**
 * Aggregate signatures together into a new signature
 *
 * # Arguments
 *
 * * `flattened_signatures_ptr` - pointer to a byte array containing signatures
 * * `flattened_signatures_len` - length of the byte array (multiple of SIGNATURE_BYTES)
 *
 * Returns `NULL` on error. Result must be freed using `destroy_aggregate_response`.
 */
AggregateResponse *aggregate(const uint8_t *flattened_signatures_ptr,
                             size_t flattened_signatures_len);

ClearCacheResponse *clear_cache(const char *cache_dir_path);

void destroy_aggregate_response(AggregateResponse *ptr);

void destroy_clear_cache_response(ClearCacheResponse *ptr);

void destroy_finalize_ticket_response(FinalizeTicketResponse *ptr);

void destroy_generate_candidates_response(GenerateCandidatesResponse *ptr);

void destroy_generate_data_commitment_response(GenerateDataCommitmentResponse *ptr);

void destroy_generate_piece_commitment_response(GeneratePieceCommitmentResponse *ptr);

void destroy_generate_post_response(GeneratePoStResponse *ptr);

void destroy_gpu_device_response(GpuDeviceResponse *ptr);

void destroy_hash_response(HashResponse *ptr);

void destroy_private_key_generate_response(PrivateKeyGenerateResponse *ptr);

void destroy_private_key_public_key_response(PrivateKeyPublicKeyResponse *ptr);

void destroy_private_key_sign_response(PrivateKeySignResponse *ptr);

void destroy_seal_commit_phase1_response(SealCommitPhase1Response *ptr);

void destroy_seal_commit_phase2_response(SealCommitPhase2Response *ptr);

void destroy_seal_pre_commit_phase1_response(SealPreCommitPhase1Response *ptr);

void destroy_seal_pre_commit_phase2_response(SealPreCommitPhase2Response *ptr);

void destroy_string_response(StringResponse *ptr);

void destroy_unseal_range_response(UnsealRangeResponse *ptr);

void destroy_unseal_response(UnsealResponse *ptr);

/**
 * Deallocates a VerifyPoStResponse.
 *
 */
void destroy_verify_post_response(VerifyPoStResponse *ptr);

/**
 * Deallocates a VerifySealResponse.
 *
 */
void destroy_verify_seal_response(VerifySealResponse *ptr);

void destroy_write_with_alignment_response(WriteWithAlignmentResponse *ptr);

void destroy_write_without_alignment_response(WriteWithoutAlignmentResponse *ptr);

/**
 * Finalize a partial_ticket.
 */
FinalizeTicketResponse *finalize_ticket(const uint8_t (*partial_ticket)[32]);

/**
 * TODO: document
 *
 */
GenerateCandidatesResponse *generate_candidates(const uint8_t (*randomness)[32],
                                                uint64_t challenge_count,
                                                const FFIPrivateReplicaInfo *replicas_ptr,
                                                size_t replicas_len,
                                                const uint8_t (*prover_id)[32]);

/**
 * Returns the merkle root for a sector containing the provided pieces.
 */
GenerateDataCommitmentResponse *generate_data_commitment(FFIRegisteredSealProof registered_proof,
                                                         const FFIPublicPieceInfo *pieces_ptr,
                                                         size_t pieces_len);

/**
 * Returns the merkle root for a piece after piece padding and alignment.
 * The caller is responsible for closing the passed in file descriptor.
 */
GeneratePieceCommitmentResponse *generate_piece_commitment(FFIRegisteredSealProof registered_proof,
                                                           int piece_fd_raw,
                                                           uint64_t unpadded_piece_size);

/**
 * TODO: document
 *
 */
GeneratePoStResponse *generate_post(const uint8_t (*randomness)[32],
                                    const FFIPrivateReplicaInfo *replicas_ptr,
                                    size_t replicas_len,
                                    const FFICandidate *winners_ptr,
                                    size_t winners_len,
                                    const uint8_t (*prover_id)[32]);

/**
 * Returns an array of strings containing the device names that can be used.
 */
GpuDeviceResponse *get_gpu_devices(void);

/**
 * Returns the number of user bytes that will fit into a staged sector.
 *
 */
uint64_t get_max_user_bytes_per_staged_sector(FFIRegisteredSealProof registered_proof);

/**
 * Returns the identity of the circuit for the provided PoSt proof type.
 *
 */
StringResponse *get_post_circuit_identifier(FFIRegisteredPoStProof registered_proof);

/**
 * Returns the CID of the Groth parameter file for generating a PoSt.
 *
 */
StringResponse *get_post_params_cid(FFIRegisteredPoStProof registered_proof);

/**
 * Returns the path from which the proofs library expects to find the Groth
 * parameter file used when generating a PoSt.
 *
 */
StringResponse *get_post_params_path(FFIRegisteredPoStProof registered_proof);

/**
 * Returns the CID of the verifying key-file for verifying a PoSt proof.
 *
 */
StringResponse *get_post_verifying_key_cid(FFIRegisteredPoStProof registered_proof);

/**
 * Returns the path from which the proofs library expects to find the verifying
 * key-file used when verifying a PoSt proof.
 *
 */
StringResponse *get_post_verifying_key_path(FFIRegisteredPoStProof registered_proof);

/**
 * Returns the version of the provided seal proof.
 *
 */
StringResponse *get_post_version(FFIRegisteredPoStProof registered_proof);

/**
 * Returns the identity of the circuit for the provided seal proof.
 *
 */
StringResponse *get_seal_circuit_identifier(FFIRegisteredSealProof registered_proof);

/**
 * Returns the CID of the Groth parameter file for sealing.
 *
 */
StringResponse *get_seal_params_cid(FFIRegisteredSealProof registered_proof);

/**
 * Returns the path from which the proofs library expects to find the Groth
 * parameter file used when sealing.
 *
 */
StringResponse *get_seal_params_path(FFIRegisteredSealProof registered_proof);

/**
 * Returns the CID of the verifying key-file for verifying a seal proof.
 *
 */
StringResponse *get_seal_verifying_key_cid(FFIRegisteredSealProof registered_proof);

/**
 * Returns the path from which the proofs library expects to find the verifying
 * key-file used when verifying a seal proof.
 *
 */
StringResponse *get_seal_verifying_key_path(FFIRegisteredSealProof registered_proof);

/**
 * Returns the version of the provided seal proof type.
 *
 */
StringResponse *get_seal_version(FFIRegisteredSealProof registered_proof);

/**
 * Compute the digest of a message
 *
 * # Arguments
 *
 * * `message_ptr` - pointer to a message byte array
 * * `message_len` - length of the byte array
 */
HashResponse *hash(const uint8_t *message_ptr, size_t message_len);

/**
 * Generate a new private key
 */
PrivateKeyGenerateResponse *private_key_generate(void);

/**
 * Generate a new private key with seed
 *
 * **Warning**: Use this function only for testing or with very secure seeds
 *
 * # Arguments
 *
 * * `raw_seed_ptr` - pointer to a seed byte array with 32 bytes
 *
 * Returns `NULL` when passed a NULL pointer.
 */
PrivateKeyGenerateResponse *private_key_generate_with_seed(const uint8_t (*raw_seed_ptr)[32]);

/**
 * Generate the public key for a private key
 *
 * # Arguments
 *
 * * `raw_private_key_ptr` - pointer to a private key byte array
 *
 * Returns `NULL` when passed invalid arguments.
 */
PrivateKeyPublicKeyResponse *private_key_public_key(const uint8_t *raw_private_key_ptr);

/**
 * Sign a message with a private key and return the signature
 *
 * # Arguments
 *
 * * `raw_private_key_ptr` - pointer to a private key byte array
 * * `message_ptr` - pointer to a message byte array
 * * `message_len` - length of the byte array
 *
 * Returns `NULL` when passed invalid arguments.
 */
PrivateKeySignResponse *private_key_sign(const uint8_t *raw_private_key_ptr,
                                         const uint8_t *message_ptr,
                                         size_t message_len);

/**
 * TODO: document
 *
 */
SealCommitPhase1Response *seal_commit_phase1(FFIRegisteredSealProof registered_proof,
                                             const uint8_t (*comm_r)[32],
                                             const uint8_t (*comm_d)[32],
                                             const char *cache_dir_path,
                                             const char *replica_path,
                                             uint64_t sector_id,
                                             const uint8_t (*prover_id)[32],
                                             const uint8_t (*ticket)[32],
                                             const uint8_t (*seed)[32],
                                             const FFIPublicPieceInfo *pieces_ptr,
                                             size_t pieces_len);

SealCommitPhase2Response *seal_commit_phase2(const uint8_t *seal_commit_phase1_output_ptr,
                                             size_t seal_commit_phase1_output_len,
                                             uint64_t sector_id,
                                             const uint8_t (*prover_id)[32]);

/**
 * TODO: document
 *
 */
SealPreCommitPhase1Response *seal_pre_commit_phase1(FFIRegisteredSealProof registered_proof,
                                                    const char *cache_dir_path,
                                                    const char *staged_sector_path,
                                                    const char *sealed_sector_path,
                                                    uint64_t sector_id,
                                                    const uint8_t (*prover_id)[32],
                                                    const uint8_t (*ticket)[32],
                                                    const FFIPublicPieceInfo *pieces_ptr,
                                                    size_t pieces_len);

/**
 * TODO: document
 *
 */
SealPreCommitPhase2Response *seal_pre_commit_phase2(const uint8_t *seal_pre_commit_phase1_output_ptr,
                                                    size_t seal_pre_commit_phase1_output_len,
                                                    const char *cache_dir_path,
                                                    const char *sealed_sector_path);

/**
 * TODO: document
 */
UnsealResponse *unseal(FFIRegisteredSealProof registered_proof,
                       const char *cache_dir_path,
                       const char *sealed_sector_path,
                       const char *unseal_output_path,
                       uint64_t sector_id,
                       const uint8_t (*prover_id)[32],
                       const uint8_t (*ticket)[32],
                       const uint8_t (*comm_d)[32]);

/**
 * TODO: document
 */
UnsealRangeResponse *unseal_range(FFIRegisteredSealProof registered_proof,
                                  const char *cache_dir_path,
                                  const char *sealed_sector_path,
                                  const char *unseal_output_path,
                                  uint64_t sector_id,
                                  const uint8_t (*prover_id)[32],
                                  const uint8_t (*ticket)[32],
                                  const uint8_t (*comm_d)[32],
                                  uint64_t offset,
                                  uint64_t length);

/**
 * Verify that a signature is the aggregated signature of hashes - pubkeys
 *
 * # Arguments
 *
 * * `signature_ptr`             - pointer to a signature byte array (SIGNATURE_BYTES long)
 * * `flattened_digests_ptr`     - pointer to a byte array containing digests
 * * `flattened_digests_len`     - length of the byte array (multiple of DIGEST_BYTES)
 * * `flattened_public_keys_ptr` - pointer to a byte array containing public keys
 */
int verify(const uint8_t *signature_ptr,
           const uint8_t *flattened_digests_ptr,
           size_t flattened_digests_len,
           const uint8_t *flattened_public_keys_ptr,
           size_t flattened_public_keys_len);

/**
 * Verifies that a proof-of-spacetime is valid.
 */
VerifyPoStResponse *verify_post(const uint8_t (*randomness)[32],
                                uint64_t challenge_count,
                                const FFIPublicReplicaInfo *replicas_ptr,
                                size_t replicas_len,
                                const FFIPoStProof *proofs_ptr,
                                size_t proofs_len,
                                const FFICandidate *winners_ptr,
                                size_t winners_len,
                                const uint8_t (*prover_id)[32]);

/**
 * Verifies the output of seal.
 *
 */
VerifySealResponse *verify_seal(FFIRegisteredSealProof registered_proof,
                                const uint8_t (*comm_r)[32],
                                const uint8_t (*comm_d)[32],
                                const uint8_t (*prover_id)[32],
                                const uint8_t (*ticket)[32],
                                const uint8_t (*seed)[32],
                                uint64_t sector_id,
                                const uint8_t *proof_ptr,
                                size_t proof_len);

/**
 * TODO: document
 *
 */
WriteWithAlignmentResponse *write_with_alignment(FFIRegisteredSealProof registered_proof,
                                                 int src_fd,
                                                 uint64_t src_size,
                                                 int dst_fd,
                                                 const uint64_t *existing_piece_sizes_ptr,
                                                 size_t existing_piece_sizes_len);

/**
 * TODO: document
 *
 */
WriteWithoutAlignmentResponse *write_without_alignment(FFIRegisteredSealProof registered_proof,
                                                       int src_fd,
                                                       uint64_t src_size,
                                                       int dst_fd);

#endif /* FILECOIN_H */

#ifdef __cplusplus
} /* extern "C" */
#endif

