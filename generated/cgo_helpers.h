// WARNING: This file has automatically been generated 
// Code generated by https://git.io/c-for-go. DO NOT EDIT.

#include "../filcrypto.h"
#include <stdlib.h>
#pragma once

#define __CGOGEN 1

// fil_NetReadCallback_eda104b4 is a proxy for callback fil_NetReadCallback.
unsigned long int fil_NetReadCallback_eda104b4(unsigned long int sector_id, char* cache_id, unsigned long int offset, unsigned long int size, char* buf);

// fil_MerkleTreeProofCallback_19bb3bc0 is a proxy for callback fil_MerkleTreeProofCallback.
unsigned long int fil_MerkleTreeProofCallback_19bb3bc0(unsigned long int sector_id, unsigned long int j, unsigned long int i, unsigned long int num_sectors_per_chunk, char* randomness, char* proof, unsigned long int proof_len);

