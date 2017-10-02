#ifndef AUXILIARY_H
#define AUXILIARY_H


#include <mongo/client/dbclient.h>
#include <cryptopp/osrng.h>
#include "Util/Config.h"
#include "soram_core/ORAM.h"
#include "soram_core/SORAM.h"
#include <gmp.h>    // gmp is included implicitly
#include <libhcs.h> // master header includes everything
#include <iostream>
#include <time.h>
#include <unistd.h>
#include <assert.h>
using std::cout;
using std::endl;

using namespace mongo;
using namespace CryptoPP;



void test_jd_encryption_efficiency();
void test_jd_decryption_efficiency();
void test_jd_add_efficiency();
void test_jd_mul_efficiency();
void test_jd_efficiency();
void test_p_encryption_efficiency();
void test_p_decryption_efficiency();
void test_p_add_efficiency();
void test_p_mul_efficiency();
void test_p_efficiency();
void test_jd_encryption();
void test_jd();
void test_pathOram();
void test_sOram();
void djcs_e01e_mul(djcs_public_key *pk, mpz_t*& rop,size_t& arrLen, mpz_t cipher1, mpz_t cipher2,uint32_t segLenInBits = 4000);
void djcs_e01e_mul_multi(djcs_public_key *pk, mpz_t*& rop,size_t& arrLen, mpz_t cipher1, mpz_t* cipher2,size_t cipher2_len,uint32_t segLenInBits = 4000,uint32_t DecryptionLen = 6155);

void djcs_decrypt_merge_array_multi(djcs_private_key *vk,mpz_t*& rop,size_t& arrLen,mpz_t* tmpArr,size_t& totolSeg,uint32_t segLenInBits = 4000,uint32_t DecryptionLen = 6155);

#endif //AUXILIARY_H
