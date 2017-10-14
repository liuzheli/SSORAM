#ifndef SORAM_H
#define SORAM_H

#include <string>
#include <gmp.h> 
#include <unordered_map>
#include <set>
#include <cryptopp/config.h>
#include <unordered_map>
#include "../Util/ServerConnector.h"
#include "ORAM.h"
#include "../Util/Util.h"
#include <libhcs.h>

extern uint32_t Dummy;
enum block_type {DummyType, RealType, NoisyType};
class SSORAM_Client_core{
public:
    SSORAM_Client_core(djcs_public_key *_pk,hcs_random* _hr,uint32_t& _n_blocks, uint32_t _height);
    virtual ~SSORAM_Client_core();
	void Read(uint32_t& level, uint32_t& off,std::vector< std::pair<std::pair<uint32_t,int32_t>, __mpz_struct> >& vec);
	void djcs_decrypt_merge_array(djcs_private_key *vk,mpz_t rop,mpz_t* src,size_t& arrLen,uint32_t segLenInBytes= (uint32_t)4000);
	void djcs_decrypt_merge_array_multi(djcs_private_key *vk,mpz_t*& rop,size_t& arrLen,mpz_t* tmpArr,size_t& totolSeg,uint32_t segLenInBits = 4000,uint32_t DecryptionLen = 6155);
	void GenVector(djcs_private_key *vk,const block_type *blockMap,const uint32_t merge_level,std::vector<__mpz_struct >& vec);
private:
    djcs_public_key *dj_pk;
    hcs_random *hr;

    mpz_t zero;
    mpz_t one;
    mpz_t encryptZero;
    mpz_t encryptOne;
    uint32_t n_blocks;
    uint32_t height;
};
class SSORAM_Server_core{
public:
    SSORAM_Server_core(const uint32_t& bufferLen,djcs_public_key *_dj_pk,ServerConnector* _conn,uint32_t _height);
    virtual ~SSORAM_Server_core();
    mpz_t* Read(djcs_private_key *vk,std::vector< std::pair<std::pair<uint32_t,int32_t>, __mpz_struct> >,size_t& segLen);
    void freshLayerSpan_vector(mpz_t& _vec);
    void insert(const uint32_t& id, mpz_t value, const std::string& ns = "");
    void update(const uint32_t& id, mpz_t value, const std::string& ns = "");
    void update(const uint32_t& id, mpz_t *value, const size_t& len, const std::string& ns = "");
    mpz_t* find(const uint32_t& id,size_t& len,const std::string& ns = "");
    uint32_t writeBack(mpz_t* A,size_t len);
    bool writeBackTo(const uint32_t empty_level);
    bool Merge(djcs_private_key *vk,const uint32_t& merge_level,std::vector<__mpz_struct >& vec,std::pair<uint32_t,int32_t>* pairs, const uint32_t& pair_len);

private:
    void djcs_e01e_mul_multi(djcs_public_key *pk, mpz_t*& rop,size_t& arrLen, mpz_t cipher1, mpz_t* cipher2,size_t cipher2_len,uint32_t segLenInBits = 4000,uint32_t DecryptionLen = 6155);
    mpz_t* djcs_e01e_add(djcs_public_key *pk,mpz_t*& rop,const size_t cipher_len1,const size_t cipher_len2,mpz_t* cipher1, mpz_t* cipher2);
    void djcs_e01e_mul(djcs_public_key *pk, mpz_t*& rop,size_t& arrLen, mpz_t cipher1, mpz_t cipher2,uint32_t segLenInBytes= (uint32_t)4000);
    ServerConnector* conn;
    djcs_public_key *dj_pk;
    mpz_t **tmpBuffer;
    size_t *tmpBuffer_dataLen;
    size_t tmpBuffer_len;
    uint32_t buffer_usage;
    uint32_t height,bufferLen;
    bool* level_usage;
    mpz_t layerSpan_vector;
};
class SSORAM: public ORAM{
public:
    SSORAM(const uint32_t& n);
    virtual ~SSORAM();

    virtual std::string get(const std::string& key);
    virtual void put(const std::string &key, const std::string &value);

    virtual std::string get(const uint32_t & key);
    virtual void put(const uint32_t & key, const std::string & value);
    void test();
private:
    void access(const char& op, const uint32_t& block_id, mpz_t& data);
    mpz_t* Read(uint32_t level, uint32_t off);
    void Write(const mpz_t& data,block_type dataType,const uint32_t& block_id);
    void Shuffle(uint32_t empty_level);
    bool Merge(const uint32_t merge_level);
    bool MergeInPlace(const uint32_t merge_level);
    void GenPairs(const uint32_t merge_level,std::pair<uint32_t,int32_t>*& vec,uint32_t& vec_len,bool TopLevel = false);
    //Guarantee the dummyset and realset has enought space or NULL pass in
    void parseSet(const uint32_t& start, const uint32_t& end,uint32_t*& dummyset,uint32_t*& realset);
    block_type getBlockType(const uint32_t& id1, const uint32_t& id2);


    uint32_t first_empty_L;
    uint32_t n_blocks;
    uint32_t height;
    ServerConnector* conn;
    SSORAM_Client_core* client_core;
    SSORAM_Server_core* server;
    std::unordered_map<uint32_t, uint32_t> pos_map;
    std::unordered_map<uint32_t, uint32_t> pos_map_inv;
    block_type *blockMap;

    djcs_public_key *dj_pk;
    djcs_private_key *dj_vk;
    hcs_random *hr;

    mpz_t dummyBlock;

    char OutputBuff[4097];
};

//patch function
uint32_t getLevel(uint32_t id);
void CharArr2Number(const char* str, uint32_t len,mpz_t rop);
// if des_str is not NULL then please make sure that the space is big enough or make gc=true
char* Number2CharArr(char* des_str, uint32_t& des_len,mpz_t data, bool gc = true);
void djcs_decrypt_merge_array(djcs_private_key *vk,mpz_t rop,mpz_t* tmpArr,size_t& totolSeg,uint32_t segLenInBytes=4000);
mpz_t* djcs_e01e_add(djcs_public_key *pk,mpz_t*& rop,const size_t cipher_len1,const size_t cipher_len2,mpz_t* cipher1, mpz_t* cipher2);
std::string blockType_str(const block_type blk);
#endif //SSORAM_H

