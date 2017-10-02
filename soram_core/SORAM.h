#ifndef SORAM_H
#define SORAM_H

#include <string>
#include <gmp.h> 
#include <unordered_map>
#include <cryptopp/config.h>
#include "../Util/ServerConnector.h"
#include "ORAM.h"
#include "../Util/Util.h"
#include <libhcs.h>

extern uint32_t Dummy;
enum block_type {DummyType, RealType, NoisyType};
struct posMap_struct{
    posMap_struct(){
        level = 0;
        offset = 0;
    }
    uint32_t level;
    int32_t offset;
};
class SSORAM_Client_core{
public:
    SSORAM_Client_core(djcs_public_key *_pk,hcs_random* _hr,uint32_t& _n_blocks, uint32_t _height);
    virtual ~SSORAM_Client_core();
	void Read(uint32_t& level, int32_t& off,std::vector< std::pair<std::pair<uint32_t,int32_t>, __mpz_struct> >& vec);
	void djcs_decrypt_merge_array(djcs_private_key *vk,mpz_t rop,mpz_t* src,size_t& arrLen,uint32_t segLenInBytes= (uint32_t)4000);
	void djcs_decrypt_merge_array_multi(djcs_private_key *vk,mpz_t*& rop,size_t& arrLen,mpz_t* tmpArr,size_t& totolSeg,uint32_t segLenInBits = 4000,uint32_t DecryptionLen = 6155);
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
    SSORAM_Server_core(const uint32_t& bufferLen,djcs_public_key *_dj_pk,ServerConnector* _conn);
    virtual ~SSORAM_Server_core();
    mpz_t* Read(std::vector< std::pair<std::pair<uint32_t,int32_t>, __mpz_struct> >,size_t& segLen);
    void receiveTwinBlock(std::string A1, std::string A2,bool insert);
private:
    void djcs_e01e_mul_multi(djcs_public_key *pk, mpz_t*& rop,size_t& arrLen, mpz_t cipher1, mpz_t* cipher2,size_t cipher2_len,uint32_t segLenInBits = 4000,uint32_t DecryptionLen = 6155);
    mpz_t* djcs_e01e_add(djcs_public_key *pk,mpz_t*& rop,const size_t cipher_len1,const size_t cipher_len2,mpz_t* cipher1, mpz_t* cipher2);
    void djcs_e01e_mul(djcs_public_key *pk, mpz_t*& rop,size_t& arrLen, mpz_t cipher1, mpz_t cipher2,uint32_t segLenInBytes= (uint32_t)4000);
    ServerConnector* conn;
    djcs_public_key *dj_pk;
    std::string* tmpBuffer;
    char OutputBuff[4097];
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
    void access(const char& op, const uint32_t& block_id, std::string& data);
    std::string Read(uint32_t& level, int32_t& off);
    void Write(std::string& data,block_type dataType,const uint32_t& block_id);

    uint32_t first_empty_L;
    uint32_t n_blocks;
    uint32_t height;
    ServerConnector* conn;
    SSORAM_Client_core* client_core;
    SSORAM_Server_core* server;
    posMap_struct* pos_map;
    block_type *blockMap;

    djcs_public_key *dj_pk;
    djcs_private_key *dj_vk;
    hcs_random *hr;

    mpz_t dummyBlock;

    char OutputBuff[4097];
};

//patch function
void djcs_decrypt_merge_array(djcs_private_key *vk,mpz_t rop,mpz_t* tmpArr,size_t& totolSeg,uint32_t segLenInBytes=4000);
mpz_t* djcs_e01e_add(djcs_public_key *pk,mpz_t*& rop,const size_t cipher_len1,const size_t cipher_len2,mpz_t* cipher1, mpz_t* cipher2);




/*
class SORAM: public ORAM {
public:
    SORAM(const uint32_t& n);
    virtual ~SORAM();

    virtual std::string get(const std::string & key);
    virtual void put(const std::string & key, const std::string & value);

    virtual std::string get(const uint32_t & key);
    virtual void put(const uint32_t & key, const std::string & value);
private:
    void access(const char& op, const uint32_t& block_id, std::string& data);
    bool check(int x, int y, int l);

    void fetchAlongPath(const uint32_t& x, std::string* sbuffer, size_t& length);
    void loadAlongPath(const uint32_t& x, const std::string* sbuffer, const size_t& length);

    std::unordered_map<uint32_t, std::string> stash;
    uint32_t *pos_map;
    std::vector< std::pair<uint32_t, std::string> > insert_buffer;

    byte* key;
    std::string* sbuffer;
    uint32_t n_blocks;
    uint32_t height;

    ServerConnector* conn;
};*/

#endif //SORAM_H

