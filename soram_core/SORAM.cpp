#include "SORAM.h"

#include <cmath>
#include <cryptopp/osrng.h>
#include <utility>      // std::pair
#include "../Util/MongoConnector.h"
#include "../Util/Config.h"


// tmp use start
#include <iostream>
#include <math.h>
#include <assert.h>
using std::cout;
using std::endl;
// tmp use end

using namespace CryptoPP;

// Warning : just allow the cipher2 to be segmented, cipher1 must be Enc(1) or Enc(0)!!!
//server side patch function
void SSORAM_Server_core::djcs_e01e_mul(djcs_public_key *pk, mpz_t*& rop,size_t& arrLen, mpz_t cipher1, mpz_t cipher2,uint32_t segLenInBytes){
	size_t cipher2_bytes,off=0;
	char *buf;
	buf = mpz_get_str(NULL,2,cipher2);
	cipher2_bytes = mpz_sizeinbase(cipher2,2);
	size_t totolSeg = ceil(double(cipher2_bytes)/segLenInBytes);
	/*parse to part
	 * first bit --|-------|-------|------|------- last bit|
	 *   part seg  segment  segment         segment
	 *   totolSeg-1  totolSeg-2        1      0
	 */
	off =cipher2_bytes - segLenInBytes;
	mpz_t* tmpArr = new mpz_t[totolSeg];
	for(int i=0;i<totolSeg-1;i++){
		mpz_init(tmpArr[i]);
		mpz_set_str (tmpArr[i], buf+off,2);
		buf[off] = 0;
		off-=segLenInBytes;
	}
	mpz_init(tmpArr[totolSeg-1]);
	mpz_set_str(tmpArr[totolSeg-1],buf,2);
	for(int i=0;i<totolSeg;i++){
		djcs_ep_mul(pk,tmpArr[i],cipher1,tmpArr[i]);
	}
	//merge
	rop = tmpArr;
	arrLen = totolSeg;
}

//client side patch function
void SSORAM_Client_core::djcs_decrypt_merge_array(djcs_private_key *vk,mpz_t rop,mpz_t* tmpArr,size_t& totolSeg,uint32_t segLenInBytes){
	size_t tmpoff=0;
	mpz_set_ui(rop,0);
	for(int i=0;i<totolSeg;i++){
		djcs_decrypt(vk,tmpArr[i],tmpArr[i]);
		mpz_mul_2exp(tmpArr[i],tmpArr[i],tmpoff);
		mpz_add(rop,rop,tmpArr[i]);
		tmpoff+=segLenInBytes;
	}
	djcs_decrypt(vk,rop,rop);
}
void djcs_decrypt_merge_array(djcs_private_key *vk,mpz_t rop,mpz_t* tmpArr,size_t& totolSeg,uint32_t segLenInBytes){
	size_t tmpoff=0;
	mpz_set_ui(rop,0);
	for(int i=0;i<totolSeg;i++){
		djcs_decrypt(vk,tmpArr[i],tmpArr[i]);
		mpz_mul_2exp(tmpArr[i],tmpArr[i],tmpoff);
		mpz_add(rop,rop,tmpArr[i]);
		tmpoff+=segLenInBytes;
	}
	djcs_decrypt(vk,rop,rop);
}
//server side patch function
//warning cipher1,cipher2 must have same segmentation length and segLen
mpz_t* SSORAM_Server_core::djcs_e01e_add(djcs_public_key *pk,mpz_t*& rop,const size_t cipher_len1,const size_t cipher_len2,mpz_t* cipher1, mpz_t* cipher2){
	assert(cipher_len1==cipher_len2);
	//calcu
	mpz_t* tmpArr = new mpz_t[cipher_len1];
	for(int i=0;i<cipher_len1;i++){
		mpz_init(tmpArr[i]);
		djcs_ee_add(pk, tmpArr[i], cipher1[i], cipher2[i]);
	}
	//return
	if(rop !=NULL)
		delete[] rop;
	rop = tmpArr;
	return tmpArr;
}
uint32_t Dummy = 0;
void SSORAM::test(){
	// there exists a potential risk on mongodb restore , but I cannot recover the bug setting now, it becomes normal! I have to remains this and check the bug later
	mpz_t c;
	mpz_init(c);
	char* buf;
	for(uint32_t id=2;id<(2<<height);id++){
			std::string data = conn->find(id);
			mpz_set_str (c, data.c_str(),16);
			buf = mpz_get_str(NULL,2,c);
			cout<<"fetch id:\t"<<id<<"\tlen:\t"<<mpz_sizeinbase(c,2)<<"datalength:\t"<<data.length()<<"\tvalue:\t\n"<<buf<<endl;
	        djcs_decrypt(dj_vk, c, c);
	        gmp_printf("fetch id:\t%d,multiply value:\t %Zd\n", id,c);
	    }
	mpz_clear(c);
}
SSORAM::SSORAM(const uint32_t& n) {
    height = (uint32_t)ceil(log2((double)(n+1)));
    n_blocks = (uint32_t)2 << (height - 1);
    pos_map = new posMap_struct[n];
    conn = new MongoConnector(server_host, "oram.path18");
    blockMap = new block_type[2<<height];
    for(int i=0;i<(2<<height);i++)
    	blockMap[i] = DummyType;
    //initialize key
    dj_pk = djcs_init_public_key();
    dj_vk = djcs_init_private_key();
    hr = hcs_init_random();
    djcs_generate_key_pair(dj_pk,dj_vk,hr,2,2048);

    //filling server space with dummy block
    mpz_t value;
    mpz_inits(dummyBlock,value,NULL);
    mpz_set_ui(dummyBlock,Dummy);
    char *buf;

    for(uint32_t id=2;id<(2<<height);id++){
        djcs_encrypt(dj_pk, hr, value, dummyBlock); 
        buf = mpz_get_str(NULL,16,value);
        conn->insert(id, std::string(buf,mpz_sizeinbase(value,16)));
    }
    mpz_clears(dummyBlock,value,NULL);
    //intialize server and client_core
    first_empty_L = 1;
    server = new SSORAM_Server_core((uint32_t) (2<<height),dj_pk,conn);
    client_core = new SSORAM_Client_core(dj_pk,hr,n_blocks,height);
}
SSORAM_Server_core::SSORAM_Server_core(const uint32_t& bufferLen,djcs_public_key *_dj_pk,ServerConnector* _conn){
    tmpBuffer = new std::string[bufferLen];
    conn = _conn;
    dj_pk = _dj_pk;
}
SSORAM_Server_core::~SSORAM_Server_core(){
    delete[] tmpBuffer;
}
SSORAM_Client_core::SSORAM_Client_core(djcs_public_key *_pk,hcs_random* _hr,uint32_t& _n_blocks, uint32_t _height){
    dj_pk = _pk;
    hr = _hr;
    mpz_inits(zero,one,encryptZero,encryptOne,NULL);
    mpz_set_ui(zero,0);
    mpz_set_ui(one,1);
    n_blocks = _n_blocks;
    height = _height;
}
SSORAM_Client_core::~SSORAM_Client_core(){
    mpz_clears(zero,one,encryptZero,encryptOne,NULL);
}

SSORAM::~SSORAM(){
    delete[] pos_map;
    delete conn;

    mpz_clear(dummyBlock);

    djcs_free_public_key(dj_pk);
    djcs_free_private_key(dj_vk);
    hcs_free_random(hr);
}

std::string SSORAM::get(const std::string & key) {
    std::string res;
    uint32_t int_key;
    sscanf(key.c_str(), "%d", &int_key);
    access('r', int_key, res);
    return res;
}


void SSORAM::put(const std::string & key, const std::string & value) {
    uint32_t int_key;
    sscanf(key.c_str(), "%d", &int_key);
    std::string value2 = value;
    access('w', int_key, value2);
}


std::string SSORAM::get(const uint32_t & key) {
    std::string res;
    access('r', key, res);
    return res;
}

void SSORAM::put(const uint32_t & key, const std::string & value) {
    std::string value2 = value;
    access('w', key, value2);
}

void SSORAM::access(const char& op, const uint32_t& block_id, std::string& data){
	/*pos_map[block_id].level = 1;
	pos_map[block_id].offset = 1;*/
	//test();
	std::string result = Read(pos_map[block_id].level,pos_map[block_id].offset);
	cout<<"result\t"<<result<<endl;
    if (op == 'w'){
    	result = data;
    	Write(result,RealType,block_id);
    }else{
    	Write(result,DummyType,block_id);
    }
    data = result;
    /*mpz_t c;
    mpz_init(c);
    //mpz_import(c, strlen(data.c_str()), 1, sizeof(char), 0, 0, data.c_str());
    mpz_import(c, data.length(), 1, sizeof(char), 0, 0, data.c_str());
    djcs_decrypt(dj_vk,c,c);
    gmp_sprintf(OutputBuff,"%Zd",c);
    data = std::string(OutputBuff);*/
}
std::string SSORAM::Read(uint32_t& level, int32_t& off){
	std::vector< std::pair<std::pair<uint32_t,int32_t>, __mpz_struct> > vec;
	size_t len;
	mpz_t data;
	mpz_init(data);
	vec.clear();
	client_core->Read(level,off,vec);
	mpz_t* result = server->Read(vec,len);
	client_core->djcs_decrypt_merge_array(dj_vk,data,result,len);
	char* buf = mpz_get_str(NULL,10,data);
	return std::string(buf,mpz_sizeinbase(data,10));
}
void SSORAM::Write(std::string& data,block_type dataType,const uint32_t& block_id){
	std::string A[2];
	char* buf;
	mpz_t tmpNum;
	mpz_init(tmpNum);
	if(dataType==DummyType){
		blockMap[0] = DummyType;
		blockMap[1] = DummyType;
		djcs_encrypt(dj_pk, hr, tmpNum, dummyBlock);
		buf = mpz_get_str(NULL,16,tmpNum);
		A[0] = std::string(buf,mpz_sizeinbase(tmpNum,16));
		djcs_encrypt(dj_pk, hr, tmpNum, dummyBlock);
		buf = mpz_get_str(NULL,16,tmpNum);
		A[1] = std::string(buf,mpz_sizeinbase(tmpNum,16));
	}else{
		size_t r = Util::rand_int(2);
		blockMap[r] = RealType;
		blockMap[1-r] = DummyType;
		A[r] = data;
		djcs_encrypt(dj_pk, hr, tmpNum, dummyBlock);
		buf = mpz_get_str(NULL,16,tmpNum);
		A[1-r] = std::string(buf,mpz_sizeinbase(tmpNum,16));
		pos_map[block_id].level = 0;
		pos_map[block_id].offset = r;
	}
	//djcs_encrypt(dj_pk, hr, encryptOne, one);

	//gc
	mpz_clear(tmpNum);
    cout<<"Evict function get\n";
}
void SSORAM_Server_core::receiveTwinBlock(std::string A1, std::string A2,bool insert){
	if(insert){
		conn->insert(2,A1);
		conn->insert(3,A2);
	}else{
		tmpBuffer[0] = A1;
		tmpBuffer[1] = A2;
	}
}
void SSORAM_Client_core::Read(uint32_t& level, int32_t& off,std::vector< std::pair<std::pair<uint32_t,int32_t>, __mpz_struct> >& vec){
	vec.clear();
	for(uint32_t i=1;i<=height;i++){
		if(i==level){
			djcs_encrypt(dj_pk, hr, encryptOne, one);
			vec.push_back(std::make_pair(std::make_pair(i,off),encryptOne[0]));
			cout<<"client ins fetch level:\t"<<i<<"\t offset\t"<<off<<endl;
		}else{
			djcs_encrypt(dj_pk, hr, encryptZero, zero);
			size_t random_offset = Util::rand_int(1<<i);
			cout<<"client ins fetch level:\t"<<i<<"\t random offset\t"<<random_offset<<endl;
			vec.push_back(std::make_pair(std::make_pair(i,random_offset),encryptZero[0]));
		}
	}
}
mpz_t* SSORAM_Server_core::Read(std::vector< std::pair<std::pair<uint32_t,int32_t>, __mpz_struct> > vec,size_t& segLen){
	std::string data;
	mpz_t c;
	mpz_t* tmp_result,*result;
	size_t tmp_len,len;
	mpz_init(c);
	data = conn->find((1<<vec[0].first.first)+vec[0].first.second);
	mpz_set_str (c, data.c_str(),16);
	//cout<<"server ins fetch level:\t"<<(vec[0].first.first)<<"\t offset\t"<<vec[0].first.second<<endl;
	djcs_e01e_mul(dj_pk,tmp_result,tmp_len,&vec[0].second,c);
	result = tmp_result;
	len = tmp_len;
	for(uint32_t i=1;i<vec.size();i++){
		data = conn->find((1<<vec[i].first.first)+vec[i].first.second);
		//cout<<"server ins fetch level:\t"<<(vec[i].first.first)<<"\t offset\t"<<vec[i].first.second<<endl;
		mpz_set_str (c, data.c_str(),16);
		djcs_e01e_mul(dj_pk,tmp_result,tmp_len,&vec[i].second,c);
 		djcs_e01e_add(dj_pk,result,tmp_len,len,tmp_result,result);
	}
	segLen = tmp_len;
	return result;

}
/*void SORAM::access(const char& op, const uint32_t& block_id, std::string& data) {
    uint32_t x = pos_map[block_id];
    pos_map[block_id] = Util::rand_int(n_blocks);

    size_t length;
    fetchAlongPath(x, sbuffer, length);
    for (size_t i = 0; i < length; ++i) {
        std::string plain;
        Util::aes_decrypt(sbuffer[i], key, plain);

        int32_t b_id;
        memcpy(&b_id, plain.c_str(), sizeof(uint32_t));
        if (b_id != -1) {
            stash[b_id] = plain.substr(sizeof(uint32_t));
        }
    }

    if (op == 'r') data = stash[block_id];
    else stash[block_id] = data;

    for (uint32_t i = 0; i < height; ++i) {
        uint32_t tot = 0;
        uint32_t base = i * PathORAM_Z;
        std::unordered_map<uint32_t, std::string>::iterator j, tmp;
        j = stash.begin();
        while (j != stash.end() && tot < PathORAM_Z) {
            if (check(pos_map[j->first], x, i)) {
                std::string b_id = std::string((const char *)(&(j->first)), sizeof(uint32_t));
                sbuffer[base + tot] = b_id + j->second;
                tmp = j; ++j; stash.erase(tmp);
                ++tot;
            } else ++j;
        }
        for (int k = tot; k < PathORAM_Z; ++k) {
            std::string tmp_block  = Util::generate_random_block(B - Util::aes_block_size - sizeof(uint32_t));
            int32_t dummyID = -1;
            std::string dID = std::string((const char *)(& dummyID), sizeof(uint32_t));
            sbuffer[base + k] = dID + tmp_block;
        }
    }

    for (size_t i = 0; i < height * PathORAM_Z; ++i) {
        std::string cipher;
        Util::aes_encrypt(sbuffer[i], key, cipher);
        sbuffer[i] = cipher;
    }
    loadAlongPath(x, sbuffer, height * PathORAM_Z);
}

bool SORAM::check(int x, int y, int l) {
    return (x >> l) == (y >> l);
}

void SORAM::fetchAlongPath(const uint32_t& x, std::string* sbuffer, size_t& length) {
    uint32_t cur_pos = x + (1 << (height - 1));
    std::vector<uint32_t> ids;
    while (cur_pos > 0) {
        for (uint32_t i = 0; i < PathORAM_Z; ++i)
            ids.push_back((cur_pos - 1) * PathORAM_Z + i);
        cur_pos >>= 1;
    }
    conn->find(ids, sbuffer, length);
}

void SORAM::loadAlongPath(const uint32_t& x, const std::string* sbuffer, const size_t& length) {
    uint32_t cur_pos = x + (1 << (height - 1));
    uint32_t offset = 0;
    insert_buffer.clear();
    while (cur_pos > 0) {
        for (uint32_t i = 0; i < PathORAM_Z; ++i)
            insert_buffer.emplace_back(std::make_pair((cur_pos - 1) * PathORAM_Z + i, sbuffer[offset + i]));
        offset += PathORAM_Z;
        cur_pos >>= 1;
    }
    conn->update(insert_buffer);
}*/
