#include "SORAM.h"

#include <cmath>
#include <cryptopp/osrng.h>
#include <utility>      // std::pair
#include "../Util/MongoConnector.h"
#include "../Util/Config.h"
#include <string>


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
	for(size_t i=0;i<totolSeg-1;i++){
		mpz_init(tmpArr[i]);
		mpz_set_str (tmpArr[i], buf+off,2);
		buf[off] = 0;
		off-=segLenInBytes;
	}
	mpz_init(tmpArr[totolSeg-1]);
	mpz_set_str(tmpArr[totolSeg-1],buf,2);
	for(size_t i=0;i<totolSeg;i++){
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
	for(size_t i=0;i<totolSeg;i++){
		djcs_decrypt(vk,tmpArr[i],tmpArr[i]);
		mpz_mul_2exp(tmpArr[i],tmpArr[i],tmpoff);
		mpz_add(rop,rop,tmpArr[i]);
		tmpoff+=segLenInBytes;
	}
	djcs_decrypt(vk,rop,rop);
}
void SSORAM_Client_core::djcs_decrypt_merge_array_multi(djcs_private_key *vk,mpz_t*& rop,size_t& arrLen,mpz_t* tmpArr,size_t& totolSeg,uint32_t segLenInBits,uint32_t DecryptionLen){
	size_t tmpoff=0,cipher2_bytes=0,off=0;
	mpz_t tmpRop;
	mpz_init(tmpRop);
	mpz_set_ui(tmpRop,0);
	for(size_t i=0;i<totolSeg;i++){
		djcs_decrypt(vk,tmpArr[i],tmpArr[i]);
		mpz_mul_2exp(tmpArr[i],tmpArr[i],tmpoff);
		mpz_add(tmpRop,tmpRop,tmpArr[i]);
		tmpoff+=segLenInBits;
	}
	cipher2_bytes = mpz_sizeinbase(tmpRop,2);
	arrLen = ceil(double(cipher2_bytes)/DecryptionLen);
	char* buf = new char[arrLen*DecryptionLen];
	memset (buf, 0, arrLen*DecryptionLen);
	buf = mpz_get_str(buf,2,tmpRop);
	buf[0] = '0';
	mpz_t* tmpAr = new mpz_t[arrLen];
	off =cipher2_bytes - DecryptionLen;
	for(int i=arrLen-1;i>0;i--){
		mpz_init(tmpAr[i]);
		mpz_set_str (tmpAr[i], buf+off,2);
		buf[off] = 0;
		off-=DecryptionLen;
	}
	mpz_init(tmpAr[0]);
	mpz_set_str(tmpAr[0],buf,2);
	//merge
	if(rop==tmpArr)
		delete[] tmpArr;
	rop = tmpAr;
}
void djcs_decrypt_merge_array(djcs_private_key *vk,mpz_t rop,mpz_t* tmpArr,size_t& totolSeg,uint32_t segLenInBytes){
	size_t tmpoff=0;
	mpz_set_ui(rop,0);
	for(size_t i=0;i<totolSeg;i++){
		djcs_decrypt(vk,tmpArr[i],tmpArr[i]);
		mpz_mul_2exp(tmpArr[i],tmpArr[i],tmpoff);
		mpz_add(rop,rop,tmpArr[i]);
		tmpoff+=segLenInBytes;
	}
	djcs_decrypt(vk,rop,rop);
}
/*void djcs_decrypt_merge_array_multi(djcs_private_key *vk,mpz_t*& rop,size_t& arrLen,mpz_t* tmpArr,size_t& totolSeg,uint32_t segLenInBits,uint32_t DecryptionLen){
	size_t tmpoff=0,cipher2_bytes=0,off=0;
	mpz_t tmpRop;
	mpz_init(tmpRop);
	mpz_set_ui(tmpRop,0);
	for(size_t i=0;i<totolSeg;i++){
		djcs_decrypt(vk,tmpArr[i],tmpArr[i]);
		mpz_mul_2exp(tmpArr[i],tmpArr[i],tmpoff);
		mpz_add(tmpRop,tmpRop,tmpArr[i]);
		tmpoff+=segLenInBits;
	}
	cipher2_bytes = mpz_sizeinbase(tmpRop,2);
	arrLen = ceil(double(cipher2_bytes)/DecryptionLen);
	char* buf = new char[arrLen*DecryptionLen];
	memset (buf, 0, arrLen*DecryptionLen);
	buf = mpz_get_str(buf,2,tmpRop);
	buf[0] = '0';
	mpz_t* tmpAr = new mpz_t[arrLen];
	off =cipher2_bytes - DecryptionLen;
	for(int i=arrLen-1;i>0;i--){
		mpz_init(tmpAr[i]);
		mpz_set_str (tmpAr[i], buf+off,2);
		buf[off] = 0;
		off-=DecryptionLen;
	}
	mpz_init(tmpAr[0]);
	mpz_set_str(tmpAr[0],buf,2);
	//merge
	if(rop==tmpArr)
		delete[] tmpArr;
	rop = tmpAr;
}*/
//server side patch function
//warning cipher1,cipher2 must have same segmentation length and segLen
mpz_t* SSORAM_Server_core::djcs_e01e_add(djcs_public_key *pk,mpz_t*& rop,const size_t cipher_len1,const size_t cipher_len2,mpz_t* cipher1, mpz_t* cipher2){
	assert(cipher_len1==cipher_len2);
	//calcu
	mpz_t* tmpArr = new mpz_t[cipher_len1];
	for(size_t i=0;i<cipher_len1;i++){
		mpz_init(tmpArr[i]);
		djcs_ee_add(pk, tmpArr[i], cipher1[i], cipher2[i]);
	}
	//return
	if(rop !=NULL)
		delete[] rop;
	rop = tmpArr;
	return tmpArr;
}
void SSORAM_Server_core::djcs_e01e_mul_multi(djcs_public_key *pk, mpz_t*& rop,size_t& arrLen, mpz_t cipher1, mpz_t* cipher2,size_t cipher2_len,uint32_t segLenInBits,uint32_t DecryptionLen){
	if(cipher2_len==1){
		djcs_e01e_mul(pk,rop,arrLen,cipher1,cipher2[0],segLenInBits);
	}else{
		size_t cipher2_bytes=0;
		size_t *mpzLen = new size_t[cipher2_len];
		for(size_t i=0;i<cipher2_len;i++){
			mpzLen[i] = mpz_sizeinbase(cipher2[i],2);
			cipher2_bytes += DecryptionLen;
		}

		size_t totolSeg = ceil(double(cipher2_bytes)/segLenInBits);
		char *buf = new char[totolSeg*segLenInBits+2];
		memset (buf, 0, totolSeg*segLenInBits+2);
		char *offBuf = buf;
		//special treat for 0
		*(offBuf++) = '1';
		int tap = DecryptionLen-mpzLen[0]-1;
		while(tap>0){
			*(offBuf++) = '0';
			tap--;
		}
		mpz_get_str(offBuf,2,cipher2[0]);
		offBuf += mpzLen[0];
		for(size_t i=1;i<cipher2_len;i++){
			tap = DecryptionLen-mpzLen[i];
			while(tap>0){
				*(offBuf++) = '0';
				tap--;
			}
			mpz_get_str(offBuf,2,cipher2[i]);
			offBuf += mpzLen[i];
		}
		size_t off =cipher2_bytes - segLenInBits;
		mpz_t* tmpArr = new mpz_t[totolSeg];
		for(size_t i=0;i<totolSeg-1;i++){
			mpz_init(tmpArr[i]);
			mpz_set_str (tmpArr[i], buf+off,2);
			buf[off] = 0;
			off-=segLenInBits;
		}
		mpz_init(tmpArr[totolSeg-1]);
		mpz_set_str(tmpArr[totolSeg-1],buf,2);
		for(size_t i=0;i<totolSeg;i++){
			djcs_ep_mul(pk,tmpArr[i],cipher1,tmpArr[i]);
		}
		//gc
		if(rop==cipher2)
			delete[] cipher2;
		//merge
		rop = tmpArr;
		arrLen = totolSeg;
	}
}
mpz_t* djcs_e01e_add(djcs_public_key *pk,mpz_t*& rop,const size_t cipher_len1,const size_t cipher_len2,mpz_t* cipher1, mpz_t* cipher2){
	assert(cipher_len1==cipher_len2);
	//calcu
	mpz_t* tmpArr = new mpz_t[cipher_len1];
	for(size_t i=0;i<cipher_len1;i++){
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
	cout<<"no potential test are waiting\n";
	// there exists a potential risk on mongodb restore , but I cannot recover the bug setting now, it becomes normal! I have to remains this and check the bug later
}
SSORAM::SSORAM(const uint32_t& n) {
    height = (uint32_t)ceil(log2((double)(n+1)));
    n_blocks = (uint32_t)2 << (height - 1);
    pos_map = new posMap_struct[n];
    conn = new MongoConnector(server_host, "oram.path"+std::to_string(Util::rand_int(102400)));
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
    //intialize server and client_core
    first_empty_L = 1;
    server = new SSORAM_Server_core((uint32_t) (2<<height),dj_pk,conn);
    client_core = new SSORAM_Client_core(dj_pk,hr,n_blocks,height);
    mpz_set_ui(dummyBlock,1);
    djcs_encrypt(dj_pk, hr, value, dummyBlock);
    server->freshLayerSpan_vector(value);
    mpz_set_ui(dummyBlock,Dummy);
    //filling database memory with dummy block
    for(uint32_t id=2;id<(uint32_t)(2<<height);id++){
		djcs_encrypt(dj_pk, hr, value, dummyBlock);
		server->insert(id,value);
	}
    //gc
    mpz_clears(dummyBlock,value,NULL);
}
SSORAM_Server_core::SSORAM_Server_core(const uint32_t& bufferLen,djcs_public_key *_dj_pk,ServerConnector* _conn){
    tmpBuffer = new std::string[bufferLen];
    conn = _conn;
    dj_pk = _dj_pk;
    mpz_init(layerSpan_vector);
}
SSORAM_Server_core::~SSORAM_Server_core(){
    delete[] tmpBuffer;
    mpz_clear(layerSpan_vector);
}

void SSORAM_Server_core::freshLayerSpan_vector(mpz_t& _vec){
	mpz_set(layerSpan_vector,_vec);
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
	pos_map[block_id].level = 1;
	pos_map[block_id].offset = 1;
	std::string result = Read(pos_map[block_id].level,pos_map[block_id].offset);
	cout<<"result\t"<<result<<endl;
    if (op == 'w'){
    	result = data;
    	Write(result,RealType,block_id);
    }else{
    	Write(result,DummyType,block_id);
    }
    data = result;
}
std::string SSORAM::Read(uint32_t& level, int32_t& off){
	std::vector< std::pair<std::pair<uint32_t,int32_t>, __mpz_struct> > vec;
	size_t len;
	mpz_t data;
	mpz_init(data);
	vec.clear();
	client_core->Read(level,off,vec);
	uint32_t maxLevel = getLevel((1<<vec[vec.size()-1].first.first)+vec[vec.size()-1].first.second);
	mpz_t* result = server->Read(dj_vk,vec,len);
	for(uint32_t i=2;i<=maxLevel;i++)
		client_core->djcs_decrypt_merge_array_multi(dj_vk,result,len,result,len);
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
		}else{
			djcs_encrypt(dj_pk, hr, encryptZero, zero);
			size_t random_offset = Util::rand_int(1<<i);
			vec.push_back(std::make_pair(std::make_pair(i,random_offset),encryptZero[0]));
		}
	}
}
mpz_t* SSORAM_Server_core::Read(djcs_private_key *vk,std::vector< std::pair<std::pair<uint32_t,int32_t>, __mpz_struct> > vec,size_t& segLen){
	mpz_t c;
	mpz_t *data,*result=NULL;
	size_t result_len,len;
	mpz_init(c);
	uint32_t id=0,level=0,maxLevel;
	// the server and the client has a protocol that the end of the vector is the element which has the biggest id
	maxLevel = getLevel((1<<vec[vec.size()-1].first.first)+vec[vec.size()-1].first.second);
	for(uint32_t i=0;i<vec.size();i++){
		id = (1<<vec[i].first.first)+vec[i].first.second;
		data = find(id,len);
		// expand to suitable encryption layer
		level = getLevel(id);
		for(uint32_t i=level+1;i<=maxLevel;i++){
			djcs_e01e_mul_multi(dj_pk,data,len,layerSpan_vector,data,len);
		}
		// multiply vector
		djcs_e01e_mul_multi(dj_pk,data,len,&vec[i].second,data,len);
		// added; if the first do initial
		if(result == NULL){
			result = data;
			result_len = len;
		}else{
			djcs_e01e_add(dj_pk,result,result_len,len,result,data);
			delete[] data;
		}
	}
	segLen = result_len;
	return result;

	/*mpz_set_str (c, data.c_str(),16);
	djcs_e01e_mul(dj_pk,tmp_result,tmp_len,&vec[0].second,c);
	result = tmp_result;
	len = tmp_len;
	for(uint32_t i=1;i<vec.size();i++){
		data = conn->find((1<<vec[i].first.first)+vec[i].first.second);
		mpz_set_str (c, data.c_str(),16);
		djcs_e01e_mul(dj_pk,tmp_result,tmp_len,&vec[i].second,c);
 		djcs_e01e_add(dj_pk,result,tmp_len,len,tmp_result,result);
	}
	segLen = tmp_len;
	return result;*/

}
uint32_t getLevel(uint32_t id){
	uint32_t level=0;
	uint32_t start_id = 2;
	while(id>=start_id){
		id = (id>>1);
		level++;
	}
	return level;
}
void SSORAM_Server_core::insert(const uint32_t& id, mpz_t value, const std::string& ns){
	uint32_t level = getLevel(id);
	//should deal with different encryption layer
	assert(level>0);
	if(level==1){
		char* buf = mpz_get_str(NULL,16,value);
		std::string data= std::string(buf,mpz_sizeinbase(value,16));
		conn->insert(id,&data,1,ns);
	}else{
		size_t len=0;
		mpz_t* result;
		char* buf;
		mpz_t tmpV;
		mpz_init(tmpV);
		mpz_set(tmpV,value);
		djcs_e01e_mul_multi(dj_pk,result,len,layerSpan_vector,&tmpV,1);
		for(uint32_t i=3;i<=level;i++){
			djcs_e01e_mul_multi(dj_pk,result,len,layerSpan_vector,result,len);
		}
		mpz_clear(tmpV);

		std::string *result_str = new std::string[len];
		for(size_t i=0;i<len;i++){
			buf = mpz_get_str(NULL,16,result[i]);
			result_str[i] = std::string(buf,mpz_sizeinbase(result[i],16));
		}
		conn->insert(id,result_str,len,ns);
		//gc
		delete[] result_str;
		delete[] result;
	}

}
mpz_t* SSORAM_Server_core::find(const uint32_t& id,size_t& len,const std::string& ns){
	std::string *data = conn->find(id,len);
	mpz_t *result = new mpz_t[len];
	//cout<<"id:\t"<<id<<"\tdata:\n";
	for(int i=0;i<len;i++){
		mpz_init(result[i]);
		mpz_set_str (result[i], data[i].c_str(),16);
		//cout<<"data seg\t"<<i<<"\tdata\t"<<data[i]<<endl;
	}
	delete [] data;
	return result;
}
