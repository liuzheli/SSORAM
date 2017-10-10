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
	//GenPairs
	// there exists a potential risk on mongodb restore , but I cannot recover the bug setting now, it becomes normal! I have to remains this and check the bug later
}
SSORAM::SSORAM(const uint32_t& n) {
    height = (uint32_t)ceil(log2((double)(n+1)));
    n_blocks = (uint32_t)2 << (height - 1);
    pos_map.clear();
    pos_map_inv.clear();
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
    server = new SSORAM_Server_core((uint32_t) (2<<height),dj_pk,conn,height);
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
    mpz_clear(value);
}
SSORAM_Server_core::SSORAM_Server_core(const uint32_t& _bufferLen,djcs_public_key *_dj_pk,ServerConnector* _conn,uint32_t _height){
    bufferLen = _bufferLen;
	tmpBuffer = new mpz_t*[bufferLen];
    tmpBuffer_dataLen = new size_t[bufferLen];
    for(uint32_t i=0;i<bufferLen;i++){
    	tmpBuffer[i] = NULL;
    	tmpBuffer_dataLen[i] = 0;
    }
    buffer_usage = 0;
    tmpBuffer_len = 0;
    height = _height;
    level_usage = new bool[height+1];
    for(uint32_t i=0;i<=height;i++)
    	level_usage[i] = false;
    conn = _conn;
    dj_pk = _dj_pk;
    mpz_init(layerSpan_vector);
}
SSORAM_Server_core::~SSORAM_Server_core(){
	for(uint32_t i=0;i<bufferLen;i++){
			if(tmpBuffer[i] != NULL)
				delete[] tmpBuffer[i];
		}
    delete[] tmpBuffer;
    delete[] tmpBuffer_dataLen;
    delete[] level_usage;
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
    delete conn;
    mpz_clear(dummyBlock);
    djcs_free_public_key(dj_pk);
    djcs_free_private_key(dj_vk);
    hcs_free_random(hr);
    delete client_core;
    //cout<<"Successfully delete client_core\n";
    delete server;
    //cout<<"Successfully delete server\n";
    //cout<<"successfully delete oram\n";

}

std::string SSORAM::get(const std::string & key) {
    uint32_t int_key;
    sscanf(key.c_str(), "%d", &int_key);
    mpz_t res;
	std::string res_str;
	mpz_init(res);
	access('r', int_key, res);
	if(mpz_cmp(dummyBlock,res)==0)
		res_str = "dummy";
	else{
		char* des_str;
		uint32_t des_len;
		des_str = Number2CharArr(NULL,des_len,res);
		res_str = std::string(des_str,des_len);
		delete []des_str;
	}
	return res_str;
}


void SSORAM::put(const std::string & key, const std::string & value) {
    uint32_t int_key;
    sscanf(key.c_str(), "%d", &int_key);
    mpz_t data;
	mpz_init(data);
	CharArr2Number(value.c_str(),value.length(),data);
	access('w', int_key, data);
}


std::string SSORAM::get(const uint32_t & key) {
    mpz_t res;
    std::string res_str;
    mpz_init(res);
    access('r', key, res);
    if(mpz_cmp(dummyBlock,res)==0)
    	res_str = "dummy";
    else{
    	char* des_str;
    	uint32_t des_len;
    	des_str = Number2CharArr(NULL,des_len,res);
    	res_str = std::string(des_str,des_len);
    	delete []des_str;
    }
    return res_str;
}

void SSORAM::put(const uint32_t & key, const std::string & value) {
	mpz_t data;
	mpz_init(data);
	CharArr2Number(value.c_str(),value.length(),data);
	//gmp_printf("the writing in data is %Zd\n",data);
    access('w', key, data);
}

void SSORAM::access(const char& op, const uint32_t& block_id, mpz_t& data){
	mpz_t result;
	mpz_init(result);
	uint32_t id;
	auto it = pos_map.find(block_id);
	if(it != pos_map.end())
			id = it->second;
	else
		id = 0;// this is for test, NOT SECURITY AT ALL
	uint32_t level = getLevel(id);
	mpz_t* return_value = Read(level,id-(1<<level));
	mpz_set(result,return_value[0]);
	delete[] return_value;
	//gmp_printf("Read result is %Zd\t\n",result);
    if (op == 'w'){
    	//cout<<"go in real type way\n";
    	mpz_set(result,data);
    	Write(result,RealType,block_id);
    }else{
    	//cout<<"go in dummy type way\n";
    	Write(result,DummyType,block_id);
    }
    mpz_set(data,result);
}
mpz_t* SSORAM::Read(uint32_t level, uint32_t off){
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
	delete[] result;
	result = new mpz_t[1];
	mpz_init(result[0]);
	mpz_set(result[0],data);
	mpz_clear(data);
	return result;
	/*char* buf = mpz_get_str(NULL,10,data);
	return std::string(buf,mpz_sizeinbase(data,10));*/
}
void SSORAM::Write(const mpz_t& data,block_type dataType,const uint32_t& block_id){
	// shuffle written block
	mpz_t A[2],tmpNum;
	mpz_inits(A[0],A[1],tmpNum,NULL);
	if(dataType==DummyType){
		blockMap[0] = DummyType;
		blockMap[1] = DummyType;
		djcs_encrypt(dj_pk, hr, tmpNum, dummyBlock);
		mpz_set(A[0],tmpNum);
		djcs_encrypt(dj_pk, hr, tmpNum, dummyBlock);
		mpz_set(A[1],tmpNum);
	}else{
		size_t r = Util::rand_int(2);
		blockMap[r] = RealType;
		blockMap[1-r] = DummyType;
		mpz_set(tmpNum,data);
		djcs_encrypt(dj_pk, hr, tmpNum, tmpNum);
		mpz_set(A[r],tmpNum);
		djcs_encrypt(dj_pk, hr, tmpNum, dummyBlock);
		mpz_set(A[1-r],tmpNum);
		pos_map[block_id] = r;
		pos_map_inv[r] = block_id;
	}
	// write back to server
	uint32_t empty_level = server->writeBack(A,2);
	//cout<<"empty_level is :\t"<<empty_level<<endl;
	if(empty_level==1){
		pos_map_inv.erase(pos_map[block_id]);
		pos_map[block_id] =  pos_map[block_id] + 2;
		pos_map_inv[pos_map[block_id]] = block_id;
		blockMap[2] = blockMap[0];
		blockMap[3] = blockMap[1];
	}
	else
	{
		cout<<"shuffle to level:\t"<<empty_level<<endl;
		cout<<"begin shuffle:\t"<<endl;
		Shuffle(empty_level);
		cout<<"Evict function haven't been finished yet\n";
		cout<<"shuffle function haven't been finished yet\n";
	}
	//gc
	mpz_clears(A[0],A[1],tmpNum,NULL);
}
void SSORAM::Shuffle(uint32_t empty_level){
	//test worst case
	bool worstCase = false;
	if(!empty_level){
		worstCase = true;
		empty_level = height;
	}
	//Normal merge operation
	for(uint32_t level = 1;level<empty_level;level++){
		assert(Merge(level));
	}
	//store back to database, differentiate the worst case
	if(worstCase)
		assert(MergeInPlace(empty_level));
	assert(server->writeBackTo(empty_level));
}
bool SSORAM::Merge(const uint32_t merge_level){
	cout<<"merge tmp array with level"<<merge_level<<endl;
	std::vector<__mpz_struct > enc_vec;
	client_core->GenVector(blockMap,merge_level,enc_vec);
	std::pair<uint32_t,int32_t>* pair_vec = NULL;
	GenPairs(merge_level,pair_vec);
	cout<<"server side merge function haven't been finished yet\n";
	return true;
}
void SSORAM::GenPairs(const uint32_t merge_level,std::pair<uint32_t,int32_t>*& vec,bool TopLevel){
	cout<<"gen pair function get:\n";
	uint32_t set_len = (1<<merge_level);
	//parse sets to dummy and real
	uint32_t *dbSet_dummy = NULL,*dbSet_real = NULL,*tmp_dummy = NULL,*tmp_real = NULL;
	//cout<<"parse tmp set\n";
	parseSet(0,set_len,tmp_dummy,tmp_real);
	//cout<<"parse db set\n";
	parseSet(set_len,set_len*2,dbSet_dummy,dbSet_real);
	//permute again
	set_len = set_len/2;
	Util::psuedo_random_permute(tmp_dummy,set_len);
	Util::psuedo_random_permute(tmp_real,set_len);
	Util::psuedo_random_permute(dbSet_dummy,set_len);
	Util::psuedo_random_permute(dbSet_real,set_len);
	//generate the vector
	if(vec==NULL){
		if(TopLevel)
			vec = new std::pair<uint32_t,int32_t>[set_len*2];
		else
			vec = new std::pair<uint32_t,int32_t>[set_len*4];
	}
	uint32_t count = 0;
	if(!TopLevel){
		for(uint32_t i=0;i<set_len;i++){
			blockMap[count] = DummyType;
			vec[count++] = std::pair<uint32_t,int32_t>(dbSet_dummy[i],tmp_dummy[i]);
			blockMap[count] = NoisyType;
			vec[count++] = std::pair<uint32_t,int32_t>(dbSet_real[i],tmp_real[i]);
		}
	}
	for(uint32_t i=0;i<set_len;i++){
		blockMap[count] = RealType;
		pos_map_inv[count] = pos_map_inv[tmp_real[i]];
		pos_map[pos_map_inv[tmp_real[i]]] = count;
		pos_map_inv.erase(tmp_real[i]);
		vec[count++] = std::pair<uint32_t,int32_t>(dbSet_dummy[i],tmp_real[i]);
		blockMap[count] = RealType;
		pos_map_inv[count] = pos_map_inv[tmp_real[i]];
		pos_map[pos_map_inv[dbSet_real[i]]] = count;
		pos_map_inv.erase(dbSet_real[i]);
		vec[count++] = std::pair<uint32_t,int32_t>(dbSet_real[i],tmp_dummy[i]);
	}
	//permute the vector
	Util::psuedo_random_permute(vec,count);
	/*cout<<"gen pair set\n";
	for(uint32_t i=0;i<count;i++){
		cout << "first:\t"<<vec[i].first<<"\tsecond\t"<<vec[i].second<<'\n';
	}*/
}
void SSORAM::parseSet(const uint32_t& start, const uint32_t& end,uint32_t*& dummyset,uint32_t*& realset){
	uint32_t len = (start+end)/2 - start;
	if(dummyset == NULL)
		dummyset = new uint32_t[len];
	if(realset == NULL)
		realset = new uint32_t[len];
	uint32_t *tmp = new uint32_t[len*2];
	uint32_t count =0;
	for(uint32_t i=start;i<end;i++)
		if(blockMap[i]==DummyType)
			tmp[count++] = i;
	Util::psuedo_random_permute(tmp,count);
	for(uint32_t i=start;i<end;i++)
		if(blockMap[i]==RealType)
			tmp[count++] = i;
	assert(count == len*2);
	for(uint32_t i=0;i<len;i++){
		dummyset[i] = tmp[i];
		realset[i] = tmp[i+len];
	}
	cout<<"dummy set\n";
	for(uint32_t i=0;i<len;i++){
		cout << dummyset[i]<<'\t';
	}
	cout<<"\nreal set\n";
	for(uint32_t i=0;i<len;i++){
		cout << realset[i]<<'\t';
	}
	cout<<endl;
	//gc
	delete[] tmp;
}

bool SSORAM::MergeInPlace(const uint32_t merge_level){
	cout<<"mergeInPlace function haven't been finished yet\n";
	return true;
}
void SSORAM_Client_core::GenVector(const block_type *blockMap,const uint32_t merge_level,std::vector<__mpz_struct >& vec){
	vec.clear();
	for(uint32_t id = 0; id<(2<<merge_level);id++){
		if(blockMap[id]==NoisyType){
			djcs_encrypt(dj_pk, hr, encryptZero, zero);
			vec.push_back(encryptZero[0]);
		}else{
			djcs_encrypt(dj_pk, hr, encryptOne, one);
			vec.push_back(encryptOne[0]);
		}
	}
	assert(vec.size()==(2<<merge_level));
}
void SSORAM_Client_core::Read(uint32_t& level, uint32_t& off,std::vector< std::pair<std::pair<uint32_t,int32_t>, __mpz_struct> >& vec){
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
void CharArr2Number(const char* str, uint32_t len,mpz_t rop){
	mpz_t tmp;
	mpz_init(tmp);
	mpz_set_ui(rop,0);
	for(uint32_t i=0;i<len;i++){
		mpz_set_ui(tmp,str[i]);
		mpz_mul_2exp(rop,rop,8);
		mpz_add(rop,rop,tmp);
	}
	//gc
	mpz_clear(tmp);
}
char* Number2CharArr(char* des_str, uint32_t& des_len,mpz_t data, bool gc){
	char* res;
	//calculate des str length
	if(mpz_sizeinbase(data,2)%8)
		des_len = mpz_sizeinbase(data,2)/8 +1;
	else
		des_len = mpz_sizeinbase(data,2)/8;
	//allocate des str memory
	if(des_str!=NULL){
		res = des_str;
		if(gc){
			delete[] res;
			res = new char[des_len];
		}
	}else
		res = new char[des_len];
	//calculate the string
	mpz_t tmp;
	mpz_init(tmp);
	uint32_t expon = 8;
	for(int i=des_len-1;i>=0;i--){
		mpz_mod_2exp(tmp,data,expon);
		res[i] = mpz_get_ui(tmp);
		mpz_div_2exp(data,data,expon);
	}
	//gc
	mpz_clear(tmp);
	return res;
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
void SSORAM_Server_core::update(const uint32_t& id, mpz_t value, const std::string& ns){
	uint32_t level = getLevel(id);
	//should deal with different encryption layer
	assert(level>0);
	if(level==1){
		char* buf = mpz_get_str(NULL,16,value);
		std::string data= std::string(buf,mpz_sizeinbase(value,16));
		conn->update(id,&data,1,ns);
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
		conn->update(id,result_str,len,ns);
		//gc
		delete[] result_str;
		delete[] result;
	}
}
mpz_t* SSORAM_Server_core::find(const uint32_t& id,size_t& len,const std::string& ns){
	std::string *data = conn->find(id,len);
	mpz_t *result = new mpz_t[len];
	//cout<<"id:\t"<<id<<"\tdata:\n";
	for(size_t i=0;i<len;i++){
		mpz_init(result[i]);
		mpz_set_str (result[i], data[i].c_str(),16);
		//cout<<"data seg\t"<<i<<"\tdata\t"<<data[i]<<endl;
	}
	delete [] data;
	return result;
}
uint32_t SSORAM_Server_core::writeBack(mpz_t* A,size_t len){
	uint32_t empty_level = 0;
	for(uint32_t i=1;i<=height;i++)
		if(!level_usage[i]){
			empty_level = i;
			break;
		}
	// simple job
	if(empty_level==1){
		update(2,A[0]);
		update(3,A[1]);
		level_usage[1] = true;
		return empty_level;
	}
	if(len==2){
		//pure evict function not involved merge operation
		tmpBuffer[0] = new mpz_t[1];
		tmpBuffer_dataLen[0] = 1;
		tmpBuffer[1] = new mpz_t[1];
		tmpBuffer_dataLen[1] = 1;
		mpz_inits(tmpBuffer[0][0],tmpBuffer[1][0],NULL);
		mpz_set(tmpBuffer[0][0],A[0]);
		mpz_set(tmpBuffer[1][0],A[0]);
		buffer_usage=2;
	}
	// remain for shuffle
	return empty_level;
}
bool SSORAM_Server_core::writeBackTo(const uint32_t empty_level){
	cout<<"Write Back to have not finished it!\n";
	return true;
}
