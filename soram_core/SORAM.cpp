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
	mpz_t tmp;
	mpz_init(tmp);
	for(size_t i=0;i<totolSeg;i++){
		djcs_decrypt(vk,tmp,tmpArr[i]);
		mpz_mul_2exp(tmp,tmp,tmpoff);
		mpz_add(rop,rop,tmp);
		tmpoff+=segLenInBytes;
	}
	djcs_decrypt(vk,rop,rop);
	mpz_clear(tmp);
}
void SSORAM_Client_core::djcs_decrypt_merge_array_multi(djcs_private_key *vk,mpz_t*& rop,size_t& arrLen,mpz_t* tmpArr,size_t& totolSeg,uint32_t segLenInBits,uint32_t DecryptionLen){
	size_t tmpoff=0,cipher2_bytes=0,off=0;
	mpz_t tmpRop,tmp;
	mpz_inits(tmpRop,tmp,NULL);
	mpz_set_ui(tmpRop,0);
	for(size_t i=0;i<totolSeg;i++){
		djcs_decrypt(vk,tmp,tmpArr[i]);
		mpz_mul_2exp(tmp,tmp,tmpoff);
		mpz_add(tmpRop,tmpRop,tmp);
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
	mpz_clears(tmpRop,tmp,NULL);
	//merge
	if(rop==tmpArr)
		delete[] tmpArr;
	rop = tmpAr;
}
void djcs_decrypt_merge_array(djcs_private_key *vk,mpz_t rop,mpz_t* tmpArr,size_t& totolSeg,uint32_t segLenInBytes){
	size_t tmpoff=0;
	mpz_set_ui(rop,0);
	mpz_t tmp;
	mpz_init(tmp);
	for(size_t i=0;i<totolSeg;i++){
		djcs_decrypt(vk,tmp,tmpArr[i]);
		mpz_mul_2exp(tmp,tmp,tmpoff);
		mpz_add(rop,rop,tmp);
		tmpoff+=segLenInBytes;
	}
	djcs_decrypt(vk,rop,rop);
	mpz_clear(tmp);
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
	/*cout<<"pos_map travelling:\n";
	for(auto it=pos_map.begin();it!=pos_map.end();it++){
		cout<<"data id:\t"<<it->first<<"\tblock id:\t"<<it->second<<endl;
	}*/
	auto it = pos_map.find(block_id);
	if(it != pos_map.end())
			id = it->second;
	else
		id = 0;// this is for test, NOT SECURITY AT ALL
	/*if(op =='r'){
		cout<<"get block id is\t"<<id;
		if(blockMap[id]==DummyType)
			cout<<"\tthe block type is dummy\n";
		else
			cout<<"\tthe block type is real\n";
	}*/
	uint32_t level = getLevel(id);
	mpz_t* return_value = Read(level,id-(1<<level));
	mpz_set(result,return_value[0]);
	delete[] return_value;
	//gmp_printf("Read result is %Zd\t\n",result);
    if (op == 'w'){
    	//cout<<"write action go in real type way\n";
    	mpz_set(result,data);
    	Write(result,RealType,block_id);
    }else{
    	//cout<<"write action go in dummy type way\n";
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
		if(dataType==DummyType){
		}else{
			pos_map_inv.erase(pos_map[block_id]);
			pos_map[block_id] =  pos_map[block_id] + 2;
			pos_map_inv[pos_map[block_id]] = block_id;
			//cout<<"data key :\t"<<block_id<<" write in block\t"<<pos_map[block_id]<<endl;
		}
		blockMap[2] = blockMap[0];
		blockMap[3] = blockMap[1];
		blockMap[0] = DummyType;
		blockMap[1] = DummyType;
	}
	else
	{
		/*cout<<"begin shuffle:\t";
		cout<<"shuffle to level:\t"<<empty_level<<endl;*/
		Shuffle(empty_level);
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
	//update blockMap and pos_map
	if(!worstCase){
		uint32_t head = (1<<empty_level),dataId;
		/*cout<<"before write to empty level:\n";
		for(uint32_t off=0;off<(2<<empty_level);off++)
			cout<<"block id:\t"<<off<<"\t type is "<<blockType_str(blockMap[off])<<"\n";*/
		for(uint32_t off=0;off<(1<<empty_level);off++){
			blockMap[head+off] = blockMap[off];
			if(blockMap[off]==RealType){
				//cout<<"off :\t"<<off<<endl;
				//cout<<"previous:\t"<<"data id:\t"<<pos_map_inv[off]<<"\tblock id:\t"<<pos_map[pos_map_inv[off]]<<endl;
				dataId = pos_map_inv[off];
				pos_map[dataId] = off+head;
				pos_map_inv[off+head] = dataId;
				pos_map_inv.erase(off);
				//cout<<"update:\t"<<"data id:\t"<<pos_map_inv[off+head]<<"\tblock id:\t"<<pos_map[pos_map_inv[off+head]]<<endl;
			}
			blockMap[off] = DummyType;
		}
		/*cout<<"after write to empty level:\n";
		for(uint32_t off=0;off<(2<<empty_level);off++)
				cout<<"block id:\t"<<off<<"\t type is "<<blockType_str(blockMap[off])<<"\n";*/
	}else{
		cout<<"worstCase blockMap arrange are not be written\n";
	}
	assert(server->writeBackTo(empty_level));
}
bool SSORAM::Merge(const uint32_t merge_level){
	//cout<<"merge tmp array with level"<<merge_level<<endl;
	std::vector<__mpz_struct > enc_vec;
	client_core->GenVector(dj_vk,blockMap,merge_level,enc_vec);
	std::pair<uint32_t,int32_t>* pair_vec = NULL;
	uint32_t pair_len=0;
	GenPairs(merge_level,pair_vec,pair_len);
	return server->Merge(dj_vk,merge_level,enc_vec,pair_vec,pair_len);
}
void SSORAM::GenPairs(const uint32_t merge_level,std::pair<uint32_t,int32_t>*& vec,uint32_t& vec_len,bool TopLevel){
	//cout<<"gen pair function get:\n";
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
	/*cout<<"tmp_dummy set:\t";
	for(uint32_t i=0;i<set_len;i++)
		cout<<tmp_dummy[i]<<"\t";
	cout<<endl;*/
	Util::psuedo_random_permute(tmp_real,set_len);
	/*cout<<"tmp_real set:\t";
	for(uint32_t i=0;i<set_len;i++)
		cout<<tmp_real[i]<<"\t";
	cout<<endl;*/
	Util::psuedo_random_permute(dbSet_dummy,set_len);
	/*cout<<"dbSet_dummy set:\t";
	for(uint32_t i=0;i<set_len;i++)
		cout<<dbSet_dummy[i]<<"\t";
	cout<<endl;*/
	Util::psuedo_random_permute(dbSet_real,set_len);
	/*cout<<"dbSet_real set:\t";
	for(uint32_t i=0;i<set_len;i++)
		cout<<dbSet_real[i]<<"\t";
	cout<<endl;*/
	//generate the vector
	////intialize
	block_type* tmp_blockMap;
	if(TopLevel)
		vec_len = set_len*2;
	else
		vec_len = set_len*4;
	tmp_blockMap = new block_type[vec_len];
	if(vec==NULL)
		vec = new std::pair<uint32_t,int32_t>[vec_len];
	////working
	uint32_t count = 0;
	if(!TopLevel){
		for(uint32_t i=0;i<set_len;i++){
			vec[count++] = std::pair<uint32_t,int32_t>(dbSet_dummy[i],tmp_dummy[i]);
			vec[count++] = std::pair<uint32_t,int32_t>(dbSet_real[i],tmp_real[i]);
		}
	}
	for(uint32_t i=0;i<set_len;i++){
		vec[count++] = std::pair<uint32_t,int32_t>(dbSet_dummy[i],tmp_real[i]);
		vec[count++] = std::pair<uint32_t,int32_t>(dbSet_real[i],tmp_dummy[i]);
	}
	//permute the vector
	Util::psuedo_random_permute(vec,count);
	assert(vec_len == count);
	//update pos_map, blockMap
	uint32_t realId,dataId;
	//cout<<"after shuffle the pos map travelling:\n";
	for(uint32_t i=0;i<count;i++){
		tmp_blockMap[i] = getBlockType(vec[i].first,vec[i].second);
		if(tmp_blockMap[i]==RealType){
			realId = (blockMap[vec[i].first]==RealType) ? vec[i].first : vec[i].second;
			//cout<<"previous:\t"<<"data id:\t"<<pos_map_inv[realId]<<"\tblock id:\t"<<pos_map[pos_map_inv[realId]]<<endl;
			dataId= pos_map_inv[realId];
			pos_map_inv[i] = dataId;
			pos_map[dataId] = i;
			pos_map_inv.erase(realId);
			//cout<<"update:\t"<<"data id:\t"<<pos_map_inv[i]<<"\tblock id:\t"<<pos_map[pos_map_inv[i]]<<endl;
		}
	}
	for(uint32_t i=0;i<vec_len;i++)
		blockMap[i] = tmp_blockMap[i];
	//test and print state
	/*cout<<"after permuter the vector is:\n";
	for(uint32_t i=0;i<count;i++){
		cout<<"block id:\t"<<i<<"\t type is "<<blockType_str(blockMap[i])<<"\n";
	}
	cout<<"gen pair set\n";
	for(uint32_t i=0;i<count;i++){
		cout << "first:\t"<<vec[i].first<<"\tsecond\t"<<vec[i].second<<'\n';
	}*/
	//gc
	delete [] tmp_blockMap;
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
	/*cout<<"dummy set\n";
	for(uint32_t i=0;i<len;i++){
		cout << dummyset[i]<<'\t';
	}
	cout<<"\nreal set\n";
	for(uint32_t i=0;i<len;i++){
		cout << realset[i]<<'\t';
	}
	cout<<endl;*/
	//gc
	delete[] tmp;
}

bool SSORAM::MergeInPlace(const uint32_t merge_level){
	cout<<"mergeInPlace function haven't been finished yet\n";
	return true;
}
void SSORAM_Client_core::GenVector(djcs_private_key *vk,const block_type *blockMap,const uint32_t merge_level,std::vector<__mpz_struct >& vec){
	vec.clear();
	mpz_t *tmp_mpz;
	for(uint32_t id = 0; id<(2<<merge_level);id++){
		if(blockMap[id]==RealType){
			djcs_encrypt(dj_pk, hr, encryptOne, one);
			tmp_mpz = new mpz_t[1];
			vec.push_back(tmp_mpz[0][0]);
			mpz_init(&vec[id]);
			mpz_set(&vec[id],encryptOne);
		}else{
			djcs_encrypt(dj_pk, hr, encryptZero, zero);
			tmp_mpz = new mpz_t[1];
			vec.push_back(tmp_mpz[0][0]);
			mpz_init(&vec[id]);
			mpz_set(&vec[id],encryptZero);
		}
	}
	/*cout<<"get vector process:\n";
	mpz_t rop;
	mpz_init(rop);
	for(uint32_t id = 0; id<(2<<merge_level);id++){
		gmp_printf("id %d encrypt one value is:\t%Zd\n",id,&(vec[id]));
		djcs_decrypt(vk,rop,&(vec[id]));
		gmp_printf("block %d's vector is %Zd\n",id,rop);
	}
	mpz_clear(rop);*/
	assert(vec.size()==(2<<merge_level));
}
void SSORAM_Client_core::Read(uint32_t& level, uint32_t& off,std::vector< std::pair<std::pair<uint32_t,int32_t>, __mpz_struct> >& vec){
	vec.clear();
	mpz_t *tmp_mpz;
	for(uint32_t i=1;i<=height;i++){
		if(i==level){
			djcs_encrypt(dj_pk, hr, encryptOne, one);
			tmp_mpz = new mpz_t[1];
			vec.push_back(std::make_pair(std::make_pair(i,off),tmp_mpz[0][0]));
			mpz_init(&vec[i-1].second);
			mpz_set(&vec[i-1].second,encryptOne);
		}else{
			djcs_encrypt(dj_pk, hr, encryptZero, zero);
			tmp_mpz = new mpz_t[1];
			size_t random_offset = Util::rand_int(1<<i);
			vec.push_back(std::make_pair(std::make_pair(i,random_offset),tmp_mpz[0][0]));
			mpz_init(&vec[i-1].second);
			mpz_set(&vec[i-1].second,encryptZero);
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
void SSORAM_Server_core::update(const uint32_t& id, mpz_t *value, const size_t& len, const std::string& ns){
	char* buf;
	std::string *result_str = new std::string[len];
	for(size_t i=0;i<len;i++){
		buf = mpz_get_str(NULL,16,value[i]);
		result_str[i] = std::string(buf,mpz_sizeinbase(value[i],16));
	}
	conn->update(id,result_str,len,ns);
	//gc
	delete[] result_str;
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
		mpz_set(tmpBuffer[1][0],A[1]);
		buffer_usage=2;
	}
	// remain for shuffle
	return empty_level;
}
bool SSORAM_Server_core::writeBackTo(const uint32_t empty_level){
	bool result_sig =false;
	uint32_t head = (1<<empty_level);
	for(uint32_t off=0;off<(1<<empty_level);off++){
		update(head+off,tmpBuffer[off],tmpBuffer_dataLen[off]);
		//cout<<"write back to id:\t"<<(head+off)<<endl;
		delete [] tmpBuffer[off];
		tmpBuffer[off] = NULL;
		tmpBuffer_dataLen[off] = 0;
	}
	buffer_usage = 0;
	result_sig = true;
	return result_sig;
}
bool SSORAM_Server_core::Merge(djcs_private_key *vk,const uint32_t& merge_level,std::vector<__mpz_struct >& vec,std::pair<uint32_t,int32_t>* pairs, const uint32_t& pair_len){
	bool return_sig= false;
	uint32_t mPoint = vec.size()/2;
	//erase noisy
	assert((mPoint*2)==vec.size());
	assert(pair_len == (mPoint*2));
	buffer_usage+= mPoint;
	for(uint32_t i=mPoint;i<mPoint*2;i++){
			tmpBuffer[i] = find(i,tmpBuffer_dataLen[i]);
		}
	mpz_t rop,zero;
	mpz_inits(rop,zero,NULL);
	mpz_set_ui(zero,0);
	/*for(uint32_t i=0;i<mPoint*2;i++){
		cout<<"block "<<i<<"value";
		djcs_decrypt(vk,rop,tmpBuffer[i][0]);
		if(mpz_cmp(rop,zero)==0)
			cout<<" is dummy\n";
		else{
			char* des_str;
			uint32_t des_len;
			des_str = Number2CharArr(NULL,des_len,rop);
			std::string res_str = std::string(des_str,des_len);
			delete []des_str;
			cout<<" is "<<res_str<<endl;
		}
		gmp_printf("block %d's plain vector is %Zd\n",i,&vec[i]);
		djcs_decrypt(vk,rop,&vec[i]);
		gmp_printf("block %d's vector is %Zd\n",i,rop);
	}*/
	for(uint32_t i=0;i<mPoint*2;i++){
		djcs_e01e_mul_multi(dj_pk,tmpBuffer[i],tmpBuffer_dataLen[i],&vec[i],tmpBuffer[i],tmpBuffer_dataLen[i]);
	}
	mpz_t **store = new mpz_t*[pair_len];
	for(uint32_t i=0;i<pair_len;i++){
		store[i] = NULL;
		djcs_e01e_add(dj_pk,store[i],tmpBuffer_dataLen[pairs[i].first],tmpBuffer_dataLen[pairs[i].second],tmpBuffer[pairs[i].first],tmpBuffer[pairs[i].second]);
		/*cout<<"multiply plain data:\t at block "<<i;
		djcs_decrypt_merge_array(vk,rop,store[i],tmpBuffer_dataLen[pairs[i].first]);
		if(mpz_cmp(rop,zero)==0)
			cout<<" is dummy\n";
		else{
			char* des_str;
			uint32_t des_len;
			des_str = Number2CharArr(NULL,des_len,rop);
			std::string res_str = std::string(des_str,des_len);
			delete []des_str;
			cout<<" is "<<res_str<<endl;
		}*/
	}
	mpz_clears(rop,zero,NULL);
	for(uint32_t i=0;i<pair_len;i++){
		if(tmpBuffer[i] != NULL)
			delete[] tmpBuffer[i];
		tmpBuffer[i] = store[i];
	}
	level_usage[merge_level] = false;
	return_sig = true;
	return return_sig;
}
std::string blockType_str(const block_type blk){
	if(blk==DummyType)
		return std::string("dummy");
	if(blk==RealType)
		return std::string("real");
	else
		return std::string("Noisy");
}
block_type SSORAM::getBlockType(const uint32_t& id1, const uint32_t& id2){
	if(blockMap[id1]==blockMap[id2]){
		if(blockMap[id1]==DummyType)
			return DummyType;
		else
			return NoisyType;
	}
	else
		return RealType;
}
