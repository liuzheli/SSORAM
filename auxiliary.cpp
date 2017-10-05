#include "auxiliary.h"
using std::cout;
using std::endl;

using namespace mongo;
using namespace CryptoPP;

void test_jd_encryption_efficiency(){
	size_t times = 100;
	cout<<"test "<<times<<" encryption times"<<endl;
	cout<<"----------------------------------------------------"<<endl;
	// key initialize
	djcs_public_key *dj_pk = djcs_init_public_key();
	djcs_private_key *dj_vk = djcs_init_private_key();
	hcs_random *hr = hcs_init_random();
	djcs_generate_key_pair(dj_pk,dj_vk,hr,2,2048);
	// data prepare
	mpz_t* arr = new mpz_t[times];
	for(size_t i=0;i<times;i++){
		mpz_init(arr[i]);
		mpz_set_ui(arr[i],i);
	}
	clock_t start,end;
	start = clock();
	//encryption test
	for(size_t i=0;i<times;i++)
		djcs_encrypt(dj_pk, hr, arr[i], arr[i]);
	end = clock();
	printf("encryption spending times %f seconds\n", (end-start)/(double)CLOCKS_PER_SEC);
	// gc
	for(size_t i=0;i<times;i++){
		mpz_clear(arr[i]);
	}
	delete [] arr;
	djcs_free_public_key(dj_pk);
	djcs_free_private_key(dj_vk);
	hcs_free_random(hr);

}
void test_p_encryption_efficiency(){
	size_t times = 100;
	cout<<"test "<<times<<" encryption times"<<endl;
	cout<<"----------------------------------------------------"<<endl;
	pcs_public_key *pk = pcs_init_public_key();
	pcs_private_key *vk = pcs_init_private_key();
	hcs_random *hr = hcs_init_random();

	// Generate a key pair with modulus of size 2048 bits
	pcs_generate_key_pair(pk, vk, hr, 2048);
	// data prepare
	mpz_t* arr = new mpz_t[times];
	for(size_t i=0;i<times;i++){
		mpz_init(arr[i]);
		mpz_set_ui(arr[i],i);
	}
	clock_t start,end;
	start = clock();
	//encryption test
	for(size_t i=0;i<times;i++)
		pcs_encrypt(pk, hr, arr[i], arr[i]);
	end = clock();
	printf("encryption spending times %f seconds\n", (end-start)/(double)CLOCKS_PER_SEC);
	// gc
	for(size_t i=0;i<times;i++){
		mpz_clear(arr[i]);
	}
	delete [] arr;
	pcs_free_public_key(pk);
	pcs_free_private_key(vk);
	hcs_free_random(hr);

}
void test_p_decryption_efficiency(){
	size_t times = 100;
	cout<<"test "<<times<<" decryption times"<<endl;
	cout<<"----------------------------------------------------"<<endl;
	// key initialize
	pcs_public_key *pk = pcs_init_public_key();
	pcs_private_key *vk = pcs_init_private_key();
	hcs_random *hr = hcs_init_random();
	pcs_generate_key_pair(pk, vk, hr, 2048);
	// data prepare
	mpz_t* arr = new mpz_t[times];
	for(size_t i=0;i<times;i++){
		mpz_init(arr[i]);
		mpz_set_ui(arr[i],i);
	}
		//encryption
	for(size_t i=0;i<times;i++)
		pcs_encrypt(pk, hr, arr[i], arr[i]);
	// decryption test
	clock_t start,end;
	start = clock();
	for(size_t i=0;i<times;i++)
		pcs_decrypt(vk, arr[i], arr[i]);
	end = clock();
	printf("decryption spending times %f seconds\n", (end-start)/(double)CLOCKS_PER_SEC);
	// gc
	for(size_t i=0;i<times;i++){
		mpz_clear(arr[i]);
	}
	delete [] arr;
	pcs_free_public_key(pk);
	pcs_free_private_key(vk);
	hcs_free_random(hr);
}
void test_jd_decryption_efficiency(){
	size_t times = 100;
	cout<<"test "<<times<<" decryption times"<<endl;
	cout<<"----------------------------------------------------"<<endl;
	// key initialize
	djcs_public_key *dj_pk = djcs_init_public_key();
	djcs_private_key *dj_vk = djcs_init_private_key();
	hcs_random *hr = hcs_init_random();
	djcs_generate_key_pair(dj_pk,dj_vk,hr,2,2048);
	// data prepare
	mpz_t* arr = new mpz_t[times];
	for(size_t i=0;i<times;i++){
		mpz_init(arr[i]);
		mpz_set_ui(arr[i],i);
	}
		//encryption
	for(size_t i=0;i<times;i++)
		djcs_encrypt(dj_pk, hr, arr[i], arr[i]);
	// decryption test
	clock_t start,end;
	start = clock();
	for(size_t i=0;i<times;i++)
		djcs_decrypt(dj_vk,arr[i], arr[i]);
	end = clock();
	printf("decryption spending times %f seconds\n", (end-start)/(double)CLOCKS_PER_SEC);
	// gc
	for(size_t i=0;i<times;i++){
		mpz_clear(arr[i]);
	}
	delete [] arr;
	djcs_free_public_key(dj_pk);
	djcs_free_private_key(dj_vk);
	hcs_free_random(hr);

}
void test_p_add_efficiency(){
	size_t times = 100;
	cout<<"test "<<times<<" add times"<<endl;
	cout<<"----------------------------------------------------"<<endl;
	// key initialize
	pcs_public_key *pk = pcs_init_public_key();
	pcs_private_key *vk = pcs_init_private_key();
	hcs_random *hr = hcs_init_random();
	pcs_generate_key_pair(pk, vk, hr, 2048);
	// data prepare
	mpz_t tmp;
	mpz_init(tmp);
	mpz_t* arr = new mpz_t[times];
	for(size_t i=0;i<times;i++){
		mpz_init(arr[i]);
		mpz_set_ui(arr[i],i);
	}
		//encryption
	for(size_t i=0;i<times;i++)
		pcs_encrypt(pk, hr, arr[i], arr[i]);
	// decryption test
	clock_t start,end;
	start = clock();
	for(size_t i=0;i<times;i++)
		pcs_ee_add(pk, tmp, arr[i], arr[i]);

	end = clock();
	printf("add spending times %f seconds\n", (end-start)/(double)CLOCKS_PER_SEC);
	// gc
	mpz_clear(tmp);
	for(size_t i=0;i<times;i++){
		mpz_clear(arr[i]);
	}
	delete [] arr;
	pcs_free_public_key(pk);
	pcs_free_private_key(vk);
	hcs_free_random(hr);
}
void test_jd_add_efficiency(){
	size_t times = 100;
	cout<<"test "<<times<<" add times"<<endl;
	cout<<"----------------------------------------------------"<<endl;
	// key initialize
	djcs_public_key *dj_pk = djcs_init_public_key();
	djcs_private_key *dj_vk = djcs_init_private_key();
	hcs_random *hr = hcs_init_random();
	djcs_generate_key_pair(dj_pk,dj_vk,hr,2,2048);
	// data prepare
	mpz_t tmp;
	mpz_init(tmp);
	mpz_t* arr = new mpz_t[times];
	for(size_t i=0;i<times;i++){
		mpz_init(arr[i]);
		mpz_set_ui(arr[i],i);
	}
		//encryption
	for(size_t i=0;i<times;i++)
		djcs_encrypt(dj_pk, hr, arr[i], arr[i]);
	// decryption test
	clock_t start,end;
	start = clock();
	for(size_t i=0;i<times;i++)
		djcs_ee_add(dj_pk, tmp, arr[i], arr[i]);
	end = clock();
	printf("add spending times %f seconds\n", (end-start)/(double)CLOCKS_PER_SEC);
	// gc
	mpz_clear(tmp);
	for(size_t i=0;i<times;i++){
		mpz_clear(arr[i]);
	}
	delete [] arr;
	djcs_free_public_key(dj_pk);
	djcs_free_private_key(dj_vk);
	hcs_free_random(hr);
}
void test_jd_mul_efficiency(){
	size_t times = 100;
	cout<<"test "<<times<<" multi times"<<endl;
	cout<<"----------------------------------------------------"<<endl;
	// key initialize
	djcs_public_key *dj_pk = djcs_init_public_key();
	djcs_private_key *dj_vk = djcs_init_private_key();
	hcs_random *hr = hcs_init_random();
	djcs_generate_key_pair(dj_pk,dj_vk,hr,2,2048);
	// data prepare
	mpz_t *result;
	size_t len;
	mpz_t tmp,zero;
	mpz_inits(tmp,zero,NULL);
	mpz_t* arr = new mpz_t[times];
	for(size_t i=0;i<times;i++){
		mpz_init(arr[i]);
		mpz_set_ui(arr[i],i);
	}
		//encryption
	for(size_t i=0;i<times;i++)
		djcs_encrypt(dj_pk, hr, arr[i], arr[i]);
	djcs_encrypt(dj_pk, hr, zero,zero);
	// decryption test
	clock_t start,end;
	start = clock();
	for(size_t i=0;i<times;i++)
		djcs_e01e_mul(dj_pk,result,len,zero,arr[i]);
	end = clock();
	printf("multi spending times %f seconds\n", (end-start)/(double)CLOCKS_PER_SEC);
	// gc
	mpz_clears(tmp,zero,NULL);
	for(size_t i=0;i<times;i++){
		mpz_clear(arr[i]);
	}
	delete [] arr;
	djcs_free_public_key(dj_pk);
	djcs_free_private_key(dj_vk);
	hcs_free_random(hr);
}
void djcs_e01e_mul(djcs_public_key *pk, mpz_t*& rop,size_t& arrLen, mpz_t cipher1, mpz_t cipher2,uint32_t segLenInBits){
	size_t cipher2_bytes,off=0;
	char *buf;
	cipher2_bytes = mpz_sizeinbase(cipher2,2);
	size_t totolSeg = ceil(double(cipher2_bytes)/segLenInBits);
	buf = new char[totolSeg*segLenInBits];
	memset (buf, 0, totolSeg*segLenInBits);
	buf = mpz_get_str(buf,2,cipher2);
	/*parse to part
	 * first bit --|-------|-------|------|------- last bit|
	 *   part seg  segment  segment         segment
	 *   totolSeg-1  totolSeg-2        1      0
	 */
	off =cipher2_bytes - segLenInBits;
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
	//merge
	rop = tmpArr;
	arrLen = totolSeg;
}

void djcs_decrypt_merge_array_multi(djcs_private_key *vk,mpz_t*& rop,size_t& arrLen,mpz_t* tmpArr,size_t& totolSeg,uint32_t segLenInBits,uint32_t DecryptionLen){
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
void djcs_e01e_mul_multi(djcs_public_key *pk, mpz_t*& rop,size_t& arrLen, mpz_t cipher1, mpz_t* cipher2,size_t cipher2_len,uint32_t segLenInBits,uint32_t DecryptionLen){
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
void test_jd_efficiency(){
	test_jd_encryption_efficiency();
	test_jd_decryption_efficiency();
	test_jd_add_efficiency();
	test_jd_mul_efficiency();
}
void test_p_efficiency(){
	test_p_encryption_efficiency();
	test_p_decryption_efficiency();
	test_p_add_efficiency();
}
void test_jd_encryption(){
	djcs_public_key *dj_pk = djcs_init_public_key();
	djcs_private_key *dj_vk = djcs_init_private_key();
	hcs_random *hr = hcs_init_random();
	djcs_generate_key_pair(dj_pk,dj_vk,hr,2,2048);
	mpz_t a,zero;
	mpz_inits(a,zero,NULL);
	mpz_set_ui(a, 17);
	mpz_set_ui(zero,0);
	djcs_encrypt(dj_pk, hr, zero, zero);
	djcs_ep_mul(dj_pk,a,zero,a);
	cout<<mpz_sizeinbase(zero,2)<<endl;
	/*size_t times = 2;
	cout<<"bits length test\n";
	cout<<"oral bits length:\t"<<mpz_sizeinbase(a,2)<<endl;
	for(int i=0;i<times;i++){
		djcs_encrypt(dj_pk, hr, a, a);
		cout<<"encrypted times:\t"<<i<<"\tbits length"<<mpz_sizeinbase(a,2)<<endl;
		gmp_printf("encrypted value:\t%Zd\n",a);
	}
	cout<<endl;
	for(int i=times-1;i>=0;i--){
		djcs_decrypt(dj_vk,a,a);
		cout<<"decrypted times:\t"<<i<<"\tbits length"<<mpz_sizeinbase(a,2)<<endl;
		gmp_printf("decrypted value:\t%Zd\n",a);
	}*/


	mpz_clear(a);
	djcs_free_public_key(dj_pk);
	djcs_free_private_key(dj_vk);
	hcs_free_random(hr);
}
void test_jd(){
    djcs_public_key *dj_pk = djcs_init_public_key();
    djcs_private_key *dj_vk = djcs_init_private_key();
    hcs_random *hr = hcs_init_random();

    djcs_generate_key_pair(dj_pk,dj_vk,hr,2,2048);

    mpz_t *resulta;//,*resultb,*resultc;
    mpz_t a,b,c,zero,one,encryptZero,encryptOne;
    mpz_inits(a,b,c,NULL);
    mpz_inits(zero,one,encryptZero,encryptOne,NULL);

    mpz_set_ui(a, 170);
    mpz_set_ui(b, 6);
    mpz_set_ui(zero,0);
    mpz_set_ui(one,1);

    size_t lena;//,lenb,lenc;
    djcs_encrypt(dj_pk, hr, encryptZero,zero);
    djcs_encrypt(dj_pk, hr, encryptOne, one);
    djcs_encrypt(dj_pk, hr, a,a);

    djcs_encrypt(dj_pk, hr, b,b);
    djcs_decrypt(dj_vk,a,a);

    //encryption 3 layers
    //djcs_e01e_mul(dj_pk,resulta,lena,encryptOne,a);
    //djcs_e01e_mul_multi(dj_pk,resulta,lena,encryptOne,&a,1);
    /*for(int i=0;i<5;i++){
    	djcs_e01e_mul_multi(dj_pk,resulta,lena,encryptOne,resulta,lena);
    }
    for(int i=0;i<5;i++){
    	djcs_decrypt_merge_array_multi(dj_vk,resulta,lena,resulta,lena);
    }*/
    //djcs_decrypt_merge_array(dj_vk,c,resulta,lena);
    gmp_printf("recoverA %Zd\n", c);



    /*djcs_e01e_mul(dj_pk,resulta,lena,encryptOne,a);
    djcs_e01e_mul(dj_pk,resultc,lenc,encryptOne,b);
    djcs_e01e_mul_multi(dj_pk,resultb,lenb,encryptOne,resulta,lena);
    djcs_e01e_mul_multi(dj_pk,resultc,lenc,encryptZero,resultc,lenc);
    djcs_e01e_add(dj_pk,resulta,lenc,lenb,resultc,resultb);
    djcs_decrypt_merge_array_multi(dj_vk,resulta,lena,resulta,lenc);
    djcs_decrypt_merge_array(dj_vk,c,resulta,lena);
    gmp_printf("recoverA %Zd\n", c);*/

    mpz_clears(zero,one,NULL);
    mpz_clears(a, b, c, NULL);
    djcs_free_public_key(dj_pk);
    djcs_free_private_key(dj_vk);
    hcs_free_random(hr);
}
void test_pathOram(){

}
void test_sOram(){
    mongo::client::initialize();

    srand((uint32_t)time(NULL));

    uint32_t N = 3;
    ORAM* oram = new SSORAM(N);


    std::string block = oram->get((uint32_t) 1);
    cout<<block<<endl;

    /*for(size_t i = 2; i < 3; i++) {

        char str[12];
        sprintf(str, "%zu\n", i);
        std::string key(str);
        std::string block = oram->get(key);
        cout<<block<<endl;
        if(block=="0")
        	cout<<block;
        else{
        	uint32_t value;
        	memcpy((& value), block.c_str(), sizeof(uint32_t));
        	printf("%d ", value);
        }
    }*/

    printf("\n=========================================================================\n");

    delete oram;
    mongo::client::shutdown();
}
