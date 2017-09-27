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
	for(int i=0;i<times;i++){
		mpz_init(arr[i]);
		mpz_set_ui(arr[i],i);
	}
	clock_t start,end;
	start = clock();
	//encryption test
	for(int i=0;i<times;i++)
		djcs_encrypt(dj_pk, hr, arr[i], arr[i]);
	end = clock();
	printf("encryption spending times %f seconds\n", (end-start)/(double)CLOCKS_PER_SEC);
	// gc
	for(int i=0;i<times;i++){
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
	for(int i=0;i<times;i++){
		mpz_init(arr[i]);
		mpz_set_ui(arr[i],i);
	}
	clock_t start,end;
	start = clock();
	//encryption test
	for(int i=0;i<times;i++)
		pcs_encrypt(pk, hr, arr[i], arr[i]);
	end = clock();
	printf("encryption spending times %f seconds\n", (end-start)/(double)CLOCKS_PER_SEC);
	// gc
	for(int i=0;i<times;i++){
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
	for(int i=0;i<times;i++){
		mpz_init(arr[i]);
		mpz_set_ui(arr[i],i);
	}
		//encryption
	for(int i=0;i<times;i++)
		pcs_encrypt(pk, hr, arr[i], arr[i]);
	// decryption test
	clock_t start,end;
	start = clock();
	for(int i=0;i<times;i++)
		pcs_decrypt(vk, arr[i], arr[i]);
	end = clock();
	printf("decryption spending times %f seconds\n", (end-start)/(double)CLOCKS_PER_SEC);
	// gc
	for(int i=0;i<times;i++){
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
	for(int i=0;i<times;i++){
		mpz_init(arr[i]);
		mpz_set_ui(arr[i],i);
	}
		//encryption
	for(int i=0;i<times;i++)
		djcs_encrypt(dj_pk, hr, arr[i], arr[i]);
	// decryption test
	clock_t start,end;
	start = clock();
	for(int i=0;i<times;i++)
		djcs_decrypt(dj_vk,arr[i], arr[i]);
	end = clock();
	printf("decryption spending times %f seconds\n", (end-start)/(double)CLOCKS_PER_SEC);
	// gc
	for(int i=0;i<times;i++){
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
	for(int i=0;i<times;i++){
		mpz_init(arr[i]);
		mpz_set_ui(arr[i],i);
	}
		//encryption
	for(int i=0;i<times;i++)
		pcs_encrypt(pk, hr, arr[i], arr[i]);
	// decryption test
	clock_t start,end;
	start = clock();
	for(int i=0;i<times;i++)
		pcs_ee_add(pk, tmp, arr[i], arr[i]);

	end = clock();
	printf("add spending times %f seconds\n", (end-start)/(double)CLOCKS_PER_SEC);
	// gc
	mpz_clear(tmp);
	for(int i=0;i<times;i++){
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
	for(int i=0;i<times;i++){
		mpz_init(arr[i]);
		mpz_set_ui(arr[i],i);
	}
		//encryption
	for(int i=0;i<times;i++)
		djcs_encrypt(dj_pk, hr, arr[i], arr[i]);
	// decryption test
	clock_t start,end;
	start = clock();
	for(int i=0;i<times;i++)
		djcs_ee_add(dj_pk, tmp, arr[i], arr[i]);
	end = clock();
	printf("add spending times %f seconds\n", (end-start)/(double)CLOCKS_PER_SEC);
	// gc
	mpz_clear(tmp);
	for(int i=0;i<times;i++){
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
	for(int i=0;i<times;i++){
		mpz_init(arr[i]);
		mpz_set_ui(arr[i],i);
	}
		//encryption
	for(int i=0;i<times;i++)
		djcs_encrypt(dj_pk, hr, arr[i], arr[i]);
	djcs_encrypt(dj_pk, hr, zero,zero);
	// decryption test
	clock_t start,end;
	start = clock();
	for(int i=0;i<times;i++)
		djcs_e01e_mul(dj_pk,result,len,zero,arr[i]);
	end = clock();
	printf("multi spending times %f seconds\n", (end-start)/(double)CLOCKS_PER_SEC);
	// gc
	mpz_clears(tmp,zero,NULL);
	for(int i=0;i<times;i++){
		mpz_clear(arr[i]);
	}
	delete [] arr;
	djcs_free_public_key(dj_pk);
	djcs_free_private_key(dj_vk);
	hcs_free_random(hr);
}
void djcs_e01e_mul(djcs_public_key *pk, mpz_t*& rop,size_t& arrLen, mpz_t cipher1, mpz_t cipher2,uint32_t segLenInBytes){
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
void djcs_e01e_mul_multi(djcs_public_key *pk, mpz_t*& rop,size_t& arrLen, mpz_t cipher1, mpz_t* cipher2,size_t cipher2_len,uint32_t segLenInBytes){
	assert(cipher2_len>0);
	assert((cipher2_len % 2)==0);
	if(cipher2_len==1){
		djcs_e01e_mul(pk,rop,arrLen,cipher1,*cipher2,segLenInBytes);
	}else{
		size_t len1;
		size_t len2;
		djcs_e01e_mul_multi(pk,rop,len1,cipher1,cipher2,(cipher2_len/2),segLenInBytes);
		djcs_e01e_mul_multi(pk,rop,len1,cipher1,&cipher2[cipher2_len/2],(cipher2_len/2),segLenInBytes);
		assert(len1==len2);
		arrLen = len1;
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

    mpz_t *resulta,*resultb;
    mpz_t a,b,c,zero,one,encryptZero,encryptOne;
    mpz_inits(a,b,c,NULL);
    mpz_inits(zero,one,encryptZero,encryptOne,NULL);

    mpz_set_ui(a, 17);
    mpz_set_ui(b, 6);
    mpz_set_ui(zero,0);
    mpz_set_ui(one,1);

    size_t lena,lenb;
    djcs_encrypt(dj_pk, hr, encryptZero,zero);
    djcs_encrypt(dj_pk, hr, encryptOne, one);
    djcs_encrypt(dj_pk, hr, a,a);
    djcs_encrypt(dj_pk, hr, b,b);
    //djcs_e01e_mul(dj_vk,dj_pk,result,len,encryptZero,encryptOne);
    djcs_e01e_mul(dj_pk,resulta,lena,encryptZero,a);
    djcs_e01e_mul(dj_pk,resultb,lenb,encryptOne,b);
    //void djcs_e01e_add(djcs_public_key *pk,mpz_t*& rop,const size_t cipher_len1,const size_t cipher_len2,mpz_t* cipher1, mpz_t* cipher2);
    djcs_e01e_add(dj_pk,resulta,lena,lenb,resulta,resultb);
    djcs_decrypt_merge_array(dj_vk,c,resulta,lena);



    //char* buf = mpz_get_str(NULL,2,encryptOne);
    //cout<<(size_t)buf[mpz_sizeinbase(encryptOne,2)]<<endl;
    //mpz_add(a,a,b);
    gmp_printf("recoverA %Zd\n", c);

//    char buf[40001];
//    buf[40000] = 0;
//    for(int i=0;i<40000;i++)
//    	buf[i] = '1';

    // add add_ee operation
    /*djcs_encrypt(dj_pk, hr, a, a);  // Encrypt a (= 50) and store back into a
    djcs_encrypt(dj_pk, hr, b, b);  // Encrypt b (= 76) and store back into b
    gmp_printf("a = %Zd\nb = %Zd\n", a, b); // can use all gmp functions still

    djcs_ee_add(dj_pk, c, a, b);    // Add encrypted a and b values together into c
    djcs_decrypt(dj_vk, c, c);      // Decrypt c back into c using private key
    gmp_printf("%Zd\n", c);     // output: c = 126*/

    //multiply ep operation
    /*djcs_encrypt(dj_pk, hr, encryptZero, zero);
    djcs_ep_mul(dj_pk,b,encryptZero,zero);*/

    //djcs_ep_mul(dj_pk,a,encryptZero,zero);
    //gmp_printf("encryptC %Zd\n", c);
    //djcs_decrypt(dj_vk,c,a);
    /*djcs_ee_add(dj_pk, c, a, b);
    djcs_decrypt(dj_vk,c,c);
    gmp_printf("plaintextC %Zd\n", c);*/
    // Cleanup all data
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

    uint32_t N = 2;
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
