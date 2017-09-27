#include "auxiliary.h"
#include "emulator_test/estimate.h"
int main(void)
{
	//test_jd();
    //test_sOram();
	//test_jd_encryption();
	//test_jd_efficiency();
	//test_p_efficiency();
	/*double write_enc=0,write_dec=0,write_add=0,write_mul=0,write=0;
	double read_enc=0,read_dec=0,read_add=0,read_mul=0,read=0;
	double enc,dec,add,mul,result;
	unsigned int baseN = 102400;
	cout<<"ssoram \t"<<endl;
	for(int i=1;i<5;i++){
		read = read_estimation(1000,read_enc,read_dec,read_add,read_mul,baseN*i);
		write = write_estimation_shuffleJob(write_enc,write_dec,write_add,write_mul,baseN*i);
		enc = write_enc+read_enc;
		dec = write_dec+read_dec;
		add = write_add+read_add;
		mul = write_mul+read_mul;
		result = write+read;
		cout<<"N:\t"<<baseN*i<<"\writecost\t"<<result<<endl;
	}
	cout<<"onion \t"<<endl;
	for(int i=1;i<5;i++){
		double Cost = onion_test(enc,dec,add,mul,baseN*i);;
		cout<<"N:\t"<<baseN*i<<"\writecost\t"<<Cost<<endl;
	}*/
	// test
	/*cout<<"ssoram\n"<<endl;
	write = write_estimation_shuffleJob(write_enc,write_dec,write_add,write_mul);
	read = read_estimation(100,read_enc,read_dec,read_add,read_mul);
	enc = write_enc+read_enc;
	dec = write_dec+read_dec;
	add = write_add+read_add;
	mul = write_mul+read_mul;
	result = write+read;
	cout<<"totol access:\t"<<result<<"\tenc:\t"<<enc<<"\tdec:\t"<<dec<<"\tadd:\t"<<add<<"\tmul:\t"<<mul<<endl;
	cout<<"onion\n"<<endl;
	onion_test(enc,dec,add,mul);*/
    return 0;
}
