
#include "estimate.h"
#include <cryptopp/osrng.h>
#include <iostream>
#include <math.h>
#include "../Util/Util.h"
using std::endl;
using std::cout;

// all in ms 2048 bits
double _standard_paillier_enc = 3.466;
double _standard_paillier_dec = 3.536;
double _standard_paillier_add = 0.739;
double _standard_paillier_mul = 14514.176;


double _virtual_paillier_enc = 13.97521;
double _virtual_paillier_dec = 13.456;
double _virtual_paillier_add = 0.00848;
double _virtual_paillier_mul = 52.2546;

double _virtual_jd_paillier_enc = 31.89319;
double _virtual_jd_paillier_dec = 15.89912;
double _virtual_jd_paillier_add = 0.00809;
double _virtual_jd_paillier_mul = 49.61759;

// all in ms 1024 bits
/*double _standard_paillier_enc = 0.694;
double _standard_paillier_dec = 0.724;
double _standard_paillier_add = 0.0002;
double _standard_paillier_mul = 2.28;


double _virtual_paillier_enc = 3.58169;
double _virtual_paillier_dec = 3.67243;
double _virtual_paillier_add = 0.00283;
double _virtual_paillier_mul = 21.28;

double _virtual_jd_paillier_enc = 6.06209;
double _virtual_jd_paillier_dec = 2.71626;
double _virtual_jd_paillier_add = 0.00267;
double _virtual_jd_paillier_mul = 8.62332;*/

// test times
/*double _standard_paillier_enc = 1;
double _standard_paillier_dec = 1;
double _standard_paillier_add = 1;
double _standard_paillier_mul = 1;

double _virtual_paillier_enc = 1;
double _virtual_paillier_dec = 1;
double _virtual_paillier_add = 1;
double _virtual_paillier_mul = 1;*/
/*double _virtual_jd_paillier_enc = 1;
double _virtual_jd_paillier_dec = 1;
double _virtual_jd_paillier_add = 1;
double _virtual_jd_paillier_mul = 1;*/
double _infer_jd_paillier_enc;
double _infer_jd_paillier_dec;
double _infer_jd_paillier_add;
double _infer_jd_paillier_mul;





void pre_process(){
	_infer_jd_paillier_enc = _virtual_jd_paillier_enc/(_virtual_paillier_enc/_standard_paillier_enc);
	_infer_jd_paillier_dec = _virtual_jd_paillier_dec/(_virtual_paillier_dec/_standard_paillier_dec);
	_infer_jd_paillier_add = _virtual_jd_paillier_add/(_virtual_paillier_enc/_standard_paillier_enc);
	_infer_jd_paillier_mul = _virtual_jd_paillier_mul/(_virtual_paillier_enc/_standard_paillier_enc);
	//cout<<"enc:\t"<<_infer_jd_paillier_enc<<"\tdec\t"<<_infer_jd_paillier_dec<<"\tadd\t"<<_infer_jd_paillier_add<<"\tmul\t"<<_infer_jd_paillier_mul<<endl;
}
// normal condition
double _write_estimation_normal(const unsigned int level,double& enc_time,double& dec_time,double& add_time,double& multi_time){
	double* mul = new double[level+1];
	double* add = new double[level+1];
	mul[1] = _infer_jd_paillier_mul;
	add[1] = _infer_jd_paillier_add;
	enc_time = 0;
	dec_time = 0;
	add_time = 0;
	multi_time = 0;
	for(int i=2;i<=level;i++){
		mul[i] = mul[i-1]*(1.5);
		add[i] = add[i-1]*(1.5);
		//mul[i] = mul[i-1];
		//add[i] = add[i-1];
	}
	double estimation_time = 0 ;
	enc_time = 2*(2<<(level+1)-1)*_infer_jd_paillier_enc;
	estimation_time+= enc_time;
	for(int i=1;i<=level;i++){
		multi_time+=mul[i]*(2<<(i+1));
		add_time+=add[i]*(2<<(i+1));
	}
	estimation_time+= multi_time;
	estimation_time+= add_time;
	//gc
	delete[] mul;
	delete[] add;
	return estimation_time;
}
double write_estimation_normal(const unsigned int level,double& enc_time,double& dec_time,double& add_time,double& multi_time){
	pre_process();
	enc_time = 0;
	dec_time = 0;
	add_time = 0;
	multi_time = 0;
	double pro;
	double result;
	double tmp_enc=0,tmp_dec=0,tmp_add=0,tmp_mul=0;
	for(int i=1;i<=level;i++){
		pro = PROBALITY(i);
		result += pro * _write_estimation_normal(i,tmp_enc,tmp_dec,tmp_add,tmp_mul);
		enc_time+= pro*tmp_enc;
		dec_time+= pro*tmp_dec;
		add_time+= pro*tmp_add;
		multi_time+= pro*tmp_mul;
	}
	//cout<<"all write time\t"<<result<<"\tenc time:\t"<<enc_time<<"\tdec_time:\t"<<dec_time<<"\tadd_time:\t"<<add_time<<"\tmulti_time:\t"<<multi_time<<endl;
	return result;

}
double write_estimation_shuffleJob(double& enc_time,double& dec_time,double& add_time,double& multi_time,const unsigned int maxBlock){
	pre_process();
	unsigned int maxLevel = ceil(log(maxBlock)/log(2));
	unsigned int shuffleBlock = maxLevel*8;
	unsigned int LL = ceil(log(maxLevel)/log(2));
	enc_time = 0;
	dec_time = 0;
	add_time = 0;
	multi_time = 0;
	double pro;
	double result=0,tmpResult=0;
	double tmp_enc=0,tmp_dec=0,tmp_add=0,tmp_mul=0;
	double enc=0,dec=0,add=0,mul=0;
	for(int i=1;i<=LL;i++){
		pro = PROBALITY(i);
		result += pro * _write_estimation_normal(i,tmp_enc,tmp_dec,tmp_add,tmp_mul);
		enc_time+= pro*tmp_enc;
		dec_time+= pro*tmp_dec;
		add_time+= pro*tmp_add;
		multi_time+= pro*tmp_mul;
	}
	unsigned int LLblock = 1<<(LL+1);
	for(int i=LL+1;i<=maxLevel;i++){
		pro = PROBALITY(i);
		tmpResult += pro * _write_estimation_normal(i,tmp_enc,tmp_dec,tmp_add,tmp_mul);
		enc+= pro*tmp_enc;
		dec+= pro*tmp_dec;
		add+= pro*tmp_add;
		mul+= pro*tmp_mul;
	}
	result+= tmpResult * shuffleBlock /(maxBlock-LLblock);
	enc_time += enc* shuffleBlock/(maxBlock-LLblock);
	dec_time += dec* shuffleBlock/(maxBlock-LLblock);
	add_time += add* shuffleBlock/(maxBlock-LLblock);
	multi_time += mul* shuffleBlock/(maxBlock-LLblock);

	//cout<<"all write time\t"<<result<<"\tenc time:\t"<<enc_time<<"\tdec_time:\t"<<dec_time<<"\tadd_time:\t"<<add_time<<"\tmulti_time:\t"<<multi_time<<endl;
	return result;

}

double _read_estimation(const unsigned int _condition,double& enc_time,double& dec_time,double& add_time,double& multi_time){
	unsigned int numArr[50];//since 17 is the normal max level
	double *mul;
	unsigned int maxLevel = 0,condition,levelNum=0;
	enc_time = 0;
	dec_time = 0;
	add_time = 0;
	multi_time = 0;
	condition = _condition;
	//cout<<"condition:\t"<<condition<<endl;
	while(condition>0){
		maxLevel++;
		if(condition&1){
			numArr[levelNum] = maxLevel;
			levelNum++;
		}
		condition = condition>>1;
	}
	//cout<<"level:\t"<<levelNum<<"\tmaxLevel\t"<<maxLevel<<endl;
	enc_time = _infer_jd_paillier_enc*levelNum;

	dec_time = _infer_jd_paillier_dec;
	for(unsigned int i=2;i<=maxLevel;i++){
		dec_time = dec_time + _infer_jd_paillier_dec*pow(i-1,1.5);
		//dec_time = dec_time + 1;
	}

	add_time = levelNum*_infer_jd_paillier_add * pow(maxLevel-1,1.5);
	//add_time = levelNum*_infer_jd_paillier_add;

	mul = new double[maxLevel+1];
	mul[1] = _infer_jd_paillier_mul;
	for(int i=2;i<=maxLevel;i++){
		mul[i] = mul[i-1]*1.5;
		//mul[i] = mul[i-1];
	}
	for(int i=0;i<levelNum;i++){
		for(int j=numArr[i];j<=maxLevel;j++){
			multi_time +=mul[j];
			//cout<<multi_time<<endl;
		}
	}

	delete []mul;
	double result = enc_time + dec_time + multi_time + add_time;
	//cout<<"all read time\t"<<result<<"\tenc time:\t"<<enc_time<<"\tdec_time:\t"<<dec_time<<"\tadd_time:\t"<<add_time<<"\tmulti_time:\t"<<multi_time<<endl;
	return result;
}
double read_estimation(const unsigned int times,double& enc_time,double& dec_time,double& add_time,double& multi_time,const unsigned int maxBlock){
	pre_process();
	double result;
	enc_time = 0;
	dec_time = 0;
	add_time = 0;
	multi_time = 0;
	double tmp_enc,tmp_dec,tmp_add,tmp_multi;
	for(int i=0;i<times;i++){
		result +=_read_estimation(Util::rand_int(maxBlock),tmp_enc,tmp_dec,tmp_add,tmp_multi);
		enc_time += tmp_enc;
		dec_time += tmp_dec;
		add_time += tmp_add;
		multi_time += tmp_multi;
	}
	result = result/times;
	enc_time = enc_time/times;
	dec_time = dec_time/times;
	add_time = add_time/times;
	multi_time = multi_time/times;
	//cout<<"all read time\t"<<result<<"\tenc time:\t"<<enc_time<<"\tdec_time:\t"<<dec_time<<"\tadd_time:\t"<<add_time<<"\tmulti_time:\t"<<multi_time<<endl;
	return result;
}
double onion_test(double& enc_time,double& dec_time,double& add_time,double& multi_time,const unsigned int maxBlock){
	pre_process();
	unsigned int averageLevel = ceil(1.2*(log(maxBlock)/log(2)));
	enc_time = 0;
	dec_time = 0;
	add_time = 0;
	multi_time = 0;
	double result;
	double read_enc = 0,read_dec=0,read_add=0,read_mul=0,read=0;
	double write_enc =0,write_dec=0,write_add=0,write_mul=0,write=0;
	read = _read_estimation((1<<averageLevel)-1,read_enc,read_dec,read_add,read_mul);
	averageLevel = ceil((log(maxBlock)/log(2)));
	write_enc = averageLevel*averageLevel*_infer_jd_paillier_enc;
	write_add = (averageLevel-1)*(averageLevel-1)*_infer_jd_paillier_add* pow(averageLevel,1.5);
	write_mul = averageLevel*averageLevel*_infer_jd_paillier_mul* pow(averageLevel,1.5);
	enc_time = write_enc+read_enc;
	dec_time = write_dec+read_dec;
	add_time = write_add+read_add;
	multi_time = write_mul+read_mul;
	write = write_enc+write_dec+write_add+write_mul;
	result = write+read;
	//cout<<"read access:\t"<<result<<"\tenc:\t"<<enc_time<<"\tdec:\t"<<dec_time<<"\tadd:\t"<<add_time<<"\tmul:\t"<<multi_time<<endl;
	return result;

}
