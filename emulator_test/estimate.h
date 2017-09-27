#ifndef ESTIMATE_H
#define ESTIMATE_H

#include <cstdint>

extern double _standard_paillier_enc;
extern double _standard_paillier_dec;
extern double _standard_paillier_add;
extern double _standard_paillier_mul;

extern double _virtual_paillier_enc;
extern double _virtual_paillier_dec;
extern double _virtual_paillier_add;
extern double _virtual_paillier_mul;

extern double _infer_jd_paillier_enc;
extern double _infer_jd_paillier_dec;
extern double _infer_jd_paillier_add;
extern double _infer_jd_paillier_mul;

extern double _virtual_jd_paillier_enc;
extern double _virtual_jd_paillier_dec;
extern double _virtual_jd_paillier_add;
extern double _virtual_jd_paillier_mul;

#define PROBALITY(level)  (double)1/(double)(1<<level)
void pre_process();
double _write_estimation_normal(const unsigned int level,double& enc_time,double& dec_time,double& add_time,double& multi_time);
double write_estimation_normal(const unsigned int level,double& enc_time,double& dec_time,double& add_time,double& multi_time);
double write_estimation_shuffleJob(double& enc_time,double& dec_time,double& add_time,double& multi_time,const unsigned int maxBlock = 102400);
double _read_estimation(const unsigned int condition,double& enc_time,double& dec_time,double& add_time,double& multi_time);
double read_estimation(const unsigned int times,double& enc_time,double& dec_time,double& add_time,double& multi_time,const unsigned int maxBlock);

double onion_test(double& enc_time,double& dec_time,double& add_time,double& multi_time,const unsigned int maxBlock = 102400);
# endif
