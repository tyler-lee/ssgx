#include <thread>
#include <stdio.h>
#include <iostream>
#include <pthread.h>
#include <sched.h>
#include <unistd.h>
#include <sys/sysinfo.h>
#include <stdlib.h>
#include <sys/ioctl.h>

using namespace std;

#include "App.h"
#include "Enclave_u.h"

#include "../Include/user_types.h"

//const int CORES_PER_CPU = get_nprocs();
//const int CORES_MASK = (1 << CORES_PER_CPU) - 1;

//TODO: switch between enclave and app
#define __USE_ENCLAVE__
#define __USE_FIFO_HIGHEST_PRIORITY__

uint64_t rdtscp() {
#ifdef __linux__
	uint64_t a, d;
	//asm volatile ("xor %%rax, %%rax\n" "cpuid"::: "rax", "rbx", "rcx", "rdx");
	asm volatile ("rdtscp" : "=a" (a), "=d" (d) : : "rcx");
	return (d << 32) | a;
#else
	unsigned int tsc;

	return __rdtscp(&tsc);
#endif
}

//ptr is of type const char*
#define clflush(p) asm volatile("clflush (%0)" : : "r" (p) : "memory")

void print_policy_string(int policy) {
	switch (policy)
	{
		case SCHED_FIFO:
			printf ("policy= SCHED_FIFO");
			break;
		case SCHED_RR:
			printf ("policy= SCHED_RR");
			break;
		case SCHED_OTHER:
			printf ("policy= SCHED_OTHER");
			break;
		default:
			printf ("policy= UNKNOWN");
			break;
	}
}
void show_thread_policy_and_priority() {
	int policy;
	sched_param sched;

	int ret = pthread_getschedparam(pthread_self(), &policy, &sched);
	if(ret != 0) printf("%s\n", strerror(errno));
	assert(ret == 0);

	printf("Thread %ld: ", pthread_self());
	print_policy_string(policy);
	printf (", priority= %d\n", sched.sched_priority);
}
void set_thread_policy_and_priority(int policy, int priority) {
	sched_param sched;
	sched.sched_priority = priority;
	int ret = pthread_setschedparam(pthread_self(), policy, &sched);
	if(ret != 0) printf("%s\n", strerror(errno));
	assert(ret == 0);

	printf ("Set thread %ld priority to %d\n", pthread_self(), priority);
}
void show_thread_policy_and_priority(pthread_attr_t *attr) {
	int policy;
	sched_param sched;

	int ret = pthread_attr_getschedparam(attr, &sched);
	assert(ret == 0);
	ret = pthread_attr_getschedpolicy(attr, &policy);
	assert(ret == 0);

	printf("Thread %ld: ", pthread_self());
	print_policy_string(policy);
	printf (", priority= %d\n", sched.sched_priority);
}
void set_thread_policy_and_priority(pthread_attr_t *attr, int policy, int priority) {
	sched_param sched;
	sched.sched_priority = priority;
	int ret = pthread_attr_setschedpolicy(attr, policy);
	assert(ret == 0);
	ret = pthread_attr_setschedparam(attr, &sched);
	assert(ret == 0);
}
void set_thread_affinity(int cpu) {
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(cpu, &mask);

	//printf("Thread %lu is running on cpu %d\n", pthread_self(), cpu);
	int ret = pthread_setaffinity_np(pthread_self(), sizeof(mask), &mask);
	assert(ret == 0);
}

#ifdef __USE_ENCLAVE__

void compute(size_t count)
{
	//bind current thread to core 0
	set_thread_affinity(0);

	printf("%s measure enclave isntances communication performance, i.e., a successful check (loops): %zu\n", __FUNCTION__, count);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	size_t hit = 0;
	size_t miss_max = 0;

	uint64_t cycles = rdtscp();
    ret = ecall_compute(global_eid, count, &hit, &miss_max);
    if (ret != SGX_SUCCESS) abort();
	cycles = rdtscp()-cycles;

	printf("Hit: %zu, Miss: %zu, Max miss: %zu\n", hit, count - hit, miss_max);
	if (hit != 0) printf("Average cycles: %zu\n", cycles/hit);
}
void seize_core(size_t cpu)
{
	set_thread_affinity(cpu);

	//cout << "Seize core " << cpu << endl;
	//printf("Seize core %zu\n", cpu);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    ret = ecall_seize_core(global_eid, cpu);
    if (ret != SGX_SUCCESS) abort();

	//printf("Release core %zu\n", cpu);
}

#else	//!__USE_ENCLAVE__

enum Commands {
	Cmd_set,
	Cmd_reset,
	Cmd_exit
};

//!!! MUST using volatile, otherwise threads CANNOT sync the latest value !!!
volatile Commands global_command = Cmd_reset;
volatile size_t cores_ready_flag = 0;

void compute(size_t count) {
	//bind current thread to core 0
	set_thread_affinity(0);

	global_command = Cmd_set;
	while (cores_ready_flag & CORES_MASK != CORES_MASK) cores_ready_flag |= 1;
	printf("Enter core: %d, cores_ready_flag: %zX\n", 0, cores_ready_flag);

	uint64_t hit = 0;
	uint64_t miss = 0;
	uint64_t miss_max = 0;
	uint64_t cycles = rdtscp();
	do {
		if (global_command == Cmd_reset) {
			cores_ready_flag = 0;
			if (cores_ready_flag == 0) {
				global_command = Cmd_set;
			}
		}
		else {
			cores_ready_flag |= 1;
		}

		if (cores_ready_flag == CORES_MASK) {
			//reset cmd
			global_command = Cmd_reset;

			//do jobs
			++hit;
			miss_max = max(miss, miss_max);
			miss = 0;
		}
		else {
			++miss;
		}
	} while (hit < count);
	cycles = rdtscp() - cycles;

	if(hit == 0) miss_max = count;
	printf("Hit: %zu, Miss: %zu, Max miss: %zu\n", hit, count - hit, miss_max);
	if (hit != 0) printf("Average cycles: %zu\n", cycles/hit);

	printf("Exit core: %d, cores_ready_flag: %zX\n", 0, cores_ready_flag);

	global_command = Cmd_exit;
}

void seize_core(int cpu) {
	//bind current thread to core
	set_thread_affinity(cpu);
	size_t cbit = 1 << cpu;

	printf("Enter core: %d, cores_ready_flag: %zX\n", cpu, cores_ready_flag);

	do {
		if (global_command == Cmd_set) {
			cores_ready_flag |= cbit;
		}
		else {
			cores_ready_flag = 0;
		}
	} while (global_command != Cmd_exit);

	printf("Exit core: %d, cores_ready_flag: %zX\n", cpu, cores_ready_flag);
}

#endif	//! __USE_ENCLAVE__

//测量enclave进出的开销
void measurement_empty_enclave() {
#ifdef __USE_ENCLAVE__
	size_t count = 1000000;
	cout << __FUNCTION__ << " (loops): " << count << endl;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	uint64_t cycles = rdtscp();
	for(int i = 0; i < count; i++) {
		ret = ecall_empty(global_eid);
		if (ret != SGX_SUCCESS) abort();
	}
	cycles = rdtscp()-cycles;
	cout << "Result (cycles per inout): " << cycles / count << endl << endl;
#else
#pragma message("Enable enclave first")
#endif
}

//测量各个enclave线程间通信开销
void measurement_internal_thread() {
	size_t count = 1000000;
	cout << __FUNCTION__ << " (loops): " << count << endl;
#ifdef __USE_ENCLAVE__
	cout << "Occupy " << CORES_PER_CPU << " cores" << endl
		<< "============ Enclave Mode =============" << endl;
#else
	cout << "Occupy " << CORES_PER_CPU << " cores" << endl
		<< "============ Application Mode =============" << endl;
#endif

	thread threads[CORES_PER_CPU];
	for(int i = 1; i < CORES_PER_CPU; i++) {
		threads[i] = thread(seize_core, i);
	}
	threads[0] = thread(compute, count);

	for(int i = 0; i < CORES_PER_CPU; i++) {
		threads[i].join();
	}
}

//测量RSA计算性能
#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_fprintf    fprintf
#define mbedtls_printf     printf
#define mbedtls_snprintf   snprintf
#endif

#if defined(MBEDTLS_BIGNUM_C) && defined(MBEDTLS_ENTROPY_C) && \
    defined(MBEDTLS_RSA_C) && defined(MBEDTLS_GENPRIME) && \
    defined(MBEDTLS_FS_IO) && defined(MBEDTLS_CTR_DRBG_C)
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/bignum.h"
#include "mbedtls/x509.h"
#include "mbedtls/rsa.h"
#include "mbedtls/md.h"

#include <stdio.h>
#include <string.h>
#endif

#define KEY_SIZE 2048
#define EXPONENT 65537

#if !defined(MBEDTLS_BIGNUM_C) || !defined(MBEDTLS_ENTROPY_C) ||   \
    !defined(MBEDTLS_RSA_C) || !defined(MBEDTLS_GENPRIME) ||      \
    !defined(MBEDTLS_FS_IO) || !defined(MBEDTLS_CTR_DRBG_C)
void measurement_rsa_sign_performance() {
    mbedtls_printf("MBEDTLS_BIGNUM_C and/or MBEDTLS_ENTROPY_C and/or "
           "MBEDTLS_RSA_C and/or MBEDTLS_GENPRIME and/or "
           "MBEDTLS_FS_IO and/or MBEDTLS_CTR_DRBG_C not defined.\n");
}
#else
void measurement_rsa_sign_performance() {
#ifdef __LHR_MEASURE__
	size_t count = 2000;
	//size_t count = 1;
    int ret;
	uint64_t cycles;
	size_t key_size_in_bit = 2048;
	cout << __FUNCTION__ << " with " << key_size_in_bit << "-bit key (loops): " << count << endl;
    fflush( stdout );

enclave:
#ifdef __USE_ENCLAVE__
	cout << "============ Enclave Mode =============" << endl;
    sgx_status_t sgx_ret = SGX_ERROR_UNEXPECTED;

    sgx_ret = ecall_rsa_sign_init(global_eid, &ret, key_size_in_bit);
    if (sgx_ret != SGX_SUCCESS || ret == -1) abort();


	cycles = rdtscp();
	sgx_ret = ecall_rsa_sign_do(global_eid, &ret, count);
	cycles = rdtscp()-cycles;
    if (sgx_ret != SGX_SUCCESS || ret == -1) abort();
	cout << "cycles per mpi_montmul: " << cycles / ret << endl << endl;


	sgx_ret = ecall_rsa_sign_destroy(global_eid, &ret);
    if (sgx_ret != SGX_SUCCESS || ret == -1) abort();

#else //!__USE_ENCLAVE__
app:
	cout << "============ Application Mode =============" << endl;

    mbedtls_rsa_context rsa;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "rsa_genkey";
    unsigned char hash[32];
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE];

    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen( pers ) ) ) != 0 ) {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        goto exit;
    }

    mbedtls_rsa_init( &rsa, MBEDTLS_RSA_PKCS_V15, 0 );

    if( ( ret = mbedtls_rsa_gen_key( &rsa, mbedtls_ctr_drbg_random, &ctr_drbg, key_size_in_bit, EXPONENT ) ) != 0 ) {
        mbedtls_printf( " failed\n  ! mbedtls_rsa_gen_key returned %d\n\n", ret );
        goto exit;
    }

	for(int ltt = 0; ltt < ltt_size; ltt++) {
		lhr_timer_reset(ltt);
	}
	cycles = rdtscp();
	for(int i = 0; i < count; i++) {
		//call rsa sign
		if( ( ret = mbedtls_rsa_pkcs1_sign( &rsa, NULL, NULL, MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_SHA256, 20, hash, buf ) ) != 0 ) {
			mbedtls_printf( " failed\n  ! mbedtls_rsa_pkcs1_sign returned -0x%0x\n\n", -ret );
			goto exit;
		}
	}
	cycles = rdtscp()-cycles;

	for(int ltt = 0; ltt < ltt_size; ltt++) {
		if(lhr_timer_get_count(ltt))
			cout << "Result for lhr_timer_t ("
				<< ltt << ") (cycles): "
				<< lhr_timer_get_cycle(ltt)/lhr_timer_get_count(ltt)
				<< endl;
	}

exit:

    mbedtls_rsa_free( &rsa );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

#if defined(_WIN32)
    mbedtls_printf( "  Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif
#endif	//!__USE_ENCLAVE__

	cout << "Result (cycles per inout): " << cycles / count << endl << endl;
#else	//!__LHR_MEASURE__
	cout << "If you want to measure performance, please enable __LHR_MEASURE__ in bignum.h or config.h"
#endif	//!__LHR_MEASURE__
}
#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_ENTROPY_C && MBEDTLS_RSA_C &&
          MBEDTLS_GENPRIME && MBEDTLS_FS_IO && MBEDTLS_CTR_DRBG_C */

void sleep_for_cycles(size_t cycles) {
	uint64_t end = rdtscp() + cycles;
	uint64_t clocks = 0;
	while ((clocks = rdtscp()) < end);
}

//put this at last
void lhr_measurement() {
	//clear screen
	//if(system("CLS")) system("clear");
	system("clear");

#ifdef __USE_FIFO_HIGHEST_PRIORITY__
	printf("In %s:\n", __FUNCTION__);
	set_thread_policy_and_priority(SCHED_FIFO, sched_get_priority_max(SCHED_FIFO));
	show_thread_policy_and_priority();
#endif

	//const size_t clocks = 1 << 14;	//1 << 20 about 5000000 clocks in NUC6i3
	//const size_t count = 1000000;
	//size_t app_i = 0;
	//volatile int access = 0;
	//uint64_t cycles = 0;
	//uint64_t temp;
	//for (size_t j = 0; j < count; ++j) {
		//app_i = 0;
		//temp = rdtscp();
		//while (++app_i < clocks) access = 0;
		//cycles += rdtscp()-temp;
	//}
	//cout << "app: " << cycles / count << endl;
	//return;

	printf("\n\n");

	//cout.setf(ios::hex,ios::basefield);//设置十六进制显示数值
	//cout.setf(ios::showbase[>|ios::uppercase<]);//设置0x头和大写
	//cout << "There are "<< CORES_PER_CPU << " cores, and CORES_MASK is " << CORES_MASK << endl;
	//cout << get_nprocs_conf() << get_nprocs() << endl << sysconf(_SC_NPROCESSORS_CONF) << sysconf(_SC_NPROCESSORS_ONLN) << endl;
	//measurement_empty_enclave();
	measurement_internal_thread();
	//measurement_rsa_sign_performance();
}
