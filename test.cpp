#include <iostream>
#include <cstdint>
using namespace std;

uint64_t rdtscp() {
	uint64_t a, d;
	asm volatile ("rdtscp" : "=a" (a), "=d" (d) : : "rcx");
	return (d << 32) | a;
}

int main() {
	volatile size_t count = 0;
	uint64_t cycles = rdtscp();

	while (++count < 1000000000);

	cycles = rdtscp()-cycles;
	cout << "result: " << 1.0 * cycles / 1000000000 << endl;
	return 0;
}
