#ifndef SIM_H
#define SIM_H
#include <stdint.h>
extern uint64_t sim_clock_us;
extern int sim_broken;
extern int sim_hash_fail;
void sim_seed_rng(uint64_t seed);
uint64_t sim_rand(void);
void sim_frame(void);
#endif
