#include <math.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <float.h>

#include "congestion_control.h"
#include "utils.h"

#define EPS_MIN 0.01f
#define EPS_MAX 0.05f

#define MSS 1460

struct ccontrol_state *init_ccontrol_state(u32 max_rate_limit, u32 num_paths) {
	struct ccontrol_state *cc_state = calloc(1, sizeof(struct ccontrol_state));
	cc_state->max_rate_limit = max_rate_limit;
	cc_state->num_paths = num_paths;
	int ret = pthread_spin_init(&cc_state->lock, PTHREAD_PROCESS_PRIVATE);
	if (ret){
		free(cc_state);
		return NULL;
	}

	continue_ccontrol(cc_state);
	return cc_state;
}

void ccontrol_start_monitoring_interval(struct ccontrol_state *cc_state)
{
	cc_state->mi_start = get_nsecs();
	cc_state->mi_end = cc_state->mi_start + cc_state->pcc_mi_duration * 1e9;
	cc_state->mi_seq_start = cc_state->last_seqnr;
	cc_state->mi_seq_end = 0;
	cc_state->excess_npkts = 0;
	atomic_store(&cc_state->mi_tx_npkts, 0);
	atomic_store(&cc_state->mi_tx_npkts_monitored, 0);
	if(cc_state->mi_nacked.bitmap != NULL) {
		bitset__reset(&cc_state->mi_nacked);
	}
}

void ccontrol_update_rtt(struct ccontrol_state *cc_state, u64 rtt)
{
	debug_printf("update rtt");
	cc_state->rtt = rtt / 1e9;

	float m = (rand() % 6) / 10.f + 1.7; // m in [1.7, 2.2]
	cc_state->pcc_mi_duration = m * cc_state->rtt;
	if(cc_state->mi_nacked.bitmap != NULL) {
		bitset__destroy(&cc_state->mi_nacked);
	}
	bitset__create(&cc_state->mi_nacked, ceil(cc_state->max_rate_limit * cc_state->pcc_mi_duration));

	if(!cc_state->curr_rate) {
		// initial rate should be per-receiver fair
		u32 initial_rate = umin32(
				(u32)(MSS / cc_state->rtt),
				cc_state->max_rate_limit / (cc_state->num_paths)
		);
		cc_state->curr_rate = initial_rate;
		cc_state->prev_rate = initial_rate;
	}

	// restart current MI
	ccontrol_start_monitoring_interval(cc_state);
}

void terminate_ccontrol(struct ccontrol_state *cc_state) {
	if (cc_state != NULL) {
		cc_state->state = pcc_terminated;
		cc_state->curr_rate = 0;
	}
}

void continue_ccontrol(struct ccontrol_state *cc_state)
{
	cc_state->prev_rate = cc_state->curr_rate;
	cc_state->state = pcc_uninitialized;
	cc_state->ignored_first_mi = false;
	cc_state->eps = EPS_MIN;
	cc_state->sign = 1;
	cc_state->rcts_iter = -1;
	cc_state->pcc_mi_duration = DBL_MAX;
	cc_state->rtt = DBL_MAX;
	ccontrol_start_monitoring_interval(cc_state);
}

u32 ccontrol_can_send_npkts(struct ccontrol_state *cc_state, u64 now)
{
	if(cc_state->state == pcc_uninitialized) {
		debug_printf("uninit");
		cc_state->state = pcc_startup;
		cc_state->mi_start = get_nsecs();
		cc_state->mi_end = cc_state->mi_start + cc_state->pcc_mi_duration * 1e9;
		now = cc_state->mi_start;
	}
	u64 dt = now - cc_state->mi_start;

	dt = umax64(dt, 1);
	u32 tx_pps = atomic_load(&cc_state->mi_tx_npkts) * 1000000000. / dt;

	if(tx_pps > cc_state->curr_rate) {
		return 0;
	}
	u32 ret = (cc_state->curr_rate - tx_pps) * cc_state->pcc_mi_duration;
	return ret;
}

void kick_ccontrol(struct ccontrol_state *cc_state)
{
	(void)cc_state;
	// TODO can / should we get rid of this?
	//cc_state->state = pcc_startup;
}

void destroy_ccontrol_state(struct ccontrol_state *cc_state)
{
	bitset__destroy(&cc_state->mi_nacked);
	free(cc_state);
}

// XXX: explicitly use symbols from old libc version to allow building on
//			ubuntu 19.04 but running on ubuntu 16.04.
__asm__(".symver expf,expf@GLIBC_2.2.5");

static float sigmoid(float x)
{
	float alpha = 100; // alpha > 0, to be chosen
	return 1.f / (1.f + expf(alpha * x));
}

// PCC utility function
static float pcc_utility(float throughput, float loss)
{
	return throughput * (1.f - loss) * sigmoid(loss - 0.05f) - throughput * loss;
}

// Startup state
static u32 pcc_control_startup(struct ccontrol_state *cc_state, float utility, float loss, u32 actual_rate)
{
	if(utility > cc_state->prev_utility) {
		cc_state->state = pcc_startup;
		return 2 * cc_state->prev_rate;
	} else {
		// Update state: Startup -> Decision
		cc_state->state = pcc_decision;
		return cc_state->prev_rate * (1 - loss);
		//return umin32(actual_rate, cc_state->prev_rate * (1 - loss));
	}
}

static inline u32 calculate_rate(double mi_duration, u32 prev_rate, float factor) {
	u32 new_rate = prev_rate * factor;
	if(factor < 1) {
		if((u32) (new_rate * mi_duration) > (u32) (prev_rate * mi_duration) - 10) {
			new_rate = (prev_rate * mi_duration - 10) / mi_duration;
		}
	} else {
		if((u32) (new_rate * mi_duration) < (u32) (prev_rate * mi_duration) + 10) {
			new_rate = (prev_rate * mi_duration + 10) / mi_duration;
		}
	}
	return new_rate;
}

// Setup randomized controlled trials
static void setup_rcts(struct ccontrol_state *cc_state)
{
	float sign;
	float eps = cc_state->eps;
	int increase_first = rand() % 2;
	for(int i = 0; i < RCTS_INTERVALS; i++) {
		if((i % 2) == increase_first) {
			sign = -1.f;
		} else {
			sign = 1.f;
		}
		struct rct trial = {.rate = calculate_rate(cc_state->pcc_mi_duration, cc_state->prev_rate, 1.f + sign * eps), .utility = 0.f};
		cc_state->rcts[i] = trial;
	}
	cc_state->rcts_iter = 0;
	cc_state->rate_before_rcts = cc_state->prev_rate;
}

// Check if RCTs are conclusive
static enum rcts_result rcts_decision(struct ccontrol_state *cc_state)
{
	float winning_sign = 0.f;
	static_assert(RCTS_INTERVALS % 2 == 0, "rcts_decision writes out of bounds if RCTS_INTERVALS is odd.");
	for(int i = 0; i < RCTS_INTERVALS; i += 2) {
		if(cc_state->rcts[i].utility > cc_state->rcts[i + 1].utility) {
			winning_sign += cc_state->rcts[i].rate > cc_state->rcts[i + 1].rate ? 1.f : -1.f;
		}
		if(cc_state->rcts[i].utility < cc_state->rcts[i + 1].utility) {
			winning_sign += cc_state->rcts[i].rate < cc_state->rcts[i + 1].rate ? 1.f : -1.f;
		}
	}
	if(winning_sign > 0.f) {
		return increase;
	} else if(winning_sign < 0.f) {
		return decrease;
	} else {
		return inconclusive;
	}
}

// Decision making state
static u32 pcc_control_decision(struct ccontrol_state *cc_state, float utility, u32 actual_rate)
{
	if(cc_state->rcts_iter == -1) {
		// Init RCTs
		setup_rcts(cc_state);
		assert(cc_state->rcts_iter == 0);
		cc_state->state = pcc_decision;
		return cc_state->rcts[cc_state->rcts_iter].rate;
	}

	// RCTs in progress

	// Collect result
	cc_state->rcts[cc_state->rcts_iter].utility = utility;

	if(cc_state->rcts_iter + 1 < RCTS_INTERVALS) {
		// Move to next trial
		cc_state->rcts_iter += 1;
		cc_state->state = pcc_decision;
		return cc_state->rcts[cc_state->rcts_iter].rate;
	}

	// RCTs completed
	cc_state->rcts_iter = -1;

	enum rcts_result decision = rcts_decision(cc_state);
	if(decision != inconclusive) {
		float trial_eps = cc_state->eps;
		cc_state->eps = EPS_MIN; // reset eps for future control_decision calls
		// Update state: Decision -> Adjust
		if(decision == increase) {
			cc_state->sign = 1.f;
		}
		if(decision == decrease) {
			cc_state->sign = -1.f;
		}
		cc_state->state = pcc_adjust;
		return cc_state->rate_before_rcts * (1 + cc_state->sign * trial_eps);
	} else {
		// Return to prev_rate, update eps
		// (Possible optimization: already setup and start new RCTs here for more reactive behavior)
		cc_state->eps = fmin(cc_state->eps + EPS_MIN, EPS_MAX);
		cc_state->state = pcc_decision;
		return cc_state->rate_before_rcts;
	}
}

// Rate adjusting state
static u32 pcc_control_adjust(struct ccontrol_state *cc_state, float utility, u32 actual_rate)
{
	if(utility > cc_state->prev_utility) {
		int n = cc_state->adjust_iter;
		float sign = cc_state->sign;
		cc_state->adjust_iter += 1;
		cc_state->state = pcc_adjust;
		return calculate_rate(cc_state->pcc_mi_duration, cc_state->prev_rate, 1.f + sign * n * EPS_MIN);
	} else {
		// Update state: Adjust -> Decision
		cc_state->state = pcc_decision;
		cc_state->adjust_iter = 1;
		return cc_state->prev_rate;
	}
}

u32 pcc_control(struct ccontrol_state *cc_state, float throughput, float loss)
{
	if(cc_state->state == pcc_uninitialized || cc_state->state == pcc_terminated) {
		return 0;
	}

	cc_state->prev_rate = cc_state->curr_rate;

	float utility = pcc_utility(throughput, loss);
	u32 new_rate = cc_state->prev_rate;

	enum pcc_state current_pcc_state = cc_state->state;
	switch(current_pcc_state) {
		case pcc_startup:
			new_rate = pcc_control_startup(cc_state, utility, loss, throughput);
			break;
		case pcc_decision:
			new_rate = pcc_control_decision(cc_state, utility, throughput);
			break;
		case pcc_adjust:
			new_rate = pcc_control_adjust(cc_state, utility, throughput);
			break;
		default:
			fprintf(stderr, "Invalid PCC state: %d\n", current_pcc_state);
			cc_state->state = pcc_startup;
	}

	new_rate = umin32(umax32(1000, new_rate), cc_state->max_rate_limit);

	cc_state->prev_utility = utility;
	cc_state->curr_rate = new_rate;
	return new_rate;
}
