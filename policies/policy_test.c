/**********************************************************************/
/* - Includes -                                                       */
/**********************************************************************/

#ifndef POLICY_TEST
#define POLICY_TEST

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <arpa/inet.h>
#include "policy.h"
#include "policy_util.h"
#include "../mam/query_handler.h"
#include "../mam/si_exp.h"

#endif

/**********************************************************************/
/* - Globals -                                                        */
/**********************************************************************/

enum priorities { 
	HIGH_BANDWIDTH=0,       LOW_DELAY, 
	LOW_JITTER,             LOW_LOSS,
	TRAIT_COUNT             /* MUST BE LAST */
};

typedef struct performance { 
	int performanceArray[TRAIT_COUNT];
	int totalValue;
	src_prefix_list_t *interface;
	struct performance *next;
} performance_t;

int prioritiesArray[TRAIT_COUNT];
performance_t *interfaceList = NULL;

#define TRACE_FLOW 1
#define TRACE_DETAILED_FLOW 1

request_context_t *rctx = NULL;
sctp_assoc_t assoc_id = 0;

//Per-prefix info 
struct test_info {
	int is_default;
};

GSList *in4_enabled = NULL;
GSList *in6_enabled = NULL;

/**********************************************************************/
/* - Headers -                                                        */
/**********************************************************************/

void tuneForBulkCategory();
void tuneForQueryCategory();
void tuneForStreamCategory();
void tuneForControlTrafficCategory();
void tuneForKeepaliveCategory();
void tuneForGivenFilesize(int fileSize);
void tuneForGivenDuration(int duration);
void tuneForGivenBitrate(int bitrate);
void tuneForRandomBursts();
void tuneForRegularBursts();
void tuneForNoBursts();
void tuneForBulkBursts();
void tuneForStreamTimeliness();
void tuneForInteractiveTimeliness();
void tuneForTransferTimeliness();
void tuneForBackgroundTrafficTimeliness();
void tuneForLossSensitive();
void tuneForLossTolerant();
void tuneForLossResilient();

void detuneForBulkCategory();
void detuneForQueryCategory();
void detuneForStreamCategory();
void detuneForControlTrafficCategory();
void detuneForKeepaliveCategory();
void detuneForFilesize();
void detuneForDuration();
void detuneForBitrate();
void detuneForRandomBursts();
void detuneForRegularBursts();
void detuneForNoBursts();
void detuneForBulkBursts();
void detuneForStreamTimeliness();
void detuneForInteractiveTimeliness();
void detuneForTransferTimeliness();
void detuneForBackgroundTrafficTimeliness();
void detuneForLossSensitive();
void detuneForLossTolerant();
void detuneForLossResilient();

void prioritizeHighBandwidth(int weight);
void prioritizeLowDelay(int weight);
void prioritizeLowJitter(int weight);
void prioritizeLowLoss(int weight);
void resetLowJitterWeight();
void resetHighBandwidthWeight();   
void resetLowDelayWeight();
void resetLowLossWeight();
void reset_state();

void init_array_to_zero();
void set_options(int intent, request_context_t *rctx);
void find_intents_in_ctx(struct socketopt *opts);
void match_cat(socketopt_t *opts);
void print_addresses(gpointer elem, gpointer data);
void push_addresses(gpointer elem, gpointer data);
void resolve_priorities(path_traits* path);
path_traits* determine_optimal_interface(path_traits* path);
char* get_readable_addr(char* readable_addr, struct sockaddr* addr);
void invert_path_values(path_traits* path);
path_traits* init_norm_path(path_traits* path);
void nomalize_data(path_traits* path);
int get_ipv(char* addr);
void free_path_trait_list(path_traits* path);

/**********************************************************************/
/*                                                                    */
/* - MAPPING -                                                        */
/*                                                                    */
/**********************************************************************/
/**********************************************************************/
/* - Atomic setters -                                                 */
/**********************************************************************/

void setRetransmissionTimeoutInitial(u_int32_t initial);
void setRetransmissionTimeoutMax(u_int32_t max_ms);
void setRetransmissionTimeoutMin(u_int32_t min_ms);
void setLingerOnOff(int bool, int time_sec);
void setReceiverBufferSize(int size_in_bytes);
void setSendBufferSize(int size_by_bytes);
void setMappingIPv4Addresses(int bool);
void setMessageFragmentaton(int bool);
void setMaximumRetransmissions(u_int32_t spp_pathmaxrxt);
void setHeartbeatInterval(u_int32_t spp_hbinterval_ms);
void setNoDelay(int bool);
void setMaximumFragmentationSize(u_int32_t size_bytes);
void setMaximumBurst(u_int32_t burst);
void setEndOfRecordMarking(int bool);
void setPortReusage(int bool);
void setSACKDelay(u_int32_t delay_ms);
void setSACKFrequency(u_int32_t freq);
void setAdaptationLayerIndicator(u_int16_t adaptation_indicator);
void setFragmentedInterleave(int level);
void setPartialDeliveryPoint(int size_bytes);
void setAuthenticationChunk(u_int8_t chunk);
void setAutomaticGenerationAsconf(int bool);
void setNumberOfStreams(u_int16_t streams);
void setMaximumInitAttempts(u_int16_t attempts);
void setMaximumInitAttemptsTimeout(u_int16_t time);
void setMaximumInboundStreams(u_int16_t instreams);
void setDefaultContext(int context);
void setSharedSecretKey(u_int16_t keynumber, u_int16_t keylength, u_int8_t key[]);
void setBroadcast(int bool);
void setDontRoute(int bool);
void setKeepalive(int bool);

/**********************************************************************/
/* - Category tuning -                                                */
/**********************************************************************/

/*	The functions below are called to tune SCTP to a given category, a 
	different mapping will require changes to these functions only. The
	actual configuration is amde by calling the setters listed above. 
	NOTE: unless a new intent is added, or a new socket option, the only
	functions to be modified are tthe tune-functions.
*/

/**********************************************************************/
/* - Categories -                                                     */
/**********************************************************************/

void tuneForBulkCategory() { 
	prioritizeLowDelay(1);
	prioritizeLowJitter(1);
	prioritizeHighBandwidth(50);
}

void tuneForQueryCategory() { }
void tuneForStreamCategory() { 
	prioritizeLowDelay(50);
	prioritizeLowJitter(1);
	prioritizeHighBandwidth(1);
}

void tuneForControlTrafficCategory() { }
void tuneForKeepaliveCategory() { }

void detuneForBulkCategory() { }
void detuneForQueryCategory() { }
void detuneForStreamCategory() { }

void detuneForControlTrafficCategory() { }
void detuneForKeepaliveCategory() { }

/**********************************************************************/
/* - Filesize -                                                       */
/**********************************************************************/

void tuneForGivenFilesize(int fileSize) { }
void tuneForGivenDuration(int duration) { }
void tuneForGivenBitrate(int bitrate) { }

void detuneForFilesize() { }
void detuneForDuration() { }
void detuneForBitrate() { }

/**********************************************************************/
/* - Burst behavior -                                                 */
/**********************************************************************/

void tuneForRandomBursts() { }
void tuneForRegularBursts() { }
void tuneForNoBursts() { }
void tuneForBulkBursts() { }

void detuneForRandomBursts() { }
void detuneForRegularBursts() { }
void detuneForNoBursts() { }
void detuneForBulkBursts() { }

/**********************************************************************/
/* - Timeliness -                                                     */
/**********************************************************************/

void tuneForStreamTimeliness() { }
void tuneForInteractiveTimeliness() { }
void tuneForTransferTimeliness() { }
void tuneForBackgroundTrafficTimeliness() { }

void detuneForStreamTimeliness() { }
void detuneForInteractiveTimeliness() { }
void detuneForTransferTimeliness() { }
void detuneForBackgroundTrafficTimeliness() { }

/**********************************************************************/
/* - Loss -                                                           */
/**********************************************************************/

void tuneForLossSensitive() { }
void tuneForLossTolerant() { }
void tuneForLossResilient() { }

void detuneForLossSensitive() { }
void detuneForLossTolerant() { }
void detuneForLossResilient() { }

/**********************************************************************/
/*                                                                    */
/**********************************************************************/
/* \__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\_ */
/* _/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/ */
/* \__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\_ */
/* _/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/ */
/* \__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\_ */
/* _/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/ */
/* \__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\_ */
/* _/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/ */
/**********************************************************************/
/*                                                                    */
/* - INTERNAL LOGIC -                                                 */
/*                                                                    */
/**********************************************************************/
/**********************************************************************/
/* - Auxiliary -                                                      */
/**********************************************************************/

void freepolicyinfo(gpointer elem, gpointer data) {
	struct src_prefix_list *spl = elem;
	if(spl->policy_info != NULL) {
		free(spl->policy_info); 
	}
}

char* get_readable_addr(char* readable_addr, struct sockaddr* addr) {
	inet_ntop(AF_INET, &( ((struct sockaddr_in *) addr)->sin_addr ), readable_addr, sizeof(readable_addr));
	return readable_addr;
}

/**********************************************************************/
/*                                                                    */
/* - MATCH AND SWITCH -                                               */
/*                                                                    */
/**********************************************************************/
/**********************************************************************/
/* - Intent match; add new intents here -                             */
/**********************************************************************/

void reset_state() { 
	resetHighBandwidthWeight();
	resetLowDelayWeight();
	resetLowJitterWeight();
	resetLowLossWeight();
}

void match_cat(struct socketopt* opts) {
	if(TRACE_FLOW) { printf("\tENTERING: match_cat()\n"); fflush(stdout); }
	if(opts != NULL) {
		int intent = *(int*)opts->optval;
		int intentType = opts->optname;
		if(TRACE_DETAILED_FLOW) { printf("\tINTENT RECEIVED: category is %d, value is %d\n", intentType, intent); fflush(stdout); }
		if(intentType == INTENT_CATEGORY) {
			
			//Start of tune, if intent is POSITIVE
			if(intent == INTENT_QUERY) {
				if(TRACE_DETAILED_FLOW) { printf("\t  INTENT_QUERY\n\a"); }
				tuneForQueryCategory();
			}
			else if(intent == INTENT_BULKTRANSFER) {
				if(TRACE_DETAILED_FLOW) { printf("\t  INTENT_BULKTRANSFER\n\a\a"); }
				tuneForBulkCategory();
			}
			else if(intent == INTENT_CONTROLTRAFFIC) {
				if(TRACE_DETAILED_FLOW) { printf("\t  INTENT_CONTROLTRAFFIC\n\a\a\a"); }
				tuneForControlTrafficCategory();
			}
			else if(intent == INTENT_KEEPALIVES) {
				if(TRACE_DETAILED_FLOW) { printf("\t  INTENT_KEEPALIVES\n\a\a\a\a"); }
				tuneForKeepaliveCategory();
			}
			else if(intent == INTENT_STREAM) {
				if(TRACE_DETAILED_FLOW) { printf("\t  INTENT_STREAM\n\a\a\a\a\a"); }
				tuneForStreamCategory();
			}
			
			//Start of detune, if intent is NEGATIVE
			else if(intent == -INTENT_QUERY) {
				if(TRACE_DETAILED_FLOW) { printf("\t  REMOVE INTENT_QUERY\n\a"); }
				detuneForQueryCategory();
			}
			else if(intent == -INTENT_BULKTRANSFER) {
				if(TRACE_DETAILED_FLOW) { printf("\t  REMOVE INTENT_BULKTRANSFER\n\a\a"); }
				detuneForBulkCategory();
			}
			else if(intent == -INTENT_CONTROLTRAFFIC) {
				if(TRACE_DETAILED_FLOW) { printf("\t  REMOVE INTENT_CONTROLTRAFFIC\n\a\a\a"); }
				detuneForControlTrafficCategory();
			}
			else if(intent == -INTENT_KEEPALIVES) {
				if(TRACE_DETAILED_FLOW) { printf("\t  REMOVE INTENT_KEEPALIVES\n\a\a\a\a"); }
				detuneForKeepaliveCategory();
			}
			else if(intent == -INTENT_STREAM) {
				if(TRACE_DETAILED_FLOW) { printf("\t  REMOVE INTENT_STREAM\n\a\a\a\a\a"); }
				detuneForStreamCategory();
			}
		}
		
		//Start of tune, if intent is POSITIVE
		else if(intentType == INTENT_FILESIZE) {
			if(TRACE_DETAILED_FLOW) { printf("\t  INTENT_FILESIZE\n"); }
			tuneForGivenFilesize(0);
		}
		else if(intentType == INTENT_DURATION) {
			if(TRACE_DETAILED_FLOW) { printf("\t  INTENT_DURATION\n"); }
			tuneForGivenDuration(0);
		}
		else if(intentType == INTENT_BITRATE) {
			if(TRACE_DETAILED_FLOW) { printf("\t  INTENT_BITRATE\n"); }
			tuneForGivenBitrate(0);
		}
		
		//Start of detune, if intent is NEGATIVE
		else if(intentType == -INTENT_FILESIZE) {
			if(TRACE_DETAILED_FLOW) { printf("\t  REMOVE INTENT_FILESIZE\n"); }
			detuneForFilesize();
		}
		else if(intentType == -INTENT_DURATION) {
			if(TRACE_DETAILED_FLOW) { printf("\t  REMOVE INTENT_DURATION\n"); }
			detuneForDuration();
		}
		else if(intentType == -INTENT_BITRATE) {
			if(TRACE_DETAILED_FLOW) { printf("\t  REMOVE INTENT_BITRATE\n"); }
			detuneForBitrate();
		}
		
		if(intentType == INTENT_BURSTINESS) {
			//Start of tune, if intent is POSITIVE
			if(intent == INTENT_RANDOMBURSTS) {
				if(TRACE_DETAILED_FLOW) { printf("\t  INTENT_RANDOMBURSTS\n"); }
				tuneForRandomBursts();
			}
			else if(intent == INTENT_REGULARBURSTS) {
				if(TRACE_DETAILED_FLOW) { printf("\t  INTENT_REGULARBURSTS\n"); }
				tuneForRegularBursts();
			}
			else if(intent == INTENT_NOBURSTS) {
				if(TRACE_DETAILED_FLOW) { printf("\t  INTENT_NOBURSTS\n"); }
				tuneForNoBursts();
			}
			else if(intent == INTENT_BULK) {
				if(TRACE_DETAILED_FLOW) { printf("\t  INTENT_BULK\n"); }
				tuneForBulkBursts();
			}
			
			//Start of detune, if intent is NEGATIVE
			else if(intent == -INTENT_RANDOMBURSTS) {
				if(TRACE_DETAILED_FLOW) { printf("\t  REMOVE INTENT_RANDOMBURSTS\n"); }
				detuneForRandomBursts();
			}
			else if(intent == -INTENT_REGULARBURSTS) {
				if(TRACE_DETAILED_FLOW) { printf("\t  REMOVE INTENT_REGULARBURSTS\n"); }
				detuneForRegularBursts();
			}
			else if(intent == -INTENT_NOBURSTS) {
				if(TRACE_DETAILED_FLOW) { printf("\t  REMOVE INTENT_NOBURSTS\n"); }
				detuneForNoBursts();
			}
			else if(intent == -INTENT_BULK) {
				if(TRACE_DETAILED_FLOW) { printf("\t  REMOVE INTENT_BULK\n"); }
				detuneForBulkBursts();
			}
		}
		

		if(intentType == INTENT_TIMELINESS) {
			//Start of tune, if intent is POSITIVE
			if(intent == INTENT_STREAMING) {
				if(TRACE_DETAILED_FLOW) { printf("\t  INTENT_STREAMING\n"); }
				tuneForStreamTimeliness();
			}
			else if(intent == INTENT_INTERACTIVE) {
				if(TRACE_DETAILED_FLOW) { printf("\t  INTENT_INTERACTIVE\n"); }
				tuneForInteractiveTimeliness();
			}
			else if(intent == INTENT_TRANSFER) {
				if(TRACE_DETAILED_FLOW) { printf("\t  INTENT_TRANSFER\n"); }
				tuneForTransferTimeliness();
			}
			else if(intent == INTENT_BACKGROUNDTRAFFIC) {
				if(TRACE_DETAILED_FLOW) { printf("\t  INTENT_BACKGROUNDTRAFFIC\n"); }
				tuneForBackgroundTrafficTimeliness();
			}
			
			//Start of detune, if intent is NEGATIVE
			else if(intent == -INTENT_STREAMING) {
				if(TRACE_DETAILED_FLOW) { printf("\t  REMOVE INTENT_STREAMING\n"); }
				detuneForStreamTimeliness();
			}
			else if(intent == -INTENT_INTERACTIVE) {
				if(TRACE_DETAILED_FLOW) { printf("\t  REMOVE INTENT_INTERACTIVE\n"); }
				detuneForInteractiveTimeliness();
			}
			else if(intent == -INTENT_TRANSFER) {
				if(TRACE_DETAILED_FLOW) { printf("\t  REMOVE INTENT_TRANSFER\n"); }
				detuneForTransferTimeliness();
			}
			else if(intent == -INTENT_BACKGROUNDTRAFFIC) {
				if(TRACE_DETAILED_FLOW) { printf("\t  REMOVE INTENT_BACKGROUNDTRAFFIC\n"); }
				detuneForBackgroundTrafficTimeliness();
			}
		}
		
		if(intentType == INTENT_RESILIENCE) {
			//Start of tune, if intent is POSITIVE
			if(intent == INTENT_SENSITIVE) {
				if(TRACE_DETAILED_FLOW) { printf("\t  INTENT_SENSITIVE\n"); }
				tuneForLossSensitive();
			}
			else if(intent == INTENT_TOLERANT) {
				if(TRACE_DETAILED_FLOW) { printf("\t  INTENT_TOLERANT\n"); }
				tuneForLossTolerant();
			}
			else if(intent == INTENT_RESILIENT) {
				if(TRACE_DETAILED_FLOW) { printf("\t  INTENT_RESILIENT\n"); }
				tuneForLossResilient();
			}
			
			//Start of detune, if intent is NEGATIVE
			else if(intent == -INTENT_SENSITIVE) {
				if(TRACE_DETAILED_FLOW) { printf("\t  REMOVE INTENT_SENSITIVE\n"); }
				detuneForLossSensitive();
			}
			else if(intent == -INTENT_TOLERANT) {
				if(TRACE_DETAILED_FLOW) { printf("\t  REMOVE INTENT_TOLERANT\n"); }
				detuneForLossTolerant();
			}
			else if(intent == -INTENT_RESILIENT) {
				if(TRACE_DETAILED_FLOW) { printf("\t  REMOVE INTENT_RESILIENT\n"); }
				detuneForLossResilient();
			}
		}
	}
	if(TRACE_FLOW) { printf("\tLEAVING: match_cat()\n"); fflush(stdout); }
}

/**********************************************************************/
/* - Intent match; add new intents here -                             */
/**********************************************************************/

void find_intents_in_ctx(struct socketopt *opts) {
	if(TRACE_FLOW) { trace_log("ENTERING: find_intents_in_ctx"); }
	struct socketopt* temp = opts;
	while(temp != NULL) {
		if(temp->level == SOL_INTENTS) {
			match_cat(temp);
		}
		temp = temp->next;
	}
	if(TRACE_FLOW) { trace_log("LEAVING: find_intents_in_ctx"); }
}

/**********************************************************************/
/*                                                                    */
/* - PRIORITIES AND RELATED -                                         */
/*                                                                    */
/**********************************************************************/
/**********************************************************************/
/* - Prioritize -                                                     */
/**********************************************************************/

void prioritizeHighBandwidth(int weight) { prioritiesArray[HIGH_BANDWIDTH] += weight; }
void prioritizeLowDelay(int weight)      { prioritiesArray[LOW_DELAY]      += weight; }
void prioritizeLowJitter(int weight)     { prioritiesArray[LOW_JITTER]     += weight; }
void prioritizeLowLoss(int weight)       { prioritiesArray[LOW_LOSS]       += weight; }
void resetLowJitterWeight()              { prioritiesArray[LOW_JITTER]      = 0;      }
void resetHighBandwidthWeight()          { prioritiesArray[HIGH_BANDWIDTH]  = 0;      }
void resetLowDelayWeight()               { prioritiesArray[LOW_DELAY]       = 0;      }
void resetLowLossWeight()                { prioritiesArray[LOW_LOSS]        = 0;      }

void init_array_to_zero() {
	int index = 0;
	while(index < TRAIT_COUNT) {
		prioritiesArray[index++] = 0;
	}
}

/**********************************************************************/
/* - Resolve priorities -                                             */
/**********************************************************************/

void print_addresses(gpointer elem, gpointer data) {
	struct src_prefix_list *pfx = elem;
	char addr_str[INET6_ADDRSTRLEN+1];
	if (pfx->family == AF_INET) {
		inet_ntop(AF_INET, &( ((struct sockaddr_in *) (pfx->if_addrs->addr))->sin_addr ), addr_str, sizeof(addr_str));
		printf("\t  ADDRESS: %s\n", addr_str);
	}
}

void push_addresses(gpointer elem, gpointer data) {
	struct src_prefix_list *pfx = elem;
	char addr_str[INET6_ADDRSTRLEN+1];
	if (pfx->family == AF_INET) {
		inet_ntop(AF_INET, &( ((struct sockaddr_in *) (pfx->if_addrs->addr))->sin_addr ), addr_str, sizeof(addr_str));
		push_query_snd_addr(addr_str);
	}
}

path_traits* determine_optimal_interface(path_traits* path) {
	int best_score = 0;
	path_traits* best_path = path;
	while(path != NULL) {
		int new_score  = path->norm_srtt * prioritiesArray[LOW_DELAY];
		new_score     += path->norm_jitt * prioritiesArray[LOW_JITTER];
		new_score     += path->norm_loss * prioritiesArray[LOW_LOSS];
		new_score     += path->norm_rate * prioritiesArray[HIGH_BANDWIDTH];
		if(new_score >= best_score) { best_path = path; best_score = new_score; }
		path = path->next;
	}
	return best_path;
}

struct sockaddr* get_nth_interface(int index, socklen_t *addr_len);
struct sockaddr* get_nth_interface(int index, socklen_t *addr_len) { 
	struct src_prefix_list *pfx = g_slist_nth_data(in4_enabled, index);
	if(pfx == NULL) { 
		pfx = g_slist_nth_data(in6_enabled, index-g_slist_length(in4_enabled));
	}
	*addr_len = pfx->if_addrs->addr_len;
	return pfx->if_addrs->addr; 
}

int TABLE_WIDTH();
int TABLE_WIDTH() { return g_slist_length(in4_enabled) + g_slist_length(in6_enabled); }

void invert_path_values(path_traits* path) {
	while(path != NULL) {
		path->norm_srtt = 100000.0 / path->norm_srtt; 
		path->norm_jitt = 100000.0 / path->norm_jitt; 
		path->norm_loss = 100000.0 / path->norm_loss; 
		path = path->next;
	}
}

path_traits* init_norm_path(path_traits* path) {
	path_traits* norm = malloc(sizeof(path_traits));
	norm->norm_srtt = INT_MAX;
	norm->norm_jitt = INT_MAX;
	norm->norm_loss = INT_MAX;
	norm->norm_rate = 0;
	while(path != NULL) {
		if(path->norm_srtt < norm->norm_srtt) { norm->norm_srtt = path->norm_srtt; }
		if(path->norm_jitt < norm->norm_jitt) { norm->norm_jitt = path->norm_jitt; }
		if(path->norm_loss < norm->norm_loss) { norm->norm_loss = path->norm_loss; }
		if(path->norm_rate > norm->norm_rate) { norm->norm_rate = path->norm_rate; }
		path = path->next;
	}
	return norm;
}

void nomalize_data(path_traits* path) {
	invert_path_values(path);
	path_traits* norm = init_norm_path(path);
	while(path != NULL) {
		path->norm_srtt = 1.0 / (path->norm_srtt * 100.0 ) / norm->norm_srtt;
		path->norm_jitt = 1.0 / (path->norm_jitt * 100.0 ) / norm->norm_jitt;
		path->norm_loss = 1.0 / (path->norm_loss * 100.0 ) / norm->norm_loss;
		path->norm_rate = 1.0 / (path->norm_rate * 100.0 ) / norm->norm_rate; //This is the wrong normalization!
		path = path->next;
	}
	free(norm);
}

int get_ipv(char* addr) { 
	int index = 0;
	while(isdigit(addr[index]) && index < FIELD_LIMIT) { index++; }
	return (addr[index] == '.') ? AF_INET : AF_INET6;
}

void free_path_trait_list(path_traits* path) {
	path_traits* temp;
	while(path != NULL) {
		temp = path;
		path = path->next;
		free(temp);
	}
}

void resolve_priorities(path_traits* path) {
	if(TRACE_FLOW) { trace_log("ENTERING: resolve_priorities"); }
	if((rctx->ctx->calls_performed & MUACC_BIND_CALLED) != MUACC_BIND_CALLED) {
		if(path != NULL) {
			nomalize_data(path);
			path_traits* optimal_interface = determine_optimal_interface(path);
			
			struct sockaddr* new = malloc(sizeof(struct sockaddr));
			memset(new, 0, sizeof(struct sockaddr));
			inet_pton(AF_INET, optimal_interface->snd_addr, &(((struct sockaddr_in *)(new))->sin_addr));
			new->sa_family = get_ipv(optimal_interface->snd_addr);
			rctx->ctx->bind_sa_suggested     = new;
			rctx->ctx->bind_sa_suggested_len = (socklen_t)sizeof(struct sockaddr_in);
			
			// Need to be debugged
			/*struct sockaddr* remote = malloc(sizeof(struct sockaddr));
			memset(remote, 0, sizeof(struct sockaddr));
			inet_pton(AF_INET, optimal_interface->rcv_addr, &(((struct sockaddr_in *)(remote))->sin_addr));
			remote->sa_family = get_ipv(optimal_interface->rcv_addr);
			rctx->ctx->remote_sa     = remote;
			rctx->ctx->remote_sa_len = (socklen_t)sizeof(struct sockaddr_in);*/
			
			if(TRACE_DETAILED_FLOW) { g_slist_foreach(in4_enabled, &print_addresses, NULL); } 
			if(TRACE_DETAILED_FLOW) { char addr_str[INET6_ADDRSTRLEN+1]; inet_ntop(AF_INET, &( ((struct sockaddr_in *) (rctx->ctx->bind_sa_suggested))->sin_addr ), addr_str, sizeof(addr_str)); printf("\t  ADDRESS CHOSEN: %s\n", addr_str); }
			if(TRACE_DETAILED_FLOW) { char addr_str[INET6_ADDRSTRLEN+1]; inet_ntop(AF_INET, &( ((struct sockaddr_in *) (rctx->ctx->remote_sa))->sin_addr ), addr_str, sizeof(addr_str)); printf("\t  ADDRESS CHOSEN: %s\n", addr_str); }
		}
		else if(TRACE_DETAILED_FLOW) { trace_log("  ERROR: no reply to query!"); }
	}
	else if(TRACE_DETAILED_FLOW) { trace_log("  ERROR: bind already performed!"); }
	if(TRACE_FLOW) { trace_log("LEAVING: resolve_priorities"); }
}

/**********************************************************************/
/*                                                                    */
/* - PUBLIC INTERFACE FOR MAM -                                       */
/*                                                                    */
/**********************************************************************/
/**********************************************************************/
/* - Auxilliary -                                                     */
/**********************************************************************/

void set_policy_info(gpointer elem, gpointer data) {
}

/**********************************************************************/
/* - Public interface; requests -                                     */
/**********************************************************************/

int on_resolve_request(request_context_t *rctx_param, struct event_base *base) {
	rctx = rctx_param;
	if(TRACE_FLOW) { printf("\tENTERING: on_resolve_request()\n"); fflush(stdout); }
	reset_state();
	//TODO
	//resolve_priorities(fetch_reply());
	if(TRACE_FLOW) { printf("\tLEAVING: on_resolve_request()\n"); fflush(stdout); }
	return 0;
}

int on_connect_request(request_context_t *rctx_param, struct event_base *base) {
	rctx = rctx_param;
	if(TRACE_FLOW) { printf("\tENTERING: on_connect_request()\n"); fflush(stdout); }
	char addr_str[INET6_ADDRSTRLEN+1];
	find_intents_in_ctx(rctx->ctx->sockopts_current);
	
	//Create and commit query
	g_slist_foreach(in4_enabled, &push_addresses, NULL);
	inet_ntop(AF_INET, &( ((struct sockaddr_in *) (rctx_param->ctx->remote_sa))->sin_addr ), addr_str, sizeof(addr_str));
	push_query_rcv_addr(addr_str);
	commit_query();
	path_traits* path = fetch_reply();
	print_struct_reply(path);
	resolve_priorities(path);
	free_path_trait_list(path);
	
	_muacc_send_ctx_event(rctx, muacc_act_connect_resp);
	if(TRACE_FLOW) { printf("\tLEAVING: on_connect_request()\n"); fflush(stdout); }
	return 0;
}

/**********************************************************************/
/* - Public interface; start & end -                                  */
/**********************************************************************/

int init(mam_context_t *mctx) {
	if(TRACE_FLOW) { printf("\n\tENTERING: init() for policy_test\n"); fflush(stdout); }
	g_slist_foreach(mctx->prefixes, &set_policy_info, NULL);
	make_v4v6_enabled_lists (mctx->prefixes, &in4_enabled, &in6_enabled);
	init_array_to_zero();
	//g_slist_foreach(mctx->prefixes, &print_addresses, NULL);
	//g_slist_foreach(in4_enabled, &print_addresses, NULL);
	if(TRACE_FLOW) { printf("\n\tLEAVING: init()\n"); fflush(stdout); }
	return 0;
}

int cleanup(mam_context_t *mctx) {
	if(TRACE_FLOW) { printf("\n\tENTERING: cleanup() for policy_test\n"); fflush(stdout); }
	g_slist_free(in4_enabled);
	g_slist_free(in6_enabled);
	g_slist_foreach(mctx->prefixes, &freepolicyinfo, NULL);
	close_query_dispatcher();
	if(TRACE_FLOW) { printf("\n\tLEAVING: cleanup()\n"); fflush(stdout); }
	return 0;
}

/**********************************************************************/
/*                                                                    */
/**********************************************************************/
/* \__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\_ */
/* _/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/ */
/* \__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\_ */
/* _/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/ */
/* \__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\_ */
/* _/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/ */
/* \__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\_ */
/* _/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/\__/ */
/**********************************************************************/
/*                                                                    */
/* - DRAGONS BELOW! -                                                 */
/*                                                                    */
/**********************************************************************/
/**********************************************************************/
/* - Headers for option calls -                                       */
/**********************************************************************/

void set_mapping_ipv4(int bool);                                        //SCTP_I_WANT_MAPPED_V4_ADDR
void set_messagefrag(int bool);                                         //SCTP_DISABLE_FRAGMENTS
void set_sctp_paddrparams(u_int32_t hbint, u_int16_t pathmaxrxt);       //SCTP_PEER_ADDR_PARAMS
void set_sctp_nodelay(int param);                                       //SCTP_NODELAY
void set_maxfragsize(u_int32_t size);                                   //SCTP_MAXSEG
void set_maxburst(u_int32_t burst);                                     //SCTP_MAX_BURST
void set_eormarking(int bool);                                          //SCTP_EXPLICIT_EOR
void set_portreusage(int bool);                                         //SCTP_REUSE_PORT
void set_delayed_sack(u_int32_t delay, u_int32_t freq);                 //SCTP_DELAYD_SACK
void set_RTO(u_int32_t initial, u_int32_t max, u_int32_t min);          //SCTP_RTO_INFO
void set_linger(int onoff, int ltime);                                  //SO_LINGER
void set_recbuffer(int size);                                           //SO_RCVBUFF
void set_sendbuffer(int size);                                          //SO_SNDBUFF
void set_assocparams(u_int16_t asocmaxrxt, u_int16_t num_of_peers,      //SCTP_ASSOCINFO (not yet implemented)
      u_int32_t peer_rwnd, u_int32_t local_rwnd, u_int32_t cookie_life);
void set_initparams(u_int16_t num_ostreams, u_int16_t max_instreams,    //SCTP_INITMSG
      u_int16_t max_attempts, u_int16_t max_init_timeo);
void set_adaptation_indicator(u_int32_t adaptation_ind);                //SCTP_ADAPTATION_LAYER
void set_fragmented_interleave(int level);                              //SCTP_FRAGMENT_INTERLEAVE
void set_partial_delivery_point(int size);                              //SCTP_PARTIAL_DELIVERY_POINT
void set_auth_chunk(u_int8_t auth_chunk);                               //SCTP_AUTH_CHUNK
void set_ASCONF(int bool);                                              //SCTP_AUTO_ASCONF
void set_context(int context);                                          //SCTP_CONTEXT
void set_shared_secret_key(u_int16_t keynumber, u_int16_t keylen,       //SCTP_AUTH_KEY
      u_int8_t key[]);
void set_broadcast(int bool);                                           //SO_BROADCAST
void set_dont_route(int bool);                                          //SO_DONTROUTE
void set_keepalive(int bool);                                           //SO_KEEPALIVE

/**********************************************************************/
/* - Set mapping to IP4 -                                             */
/**********************************************************************/

void set_mapping_ipv4(int bool) {
	int* val = malloc(sizeof(int));
	*val = bool;

	socketopt_t* new_opt = malloc(sizeof(socketopt_t));
	new_opt->level = SOL_SCTP;
	new_opt->optname = SCTP_I_WANT_MAPPED_V4_ADDR;
	new_opt->optval = val;
	new_opt->optlen = sizeof(int);
	new_opt->returnvalue = 0;
	new_opt->flags = 0;
	new_opt->next = rctx->ctx->sockopts_suggested;
	
	rctx->ctx->sockopts_suggested = new_opt;
}

/**********************************************************************/
/* - Set message fragmentation -                                      */
/**********************************************************************/

void set_messagefrag(int bool) {
	int* val = malloc(sizeof(int));
	*val = bool;

	socketopt_t* new_opt = malloc(sizeof(socketopt_t));
	new_opt->level = SOL_SCTP;
	new_opt->optname = SCTP_DISABLE_FRAGMENTS;
	new_opt->optval = val;
	new_opt->optlen = sizeof(int);
	new_opt->returnvalue = 0;
	new_opt->flags = 0;
	new_opt->next = rctx->ctx->sockopts_suggested;
	
	rctx->ctx->sockopts_suggested = new_opt;
}

/**********************************************************************/
/* - Set_sctp_paddrparams -            							      */
/**********************************************************************/

void set_sctp_paddrparams(u_int32_t spp_hbinterval, u_int16_t spp_pathmaxrxt) {
	/*struct sctp_paddrparams *val = malloc(sizeof(struct sctp_paddrparams));
	val->spp_assoc_id 	= assoc_id;	  									//global
	val->spp_addres 	= ip_address; 									//global
	val->spp_hbinterval = spp_hbinterval;
	val->spp_pathmaxrxt = spp_pathmaxrxt;
	
	socketopt_t* new_opt = malloc(sizeof(socketopt_t));
	new_opt->level = SOL_SCTP;
	new_opt->optname = SCTP_PEER_ADDR_PARAM;
	new_opt->optval = val;
	new_opt->optlen = sizeof(struct sctp_paddrparams);
	new_opt->returnvalue = 0;
	new_opt->flags = 0;
	new_opt->next = rctx->ctx->sockopts_suggested;
	
	rctx->ctx->sockopts_suggested = new_opt; //rctx global*/
}

/**********************************************************************/
/* - Set no delay -                                                   */
/**********************************************************************/

void set_sctp_nodelay(int param) {
	int* val = malloc(sizeof(int));
	*val = param;

	socketopt_t* new_opt = malloc(sizeof(socketopt_t));
	new_opt->level = SOL_SCTP;
	new_opt->optname = SCTP_NODELAY;
	new_opt->optval = val;
	new_opt->optlen = sizeof(int);
	new_opt->returnvalue = 0;
	new_opt->flags = 0;
	new_opt->next = rctx->ctx->sockopts_suggested;
	
	rctx->ctx->sockopts_suggested = new_opt;
}

/**********************************************************************/
/* - Set maximum fragmentation size -                                 */
/**********************************************************************/

void set_maxfragsize(u_int32_t size) {
	struct sctp_assoc_value *val = malloc(sizeof(struct sctp_assoc_value));
	val->assoc_id 	 = assoc_id;	  
	val->assoc_value = size; 
	
	socketopt_t* new_opt = malloc(sizeof(socketopt_t));
	new_opt->level = SOL_SCTP;
	new_opt->optname = SCTP_MAXSEG;
	new_opt->optval = val;
	new_opt->optlen = sizeof(struct sctp_assoc_value);
	new_opt->returnvalue = 0;
	new_opt->flags = 0;
	new_opt->next = rctx->ctx->sockopts_suggested;
	
	rctx->ctx->sockopts_suggested = new_opt; //rctx global
}

/**********************************************************************/
/* - Set maximum burst -                                              */
/**********************************************************************/

void set_maxburst(u_int32_t burst) {
	struct sctp_assoc_value *val = malloc(sizeof(struct sctp_assoc_value));
	val->assoc_id 	 = assoc_id;	  
	val->assoc_value = burst; 
	
	socketopt_t* new_opt = malloc(sizeof(socketopt_t));
	new_opt->level = SOL_SCTP;
	new_opt->optname = SCTP_MAX_BURST;
	new_opt->optval = val;
	new_opt->optlen = sizeof(struct sctp_assoc_value);
	new_opt->returnvalue = 0;
	new_opt->flags = 0;
	new_opt->next = rctx->ctx->sockopts_suggested;
	
	rctx->ctx->sockopts_suggested = new_opt; //rctx global
}

/**********************************************************************/
/* - Enable/dicable EOR marking -                                     */
/**********************************************************************/

void set_eormarking(int bool) {
	/*int* val = malloc(sizeof(int));
	*val = bool;

	socketopt_t* new_opt = malloc(sizeof(socketopt_t));
	new_opt->level = SOL_SCTP;
	new_opt->optname = SCTP_EXPLICIT_EOR;
	new_opt->optval = val;
	new_opt->optlen = sizeof(int);
	new_opt->returnvalue = 0;
	new_opt->flags = 0;
	new_opt->next = rctx->ctx->sockopts_suggested;
	
	rctx->ctx->sockopts_suggested = new_opt;*/
}

/**********************************************************************/
/* - Enable sctp port reusage -                                       */
/**********************************************************************/

void set_portreusage(int bool) {
	/*int* val = malloc(sizeof(int));
	*val = bool;

	socketopt_t* new_opt = malloc(sizeof(socketopt_t));
	new_opt->level = SOL_SCTP;
	new_opt->optname = SCTP_REUSE_PORT;
	new_opt->optval = val;
	new_opt->optlen = sizeof(int);
	new_opt->returnvalue = 0;
	new_opt->flags = 0;
	new_opt->next = rctx->ctx->sockopts_suggested;
	
	rctx->ctx->sockopts_suggested = new_opt;*/
}

/**********************************************************************/
/* - Set delayed sack timer -                                         */
/**********************************************************************/

void set_delayed_sack(u_int32_t delay, u_int32_t freq) {
	struct sctp_sack_info *val = malloc(sizeof(struct sctp_sack_info));
	val->sack_assoc_id 	 = assoc_id;	  
	val->sack_delay 	 = delay; 
	val->sack_freq 	     = freq; 
	
	socketopt_t* new_opt = malloc(sizeof(socketopt_t));
	new_opt->level = SOL_SCTP;
	new_opt->optname = SCTP_DELAYED_SACK;
	new_opt->optval = val;
	new_opt->optlen = sizeof(struct sctp_sack_info);
	new_opt->returnvalue = 0;
	new_opt->flags = 0;
	new_opt->next = rctx->ctx->sockopts_suggested;
	
	rctx->ctx->sockopts_suggested = new_opt; //rctx global
}

/**********************************************************************/
/* - Set Retransmission timeout parameters -                          */
/**********************************************************************/

void set_RTO(u_int32_t initial, u_int32_t max, u_int32_t min) {
	struct sctp_rtoinfo *val = malloc(sizeof(struct sctp_rtoinfo));
	val->srto_assoc_id = assoc_id;
	val->srto_initial  = initial; //only for read??
	val->srto_max	   = max; 
	val->srto_min	   = min; 
	
	socketopt_t* new_opt = malloc(sizeof(socketopt_t));
	new_opt->level   = SOL_SCTP;
	new_opt->optname = SCTP_RTOINFO;
	new_opt->optval  = val;
	new_opt->optlen  = sizeof(struct sctp_rtoinfo);
	new_opt->returnvalue = 0;
	new_opt->flags   = 0;
	new_opt->next    = rctx->ctx->sockopts_suggested;
	
	rctx->ctx->sockopts_suggested = new_opt; //rctx global
}

/**********************************************************************/	//SCTP_INITMSG
/* - Set Initialization parameters -                                  */
/**********************************************************************/

void set_initparams(u_int16_t num_ostreams, u_int16_t max_instreams, u_int16_t max_attempts, u_int16_t max_init_timeo) {
	struct sctp_initmsg *val = malloc(sizeof(struct sctp_initmsg));
	val->sinit_num_ostreams   = num_ostreams;
	val->sinit_max_instreams  = max_instreams;
	val->sinit_max_attempts   = max_attempts;
	val->sinit_max_init_timeo = max_init_timeo;
	
	socketopt_t* new_opt = malloc(sizeof(socketopt_t));
	new_opt->level   = SOL_SCTP; 
	new_opt->optname = SCTP_INITMSG;
	new_opt->optval  = val;
	new_opt->optlen  = sizeof(struct sctp_initmsg);
	new_opt->returnvalue = 0;
	new_opt->flags   = 0;
	new_opt->next    = rctx->ctx->sockopts_suggested;
	
	rctx->ctx->sockopts_suggested = new_opt; //rctx global
}

/**********************************************************************/
/* - Set Linger/Abort primitive (SO_LINGER) -                         */
/**********************************************************************/

void set_linger(int onoff, int ltime){
	struct linger *val = malloc(sizeof(struct sctp_rtoinfo));
	val->l_onoff	   = onoff; 
	val->l_linger	   = ltime; 
	
	socketopt_t* new_opt = malloc(sizeof(socketopt_t));
	new_opt->level   = SOL_SOCKET; //SOL_SOCKET
	new_opt->optname = SO_LINGER;
	new_opt->optval  = val;
	new_opt->optlen  = sizeof(struct linger);
	new_opt->returnvalue = 0;
	new_opt->flags   = 0;
	new_opt->next    = rctx->ctx->sockopts_suggested;
	
	rctx->ctx->sockopts_suggested = new_opt; //rctx global
}

/**********************************************************************/
/* - Set the receive buffer size -                                    */
/**********************************************************************/

void set_recbuffer(int size){
	int* val = malloc(sizeof(int));
	*val = size;

	socketopt_t* new_opt = malloc(sizeof(socketopt_t));
	new_opt->level = SOL_SOCKET; //SOL_SOCKET
	new_opt->optname = SO_RCVBUF;
	new_opt->optval = val;
	new_opt->optlen = sizeof(int);
	new_opt->returnvalue = 0;
	new_opt->flags = 0;
	new_opt->next = rctx->ctx->sockopts_suggested;
	
	rctx->ctx->sockopts_suggested = new_opt;
}

/**********************************************************************/
/* - Set the send buffer size -                                       */
/**********************************************************************/

void set_sendbuffer(int size) {
	int* val = malloc(sizeof(int));
	*val = size;

	socketopt_t* new_opt = malloc(sizeof(socketopt_t));
	new_opt->level = SOL_SOCKET; //SOL_SOCKET
	new_opt->optname = SO_SNDBUF;
	new_opt->optval = val;
	new_opt->optlen = sizeof(int);
	new_opt->returnvalue = 0;
	new_opt->flags = 0;
	new_opt->next = rctx->ctx->sockopts_suggested;
	
	rctx->ctx->sockopts_suggested = new_opt;
}

/**********************************************************************/
/* - Set association params   -                                       */ // NB: not yet implemented! What do we need to set in this option? We already have setMaximumRetransmission e.g.
/**********************************************************************/

void set_assocparams(u_int16_t asocmaxrxt, u_int16_t num_of_peers, u_int32_t peer_rwnd, u_int32_t local_rwnd, u_int32_t cookie_life) {
/*	struct sctp_assocparams *val = malloc(sizeof(struct sctp_assocparams));
	val->sasoc_assoc_id = assoc_id;
	val->sasoc_asocmaxrxt = asocmaxrxt;
	val->sasoc_number_peer_destinations = num_of_peers;
	val->sasoc_peer_rwnd = peer_rwnd;
	val->sasoc_local_rwnd = local_rwnd;
	val->sasoc_cookie_life = cookie_life;
	
	socketopt_t* new_opt = malloc(sizeof(socketopt_t));
	new_opt->level   = SOL_SCTP;
	new_opt->optname = SCTP_SCTP_ASSOCINFO;
	new_opt->optval  = val;
	new_opt->optlen  = sizeof(struct sctp_assocparams);
	new_opt->returnvalue = 0;
	new_opt->flags   = 0;
	new_opt->next    = rctx->ctx->sockopts_suggested;
	
	rctx->ctx->sockopts_suggested = new_opt; //rctx global*/
}

/**********************************************************************/ 	//SCTP_AUTOCLOSE    one-to-many only
/* - Set Automatic Close Of Associations -                            */	
/**********************************************************************/

/**********************************************************************/	//SCTP_PRIMARY_ADDR
/* - Set Primary Address -                                            */
/**********************************************************************/

/**********************************************************************/	//SCTP_ADAPTATION_LAYER
/* - Set Adaption Layer Indicator -                                   */
/**********************************************************************/

void set_adaptation_indicator(u_int32_t adaptation_ind) {
	u_int32_t* val = malloc(sizeof(u_int32_t));
	*val = adaptation_ind;

	socketopt_t* new_opt = malloc(sizeof(socketopt_t));
	new_opt->level = SOL_SCTP;
	new_opt->optname = SCTP_ADAPTATION_LAYER;
	new_opt->optval = val;
	new_opt->optlen = sizeof(u_int32_t);
	new_opt->returnvalue = 0;
	new_opt->flags = 0;
	new_opt->next = rctx->ctx->sockopts_suggested;
	
	rctx->ctx->sockopts_suggested = new_opt;
}

/**********************************************************************/	//SCTP_FRAGMENT_INTERLEAVE
/* - Set Fragmented Interleave -                                      */
/**********************************************************************/

void set_fragmented_interleave(int level) {
	int* val = malloc(sizeof(int));
	*val = level;

	socketopt_t* new_opt = malloc(sizeof(socketopt_t));
	new_opt->level = SOL_SCTP; 
	new_opt->optname = SCTP_FRAGMENT_INTERLEAVE;
	new_opt->optval = val;
	new_opt->optlen = sizeof(int);
	new_opt->returnvalue = 0;
	new_opt->flags = 0;
	new_opt->next = rctx->ctx->sockopts_suggested;
	
	rctx->ctx->sockopts_suggested = new_opt;
}

/**********************************************************************/	//SCTP_PARTIAL_DELIVERY_POINT
/* - Set Partial Delivery Point -                                     */
/**********************************************************************/

void set_partial_delivery_point(int size) {
	int* val = malloc(sizeof(int));
	*val = size;

	socketopt_t* new_opt = malloc(sizeof(socketopt_t));
	new_opt->level = SOL_SCTP; 
	new_opt->optname = SCTP_PARTIAL_DELIVERY_POINT;
	new_opt->optval = val;
	new_opt->optlen = sizeof(int);
	new_opt->returnvalue = 0;
	new_opt->flags = 0;
	new_opt->next = rctx->ctx->sockopts_suggested;
	
	rctx->ctx->sockopts_suggested = new_opt;
}

/**********************************************************************/	//SCTP_AUTH_CHUNK
/* - Set (add) Auth Chunk -                                           */
/**********************************************************************/

void set_auth_chunk(u_int8_t auth_chunk) {
	u_int8_t* val = malloc(sizeof(u_int8_t));
	*val = auth_chunk;

	socketopt_t* new_opt = malloc(sizeof(socketopt_t));
	new_opt->level = SOL_SCTP;
	new_opt->optname = SCTP_AUTH_CHUNK;
	new_opt->optval = val;
	new_opt->optlen = sizeof(u_int8_t);
	new_opt->returnvalue = 0;
	new_opt->flags = 0;
	new_opt->next = rctx->ctx->sockopts_suggested;
	
	rctx->ctx->sockopts_suggested = new_opt;
}

/**********************************************************************/	//SCTP_AUTH_KEY
/* - Set Auth Key -                                                   */
/**********************************************************************/

void set_shared_secret_key(u_int16_t keynumber, u_int16_t keylen, u_int8_t key[]){
	struct sctp_authkey *val = malloc(sizeof(struct sctp_authkey));
	val->sca_assoc_id  = assoc_id;
	val->sca_keylength = keylen;
	memcpy(val->sca_key, key, keylen); //val->sca_key = key
	
	socketopt_t* new_opt = malloc(sizeof(socketopt_t));
	new_opt->level   = SOL_SCTP; 
	new_opt->optname = SCTP_AUTH_KEY;
	new_opt->optval  = val;
	new_opt->optlen  = sizeof(struct sctp_authkey);
	new_opt->returnvalue = 0;
	new_opt->flags   = 0;
	new_opt->next    = rctx->ctx->sockopts_suggested;
	
	rctx->ctx->sockopts_suggested = new_opt;
}

/**********************************************************************/	//SCTP_HMAC_IDENT
/* - Set Hashed Message Authentication -                              */
/**********************************************************************/

/**********************************************************************/	//SCTP_AUTH_ACTIVE_KEY
/* - Set the Active Shared Key -                                      */
/**********************************************************************/

/**********************************************************************/	//SCTP_AUTH_DELETE_KEY
/* - Set "Delete Authentication Key" -                                */
/**********************************************************************/

/**********************************************************************/	//SCTP_AUTO_ASCONF
/* - Set Auto ASCONF Flag -                                           */
/**********************************************************************/

void set_ASCONF(int bool) {
	/*int* val = malloc(sizeof(int));
	*val = bool;

	socketopt_t* new_opt = malloc(sizeof(socketopt_t));
	new_opt->level = SOL_SCTP;
	new_opt->optname = SCTP_AUTO_ASCONF;
	new_opt->optval = val;
	new_opt->optlen = sizeof(int);
	new_opt->returnvalue = 0;
	new_opt->flags = 0;
	new_opt->next = rctx->ctx->sockopts_suggested;
	
	rctx->ctx->sockopts_suggested = new_opt;*/
}

/**********************************************************************/	//SCTP_CONTEXT
/* - Set Default Context -                                            */
/**********************************************************************/

void set_context(int context){
	int* val = malloc(sizeof(int));
	*val = context;

	socketopt_t* new_opt = malloc(sizeof(socketopt_t));
	new_opt->level = SOL_SCTP;
	new_opt->optname = SCTP_CONTEXT;
	new_opt->optval = val;
	new_opt->optlen = sizeof(int);
	new_opt->returnvalue = 0;
	new_opt->flags = 0;
	new_opt->next = rctx->ctx->sockopts_suggested;
	
	rctx->ctx->sockopts_suggested = new_opt;
}

/**********************************************************************/	//SO_BROADCAST
/* - Set Broadcast flag -                                             */
/**********************************************************************/

void set_broadcast(int bool){
	int* val = malloc(sizeof(int));
	*val = bool;

	socketopt_t* new_opt = malloc(sizeof(socketopt_t));
	new_opt->level = SOL_SOCKET;
	new_opt->optname = SO_BROADCAST;
	new_opt->optval = val;
	new_opt->optlen = sizeof(int);
	new_opt->returnvalue = 0;
	new_opt->flags = 0;
	new_opt->next = rctx->ctx->sockopts_suggested;
	
	rctx->ctx->sockopts_suggested = new_opt;
}

/**********************************************************************/	//SO_DEBUG
/* - Set Broadcast flag -                                             */
/**********************************************************************/

/**********************************************************************/	//SO_DONTROUTE
/* - Set/(disable/enable routing -                                    */
/**********************************************************************/

void set_dont_route(int bool) {
	int* val = malloc(sizeof(int));
	*val = bool;

	socketopt_t* new_opt = malloc(sizeof(socketopt_t));
	new_opt->level = SOL_SOCKET;
	new_opt->optname = SO_DONTROUTE;
	new_opt->optval = val;
	new_opt->optlen = sizeof(int);
	new_opt->returnvalue = 0;
	new_opt->flags = 0;
	new_opt->next = rctx->ctx->sockopts_suggested;
	
	rctx->ctx->sockopts_suggested = new_opt;
}

/**********************************************************************/	//SO_KEEPALIVE
/* - Set keepalive (enable/disable sending of keepalive messages) -   */
/**********************************************************************/

void set_keepalive(int bool) {
	int* val = malloc(sizeof(int));
	*val = bool;

	socketopt_t* new_opt = malloc(sizeof(socketopt_t));
	new_opt->level = SOL_SOCKET;
	new_opt->optname = SO_KEEPALIVE;
	new_opt->optval = val;
	new_opt->optlen = sizeof(int);
	new_opt->returnvalue = 0;
	new_opt->flags = 0;
	new_opt->next = rctx->ctx->sockopts_suggested;
	
	rctx->ctx->sockopts_suggested = new_opt;
}

/**********************************************************************/	//SO_MARK
/* - Set Broadcast flag -                                             */
/**********************************************************************/

/**********************************************************************/	//SO_OOBINLINE
/* - Set Broadcast flag -                                             */
/**********************************************************************/

/**********************************************************************/	//SO_PASSCRED
/* - Set Broadcast flag -                                             */
/**********************************************************************/

/**********************************************************************/
/*                                                                    */
/* - INTERNAL INTERFACE -                                             */
/*                                                                    */
/**********************************************************************/
/**********************************************************************/
/* - Interface for mapper -                                           */
/**********************************************************************/

void setMappingIPv4Addresses(int bool) {
	set_mapping_ipv4(bool);
}

void setMessageFragmentaton(int bool) {
	set_messagefrag(bool);
}

void setHeartbeatInterval(u_int32_t spp_hbinterval) {
	set_sctp_paddrparams(spp_hbinterval, 0);
}

void setMaximumRetransmissions(u_int32_t spp_pathmaxrxt) {
	set_sctp_paddrparams(0, spp_pathmaxrxt);
}

void setNoDelay(int bool) {
	set_sctp_nodelay(bool);
}

void setMaximumFragmentationSize(u_int32_t size) {
	set_maxfragsize(size);
}

void setMaximumBurst(u_int32_t burst) {
	set_maxburst(burst);
}

void setEndOfRecordMarking(int bool) {
	set_eormarking(bool);
}

void setPortReusage(int bool) {
	set_portreusage(bool);
}

void setSACKDelay(u_int32_t delay) {
	set_delayed_sack(delay, 0);
}

void setSACKFrequency(u_int32_t freq) {
	set_delayed_sack(0, freq);
}

void setRetransmissionTimeoutInitial(u_int32_t initial){
	set_RTO(initial, 0, 0);
}

void setRetransmissionTimeoutMax(u_int32_t max){
	set_RTO(0, max, 0);
}

void setRetransmissionTimeoutMin(u_int32_t min){
	set_RTO(0, 0, min);
}

void setLingerOnOff(int bool, int time){ //time in seconds
	set_linger(bool, time);
}

void setReceiverBufferSize(int size){
	set_recbuffer(size);
}

void setSendBufferSize(int size){
	set_sendbuffer(size);
}

void setNumberOfStreams(u_int16_t streams){
	set_initparams(streams, 0, 0, 0);
}

void setMaximumInboundStreams(u_int16_t instreams){
	set_initparams(0, instreams, 0, 0);
}

void setMaximumInitAttempts(u_int16_t attempts){
	set_initparams(0, 0, attempts, 0);
}

void setMaximumInitAttemptsTimeout(u_int16_t time){
	set_initparams(0, 0, 0, time);
}

void setAdaptationLayerIndicator(u_int16_t adaptation_indicator){
	set_adaptation_indicator(adaptation_indicator);
}

void setFragmentedInterleave(int level){
	set_fragmented_interleave(level);
}

void setPartialDeliveryPoint(int size){
	set_partial_delivery_point(size);
}

void setAuthenticationChunk(u_int8_t chunk){ //add a "auth chunk" to list
	set_auth_chunk(chunk);
}

void setAutomaticGenerationAsconf(int bool){
	set_ASCONF(bool);
}

void setDefaultContext(int context){
	set_context(context);
}

void setSharedSecretKey(u_int16_t keynumber, u_int16_t keylength, u_int8_t key[]){
	set_shared_secret_key(keynumber, keylength, key);
}

void setBroadcast(int bool) {
	set_broadcast(bool);
}

void setDontRoute(int bool) {
	set_dont_route(bool);
}

void setKeepalive(int bool) {
	set_keepalive(bool);
}
/**********************************************************************/
/*                                                                    */
/**********************************************************************/





















