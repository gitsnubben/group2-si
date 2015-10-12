/**********************************************************************/
/* - Includes -                                                       */
/**********************************************************************/

#ifndef POLICY_TEST
#define POLICY_TEST

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include "policy.h"
#include "policy_util.h"

#endif

/**********************************************************************/
/* - Globals -                                                        */
/**********************************************************************/

#define TRACE_FLOW 1
#define TRACE_DETAILED_FLOW 1

request_context_t *rctx = NULL;
sctp_assoc_t assoc_id = 0;

/* Per-prefix info about filesize range */
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

void set_options(int intent, request_context_t *rctx);
struct socketopt *find_and_return_cat(socketopt_t *opts);
void match_cat(socketopt_t *opts);

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
}

void tuneForQueryCategory() {
	setNoDelay(1);
}

void tuneForStreamCategory() {
	setMaximumRetransmissions(2);
	setNoDelay(1);
}

void tuneForControlTrafficCategory() {
}

void tuneForKeepaliveCategory() {
}

/**********************************************************************/
/* - Filesize -                                                       */
/**********************************************************************/

void tuneForGivenFilesize(int fileSize) {	
}

void tuneForGivenDuration(int duration) {
}

void tuneForGivenBitrate(int bitrate) {
}

/**********************************************************************/
/* - Burst behavior -                                                 */
/**********************************************************************/

void tuneForRandomBursts() {
}

void tuneForRegularBursts() {
}

void tuneForNoBursts() {
}

void tuneForBulkBursts() {
}

/**********************************************************************/
/* - Timeliness -                                                     */
/**********************************************************************/

void tuneForStreamTimeliness() {
}

void tuneForInteractiveTimeliness() {
}

void tuneForTransferTimeliness() {
}

void tuneForBackgroundTrafficTimeliness() {
}

/**********************************************************************/
/* - Loss -                                                           */
/**********************************************************************/

void tuneForLossSensitive() {
}

void tuneForLossTolerant() {
}

void tuneForLossResilient() {
	
}

/**********************************************************************/
/*                                                                    */
/* - INTERNAL LOGIC -                                                 */
/*                                                                    */
/**********************************************************************/
/**********************************************************************/
/* - Interface for tune-functions -                                   */
/**********************************************************************/

void freepolicyinfo(gpointer elem, gpointer data) {
	/*struct src_prefix_list *spl = elem;

	if(spl->policy_info != NULL) {
		free(spl->policy_info); 
	}*/
}

/**********************************************************************/
/* - Interface for tune-functions -                                   */
/**********************************************************************/

/**********************************************************************/
/* - Intent match; add new intents here -                             */
/**********************************************************************/

void match_cat(struct socketopt* opts) {
	if(TRACE_FLOW) { printf("\tENTERING: match_cat()\n"); fflush(stdout); }
	if(opts != NULL) {
		int intent = *(int*)opts->optval;
		int intentType = opts->optname;
		
		if(intentType == INTENT_CATEGORY) {
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
		}
		
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
		
		if(intentType == INTENT_BURSTINESS) {
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
		}
		
		if(intentType == INTENT_TIMELINESS) {
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
		}
		
		if(intentType == INTENT_RESILIENCE) {
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
		}
	}
	if(TRACE_FLOW) { printf("\tLEAVING: match_cat()\n"); fflush(stdout); }
}

/**********************************************************************/
/* - Intent match; add new intents here -                             */
/**********************************************************************/

struct socketopt *find_and_return_cat(struct socketopt *opts) {
	if(TRACE_FLOW) { printf("\tENTERING: find_and_return_cat()\n"); fflush(stdout); }
	struct socketopt* temp = opts;
	while(temp != NULL) {
		if(TRACE_DETAILED_FLOW) { printf("\t  LOOPING\n"); fflush(stdout); }
		if(temp->level == SOL_INTENTS && temp->optname == INTENT_CATEGORY) {
			if(TRACE_DETAILED_FLOW) { printf("\t  MATCHING\n"); fflush(stdout); }
			if(TRACE_FLOW) { printf("\tLEAVING: find_and_return_cat()\n"); fflush(stdout); }
			return temp;
		}
		temp = temp->next;
	}
	if(TRACE_FLOW) { printf("\tLEAVING: find_and_return_cat()\n"); fflush(stdout); }
	return NULL;
}

/**********************************************************************/
/*                                                                    */
/* - PUBLIC INTERFACE -                                               */
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
	if(TRACE_FLOW) { printf("\tLEAVING: on_resolve_request()\n"); fflush(stdout); }
	return 0;
}

int on_connect_request(request_context_t *rctx_param, struct event_base *base) {
	rctx = rctx_param;
	if(TRACE_FLOW) { printf("\tENTERING: on_resolve_request()\n"); fflush(stdout); }
	match_cat(find_and_return_cat(rctx->ctx->sockopts_current));
	_muacc_send_ctx_event(rctx, muacc_act_connect_resp);
	if(TRACE_FLOW) { printf("\tLEAVING: on_resolve_request()\n"); fflush(stdout); }
	return 0;
}

/**********************************************************************/
/* - Public interface; start & end -                                  */
/**********************************************************************/

int init(mam_context_t *mctx) {
	if(TRACE_FLOW) { printf("\n\tENTERING: init() for policy_test\n"); fflush(stdout); }
	g_slist_foreach(mctx->prefixes, &set_policy_info, NULL);
	make_v4v6_enabled_lists (mctx->prefixes, &in4_enabled, &in6_enabled);
	if(TRACE_FLOW) { printf("\n\tLEAVING: init()\n"); fflush(stdout); }
	return 0;
}

int cleanup(mam_context_t *mctx) {
	if(TRACE_FLOW) { printf("\n\tENTERING: cleanup() for policy_test\n"); fflush(stdout); }
	g_slist_free(in4_enabled);
	g_slist_free(in6_enabled);
	g_slist_foreach(mctx->prefixes, &freepolicyinfo, NULL);
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
/**********************************************************************/
/*                                                                    */
/**********************************************************************/





















