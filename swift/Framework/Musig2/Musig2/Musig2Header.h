//
//  Musig2Header.h
//  Musig2
//
//  Created by daiwei on 2021/10/16.
//

#ifndef Musig2Header_h
#define Musig2Header_h

#include <stdio.h>

#endif /* Musig2Header_h */

const char *get_my_pubkey(const char *privkey);

typedef struct State State;

State *get_round1_state();

char *encode_round1_state(State *state);

State *decode_round1_state(const char *round1_state);

char *get_round1_msg(State *state);

char *get_round2_msg(State *state, const char *msg, const char *privkey, const char *pubkeys, const char * received_round1_msg);

char *get_signature(const char *round2_msg);

char *get_key_agg(const char *pubkeys);

char *generate_threshold_pubkey(const char *pubkeys, uint8_t threshold, const char *network);

char *generate_control_block(const char *pubkeys, uint8_t threshold, const char *agg_pubkey);

char *get_base_tx(const char *txid, uint32_t index);

char *add_input(const char *base_tx, const char *txid, uint32_t index);

char *add_output(const char *base_tx, const char *address, uint64_t amount);

char *get_sighash(const char *prev_tx,
                  const char *tx,
                  uint32_t input_index,
                  const char *agg_pubkey,
                  uint32_t sigversion);

char *build_raw_scirpt_tx(const char *base_tx,
                          const char *agg_signature,
                          const char *agg_pubkey,
                          const char *control,
                          uint32_t input_index);

char *build_raw_key_tx(const char *base_tx, const char *signature, uint32_t input_index);

char *generate_schnorr_signature(const char *message, const char *privkey);

char *get_my_privkey(const char *phrase, const char *pd_passphrase);

char *get_scirpt_pubkey(const char *addr);
