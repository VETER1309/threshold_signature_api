//
//  MusigHeader.h
//  Musig
//
//  Created by daiwei on 2021/9/30.
//

#ifndef MusigHeader_h
#define MusigHeader_h

#include <stdio.h>

#endif /* MusigHeader_h */

const char *get_my_privkey(const char *phrase);

const char *get_my_pubkey(const char *privkey);

typedef struct Musig Musig;

Musig *get_musig(uint32_t message, const char *privkey);

char *encode_reveal_stage(Musig *musig);

Musig *decode_reveal_stage(const char *reveal_stage);

char *get_my_reveal(Musig *musig);

Musig *cosign_stage(Musig *musig, const char *reveals,const char *pubkeys);

char *get_my_cosign(Musig *musig);

char *get_signature(uint32_t message, const char *reveals, const char *pubkeys, const char *cosign);

char *get_agg_pubkey(const char *pubkeys);

char *generate_threshold_pubkey(const char *pubkeys, uint8_t threshold);

char *generate_control_block(const char *pubkeys, uint8_t threshold, const char *agg_pubkey);
