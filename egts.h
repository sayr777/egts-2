/*
 *  Created on: 08 may 2016.
 *  File: egts.c
 *  Author: Moksyakov Alexey
 *  email:  yavtuk@ya.ru
 */


#ifndef SRC_EGTS_EGTS_H_
#define SRC_EGTS_EGTS_H_

#include "data_types.h"
#include "egts_def.h"

void egts_init(void);
void handler_msg_egts(const uint8_t new_byte,  uint16_t const index);
BOOL_T egts_is_auth_none(void);

#endif /* SRC_EGTS_EGTS_H_ */
