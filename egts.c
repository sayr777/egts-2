/*
 *  Created on: 08 may 2016.
 *  File: egts.c
 *  Author: Moksyakov Alexey
 *  email:  yavtuk@ya.ru
 */


#include <string.h>
#include "crc.h"
#include "printf-stdarg.h"
#include "egts.h"
#include "data_types.h"
#include "time.h"
#include "modem.h"
#include "device.h"
#include "fifo.h"
#include "revision.h"
#include "gost_28147_89.h"

#if defined (TS083I) || defined (TS100E)

// Fifo
static __fifo_data pack_fifo;
static __fifo_data * const fifo = &pack_fifo;

static uint8_t rx_data[EGTS_MAX_SIZE_DATA];

static __sub_record_t sub_record;
static __sub_record_t * const pSub_record= &sub_record;

static __egts_state_t state;
static __egts_state_t * const pState = &state;

static __services_frame_data_t egts_header_record;
static __services_frame_data_t * const pEgts_header_record = &egts_header_record;

static __header_transport_layer_t egts_header_trans_layer;
static __header_transport_layer_t * const pEgts_header_trans_layer = &egts_header_trans_layer;


static void set_state_auth(const uint16_t state);
static void clear_state_auth(void);
static BOOL_T is_header_recived(void);
static void fill_header(void);
static BOOL_T is_full_pack_received(void);
static BOOL_T is_crc_ok(void);
static void fill_record_header(void);
static BOOL_T is_not_answer_from_server(void);
static void  check_response(void);
static BOOL_T is_buffer_not_empty(void);
static void get_pack_data(void);
static void record_response(void);
static void auth_term_id(void);
static void auth_module_data(void);
static void auth_vehicle(void);
static void auth_params(void);
static void empty(void); 
static void auth_info(void); 
static void auth_service_info(void);
static void auth_res_code(void);
static void handler_auth(void);
static void handler_teledata(void);
static void handler_data(void);
static void get_crc_frame_data(void);
static void replace_frame_data_len(const uint32_t hl);
static void replace_head_crc(const uint32_t hl);
static void replace_record_len(const uint32_t hl);
static void encrypt_data(const uint8_t hl);
static void calc_params_heads(const uint32_t head_len);
static void auth_answer_param_info(void);
static void handler_auth_req(void);
static void add_subrec_for_answer(void);
static void create_data_to_answer(void);
static void send_answer(void);

void egts_init(void) 
{
	gsm_head_set(REG_NONE);
	memset((uint8_t*)pEgts_header_trans_layer, 0, sizeof(__header_transport_layer_t));
	memset((uint8_t*)pEgts_header_record, 0, sizeof(__services_frame_data_t));
	memset((uint8_t*)pState, 0, sizeof(__egts_state_t));
	pState->link = DEV_GSM;
	cypher_gost_init();
	
	create_fifo(fifo, rxData, EGTS_MAX_SIZE_DATA);
}

BOOL_T egts_is_auth_none(void)
{
    return (pState->authState != AUTH_LOGIN_NONE) ? TRUE_T : FALSE_T;
}

void handler_msg_egts(const uint8_t new_byte,  uint16_t const index) 
{
    static BOOL_T init_head = TRUE_T;

    if(init_head && (index >= EGTS_HEAD_MIN_LEN) ) {
        pEgts_header_trans_layer->frameDataLength= *(get_pntr_rx_buff() + 6);
        pEgts_header_trans_layer->frameDataLength <<= 8;
        pEgts_header_trans_layer->frameDataLength |= *(get_pntr_rx_buff() + 5);
        init_head = FALSE_T;
    }
    if(index != ( EGTS_HEAD_MIN_LEN + pEgts_header_trans_layer->frameDataLength + sizeof(uint16_t) ) ){
        return;
    }

    FIFO_CLEAR();
    for(uint32_t i = 0; i < ( EGTS_HEAD_MIN_LEN + pEgts_header_trans_layer->frameDataLength + sizeof(uint16_t)); i++) {
        FIFO_PUSH_BYTE(*(get_pntr_rx_buff() + i));
    }

    fill_header();

    check_response();

    fill_record_header();

    if(pEgts_header_record->recordLength) {
        for(uint16_t parse_data_count = 0; parse_data_count < pEgts_header_record->recordLength; ) {
            get_pack_data();

            if(pSubRecord->length) {
                handler_data();
                parse_data_count += sizeof( pSubRecord->type ) + sizeof( pEgts_header_record->recordLength ) \
                                 + pEgts_header_record->recordLength;
            }
        }
    }
    get_crc_frame_data();


    init_head = TRUE_T;
    modem_clr_rx_buf();
    FIFO_CLEAR();

    if(pState->req_type == EGTS_ANSW) {
        create_data_to_answer();
        send_answer();
        FIFO_CLEAR();
    }

    if(gsm_head_get() == REG_HALF) {
        gsm_head_set(REG_FULL);
    }

}

static void set_state_auth(const uint16_t state) 
{
	pState->authState = state;
}

static void clear_state_auth(void) 
{
    pState->authState = AUTH_LOGIN_NONE;
}

static BOOL_T is_header_recived(void)
{
	return (FIFO_DATA_SIZE() == EGTS_HEAD_MIN_LEN ) ? TRUE_T : FALSE_T;
}

static void fill_header(void)
{
	uint8_t val8;
	pEgts_header_trans_layer->protocolVersion = FIFO_POP_BYTE();
	pEgts_header_trans_layer->securityKeyId = FIFO_POP_BYTE();
	pEgts_header_trans_layer->flags = FIFO_POP_BYTE();
	pEgts_header_trans_layer->headerLen = FIFO_POP_BYTE();
	pEgts_header_trans_layer->headerEncoder = FIFO_POP_BYTE();

	val8 = FIFO_POP_BYTE();
	pEgts_header_trans_layer->frameDataLength = FIFO_POP_BYTE();
	pEgts_header_trans_layer->frameDataLength <<= 8;
	pEgts_header_trans_layer->frameDataLength |= val8;

	val8 = FIFO_POP_BYTE();
	pEgts_header_trans_layer->packetId = FIFO_POP_BYTE();
	pEgts_header_trans_layer->packetId <<= 8;
	pEgts_header_trans_layer->packetId |= val8;

	pEgts_header_trans_layer->packetType = FIFO_POP_BYTE();
	pEgts_header_trans_layer->crcHeader = FIFO_POP_BYTE();

	pState->req_type = (EGTS_PT_APPDATA == pEgts_header_trans_layer->packetType) ? EGTS_ANSW : EGTS_ANSWER_NOT;
}

static BOOL_T is_full_pack_received(void) 
{
	return (FIFO_DATA_SIZE() != (pEgts_header_trans_layer->frameDataLength + sizeof(uint16_t))) ? TRUE_T : FALSE_T;
}

static BOOL_T is_crc_ok(void)
{
	return FALSE_T;
}

static void fill_record_header(void)
{
	uint8_t val8;

	val8 = FIFO_POP_BYTE();
	pEgts_header_record->recordLength = FIFO_POP_BYTE();
	pEgts_header_record->recordLength <<= 8;
	pEgts_header_record->recordLength |= val8;

	val8 = FIFO_POP_BYTE();
	pEgts_header_record->recordNumber = FIFO_POP_BYTE();
	pEgts_header_record->recordNumber <<= 8;
	pEgts_header_record->recordNumber |= val8;

	pEgts_header_record->recordFlags  = FIFO_POP_BYTE();

	/* TODO: egts */
	if(pEgts_header_record->recordFlags){

	}
	pEgts_header_record->sourceServiceType = FIFO_POP_BYTE();
	pEgts_header_record->recipientServiceType = FIFO_POP_BYTE();
}

static BOOL_T is_not_answer_from_server(void) 
{
	return ( pEgts_header_trans_layer->packetType != EGTS_PT_RESPONSE ) ? TRUE_T : FALSE_T;
}

static void  check_response(void) 
{
	uint8_t val8;
	
	if( is_not_answer_from_server() ){
		return;
	}
	val8 = FIFO_POP_BYTE();
	pState->pid = FIFO_POP_BYTE();
	pState->pid <<= 8;
	pState->pid |= val8;
	pState->error = FIFO_POP_BYTE();
}
static BOOL_T is_buffer_not_empty(void) 
{
	return (FIFO_DATA_SIZE() > 0) ? TRUE_T : FALSE_T;
}

static void get_pack_data(void)
{
	uint8_t val8;

	pSubRecord->type = FIFO_POP_BYTE();
	val8 = FIFO_POP_BYTE();
	pSubRecord->length = FIFO_POP_BYTE();
	pSubRecord->length <<= 8;
	pSubRecord->length |= val8;
}

static void record_response(void) 
{
	uint8_t data[pSubRecord->length];
	
	DEBUG_PRINT("Record Response\n");
	
	for(uint16_t i = 0; i < pSubRecord->length ; i++) {
		 data[i] = FIFO_POP_BYTE();
	}
	if( EGTS_PC_OK == data[2]){
	    DEBUG_PRINT("OK response\n");
		if(EGTS_SR_AUTH_SERVICE == pEgts_header_record->sourceServiceType)
			set_state_auth(AUTH_LOGIN_ANSWER);
	}
	else{
	    DEBUG_PRINT("ERROR response\n");
	}
}

static void auth_term_id(void) 
{
    DEBUG_PRINT("auth_term_id\n");
	for(uint16_t i = 0; i < pSubRecord->length ; i++) {
	    DEBUG_PRINTF("%02x ", FIFO_POP_BYTE());
	}
}

static void auth_module_data(void) 
{
    DEBUG_PRINT("auth_module_data\n");
	for(uint16_t i = 0; i < pSubRecord->length ; i++) {
	    DEBUG_PRINTF("%02x ", FIFO_POP_BYTE());
	}
}
static void auth_vehicle(void) 
{
    DEBUG_PRINT("auth_vehicle\n");
	for(uint16_t i = 0; i < pSubRecord->length ; i++) {
	    DEBUG_PRINTF("%02x ", FIFO_POP_BYTE());
	}
}

static void	auth_params(void) 
{
    DEBUG_PRINT("Params\n");
	uint8_t data[pSubRecord->length];

	for(uint16_t i = 0; i < pSubRecord->length ; i++) {
		data[i] = FIFO_POP_BYTE();
		DEBUG_PRINTH(data[i]);
	}
	gsm_head_set(REG_HALF);
}

static void empty(void) 
{

}

static void	auth_info(void) 
{

}

static void auth_service_info(void)
{
	DEBUG_PRINT("Service info\n");
	
	for(uint16_t i = 0; i < pSubRecord->length ; i++) {
		DEBUG_PRINTF("%02x ", FIFO_POP_BYTE());
	}
}

static void	auth_res_code(void) 
{
    DEBUG_PRINT("RESULT CODE\n");
	if( EGTS_PC_OK ==  FIFO_POP_BYTE()){
	    DEBUG_PRINT("OK\n");
	}
	else{
		set_error_dev();
		DEBUG_PRINT("ERROR\n");
	}
}
static void handler_auth(void)
{

	void ( *options[EGTS_SR_AUTH_SR_END])(void) = { record_response, auth_term_id, auth_module_data, auth_vehicle, empty, empty,  auth_params, auth_info, auth_service_info, auth_res_code };
	void ( *auth_service)(void);

	auth_service = options[pSubRecord->type];
	auth_service();
}

static void handler_teledata(void) 
{
    const uint8_t FUNC_NUMBER = 1;
    
	void ( *options[FUNC_NUMBER])(void) = { record_response } ;
	void ( *tele_data_service)(void);

	tele_data_service = options[pSubRecord->type];
	tele_data_service();
}

static void handler_data(void)
{
	set_ok_dev();
	switch( pEgts_header_record->sourceServiceType) {

		case EGTS_SR_RESPONSE:
			record_response();
			break;

		case EGTS_SR_AUTH_SERVICE:
			handler_auth();
			break;

		case EGTS_SR_TELEDATA_SERVICE:
			handler_teledata();
			break;

		case EGTS_SR_COMMAND_SERVICE:
		case EGTS_SR_FIRMWARE_SERVICE:
		case EGTS_SR_ECALL_SERVICE:
			break;

		default:
			break;
	}
	set_cmd_type_mod(MODEM_CMD_FREE);
}
static void get_crc_frame_data(void)
{
	uint8_t val8;
	val8 = FIFO_POP_BYTE();
	pEgts_header_record->frameCRC = FIFO_POP_BYTE();
	pEgts_header_record->frameCRC <<= 8;
	pEgts_header_record->frameCRC |= val8;
}

static void replace_frame_data_len(const uint32_t hl)
{
	const uint16_t LEN_FRAME = FIFO_DATA_SIZE() - hl;
	FIFO_REPLACE(5, (uint8_t *)&LEN_FRAME, (uint16_t) 2);
}

static void replace_head_crc(const uint32_t hl) 
{
	const uint8_t CRC = crc8_poly_31(rx_data, hl - 1);
	FIFO_REPLACE(hl - 1, (uint8_t *)&CRC,(uint16_t) 1);
}

static void replace_record_len(const uint32_t hl) 
{
	const uint16_t DATA = FIFO_DATA_SIZE() - 25;
	FIFO_REPLACE(hl + 3, (uint8_t *)&DATA,(uint16_t) 2);
}

static void encrypt_data(const uint8_t hl)
{
	const uint32_t CYPHER_GOST_IN_BLOCK_DATA = 64;
	uint32_t *pVal32 =(uint32_t *)&rx_data[hl];
	uint32_t cipher[2];
	uint32_t plain[2];

	uint32_t frame_len = rx_data[6];
	frame_len <<= 8;
	frame_len |= rx_data[5];

	while((frame_len * 8) % CYPHER_GOST_IN_BLOCK_DATA){
		FIFO_PUSH_BYTE(0);
		frame_len += 1;
	}
	replace_frame_data_len(hl);
	replace_head_crc(hl);

	for (uint32_t i = 0; i < (frame_len >> 3); i++){
		plain[0] = *( pVal32 + 2 * i);
		plain[1] = *( pVal32 + 2 * i + 1);
		gost_crypt(plain, cipher, gost_ret_key());
		FIFO_REPLACE(hl + ( i * 8 ), (uint8_t *)&cipher,(uint16_t) 8);
	}
}

static void calc_params_heads(const uint32_t head_len)
{
	replace_frame_data_len(head_len);
	replace_head_crc(head_len);
	replace_record_len(head_len);

#if EGTS_CRYPT
	encrypt_data(head_len);
#endif
	
	const uint16_t crc = crc16(rx_data + head_len,  FIFO_DATA_SIZE() - head_len);
	FIFO_PUSH_DATA((uint8_t *)&crc, 2);
}

static void auth_answer_param_info(void) 
{
	const uint16_t LEN = 4;
	FIFO_PUSH_BYTE( EGTS_SR_AUTH_SR_AUTH_INFO );
	FIFO_PUSH_DATA((uint8_t *)&LEN, 2);
	FIFO_PUSH_BYTE(0);
	FIFO_PUSH_BYTE(0);
	FIFO_PUSH_BYTE(0);
	FIFO_PUSH_BYTE(0);
}

static void handler_auth_req(void)
{
	switch(pSubRecord->type) {
		case EGTS_SR_AUTH_SR_AUTH_PARAMS:
			auth_answer_param_info();
			break;

		default:
			break;
	}
}

static void add_subrec_for_answer(void)
{

	switch( pEgts_header_record->sourceServiceType) {

		case EGTS_SR_AUTH_SERVICE:
			handler_auth_req();
			break;

		default: 
		    PRINTD(pEgts_header_record->sourceServiceType);
			break;
	}
}

static void create_data_to_answer(void)
{
	const uint8_t VER = 1;
	FIFO_PUSH_BYTE(VER);

#if EGTS_CRYPT
	const uint8_t SKID = 1;
	FIFO_PUSH_BYTE(SKID);

	const uint8_t FLAGS = 0x08;
	FIFO_PUSH_BYTE(FLAGS);
#else
	const uint8_t SKID = 0;
	FIFO_PUSH_BYTE(SKID);

	const uint8_t FLAGS = 0;
	FIFO_PUSH_BYTE(FLAGS);
#endif
	
	const uint8_t HEADER_LEN = 11;
	FIFO_PUSH_BYTE(HEADER_LEN);

	const uint8_t HEADER_ENCODER = 0;
	FIFO_PUSH_BYTE(HEADER_ENCODER);

	const uint16_t FRAME_DATA_LENGTH = 0;
	const uint16_t index_frame_data_len_header = FIFO_DATA_SIZE();

	FIFO_PUSH_DATA((uint8_t *)&FRAME_DATA_LENGTH, 2);
	FIFO_PUSH_DATA((uint8_t *)&pEgts_header_trans_layer->packetId, 2);
	FIFO_PUSH_BYTE(EGTS_PT_RESPONSE);

	const uint8_t sizeHeader = FIFO_DATA_SIZE();
	const uint8_t HEADER_CRC = 0;
	FIFO_PUSH_BYTE(HEADER_CRC);

	/*EGTS_PT_RESPONSE RPID */
	FIFO_PUSH_DATA((uint8_t *)&pEgts_header_trans_layer->packetId, 2);
	/*EGTS_PT_RESPONSE PR */
	FIFO_PUSH_BYTE(0);

	FIFO_PUSH_DATA((uint8_t *)&pEgts_header_record->recordLength, 2);
	FIFO_PUSH_DATA((uint8_t *)&pEgts_header_record->recordNumber, 2);
	const uint8_t REC_FLAG = 0x81;
	FIFO_PUSH_BYTE(REC_FLAG);

	const uint32_t EXAMPLE_ID = 219999;
	FIFO_PUSH_DATA((uint8_t *)&EXAMPLE_ID, 4);
	FIFO_PUSH_BYTE(pEgts_header_record->sourceServiceType);
	FIFO_PUSH_BYTE(pEgts_header_record->recipientServiceType);

	add_subrec_for_answer();
	calc_params_heads(HEADER_LEN);
	return;
}

static void send_answer(void)
{
    switch(pState->link)
    {
        case DEV_GSM:
        	 set_tx_data_mod((const uint8_t *)rxData, FIFO_DATA_SIZE(), TRUE_T);
        break;

        case DEV_SMS:
        break;

        default:
          break;
    }
    vTaskDelay(300);
}

#else
#if defined (TS082I)
void handler_msg_egts(const uint8_t new_byte,  uint16_t const index) 
{
}
#endif
#endif
