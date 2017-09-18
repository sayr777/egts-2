/*
 *  Created on: 08 may 2016.
 *  File: egts.c
 *  Author: Moksyakov Alexey
 *  email:  yavtuk@ya.ru
 */


#ifndef SRC_EGTS_EGTS_DEF_H_
#define SRC_EGTS_EGTS_DEF_H_

#define EGTS_CRYPT						1

#define EGTS_MAX_SIZE_DATA				(1100)
#define EGTS_MAX_SUB_RECORD_COUNT		(7)		

#define EGTS_PROTO_VERSION				(1)

#define EGTS_HEAD_MIN_LEN				11

#define EGTS_ANSWER_NOT      	0
#define EGTS_ANSWER_OK      	1
#define EGTS_ANSWER_ERROR		2
#define EGTS_ANSW		 		3
#define EGTS_ANSW_END		 	4

#define EGTS_PT_RESPONSE					0
#define EGTS_PT_APPDATA						1
#define EGTS_PT_SIGNED_APPDATA				2

#define EGTS_SR_RESPONSE  					0
#define EGTS_SR_AUTH_SERVICE				1
#define EGTS_SR_TELEDATA_SERVICE			2
#define EGTS_SR_COMMAND_SERVICE				4
#define EGTS_SR_FIRMWARE_SERVICE			9
#define EGTS_SR_ECALL_SERVICE				10

#define EGTS_SR_AUTH_SR_TERM_IDENTITY		1
#define EGTS_SR_AUTH_SR_MODULE_DATA			2
#define EGTS_SR_AUTH_SR_VECIHLE_DATA		3
#define EGTS_SR_AUTH_SR_AUTH_PARAMS			6
#define EGTS_SR_AUTH_SR_AUTH_INFO			7
#define EGTS_SR_AUTH_SR_SERVICE_INFO		8
#define EGTS_SR_AUTH_SR_RESULT_CODE			9
#define EGTS_SR_AUTH_SR_END					10

#define EGTS_PC_OK 							0
#define EGTS_PC_IN_PROGRESS					1

#define EGTS_TELEDATA_SR_POS_DATA			16
#define EGTS_TELEDATA_SR_AD_SENSORS_DATA	18
#define EGTS_TELEDATA_SR_STATE_DATA			20
#define EGTS_TELEDATA_SR_LIQUID_LEVEL		27
#define EGTS_TELEDATA_SR_PASS_COUNTERS		28

#define EGTS_SRC_EVENT_TIME_IGN_ON			0
#define EGTS_SRC_EVENT_COURSE				2
#define EGTS_SRC_EVENT_DIN					4
#define EGTS_SRC_EVENT_TIME_IGN_OFF			5
#define EGTS_SRC_EVENT_SPEED_OVER			7
#define EGTS_SRC_EVENT_DEV_RESTART			8
#define EGTS_SRC_EVENT_BATTERY_BACKUP		11

typedef enum {
    EGTS_EAST = 0, EGTS_WEST = 1
} __egts_lohs_t;

typedef enum {
    EGTS_NORTH = 0, EGTS_SOUTH = 1
} __egts_lahs_t;

typedef enum {
    EGTS_STOP = 0, EGTS_MOVE = 1
} __egts_vehicle_t;

/* liquid level service data */
#pragma pack(1)
typedef struct {
    uint16_t lsn :3;
    uint16_t rdf :1;
    uint16_t llsvu :2;
    uint16_t llsef :1;
} __sub_record_liquid_level_state_t;

typedef struct {
    __sub_record_liquid_level_state_t state;
    uint16_t moduleAddress;
    uint32_t level;
} __service_liquid_level_t;
#pragma pack()
/* end liquid level service data  */

/* service pos data */
#pragma pack(1)
typedef struct {
    uint16_t vld :1;
    uint16_t fix :1;
    uint16_t cs :1;
    uint16_t bb :1;
    uint16_t mv :1;
    uint16_t lahs :1;
    uint16_t lohs :1;
    uint16_t alte :1;
} __sub_record_pos_data_flags_t;

typedef struct {
    uint16_t speed :14;
    uint16_t dirh :1;
    uint16_t alts :1;
} __sub_record_pos_data_speed_t;

typedef struct {
    uint8_t val[3];
} __sub_record_pos_data_odometr_t;

typedef struct {
    uint32_t timeUTC;
    uint32_t lat;
    uint32_t lng;
    __sub_record_pos_data_flags_t flags;
    __sub_record_pos_data_speed_t speed;
    uint8_t dir;
    __sub_record_pos_data_odometr_t odometr;
    uint8_t din;
    uint16_t hdop;
    uint8_t sat;
    uint8_t src;
} __sub_record_pos_data_t;
#pragma pack()
/* end service pos data */

/* ain/din service data */
#pragma pack(1)
typedef struct {
    uint8_t din;
    uint8_t dout;
    uint8_t ain;
    uint16_t ain1;
} __service_ain_din_t;
#pragma pack()
/* end ain/din service data  */

/* power state service data */
#pragma pack(1)
typedef enum {
    STATE_PASSIVE = 0,
    STATE_ERA,
    STATE_ACTIVE,
    STATE_EMERGENCY_CALL,
    STATE_EMERGENCY_TRACKING,
    STATE_TESTING,
    STATE_AVTO_SERVICE,
    STATE_DWNLD_FW
} __egts_state_enum;
typedef struct {
    uint16_t bbu :1;
    uint16_t ibu :1;
    uint16_t nms :1;
} __add_state_t;

typedef struct {
    uint8_t state;
    uint8_t mainSourcePower;
    uint8_t backUpBatteryVoltage;
    uint8_t internalBatteryVoltage;
    __add_state_t additional;
} __service_state_t;
#pragma pack()
/* end state service data  */

#pragma pack(1)
typedef struct {
    uint16_t priority :2;
    uint16_t compressed :1;
    uint16_t encryptAlgorithm :2;
    uint16_t routingDataExists :1;
    uint16_t prefix :2;
} __flags_t;
#pragma pack()

#pragma pack(1)
typedef struct {
    uint16_t peerAddress;
    uint16_t recipientAddress;
    uint8_t timeToLives;
} __routing_data_t;
#pragma pack()

typedef struct {
    uint8_t protocolVersion;
    uint8_t securityKeyId;
    uint8_t flags;
    uint8_t headerLen;
    uint8_t headerEncoder;
    uint16_t frameDataLength;
    uint16_t packetId;
    uint8_t packetType;
    uint8_t crcHeader;
} __header_transport_layer_t;

#pragma pack(1)
typedef struct {
    uint16_t objIdFieldExists :1;
    uint16_t eventIdFieldExists :1;
    uint16_t timeFieldExists :1;
    uint16_t recordProcessingPriority :2;
    uint16_t groupFlags :1;
    uint16_t recipientServiceOnDevice :1;
    uint16_t sourceServiceOnDevice :1;
} __record_flags_t;
#pragma pack()

#pragma pack(1)
typedef struct {
    uint8_t type;
    uint16_t length;
    uint8_t *pData;
} __sub_record_t;

typedef struct {
    uint16_t recordLength;
    uint16_t recordNumber;
    uint8_t recordFlags;
    uint32_t objectIdentifier;
    uint32_t eventIdentifier;
    uint32_t timeStamp;
    uint8_t sourceServiceType;
    uint8_t recipientServiceType;
    uint16_t frameCRC;
} __services_frame_data_t;

typedef enum {
    AUTH_LOGIN_NONE = 0,
    AUTH_LOGIN_SEND = 1,
    AUTH_LOGIN_ANSWER = 2,
    AUTH_LOGIN_WAIT = 3,
    AUTH_LOGIN_WAIT_ANSW = 4
} __auth_state_t;

typedef struct {
    uint8_t req_type;
    uint8_t error;
    uint8_t link;
    uint16_t pid;
    uint16_t authState;
} __egts_state_t;
#pragma pack()
#endif /* SRC_EGTS_EGTS_DEF_H_ */
