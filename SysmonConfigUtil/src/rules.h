#ifndef RULES_H
#define RULES_H

#ifdef _MSC_VER
#pragma once
#endif  // _MSC_VER


#include <cstdint>

//Constants
const char version_stuff[] = { (char)0x0, (char)0x0, (char)0x0, (char)0x0, (char)0x0, (char)0x0, (char)0x0, (char)0x0,
	(char)0x0, (char)0x0, (char)0x0, (char)0x0, (char)0x0, (char)0x0, (char)0xf0, (char)0xa1};

/*
 * Struct for the hashes
 */
typedef struct {
    uint16_t some_short_0;  
	uint16_t some_short_2;
	uint16_t some_short_4;  
	uint16_t some_short_6;
	uint32_t some_data_8;
	uint32_t some_data_12;

} RULE_DATA_STRUCT, *PRULE_DATA_STRUCT;

/*
 * Struct for the rules
 */
typedef struct {

    uint32_t some_int_0;                   
	uint16_t some_short_4;  
	uint16_t some_short_6;
	PRULE_DATA_STRUCT rule_data_ptr;
	uint32_t RULE_ID_NUM;

	uintptr_t RULE_ID_PTR;    //SYSMON RULE ID
	uintptr_t RULE_DESC_PTR;  //SYSMON RULE DESCRIPTION
	uintptr_t some_data_24;
	uintptr_t *RULE_STR_TABLE;

	uintptr_t some_int_32;
	uintptr_t some_int_36;
	uintptr_t RULE_FUNC;
	uintptr_t some_int_44;

} RULE_STRUCT, *PRULE_STRUCT;


//-----------------------------------------------------------------------------

//Error string table
static const wchar_t *ERROR_STR_TABLE[] = { L"ID", L"Description" };

//Error data struct
static const RULE_DATA_STRUCT error_data_struct = {0xff, 0x1002, 2, 0xff, 0, 0x80000000}; 

//Error rule struct
static const RULE_STRUCT error_rule_struct = { 2, 0x00ff, 0xc006, (PRULE_DATA_STRUCT)&error_data_struct, 0xff,
	(uintptr_t)L"SYSMON_ERROR", (uintptr_t)L"Error report",0, (uintptr_t *)&ERROR_STR_TABLE, 
	0xffffffff, 0xffffffff, 0, 1 };

//-----------------------------------------------------------------------------

//Create process string table
static const uintptr_t CREATE_PROC_STR_TABLE[] = { (uintptr_t)L"SequenceNumber", (uintptr_t)L"UtcTime", (uintptr_t)L"ProcessGuid", (uintptr_t)L"ProcessId", (uintptr_t)L"Image",
  (uintptr_t)L"CommandLine", (uintptr_t)L"CurrentDirectory", (uintptr_t)L"User", (uintptr_t)L"LogonGuid", (uintptr_t)L"LogonId", (uintptr_t)L"TerminalSessionId",(uintptr_t)L"IntegrityLeve(uintptr_t)L", (uintptr_t)L"Hashes",
  (uintptr_t)L"ParentProcessGuid", (uintptr_t)L"ParentProcessId", (uintptr_t)L"ParentImage", (uintptr_t)L"ParentCommandLine"};

//Create Process data struct
static const RULE_DATA_STRUCT create_process_data_struct = {0xff, 0x1002, 2, 0xff, 0, 0x80000000}; 

//Create Process rule struct
static const RULE_STRUCT create_process_rule_struct = { 0x11, 1, 0x4006, (PRULE_DATA_STRUCT)&create_process_data_struct, 1,
	(uintptr_t)L"SYSMON_CREATE_PROCESS", (uintptr_t)L"Process Create",0, (uintptr_t *)&CREATE_PROC_STR_TABLE,
	1, 0, (uintptr_t)L"ProcessCreate", 0};

//-----------------------------------------------------------------------------

//File time string table
static const wchar_t *FILE_CREATE_STR_TABLE[] = { L"SequenceNumber", L"UtcTime", L"ProcessGuid", L"ProcessId", L"Image",
  L"TargetFilename", L"CreationUtcTime"};

//File time data struct
static const RULE_DATA_STRUCT file_time_data_struct = {2, 0x1003, 0x4, 0x2, 0, 0x80000000}; 

//File time rule struct
static const RULE_STRUCT file_time_rule_struct = { 8, 2, 0x4006, (PRULE_DATA_STRUCT)&file_time_data_struct, 2,
	(uintptr_t)L"SYSMON_FILE_TIME", (uintptr_t)L"File creation time changed",0, (uintptr_t *)&FILE_CREATE_STR_TABLE,
	1, 0, (uintptr_t)L"FileCreateTime", 0};

//-----------------------------------------------------------------------------

//Create process string table
static const wchar_t *NETWORK_CONNECT_STR_TABLE[] = { L"SequenceNumber", L"UtcTime", L"ProcessGuid", L"ProcessId", L"Image",
  L"User", L"Protocol", L"Initiated", L"SourceIsIpv6", L"SourceIp", L"SourceHostname",
  L"SourcePort", L"SourcePortName", L"DestinationIsIpv6", L"DestinationIp", L"DestinationHostname",
  L"DestinationPort", L"DestinationPortName"};

//Network connect data struct
static const RULE_DATA_STRUCT network_connect_data_struct = {3, 0x1004, 0x4, 0x3, 0, 0x80000000}; 

//Network connect rule struct
static const RULE_STRUCT network_connect_rule_struct = { 0x12, 3, 0x4006, (PRULE_DATA_STRUCT)&network_connect_data_struct, 3,
	(uintptr_t)L"SYSMON_NETWORK_CONNECT", (uintptr_t)L"Network connection detected",0, (uintptr_t *)&NETWORK_CONNECT_STR_TABLE,
	1, 0, (uintptr_t)L"NetworkConnect", 1};



//-----------------------------------------------------------------------------

static const wchar_t *SERVICE_STATE_STR_TABLE[] = { L"SequenceNumber", L"State"};

//Service state data struct
static const RULE_DATA_STRUCT service_state_data_struct = {4, 0x1002, 4, 4, 0, 0x80000000};

//Service state rule struct
static const RULE_STRUCT service_state_rule_struct = { 2, 4, 0x4006, (PRULE_DATA_STRUCT)&service_state_data_struct, 4,
	(uintptr_t)L"SYSMON_SERVICE_STATE_CHANGE", (uintptr_t)L"Sysmon service state changed",0, (uintptr_t *)&SERVICE_STATE_STR_TABLE,
	0xffffffff, 0, 0, 1};

//-----------------------------------------------------------------------------

//Process terminate string table
static const wchar_t *PROC_TERM_STR_TABLE[] = { L"SequenceNumber", L"UtcTime", L"ProcessGuid", L"ProcessId", L"Image"};

//Process terminate data struct
static const RULE_DATA_STRUCT process_term_data_struct = {5, 0x1002, 4, 5, 0, 0x80000000}; 

//Process terminate rule struct
static const RULE_STRUCT process_term_rule_struct = { 5, 5, 0x4006, (PRULE_DATA_STRUCT) &process_term_data_struct, 5,
	(uintptr_t)L"SYSMON_PROCESS_TERMINATE", (uintptr_t)L"Process terminated",0, (uintptr_t *)&PROC_TERM_STR_TABLE,
	1, 0, (uintptr_t)L"ProcessTerminate", 0};


//-----------------------------------------------------------------------------

//Driver loaded string table
static const wchar_t *DRV_LOADED_STR_TABLE[] = { L"SequenceNumber", L"UtcTime", L"ImageLoaded", L"Hashes", L"Signed", L"Signature"};

//Driver loaded data struct
static const RULE_DATA_STRUCT driver_loaded_data_struct = {6, 0x1002, 4, 6, 0, 0x80000000}; 

//Driver loaded rule struct
static const RULE_STRUCT driver_loaded_rule_struct = { 6, 6, 0x4006,(PRULE_DATA_STRUCT) &driver_loaded_data_struct, 6,
	(uintptr_t)L"SYSMON_DRIVER_LOAD", (uintptr_t)L"Driver loaded",0, (uintptr_t *)&DRV_LOADED_STR_TABLE,
	1, 0, (uintptr_t)L"DriverLoad", 0};

//-----------------------------------------------------------------------------

//Image loaded string table
static const wchar_t *IMG_LOADED_STR_TABLE[] = { L"SequenceNumber", L"UtcTime", L"ProcessGuid", L"ProcessId", L"Image",
	L"ImageLoaded", L"Hashes", L"Signed", L"Signature"};

//Image loaded data struct
static const RULE_DATA_STRUCT image_loaded_data_struct = {7, 0x1002, 4, 7, 0, 0x80000000}; 

//Image loaded rule struct
static const RULE_STRUCT image_loaded_rule_struct = { 9, 7, 0x4006, (PRULE_DATA_STRUCT)&image_loaded_data_struct, 7,
	(uintptr_t)L"SYSMON_IMAGE_LOAD", (uintptr_t)L"Image loaded",0, (uintptr_t *)&IMG_LOADED_STR_TABLE,
	1, 0, (uintptr_t)L"ImageLoad", 0};

//-----------------------------------------------------------------------------

//Create process string table
static const wchar_t *CREATE_REMOTE_THREAD_STR_TABLE[] = { L"SequenceNumber", L"UtcTime", L"SourceProcessGuid", L"SourceProcessId", L"SourceImage",
  L"TargetProcessGuid", L"TargetProcessId", L"TargetImage", L"NewThreadId"};

//Image loaded data struct
static const RULE_DATA_STRUCT create_remote_thread_data_struct = {8, 0x1001, 4, 8, 0, 0x80000000}; 

//Create remote thread rule struct
static const RULE_STRUCT create_remote_thread_rule_struct = { 9, 8, 0x4006,(PRULE_DATA_STRUCT) &create_remote_thread_data_struct, 8,
	(uintptr_t)L"SYSMON_CREATE_REMOTE_THREAD", (uintptr_t)L"CreateRemoteThread detected",0, (uintptr_t *)&CREATE_REMOTE_THREAD_STR_TABLE,
	1, 0, (uintptr_t)L"CreateRemoteThread", 0};



static const RULE_STRUCT rule_arr[] = { error_rule_struct, create_process_rule_struct, file_time_rule_struct, network_connect_rule_struct,
	service_state_rule_struct, process_term_rule_struct, driver_loaded_rule_struct, image_loaded_rule_struct, create_remote_thread_rule_struct};

#define __ROL__(x, y) _rotl(x, y)       // Rotate left
#define __ROR__(x, y) _rotr(x, y)       // Rotate right

static const wchar_t *ServiceName = L"SysmonDrv";

/*
 * Struct for the sysmon rule buffer
 */
typedef struct {
    uint32_t some_num_idx_0;                   
    uintptr_t rules_buf;
	uint32_t rule_buf_size;
	uint32_t some_num_idx_12;
	uint32_t some_num_idx_16;
} RULES_STRUCT, *PRULES_STRUCT;



void parse_sysmon_rules( void *rules_buf_cpy, DWORD regValue_size );
char ruleEngine(void *rules_buffer, int rule_size);
char check_rules(PRULES_STRUCT rules_ptr);
void recursive_count(unsigned int *ptr);
PRULES_STRUCT get_struct_data();
PRULE_STRUCT get_rule_func( uint32_t rule_num);
boolean get_struct_data_wrap2(PRULES_STRUCT stack_ptr1, unsigned int *stack_ptr2 );
boolean get_struct_data_wrap( PRULES_STRUCT *rules_struct );
wchar_t *resolve_hashmap(unsigned int hash_reg_val);
unsigned int iterate_rule_type( PRULES_STRUCT *a1, unsigned int *a2);
unsigned char *iterate_rule(unsigned char *a1, PRULES_STRUCT *a2, unsigned char *a3);
const wchar_t *check_include_exclude(void *include_bool);
const wchar_t *get_rule_modifier(uint32_t mod_value);

#endif