#ifndef RULES_H
#define RULES_H

#ifdef _MSC_VER
#pragma once
#endif  // _MSC_VER


#include <cstdint>
#include <unordered_map>
#include "config.h"

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

    uint32_t EVENT_FILTER_COUNT;                   
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
static const char *ERROR_STR_TABLE[] = { "ID", "Description" };
static const char *ERROR_STR_TABLE_3[] = { "UtcTime", "ID", "Description" };

//Error data struct
static const RULE_DATA_STRUCT error_data_struct = {0xff, 0x1002, 2, 0xff, 0, 0x80000000}; 

//Error rule struct
static RULE_STRUCT error_rule_struct = { 2, 0x00ff, 0xc006, (PRULE_DATA_STRUCT)&error_data_struct, 0xff,
	(uintptr_t)"SYSMON_ERROR", (uintptr_t)"Error report",0, (uintptr_t *)&ERROR_STR_TABLE, 
	0xffffffff, 0xffffffff, 0, 1 };

//-----------------------------------------------------------------------------

//Create process string table
static const char *CREATE_PROC_STR_TABLE[] = { "SequenceNumber", "UtcTime", "ProcessGuid", "ProcessId", "Image",
  "CommandLine", "CurrentDirectory", "User", "LogonGuid", "LogonId", "TerminalSessionId","IntegrityLeve", "Hashes",
  "ParentProcessGuid", "ParentProcessId", "ParentImage", "ParentCommandLine"};

//Create process string table
static const char *CREATE_PROC_STR_TABLE_3[] = { "UtcTime", "ProcessGuid", "ProcessId", "Image",
  "CommandLine", "CurrentDirectory", "User", "LogonGuid", "LogonId", "TerminalSessionId","IntegrityLeve", "Hashes",
  "ParentProcessGuid", "ParentProcessId", "ParentImage", "ParentCommandLine"};

//Create process string table
static const char *CREATE_PROC_STR_TABLE_4[] = { "UtcTime", "ProcessGuid", "ProcessId", "Image", "FileVersion",
  "Description", "Product", "Company","CommandLine", "CurrentDirectory", "User", "LogonGuid", "LogonId", "TerminalSessionId","IntegrityLevel", "Hashes",
  "ParentProcessGuid", "ParentProcessId", "ParentImage", "ParentCommandLine"};


//Create Process data struct
static const RULE_DATA_STRUCT create_process_data_struct = {0xff, 0x1002, 2, 0xff, 0, 0x80000000}; 

//Create Process rule struct
static RULE_STRUCT create_process_rule_struct = { 0x11, 1, 0x4006, (PRULE_DATA_STRUCT)&create_process_data_struct, 1,
	(uintptr_t)"SYSMON_CREATE_PROCESS", (uintptr_t)"Process Create",0, (uintptr_t *)&CREATE_PROC_STR_TABLE,
	1, 0, (uintptr_t)"ProcessCreate", 0};

//-----------------------------------------------------------------------------

//File create time string table
static const char *FILE_CREATE_STR_TABLE[] = { "SequenceNumber", "UtcTime", "ProcessGuid", "ProcessId", "Image",
  "TargetFilename", "CreationUtcTime", "PreviousCreationUtcTime"};

//File create time string table
static const char *FILE_CREATE_STR_TABLE_3[] = { "UtcTime", "ProcessGuid", "ProcessId", "Image",
  "TargetFilename", "CreationUtcTime", "PreviousCreationUtcTime"};


//File time data struct
static const RULE_DATA_STRUCT file_time_data_struct = {2, 0x1003, 0x4, 0x2, 0, 0x80000000}; 

//File time rule struct
static RULE_STRUCT file_time_rule_struct = { 8, 2, 0x4006, (PRULE_DATA_STRUCT)&file_time_data_struct, 2,
	(uintptr_t)"SYSMON_FILE_TIME", (uintptr_t)"File creation time changed",0, (uintptr_t *)&FILE_CREATE_STR_TABLE,
	1, 0, (uintptr_t)"FileCreateTime", 0};

//-----------------------------------------------------------------------------

//Create process string table
static const char * NETWORK_CONNECT_STR_TABLE[] = { "SequenceNumber", "UtcTime", "ProcessGuid", "ProcessId", "Image",
  "User", "Protoco", "Initiated", "SourceIsIpv6", "SourceIp", "SourceHostname",
  "SourcePort", "SourcePortName", "DestinationIsIpv6", "DestinationIp", "DestinationHostname",
  "DestinationPort", "DestinationPortName"};

//Create process string table
static const char *NETWORK_CONNECT_STR_TABLE_3[] = { "UtcTime", "ProcessGuid", "ProcessId", "Image",
  "User", "Protoco", "Initiated", "SourceIsIpv6", "SourceIp", "SourceHostname",
  "SourcePort", "SourcePortName", "DestinationIsIpv6", "DestinationIp", "DestinationHostname",
  "DestinationPort", "DestinationPortName"};

//Network connect data struct
static const RULE_DATA_STRUCT network_connect_data_struct = {3, 0x1004, 0x4, 0x3, 0, 0x80000000}; 

//Network connect rule struct
static RULE_STRUCT network_connect_rule_struct = { 0x12, 3, 0x4006, (PRULE_DATA_STRUCT)&network_connect_data_struct, 3,
	(uintptr_t)"SYSMON_NETWORK_CONNECT", (uintptr_t)"Network connection detected",0, (uintptr_t *)&NETWORK_CONNECT_STR_TABLE,
	1, 0, (uintptr_t)"NetworkConnect", 1};



//-----------------------------------------------------------------------------

static const char *SERVICE_STATE_STR_TABLE[] = { "SequenceNumber", "State"};

static const char *SERVICE_STATE_STR_TABLE_3[] = { "UtcTime", "State", "Version", "SchemaVersion"};

//Service state data struct
static const RULE_DATA_STRUCT service_state_data_struct = {4, 0x1002, 4, 4, 0, 0x80000000};

//Service state rule struct
static RULE_STRUCT service_state_rule_struct = { 2, 4, 0x4006, (PRULE_DATA_STRUCT)&service_state_data_struct, 4,
	(uintptr_t)"SYSMON_SERVICE_STATE_CHANGE", (uintptr_t)"Sysmon service state changed",0, (uintptr_t *)&SERVICE_STATE_STR_TABLE,
	0xffffffff, 0, 0, 1};

//-----------------------------------------------------------------------------

//Process terminate string table
static const char *PROC_TERM_STR_TABLE[] = { "SequenceNumber", "UtcTime", "ProcessGuid", "ProcessId", "Image"};

static const char *PROC_TERM_STR_TABLE_3[] = { "UtcTime", "ProcessGuid", "ProcessId", "Image"};

//Process terminate data struct
static const RULE_DATA_STRUCT process_term_data_struct = {5, 0x1002, 4, 5, 0, 0x80000000}; 

//Process terminate rule struct
static RULE_STRUCT process_term_rule_struct = { 5, 5, 0x4006, (PRULE_DATA_STRUCT) &process_term_data_struct, 5,
	(uintptr_t)"SYSMON_PROCESS_TERMINATE", (uintptr_t)"Process terminated",0, (uintptr_t *)&PROC_TERM_STR_TABLE,
	1, 0, (uintptr_t)"ProcessTerminate", 0};


//-----------------------------------------------------------------------------

//Driver loaded string table
static const char *DRV_LOADED_STR_TABLE[] = { "SequenceNumber", "UtcTime", "ImageLoaded", "Hashes", "Signed", "Signature"};

static const char *DRV_LOADED_STR_TABLE_3[] = { "UtcTime", "ImageLoaded", "Hashes", "Signed", "Signature", "SignatureStatus",};

//Driver loaded data struct
static const RULE_DATA_STRUCT driver_loaded_data_struct = {6, 0x1002, 4, 6, 0, 0x80000000}; 

//Driver loaded rule struct
static RULE_STRUCT driver_loaded_rule_struct = { 6, 6, 0x4006,(PRULE_DATA_STRUCT) &driver_loaded_data_struct, 6,
	(uintptr_t)"SYSMON_DRIVER_LOAD", (uintptr_t)"Driver loaded",0, (uintptr_t *)&DRV_LOADED_STR_TABLE,
	1, 0, (uintptr_t)"DriverLoad", 0};

//-----------------------------------------------------------------------------

//Image loaded string table
static const char *IMG_LOADED_STR_TABLE[] = { "SequenceNumber", "UtcTime", "ProcessGuid", "ProcessId", "Image",
	"ImageLoaded", "Hashes", "Signed", "Signature"};

static const char *IMG_LOADED_STR_TABLE_3[] = { "UtcTime", "ProcessGuid", "ProcessId", "Image", "ImageLoaded", 
	"Hashes", "Signed", "Signature", "SignatureStatus"};

static const char *IMG_LOADED_STR_TABLE_4[] = { "UtcTime", "ProcessGuid", "ProcessId", "Image", "ImageLoaded", 
	"FileVersion", "Description", "Product", "Company""Hashes", "Signed", "Signature", "SignatureStatus"};

//Image loaded data struct
static const RULE_DATA_STRUCT image_loaded_data_struct = {7, 0x1002, 4, 7, 0, 0x80000000}; 

//Image loaded rule struct
static RULE_STRUCT image_loaded_rule_struct = { 9, 7, 0x4006, (PRULE_DATA_STRUCT)&image_loaded_data_struct, 7,
	(uintptr_t)"SYSMON_IMAGE_LOAD", (uintptr_t)"Image loaded",0, (uintptr_t *)&IMG_LOADED_STR_TABLE,
	1, 0, (uintptr_t)"ImageLoad", 1};

//-----------------------------------------------------------------------------

//Create remote thread string table
static const char *CREATE_REMOTE_THREAD_STR_TABLE[] = { "SequenceNumber", "UtcTime", "SourceProcessGuid", "SourceProcessId", "SourceImage",
  "TargetProcessGuid", "TargetProcessId", "TargetImage", "NewThreadId"};

static const char *CREATE_REMOTE_THREAD_STR_TABLE_3[] = { "UtcTime", "SourceProcessGuid", "SourceProcessId", "SourceImage",
  "TargetProcessGuid", "TargetProcessId", "TargetImage", "NewThreadId", "StartAddress", "StartModule", "StartFunction"};

//Image loaded data struct
static const RULE_DATA_STRUCT create_remote_thread_data_struct = {8, 0x1001, 4, 8, 0, 0x80000000}; 

//Create remote thread rule struct
static RULE_STRUCT create_remote_thread_rule_struct = { 9, 8, 0x4006,(PRULE_DATA_STRUCT) &create_remote_thread_data_struct, 8,
	(uintptr_t)"SYSMON_CREATE_REMOTE_THREAD", (uintptr_t)"CreateRemoteThread detected",0, (uintptr_t *)&CREATE_REMOTE_THREAD_STR_TABLE,
	1, 0, (uintptr_t)"CreateRemoteThread", 1};


//-----------------------------------------------------------------------------

//Raw access read event

//Image loaded string table
static const char *RAW_ACCESS_READ_STR_TABLE[] = { "UtcTime", "ProcessGuid", "ProcessId", "Image", "Device"};

//Raw access data struct
static const RULE_DATA_STRUCT raw_access_data_struct = {9, 0x1001, 4, 9, 0, 0x80000000}; 

//Raw access rule struct
static const RULE_STRUCT raw_access_rule_struct = { 5, 9, 0x4006,(PRULE_DATA_STRUCT) &raw_access_data_struct, 9,
	(uintptr_t)"SYSMON_RAWACCESS_READ", (uintptr_t)"RawAccessRead detected",0, (uintptr_t *)&RAW_ACCESS_READ_STR_TABLE,
	1, 0, (uintptr_t)"RawAccessRead", 1};


//-----------------------------------------------------------------------------

//Process accessed event

//Process accessed string table
static const char *PROC_ACCESSED_STR_TABLE[] = { "UtcTime", "SourceProcessGUID", "SourceProcessId", "SourceThreadId", "SourceImage",
"TargetProcessGUID", "TargetProcessId", "TargetImage", "GrantedAccess", "CallTrace"};

//Process accessed data struct
static const RULE_DATA_STRUCT proc_accessed_data_struct = {10, 0x1003, 4, 10, 0, 0x80000000}; 

//Process accessed rule struct
static const RULE_STRUCT proc_accessed_rule_struct = { 10, 10, 0x4006,(PRULE_DATA_STRUCT) &proc_accessed_data_struct, 10,
	(uintptr_t)"SYSMON_ACCESS_PROCESS", (uintptr_t)"Process accessed",0, (uintptr_t *)&PROC_ACCESSED_STR_TABLE,
	1, 0, (uintptr_t)"ProcessAccess", 1};


//-----------------------------------------------------------------------------

//File created event

//File created string table
static const char *FILE_CREATED_STR_TABLE[] = { "UtcTime", "ProcessGuid", "ProcessId", "Image", "TargetFilename", "CreationUtcTime"};

//File created data struct
static const RULE_DATA_STRUCT file_created_data_struct = {11, 0x1002, 4, 11, 0, 0x80000000}; 

//File createdrule struct
static const RULE_STRUCT file_created_rule_struct = { 6, 11, 0x4006,(PRULE_DATA_STRUCT) &file_created_data_struct, 11,
	(uintptr_t)"SYSMON_FILE_CREATE", (uintptr_t)"File created",0, (uintptr_t *)&FILE_CREATED_STR_TABLE,
	1, 0, (uintptr_t)"FileCreate", 0};


//-----------------------------------------------------------------------------


//Reg new/delete event

//Reg new/delete string table
static const char *REG_NEW_STR_TABLE[] = { "EventType", "UtcTime", "ProcessGuid", "ProcessId", "Image", "TargetObject"};

//Reg new/delete data struct
static const RULE_DATA_STRUCT reg_new_data_struct = {12, 0x1002, 4, 12, 0, 0x80000000}; 

//Reg new/delete rule struct
static const RULE_STRUCT reg_new_del_rule_struct = { 6, 12, 0x4006,(PRULE_DATA_STRUCT) &reg_new_data_struct, 12,
	(uintptr_t)"SYSMON_REG_KEY", (uintptr_t)"Registry object added or deleted",0, (uintptr_t *)&REG_NEW_STR_TABLE,
	1, 1, (uintptr_t)"RegistryEvent", 0};


//-----------------------------------------------------------------------------


//Reg modified event

//Reg modified string table
static const char *REG_MODIFIED_STR_TABLE[] = { "EventType", "UtcTime", "ProcessGuid", "ProcessId", "Image", "TargetObject", "Details"};

//Reg modified data struct
static const RULE_DATA_STRUCT reg_modified_data_struct = {13, 0x1002, 4, 13, 0, 0x80000000}; 

//Reg modified rule struct
static const RULE_STRUCT reg_modified_rule_struct = { 7, 13, 0x4006,(PRULE_DATA_STRUCT) &reg_modified_data_struct, 13,
	(uintptr_t)"SYSMON_REG_SETVALUE", (uintptr_t)"Registry value set",0, (uintptr_t *)&REG_MODIFIED_STR_TABLE,
	1, 1, (uintptr_t)"RegistryEvent", 0};


//-----------------------------------------------------------------------------


//Reg renamed event

//Reg renamed string table
static const char *REG_RENAMED_STR_TABLE[] = { "EventType", "UtcTime", "ProcessGuid", "ProcessId", "Image", "TargetObject", "NewName"};

//Reg renamed data struct
static const RULE_DATA_STRUCT reg_renamed_data_struct = {14, 0x1002, 4, 14, 0, 0x80000000}; 

//Reg renamed rule struct
static const RULE_STRUCT reg_renamed_rule_struct = { 7, 14, 0x4006,(PRULE_DATA_STRUCT) &reg_renamed_data_struct, 14,
	(uintptr_t)"SYSMON_REG_NAME", (uintptr_t)"Registry object renamed",0, (uintptr_t *)&REG_RENAMED_STR_TABLE,
	1, 1, (uintptr_t)"RegistryEvent", 0};


//-----------------------------------------------------------------------------


//File create stream hash event

//File create stream hash string table
static const char *FILE_HASH_STR_TABLE[] = { "UtcTime", "ProcessGuid", "ProcessId", "Image", "TargetFilename", "CreationUtcTime", "Hash" };

//File create stream hash data struct
static const RULE_DATA_STRUCT file_hash_data_struct = {15, 0x1002, 4, 15, 0, 0x80000000}; 

//File create stream hash rule struct
static const RULE_STRUCT file_hash_rule_struct = { 7, 15, 0x4006,(PRULE_DATA_STRUCT) &file_hash_data_struct, 15,
	(uintptr_t)"SYSMON_FILE_CREATE_STREAM_HASH", (uintptr_t)"File stream created",0, (uintptr_t *)&FILE_HASH_STR_TABLE,
	1, 0, (uintptr_t)"FileCreateStreamHash", 0};

//-----------------------------------------------------------------------------


//Sysmon config state event

//Sysmon config state string table
static const char *SYSMON_CONFIG_STATE_STR_TABLE[] = { "UtcTime", "Configuration", "ConfigurationFileHash" };

//Sysmon config state data struct
static const RULE_DATA_STRUCT sysmon_config_state_struct = {16, 0x1003, 4, 16, 0, 0x80000000}; 

//Sysmon config state rule struct
static const RULE_STRUCT sysmon_cfg_state_rule_struct = { 3, 16, 0x4006,(PRULE_DATA_STRUCT) &sysmon_config_state_struct, 16,
	(uintptr_t)"SYSMON_SERVICE_CONFIGURATION_CHANGE", (uintptr_t)"Sysmon config state changed",0, (uintptr_t *)&SYSMON_CONFIG_STATE_STR_TABLE,
	1, 0, 0, 1};


//-----------------------------------------------------------------------------


//pipe create event

//pipe create string table
static const char *PIPE_CREATE_STR_TABLE[] = { "UtcTime", "ProcessGuid", "ProcessId", "PipeName", "Image" };

//pipe create data struct
static const RULE_DATA_STRUCT pipe_create_struct = {17, 0x1001, 4, 17, 0, 0x80000000}; 

//pipe create rule struct
static const RULE_STRUCT pipe_create_rule_struct = { 5, 17, 0x4006,(PRULE_DATA_STRUCT) &pipe_create_struct, 17,
	(uintptr_t)"SYSMON_CREATE_NAMEDPIPE", (uintptr_t)"Pipe Created",0, (uintptr_t *)&PIPE_CREATE_STR_TABLE,
	1, 0, (uintptr_t)"PipeEvent", 1};


//-----------------------------------------------------------------------------


//pipe connected event

//pipe connected string table
static const char *PIPE_CONNECTED_STR_TABLE[] = { "UtcTime", "ProcessGuid", "ProcessId", "PipeName", "Image" };

//pipe connected data struct
static const RULE_DATA_STRUCT pipe_connected_struct = {18, 0x1001, 4, 18, 0, 0x80000000}; 

//pipe connected rule struct
static const RULE_STRUCT pipe_connected_rule_struct = { 5, 18, 0x4006,(PRULE_DATA_STRUCT) &pipe_connected_struct, 18,
	(uintptr_t)"SYSMON_CONNECT_NAMEDPIPE", (uintptr_t)"Pipe Connected",0, (uintptr_t *)&PIPE_CONNECTED_STR_TABLE,
	1, 0, (uintptr_t)"PipeEvent", 1};

//-----------------------------------------------------------------------------


//wmi event event

//wmi event string table
static const char *WMI_EVENT_STR_TABLE[] = { "EventType", "UtcTime", "Operation", "User", "EventNamespace", "Name", "Query" };

//wmi event data struct
static const RULE_DATA_STRUCT wmi_event_data_struct = {19, 0x1003, 4, 19, 0, 0x80000000}; 

//wmi event rule struct
static const RULE_STRUCT wmi_event_rule_struct = { 7, 19, 0x4006,(PRULE_DATA_STRUCT) &wmi_event_data_struct, 19,
	(uintptr_t)"SYSMON_WMI_FILTER", (uintptr_t)"WmiEventFilter activity detected",0, (uintptr_t *)&WMI_EVENT_STR_TABLE,
	1, 0, (uintptr_t)"WmiEvent", 1};

//-----------------------------------------------------------------------------


//wmi event consumer event

//wmi event consumer string table
static const char *WMI_EVENT_CONSUMER_STR_TABLE[] = { "EventType", "UtcTime", "Operation", "User", "Name", "Type", "Destination" };

//wmi event consumer data struct
static const RULE_DATA_STRUCT wmi_event_consumer_data_struct = {20, 0x1003, 4, 20, 0, 0x80000000}; 

//wmi event consumer rule struct
static const RULE_STRUCT wmi_event_consumer_rule_struct = { 7, 20, 0x4006,(PRULE_DATA_STRUCT) &wmi_event_consumer_data_struct, 20,
	(uintptr_t)"SYSMON_WMI_CONSUMER", (uintptr_t)"WmiEventConsumer activity detected",0, (uintptr_t *)&WMI_EVENT_CONSUMER_STR_TABLE,
	1, 0, (uintptr_t)"WmiEvent", 1};

//-----------------------------------------------------------------------------


//wmi event consumer filter event

//wmi event consumer filter string table
static const char *WMI_EVENT_CONSUMER_FILTER_STR_TABLE[] = { "EventType", "UtcTime", "Operation", "User", "Name", "Type", "Destination" };

//wmi event consumer filter data struct
static const RULE_DATA_STRUCT wmi_event_consumer_filter_data_struct = {21, 0x1003, 4, 21, 0, 0x80000000}; 

//wmi event consumer filter rule struct
static const RULE_STRUCT wmi_event_consumer_filter_rule_struct = { 6, 21, 0x4006,(PRULE_DATA_STRUCT) &wmi_event_consumer_filter_data_struct, 21,
	(uintptr_t)"SYSMON_WMI_BINDING", (uintptr_t)"WmiEventConsumerToFilter activity detected",0, (uintptr_t *)&WMI_EVENT_CONSUMER_FILTER_STR_TABLE,
	1, 0, (uintptr_t)"WmiEvent", 1};

//-----------------------------------------------------------------------------

//Add each of the events to the event array
static std::unordered_map<uint32_t, PRULE_STRUCT> event_type_map;


//Macros for bit rotations
#define __ROL__(x, y) _rotl(x, y)       // Rotate left
#define __ROR__(x, y) _rotr(x, y)       // Rotate right

//Static strings
static const char *ServiceName = "SysmonDrv";

/*
 * Struct for the sysmon rule buffer
 */
typedef struct {
    uint32_t some_num_idx_0;                   
    char *rules_buf;
	uint32_t rule_buf_size;
	uint32_t some_num_idx_12;
	uint32_t some_num_idx_16;
} RULES_STRUCT, *PRULES_STRUCT;



sysmon_configuration * parse_sysmon_rules( void *rules_buf_cpy, DWORD regValue_size );
char validate_config(void *rules_buffer, int rule_size);
char check_rules(PRULES_STRUCT rules_ptr);
void recursive_count(unsigned int *ptr);
PRULES_STRUCT get_struct_data();
boolean get_config_version(PRULES_STRUCT stack_ptr1, unsigned int *stack_ptr2 );
boolean get_struct_data_wrap( PRULES_STRUCT *rules_struct );
char *resolve_hashmap(unsigned int hash_reg_val);
unsigned int iterate_rule_type( PRULES_STRUCT *a1, char *a2);
unsigned char *iterate_rule(unsigned char *a1, PRULES_STRUCT *a2, unsigned char *a3);
const char *check_include_exclude(void *include_bool);
const char *get_rule_modifier(uint32_t mod_value);
unsigned int get_config_header_len( char *rules_buf_ptr );
void initialize_event_types( double version );

#endif