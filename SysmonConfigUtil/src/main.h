#ifndef _MAINHDR_
#define _MAINHDR_

/*
 * Struct for the rules
 */
typedef struct {

    DWORD sysmon_options;                   
	DWORD sysmon_hash;  
	uintptr_t sysmon_rules;
	DWORD sysmon_rules_size;

} SYSMON_CONFIG_STRUCT, *PSYSMON_CONFIG_STRUCT;


void __cdecl main(int argc, char *argv[]);
PSYSMON_CONFIG_STRUCT read_reg_values( std::string target );
void print_usage();
PSYSMON_CONFIG_STRUCT read_sysmon_reg_file( std::string file_path, boolean ascii_hex );
void stop_remote_registry_svc( SC_HANDLE sc );
SC_HANDLE start_remote_registry_svc( SC_HANDLE sc, std::string target );
std::string GetLastErrorAsString( DWORD err );

#endif