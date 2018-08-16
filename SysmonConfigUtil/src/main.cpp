#include <windows.h>
#include <stdio.h>
#include <string>
#include <vector>
#include "main.h"
#include "rules.h"


/*
 * Current DLL hmodule.
 */
static HMODULE dll_handle = NULL;

extern "C" __declspec (dllexport) void __cdecl RegisterDll (
   HWND hwnd,        // handle to owner window
   HINSTANCE hinst,  // instance handle for the DLL
   LPTSTR lpCmdLine, // string the DLL will parse
   int nCmdShow      // show state
){
  //::MessageBox(0,lpCmdLine,0,0);
}

//===============================================================================================//
BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved )
{
    BOOL bReturnValue = TRUE;
	DWORD dwResult = 0;
	unsigned int ret =0;

	switch( dwReason ) 
    { 
		case DLL_PROCESS_ATTACH:
			dll_handle = (HMODULE)hinstDLL;			
			main(0, nullptr);

		case DLL_PROCESS_DETACH:
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
            break;
    }
	return bReturnValue;
}

void __cdecl main(int argc, char *argv[]){

	PSYSMON_CONFIG_STRUCT sysmon_struct = nullptr;
	char* rules_file_path = nullptr;
	boolean ascii_hex = false;
	if (argc > 0) { // Check the value of argc. If not enough parameters have been passed, inform user and exit.

        for (int i = 1; i < argc; i++) {            
			char *cur_arg = argv[i];
            if ( strcmp(cur_arg, "-f") == 0 && (i + 1 != argc)) {
               rules_file_path = argv[i + 1];
			   i++;
            } else if ( strcmp(cur_arg, "-a") == 0) {
                ascii_hex = true;
			} else if ( strcmp(cur_arg, "-h") == 0 ) {
				print_usage();
				exit(0);
			}            
        }
	}

	//Read sysmon config data from file
	if( rules_file_path != nullptr )
		sysmon_struct = read_sysmon_reg_file( rules_file_path, ascii_hex );		
    else
		sysmon_struct = read_reg_values(); 
	

	if( sysmon_struct != NULL ){

		//Initialize COM
		::CoInitialize(NULL);

		//Parse the config buffer
		sysmon_configuration *sysmon_config = parse_sysmon_rules( (void *)sysmon_struct->sysmon_rules, sysmon_struct->sysmon_rules_size );
		
		//Set the hash
		char *ret_buf = resolve_hashmap(sysmon_struct->sysmon_hash);
		sysmon_config->set_hash_algorithms(ret_buf);
		free(ret_buf);

		//Convert to XML
		std::string xml_str = sysmon_config->toXml();
		puts(xml_str.c_str());

		//Free memory
		if( sysmon_struct->sysmon_rules)
			free( (void*)sysmon_struct->sysmon_rules);
		free(sysmon_struct);

		//Uninitialize COM
		::CoUninitialize();
	}

}

void print_usage(){
	wprintf(L"Usage: sysmon_util <options>\n\t-h\tUsage\n\t-f\tFile path of sysmon configuration from registry\n\t-a\tRegistry dump is ASCII hex format\n\n");
}

PSYSMON_CONFIG_STRUCT read_sysmon_reg_file( char *file_path, boolean ascii_hex ){

	FILE * pFile;
	long lSize;
	char * buffer;
	size_t result;

	fopen_s( &pFile, file_path, "rb" );
	if (pFile==NULL) { fputs ("[-] File error",stderr); return nullptr;}

	// obtain file size:
	fseek (pFile , 0 , SEEK_END);
	lSize = ftell (pFile);
	rewind (pFile);

	// allocate memory to contain the whole file:
	buffer = (char*) malloc (sizeof(char)*lSize);
	if (buffer == NULL) {fputs ("[-] Memory error",stderr); return nullptr;}

	// copy the file into the buffer:
	result = fread (buffer,1,lSize,pFile);
	if (result != lSize) {fputs ("[-] Reading error",stderr); return nullptr;}	

	// close file
	fclose (pFile);

	//Allocate memory for struct and initialize
	PSYSMON_CONFIG_STRUCT sysmon_config = (PSYSMON_CONFIG_STRUCT)malloc(sizeof(SYSMON_CONFIG_STRUCT));
	memset(sysmon_config, 0, sizeof(SYSMON_CONFIG_STRUCT));

	//Convert from hex to binary
	if( ascii_hex ){

		std::string buffer_string(buffer);
		std::vector<unsigned char> ret_str;
		for(int i=0; i < lSize; i+=2)
		{
			if( i + 1 < lSize){
				std::string byte = buffer_string.substr(i,2);
				char chr = (char) (int)strtol(byte.c_str(), NULL, 16);
				ret_str.push_back(chr);
			} else {
				fputs ("[-] Invalid configuration. Odd length ascii hex string.",stderr); 
				free(buffer);
				return nullptr;	
			}
		}

		//Resize the buffer
		unsigned int lSize = ret_str.size();
		realloc(buffer, lSize);
		memcpy(buffer, ret_str.data(), lSize);
	
	}

	//Set the values in the struct
	sysmon_config->sysmon_rules_size = lSize;
	sysmon_config->sysmon_rules = (uintptr_t)buffer;

	return sysmon_config;

}

PSYSMON_CONFIG_STRUCT read_reg_values(){

	LSTATUS ret_val;
	BYTE reg_options_val[4];
	DWORD reg_val_type;
	
	unsigned char *rules_buf = nullptr;
	char SubKey[0x108];
	HKEY phkResult;
	PSYSMON_CONFIG_STRUCT sysmon_config;

	DWORD reg_hash_val = 1;
	unsigned char *rules_buf_cpy = nullptr;
	memset(&SubKey, 0, sizeof(SubKey));

	_snprintf_s(SubKey, 0x104u, "System\\CurrentControlSet\\Services\\%s\\Parameters", ServiceName);
	ret_val = RegOpenKeyEx(HKEY_LOCAL_MACHINE, (LPCSTR)&SubKey, 0, 0x20019u, &phkResult);
	if ( !ret_val )
	{
		//Allocate memory for struct and initialize
		sysmon_config = (PSYSMON_CONFIG_STRUCT)malloc(sizeof(SYSMON_CONFIG_STRUCT));
		memset(sysmon_config, 0, sizeof(SYSMON_CONFIG_STRUCT));

		//printf("Current configuration:\n");
		//printf("%-34s%s\n", " - Service name:", "Sysmon");
		//printf("%-34s%s\n", " - Driver name:", ServiceName);

		//Get sysmon options
		*(DWORD *)reg_options_val = 0;
		DWORD reg_val_size = 4;
		ret_val = RegQueryValueEx(phkResult, "Options", 0, &reg_val_type, reg_options_val, &reg_val_size);
		if ( ret_val ) {
			if ( ret_val != 2 ){
				printf("Failed to open %s configuration with last error %d\n", "Options", ret_val);
				return nullptr;
			}
		} else if ( reg_val_type != 4 ){
			printf("[-] Failed to open %s configuration with incorrect type %d / %d\n", "Options", reg_val_type, 4);
			return nullptr;
		} else {
			sysmon_config->sysmon_options = (DWORD)reg_options_val;
		}

		//Get sysmon hashing algorithm
		reg_val_size = 4;
		ret_val = RegQueryValueEx(phkResult, "HashingAlgorithm", 0, &reg_val_type, (LPBYTE)&reg_hash_val, &reg_val_size);
		if ( ret_val ){
			
			if ( ret_val != 2 ){
				printf("[-] Failed to open %s configuration with last error %d\n", "HashingAlgorithm", ret_val);
				return nullptr;
			}

		} else if ( reg_val_type != 4 ) {
			printf("[-] Failed to open %s configuration with incorrect type %d / %d\n", "HashingAlgorithm", reg_val_type, 4);
			return nullptr;
		} else {
			sysmon_config->sysmon_hash = (DWORD)reg_hash_val;
		}

		char *ret_buf = resolve_hashmap(reg_hash_val);
		//printf("%-34s%s\n", " - HashingAlgorithms:", ret_buf);
		free(ret_buf);

		const char *enabled_str = "enabled";
		if ( !(reg_options_val[0] & 1) )
			enabled_str = "disabled";
		//printf("%-34s%s\n", " - Network connection:", enabled_str);

		enabled_str = "enabled";
		if ( !(reg_options_val[0] & 2) )
			enabled_str = "disabled";
		//printf("%-34s%s\n\n", " - Image loading:", enabled_str);

		ret_val = RegQueryValueEx(phkResult, "Rules", 0, &reg_val_type, 0, &reg_val_size);
		if ( !ret_val )
		{
			//Allocate memory
			rules_buf = (unsigned char *)malloc(reg_val_size);
			memset(rules_buf, 0, reg_val_size);
			if ( rules_buf )
			{
				ret_val = RegQueryValueEx(phkResult, "Rules", 0, &reg_val_type, rules_buf, &reg_val_size);
				if ( !ret_val ){
					sysmon_config->sysmon_rules = (uintptr_t)rules_buf;
					sysmon_config->sysmon_rules_size = reg_val_size;	
					return sysmon_config;
				}			
			}
	    } else {
			
			if ( ret_val == 2 )
				printf("[-] No rules installed\n");				
					
		}

	} else {

		if ( ret_val == 2 )
			printf("[-] Sysmon is not installed on this computer\n");
		else
			printf("[-] Failed to open driver configuration with last error %d\n", ret_val);
	}

	
	//Free rules buffer
	if ( rules_buf )
		free((void *)rules_buf);

	//Free sysmon struct
	if ( sysmon_config )
		free((void *)sysmon_config);	
	
	return NULL;

}
