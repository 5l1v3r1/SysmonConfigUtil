
#include <windows.h>
#include <stdio.h>
#include "rules.h"
#include "hash.h"
#include "config.h"


PRULES_STRUCT rule_struct_data;

sysmon_configuration * parse_sysmon_rules( void *rules_buf_cpy, DWORD regValue_size )
{
	PRULES_STRUCT rule_struct_ptr_cpy; // esi
	unsigned int buf_size; // edx
	char *rules_buf_ptr; // eax
	void **rule_ptr; // esi
	PRULE_STRUCT rule_func_ptr; // ebx
	const char *inc_exc_str; // eax
	unsigned char *i; // edi
	const char *rule_modifier_ptr; // eax
	const char *filter_type = 0; // eax
	unsigned int version_arr[4] = { 0, 0 }; // [esp+18h] [ebp-230h]
	PRULES_STRUCT rule_struct_ptr = 0; // [esp+2Ch] [ebp-21Ch]
	sysmon_configuration *sysmon_config_inst = nullptr;
	char version_buf[100];
	unsigned int header_len;
	
	if ( !validate_config(rules_buf_cpy, regValue_size) )
		return sysmon_config_inst;
	
	if ( get_struct_data_wrap( &rule_struct_ptr) )
	{
		if ( get_config_version( rule_struct_ptr, (unsigned int *)&version_arr) )
		{
			if ( version_arr[1] )
			{
				sysmon_config_inst = new sysmon_configuration();	
				double version;
				if ( version_arr[0] )
				{
					version =  (version_arr[0] >> 16) + ((unsigned short)version_arr[0]) * 0.01;					
					if ( version > 1.00 )
						version =  (version_arr[3] >> 16) + ((unsigned short)version_arr[3]) * 0.01;
					
				}

				//Init the map
				initialize_event_types(version);
				
				memset(version_buf, 0, 100);
				_snprintf_s(version_buf, sizeof(version_buf), "%.2f", version);
			
				//Set binary version
				sysmon_config_inst->set_binary_version(version_buf);

				rule_struct_ptr_cpy = rule_struct_ptr;
				buf_size = rule_struct_ptr_cpy->rule_buf_size;

				if ( buf_size < 8 )
					return nullptr;				

				//Get the start of the rules buffer
				rules_buf_ptr = (char *)rule_struct_ptr->rules_buf;
				header_len = get_config_header_len(rules_buf_ptr);
		
				char *config_buf_ptr = &rules_buf_ptr[header_len];
				if ( !*(DWORD *)(rules_buf_ptr + 4) || config_buf_ptr < rules_buf_ptr || config_buf_ptr >= buf_size + rules_buf_ptr)
					return nullptr;
				

				//Set to beginning of rules data
				rule_ptr = (void **)config_buf_ptr;
				do 
				{
					rule_func_ptr = event_type_map[(uint32_t)*rule_ptr];
					if ( rule_func_ptr )
					{
						//Create new sysmon event type
						sysmon_event_type *new_event_type = new sysmon_event_type( (char *)rule_func_ptr->RULE_FUNC);

						//Get inclue or exclude
						inc_exc_str = check_include_exclude(rule_ptr[1]);
						new_event_type->set_onmatch( (char *)inc_exc_str);

						//printf(" - %-34s onmatch: %s\n", rule_func_ptr->RULE_FUNC, inc_exc_str);
						for ( i = iterate_rule((unsigned char *)rule_ptr, &rule_struct_ptr, 0); i;
								i = iterate_rule((unsigned char *)rule_ptr, &rule_struct_ptr, i) )
						{
							int idx = *(DWORD *)i;
							filter_type = (const char *)( (uintptr_t *)rule_func_ptr->RULE_STR_TABLE[ idx ] );
							if ( *(DWORD *)i < (unsigned int)rule_func_ptr->EVENT_FILTER_COUNT 	&& *filter_type )
							{
								//Create a new event entry
								sysmon_event_entry *new_event_entry = new sysmon_event_entry((char *)filter_type);
								rule_modifier_ptr = get_rule_modifier(*(i + 4));
								std::wstring event_val_wstr = (wchar_t *)(i + 16);
								std::string event_val_str(event_val_wstr.begin(), event_val_wstr.end());

								//Add condition
								new_event_entry->set_condition((char *)rule_modifier_ptr);
								new_event_entry->set_value(event_val_str);

								//Add event entry to list
								new_event_type->add_event_entry(new_event_entry);								

								//printf("\t%-30s filter: %-12s value: '%s'\n", filter_type, rule_modifier_ptr, event_val_str.c_str());
							}
						}
					
						//Set the event type entry in the config map
						sysmon_config_inst->add_event_type( new_event_type );
					
					} else {					
						printf("[-] Rule not found");
					}
					
					rule_ptr = (void **)iterate_rule_type( (PRULES_STRUCT *)&rule_struct_ptr, (char *)rule_ptr);

				} while ( rule_ptr );

				return sysmon_config_inst;
			}
		}
	}
		
	return sysmon_config_inst;
}

const char *get_rule_modifier(uint32_t mod_value)
{
	const char *result;
	switch ( mod_value )
	{
		case 1u:
			result = "is not";
			break;
		case 2u:
			result = "contains";
			break;
		case 3u:
			result = "excludes";
			break;
		case 4u:
			result = "begin with";
			break;
		case 5u:
			result = "end with";
			break;
		case 6u:
			result = "less than";
			break;
		case 7u:
			result = "more than";
			break;
		case 8u:
			result = "image";
			break;
		default:
			result = "is";
			break;
	}
	return result;
}

const char *check_include_exclude(void *include_bool)
{
	if ( !include_bool )
		return "exclude";
	if ( include_bool == (void *)1 )
		return "include";
	return (const char *)"?";
}

unsigned char *iterate_rule(unsigned char *rule_ptr, PRULES_STRUCT *a2, unsigned char *a3)
{
	PRULES_STRUCT v3; // edi
	unsigned char *rule_buf_ptr; // ecx
	unsigned int rule_buf_size; // edi
	unsigned int v6; // edx
	unsigned char *v7; // esi
	unsigned int v8; // eax

	v3 = *a2;
	rule_buf_ptr = (unsigned char *)v3->rules_buf;
	if ( rule_ptr < rule_buf_ptr )
		return 0;
	rule_buf_size = v3->rule_buf_size;
	if ( rule_ptr >= rule_buf_size + rule_buf_ptr || !*(DWORD *)(rule_ptr + 12) )	
		return 0;
	if ( a3 )
	{
		if ( a3 < rule_buf_ptr || a3 >= rule_buf_size + rule_buf_ptr )
			return 0;
		v6 = *(DWORD *)(a3 + 8);	
	}
	else
	{
		v6 = rule_ptr - rule_buf_ptr + 16;
	}
	v7 = rule_buf_ptr + v6;
	if ( rule_buf_ptr + v6 < rule_buf_ptr )
		return 0;
	if ( v7 >= rule_buf_size + rule_buf_ptr )
		return 0;
	v8 = *(DWORD *)(v7 + 12);
	if ( v8 & 1 || v8 + v6 <= v6 || v8 + v6 >= rule_buf_size )
		return 0;
	if ( *(WORD *)(v7 + 2 * (v8 >> 1) + 14) )
		v7 = 0;
	return v7;
}

unsigned int iterate_rule_type( PRULES_STRUCT *rules_struct_ptr, char *cur_rule_ptr)
{
	unsigned int buf_size; 
	char *rule_buf; 
	unsigned int rule_len; 
	PRULES_STRUCT rules_struct; 
	unsigned int v7;
	unsigned int result; 

	if ( cur_rule_ptr )
	{
		rules_struct = *rules_struct_ptr;
		rule_buf = (char *)rules_struct->rules_buf;	
		if ( cur_rule_ptr < rule_buf )
			return 0;
		buf_size = rules_struct->rule_buf_size;
		if ( cur_rule_ptr >= buf_size + rule_buf )
			return 0;
		rule_len = *((DWORD *)cur_rule_ptr + 2);
		if ( !rule_len )
			return 0;
	}
	else
	{
		rules_struct = *rules_struct_ptr;
		buf_size = rules_struct->rule_buf_size;
		if ( buf_size < 8 )
			return 0;
		rule_buf = (char *)rules_struct->rules_buf;

		if ( !*((DWORD *)rule_buf + 1) )
			return 0;
		v7 = *(DWORD *)rule_buf >> 16;
		if ( v7 >= 1 && (v7 != 1 || (unsigned __int16)*rule_buf) )
		  rule_len = *((DWORD *)rule_buf + 2);
		else
		  rule_len = 8;
	}
	result = (unsigned int)(rule_buf + rule_len);
	if ( result < (unsigned int)rule_buf || result >= (unsigned int)(buf_size + rule_buf) )
		return 0;
	return result;
}

char validate_config(void *rules_buffer, int rule_size)
{
	PRULES_STRUCT rule_struct; // esi
	int rule_size_cpy; // edi
	char result; 

	rule_struct = 0;
	rule_size_cpy = rule_size;
	if ( !rules_buffer || !rule_size ){
		rule_struct_data = rule_struct;
		return 1;
	}

	rule_struct = (PRULES_STRUCT)malloc(0x14u);
	if ( !rule_struct )
	{
		//dbg_msg((int)L"RuleEngine", 0xEu, (int)L"Failed to allocate memory", v7);
		printf("RuleEngine: Failed to allocate memory");
		return 0;
	}
	rule_struct->some_num_idx_0 = 1;
	rule_struct->rules_buf = (char *)rules_buffer;
	rule_struct->rule_buf_size = rule_size_cpy;
	rule_struct->some_num_idx_12 = 0;
	rule_struct->some_num_idx_16 = 1;

	if ( !check_rules(rule_struct) )  {
		free(rule_struct);
		result = 0;
	}  else  {
		rule_struct_data = rule_struct;
		result = 1;
	}
	return result;
}

unsigned int get_config_header_len( char *rules_buf_ptr ){

	unsigned int ret_len;
	unsigned int rules_buf_val_0 = *(unsigned int *)rules_buf_ptr;	
	unsigned short rules_buf_val_HL_1 = rules_buf_val_0 >> 16;

	if ( rules_buf_val_HL_1 >= 1 && (rules_buf_val_HL_1 != 1 || (unsigned short)rules_buf_val_0) )
		ret_len = *((DWORD *)rules_buf_ptr + 2);
	else
		ret_len = 8;

	return ret_len;

}


char check_rules(PRULES_STRUCT rules_struct_ptr)
{

	PRULES_STRUCT rule_struct_orig;
	int loop_counter; 
	unsigned int rule_buf_size; 
	char *rule_buf_cpy; 
	unsigned int rules_buf_val_0; 
	unsigned int header_len;
	double v7; 
	char result; 
	char *config_buf_ptr; 
	int some_counter; 
	int v11; 
	unsigned int event_type_count; // esi
	uint32_t *new_buf; // eax
	uint32_t *new_buf_cpy3; // ecx
	PRULES_STRUCT rule_struct_cpy2; // edi
	unsigned int rule_buf_size_cpy; // esi
	char * rules_buf_cpy2; // edx
	char *config_buf_ptr2; // ebx
	signed int event_type; // eax
	unsigned int v28; 
	unsigned int v31; // eax
	uint32_t *buf_ptr; 
	unsigned int rules_buf_size4; // esi

	unsigned int v46; 
	unsigned int v47; 
	PRULES_STRUCT rule_struct_cpy3; 
	char *rules_buf_cpy3; 
	unsigned int v58; 

	unsigned int v60;
	const char *err_str; 
	unsigned int v65; 
	unsigned int v66; 
	uint32_t *new_buf_cpy; 
	PRULES_STRUCT rule_struct_cpy5; 

	rule_struct_orig = rules_struct_ptr;
	loop_counter = 0;
	rule_struct_cpy3 = rules_struct_ptr;
	rule_struct_cpy5 = rules_struct_ptr;

	rule_buf_size = rules_struct_ptr->rule_buf_size;
	rule_buf_cpy = (char *)rules_struct_ptr->rules_buf;

	if ( !rules_struct_ptr || ( rule_buf_size < 8) || ( rules_buf_val_0 = *(unsigned int *)rule_buf_cpy, !*((DWORD *)rule_buf_cpy + 1)) )
	{
		err_str = "Invalid configuration";
		LABEL_127:
		printf("Invalid configuration");
		//dbg_msg((int)L"RuleEngine", 0xDu, (int)v63, v64);
		return 0;
	}
	if ( rules_buf_val_0 >> 16 != 1 )
	{
		v7 = (rules_buf_val_0 >> 16) + ((unsigned short)rules_buf_val_0) * 0.01;					
		//v7 = ((double)(unsigned __int16)rules_buf_val_0 + 0.0) * 0.01 + (double)(rules_buf_val_0 >> 16) + version_stuff[rules_buf_val_0 >> 47];
		printf("Registry rule version %.2f is incompatible with Sysmon rule version %.2f. Please rebuild your manifest.",rules_buf_val_0, v7);
		return 0;
	}
	if ( *((DWORD *)rule_buf_cpy + 1) )
	{

		header_len = get_config_header_len(rule_buf_cpy);
		config_buf_ptr = &rule_buf_cpy[header_len];

		if ( config_buf_ptr >= rule_buf_cpy && config_buf_ptr < &rule_buf_cpy[rule_buf_size] && config_buf_ptr )//rule_buf_cpy != (unsigned int *)-8 )
		{
			while ( config_buf_ptr )
			{
				some_counter = *(DWORD *)config_buf_ptr;
				if ( some_counter == 255 )
				{
					some_counter = 0;
				}
				else if ( some_counter < 0 )
				{
					goto LABEL_17;
				}
				if ( loop_counter < some_counter )
					loop_counter = some_counter;
				v11 = *((DWORD *)config_buf_ptr + 1);
				if ( v11 && v11 != 1 )
				{
					err_str = "Invalid data in rules";
					goto LABEL_127;
				}
LABEL_17:
				config_buf_ptr = (char *)iterate_rule_type( (PRULES_STRUCT *)&rule_struct_cpy5, (char *)config_buf_ptr);
			}
		}
	}
	event_type_count = loop_counter + 1;
	if ( event_type_count > 0xFFFF || (new_buf = (unsigned int *)malloc(16 * event_type_count + 4), (new_buf_cpy = new_buf) == 0) )
	{
		printf("RuleEngine: Failed to allocate memory");
		return 0;
	}
	
	//Create temp bufer
	memset(new_buf, 0, 16 * event_type_count + 4);
	new_buf_cpy3 = new_buf_cpy;
	rule_struct_cpy2 = rule_struct_orig;
	*new_buf_cpy = event_type_count;
	rule_buf_size_cpy = rule_struct_orig->rule_buf_size;

	//Get start of config in buffer
	header_len = get_config_header_len(rule_buf_cpy);
	config_buf_ptr2 = &rule_buf_cpy[header_len];

	if ( rule_buf_size_cpy >= 8
		&& (rules_buf_cpy2 = rule_struct_orig->rules_buf, *(DWORD *)(rules_buf_cpy2 + 4))
		&& ( v65 = (unsigned int)config_buf_ptr2, config_buf_ptr2 >= rules_buf_cpy2)
		&& config_buf_ptr2 < rule_buf_size_cpy + rules_buf_cpy2
	){

		while ( 1 )
		{
		  event_type = *(DWORD *)config_buf_ptr2;
		  if ( event_type == 255 )
			break;
		  if ( event_type >= 0 )
			goto LABEL_42;
	LABEL_119:
		  rule_buf_cpy = (char *)rule_struct_cpy2->rules_buf;
		  if ( (char *)config_buf_ptr2 >= rule_buf_cpy )
		  {
			rule_buf_size = rule_struct_cpy2->rule_buf_size;
			if ( (char *)config_buf_ptr2 < &rule_buf_cpy[rule_buf_size] )
			{
			  v66 = *((DWORD *)config_buf_ptr2 + 2);
			  if ( v66 )
			  {
				config_buf_ptr2 = &rule_buf_cpy[v66];
				if ( &rule_buf_cpy[v66] >= rule_buf_cpy && config_buf_ptr2 < &rule_buf_cpy[rule_buf_size] && config_buf_ptr2 )
				  continue;
			  }
			}
		  }
		  goto LABEL_117;
		}
		event_type = 0;

LABEL_42:

		uint32_t event_type_offset = 4 * event_type + *((DWORD *)config_buf_ptr2 + 1);
		uint32_t *new_buf3_cpy = (uint32_t *)(4 * event_type);

		if ( *((DWORD *)new_buf_cpy3 + event_type_offset + 1) ){
		
			printf("RuleEngine: Multiple rule filters of the same type");
		
		} else {

		  uint32_t *v30;
		  v28 = 0;
		  uint32_t v78 = 0;
		  if ( config_buf_ptr2 >= rule_buf_cpy
			&& config_buf_ptr2 < &rule_buf_cpy[rule_buf_size]
			&& *((DWORD *)config_buf_ptr2 + 3) )
		  {
			uint32_t v29 = config_buf_ptr2 - rule_buf_cpy + 16;
			v30 = (uint32_t *)(config_buf_ptr2 + 16);
			if ( config_buf_ptr2 + 16 < rule_buf_cpy
			  || v30 >= (unsigned int *)&rule_buf_cpy[rule_struct_cpy2->rule_buf_size]
			  || (v31 = *((DWORD *)config_buf_ptr2 + 7), v31 & 1)
			  || v29 + v31 <= v29
			  || v29 + v31 >= rule_struct_cpy2->rule_buf_size
			  || *((WORD *)v30 + (v31 >> 1) + 7) )
			{
	LABEL_64:
			  v28 = v78;
			}
			else
			{

			  while ( 1 )
			  {
				v28 = v78;
				char *rules_buf_cpy = rule_struct_cpy2->rules_buf;
				if ( *v30 > v78 )
				  v28 = *v30;
				v78 = v28;
				if ( config_buf_ptr2 < rules_buf_cpy
				  || config_buf_ptr2 >= rules_buf_cpy + rule_struct_cpy2->rule_buf_size
				  || (unsigned int)v30 < (uint32_t)rules_buf_cpy
				  || (unsigned int)v30 >= (uint32_t)rules_buf_cpy + rule_struct_cpy2->rule_buf_size )
				{
				  break;
				}

				uint32_t some_num8 = v30[2];
				rules_buf_cpy2 = rule_struct_cpy2->rules_buf;
				v30 = (unsigned int *)(some_num8 + rule_struct_cpy2->rules_buf);
				if ( (unsigned int)v30 >= (uint32_t)rules_buf_cpy2
				  && (unsigned int)v30 < (uint32_t)rules_buf_cpy2 + rule_struct_cpy2->rule_buf_size )
				{
				  uint32_t some_val = v30[3];
				  if ( !(some_val & 1)
					&& some_num8 + some_val > some_num8
					&& some_num8 + some_val < rule_struct_cpy2->rule_buf_size
					&& !*((WORD *)v30 + (some_val >> 1) + 7) )
				  {
					continue;
				  }
				}
				goto LABEL_64;
			  }
			}
		  }
		  if ( v28 + 1 <= 0xFFFF )
		  {
			uint32_t new_buf_size = 16 * (v28 + 1) + 4;
			new_buf = (unsigned int *)malloc(new_buf_size);
			new_buf_cpy = new_buf;
			if ( new_buf )
			{
			  memset(new_buf, 0, new_buf_size);
			  uint32_t *new_buf_cpy2 = (uint32_t *)new_buf_cpy;
			  buf_ptr = new_buf_cpy3;
			  *new_buf_cpy = v78 + 1;
			  buf_ptr[(DWORD)new_buf3_cpy + *((DWORD *)config_buf_ptr2 + 1) + 1] = (uint32_t)new_buf_cpy2;
			  buf_ptr[(DWORD)new_buf3_cpy + *((DWORD *)config_buf_ptr2 + 1) + 3] = (uint32_t)config_buf_ptr2;
			  uint32_t v40 = (uint32_t)rule_struct_cpy2->rules_buf;
			  if ( (unsigned int)config_buf_ptr2 >= v40
				&& (unsigned int)config_buf_ptr2 < v40 + rule_struct_cpy2->rule_buf_size )
			  {
				if ( *((DWORD *)config_buf_ptr2 + 3) )
				{
				  uint32_t buf_addr2 = (unsigned int)&config_buf_ptr2[-v40 + 16];
				  uint32_t *some_addr4 = (uint32_t *)(config_buf_ptr2 + 16);
				  if ( (unsigned int)(config_buf_ptr2 + 16) >= v40
					&& (unsigned int)some_addr4 < v40 + rule_struct_cpy2->rule_buf_size )
				  {
					uint32_t some_num2 = *((DWORD *)config_buf_ptr2 + 7);
					if ( !(some_num2 & 1)
					  && some_num2 + buf_addr2 > buf_addr2
					  && some_num2 + buf_addr2 < rule_struct_cpy2->rule_buf_size
					  && !*((WORD *)some_addr4 + (some_num2 >> 1) + 7) )
					{
					  while ( 1 )
					  {
						++new_buf_cpy[4 * *some_addr4 + 3];
						rules_buf_cpy3 = rule_struct_cpy2->rules_buf;
						if ( config_buf_ptr2 < rules_buf_cpy3 )
						  break;
						uint32_t rules_buf_size3 = rule_struct_cpy2->rule_buf_size;
						if ( config_buf_ptr2 >= rules_buf_size3 + rules_buf_cpy3 )
						  break;
						if ( !*((DWORD *)config_buf_ptr2 + 3) )
						  break;
						if ( (uint32_t)some_addr4 < (uint32_t)rules_buf_cpy3 )
						  break;
						if ( (uint32_t)some_addr4 >= (uint32_t)(rules_buf_size3 + rules_buf_cpy3) )
						  break;
						v46 = some_addr4[2];
						some_addr4 = (uint32_t *)(rules_buf_cpy3 + v46);
						if ( rules_buf_cpy3 + v46 < rules_buf_cpy3 )
						  break;
						if ( (unsigned int)some_addr4 >= (uint32_t)(rules_buf_size3 + rules_buf_cpy3 ))
						  break;
						v47 = some_addr4[3];
						if ( v47 & 1 || v46 + v47 <= v46 || v46 + v47 >= rules_buf_size3 || *((WORD *)some_addr4 + (v47 >> 1) + 7) )
						  break;
						rule_struct_cpy2 = rule_struct_cpy3;
					  }
					}
				  }
				}
			  }
			  
			  uint32_t some_num4 = v78;
			  size_t some_addr = (size_t)(new_buf_cpy + 3);
			  new_buf_cpy = (uint32_t *)some_addr;
			  size_t some_addr_cpy = some_addr;
			  uint32_t some_num5 = 0;
			  uint32_t counter = 0;
			  while ( 1 )
			  {
				uint32_t some_size  = *(uint32_t *)some_addr_cpy;
				if ( some_size )
				{
				  uint32_t * new_buf3;
				  if ( some_size > 0xFFFF  || (new_buf3 = (uint32_t *)malloc(16 * some_size + 4), (new_buf3_cpy = new_buf3) == 0) )
				  {
					*new_buf_cpy = 0;
					break;
				  }
				  memset(new_buf3, 0, 16 * some_size + 4);
				  uint32_t *new_buf3_cpy2 = new_buf3_cpy;
				  uint32_t *new_buf_cpy7 = new_buf_cpy;
				  *new_buf3_cpy = some_size;
				  rule_struct_cpy2 = rule_struct_cpy3;
				  *new_buf_cpy7 = 0;
				  *(new_buf_cpy7 - 2) = (unsigned int)new_buf3_cpy2;

				  uint32_t rules_buf_cpy5 = (uint32_t)rule_struct_cpy2->rules_buf;
				  if ( (unsigned int)config_buf_ptr2 >= rules_buf_cpy5 )
				  {
					rules_buf_size4 = rule_struct_cpy2->rule_buf_size;
					uint32_t *some_num7;

					if ( (unsigned int)config_buf_ptr2 >= rules_buf_size4 + rules_buf_cpy5
					  || !*((DWORD *)config_buf_ptr2 + 3)
					  || (v58 = (unsigned int)&config_buf_ptr2[-rules_buf_cpy5 + 16],
						  some_num7 = (uint32_t *)(config_buf_ptr2 + 16),
						  (unsigned int)(config_buf_ptr2 + 16) < rules_buf_cpy5)
					  || (unsigned int)some_num7 >= rules_buf_size4 + rules_buf_cpy5
					  || (v60 = *((DWORD *)config_buf_ptr2 + 7), v60 & 1)
					  || v60 + v58 <= v58
					  || v60 + v58 >= rules_buf_size4
					  || *((WORD *)some_num7 + (v60 >> 1) + 7) )
					{
	LABEL_116:
					  rule_struct_cpy2 = rule_struct_cpy3;
					}
					else
					{
					  uint32_t *some_addr3 = new_buf3_cpy + 3;
					  for ( new_buf3_cpy += 3; ; some_addr3 = new_buf3_cpy )
					  {
						if ( *some_num7 == some_num5 )
						{
						  *some_addr3 = (unsigned int)some_num7;
						  new_buf3_cpy = some_addr3 + 4;
						}
						rule_struct_cpy2 = rule_struct_cpy3;
						char *rules_buf_cpy6 = rule_struct_cpy3->rules_buf;
						if ( config_buf_ptr2 < rules_buf_cpy6 )
						  break;

						uint32_t rules_buf_size5 = rule_struct_cpy3->rule_buf_size;
						if ( config_buf_ptr2 >= rules_buf_size5 + rules_buf_cpy6
						  || !*((DWORD *)config_buf_ptr2 + 3)
						  || (size_t)some_num7 < (size_t)rules_buf_cpy6
						  || (size_t)some_num7 >= (size_t)(rules_buf_size5 + rules_buf_cpy6) )
						{
						  break;
						}

						uint32_t some_val = some_num7[2];
						some_num7 = (uint32_t *)(rules_buf_cpy6 + some_val);
						if ( rules_buf_cpy6 + some_val < rules_buf_cpy6 )
						  goto LABEL_116;
						if ( (unsigned int)some_num7 >= (uint32_t)(rules_buf_size5 + rules_buf_cpy6 ))
						  goto LABEL_116;
						v65 = some_num7[3];
						if ( v65 & 1 || some_val + v65 <= some_val || some_val + v65 >= rules_buf_size5 || *((WORD *)some_num7 + (v65 >> 1) + 7) )
						  goto LABEL_116;
					  }
					}
				  }
				  some_num4 = v78;
				  some_addr_cpy = (size_t)new_buf_cpy;
				  counter = some_num5;
				}
				else
				{
				  rule_struct_cpy2 = rule_struct_cpy3;
				}
				++counter;
				some_addr_cpy += 4;
				some_num5 = counter;
				new_buf_cpy = (uint32_t *)some_addr_cpy;
				if ( counter > some_num4 )
				  goto LABEL_119;
			  }
			}
		  }

		  printf("RuleEngine: Failed to allocate memory");

		}

		//Free structures
		uint32_t * event_type_buf_cpy2 = (uint32_t *)new_buf_cpy3;
		uint32_t mem_free_counter = 0;
		if ( *(DWORD *)new_buf_cpy3 )
		{
			uint32_t **some_buf_ptr = (unsigned int **)((char *)new_buf_cpy3 + 8);
			do
			{
				recursive_count(*(some_buf_ptr - 1));
				recursive_count(*some_buf_ptr);
				++mem_free_counter;
				some_buf_ptr += 4;
			}
			while ( mem_free_counter < *event_type_buf_cpy2 );
		}
		free(event_type_buf_cpy2);
		result = 0;
		
	} else {

	LABEL_117:
		rules_struct_ptr->some_num_idx_12 = (unsigned int )new_buf_cpy3;
		result = 1;
	}
	return result;
}

void recursive_count(unsigned int *ptr)
{
	unsigned int *ptr_cpy; 
	unsigned int counter; 
	unsigned int **v3; 

	ptr_cpy = ptr;
	if ( ptr )
	{
		counter = 0;
		if ( *ptr )
		{
			v3 = (unsigned int **)(ptr + 1);
			do
			{
				recursive_count(*v3);
				++counter;
				v3 += 2;
			}
			while ( counter < *ptr_cpy );
		}
		free(ptr_cpy);
	}
}


boolean get_struct_data_wrap(PRULES_STRUCT *stack_ptr)
{
	PRULES_STRUCT *stack_ptr_cpy; 
	PRULES_STRUCT ret_ptr; 

	stack_ptr_cpy = stack_ptr;
	*stack_ptr = 0;
	ret_ptr = get_struct_data();
	if ( !ret_ptr )
		 return 0;
	*stack_ptr_cpy = ret_ptr;
	return 1;

}

boolean get_config_version( PRULES_STRUCT stack_ptr1, unsigned int *stack_ptr2 ) {

	unsigned int *stack_ptr2_cpy = 0; // ebx
	PRULES_STRUCT ret_ptr; // esi
	unsigned int *ret_ptr_cpy; // ecx
	unsigned int schema_version;
	size_t copy_len;

	stack_ptr2_cpy = stack_ptr2;
	if ( stack_ptr1 )
		ret_ptr = stack_ptr1;
	else
		ret_ptr = get_struct_data();

	if ( !ret_ptr )
		return 0;

	ret_ptr_cpy = (unsigned int *)ret_ptr->rules_buf;
	stack_ptr2_cpy[0] = ret_ptr_cpy[0];
	stack_ptr2_cpy[1] = ret_ptr_cpy[1];
	stack_ptr2_cpy[2] = ret_ptr_cpy[2];

	schema_version = stack_ptr2_cpy[0] >> 16;
	if ( schema_version >= 1 && (schema_version != 1 || stack_ptr2_cpy[0] && ret_ptr->rule_buf_size >= 0xC ))
	{
		copy_len = stack_ptr2_cpy[2];
		if ( copy_len > 0x10 )
			copy_len = 0x10;
		if ( ret_ptr->rule_buf_size >= copy_len )
			memmove(stack_ptr2_cpy, ret_ptr_cpy, copy_len);
	}

	return 1;
}

PRULES_STRUCT get_struct_data() {

	PRULES_STRUCT ret_ptr;

	ret_ptr = 0;
	if ( rule_struct_data ){
		ret_ptr = rule_struct_data;
	}
 
	return ret_ptr;
}

char *resolve_hashmap(unsigned int hash_reg_val)
{
	unsigned int hash_reg_val_cpy; // edx
	unsigned int v2; // ecx
	rsize_t strlen_2; // edi
	unsigned int v4; // ebx
	signed int v5; // esi
	char *ret_str; // eax
	unsigned int str_len; // kr00_4
	char *new_buf; // eax
	char *new_buf_cpy; // edi
	unsigned int index; // esi
	unsigned int v12; // esi
	char *result; // eax
	const char *cur_hash; // eax
	unsigned int hash_reg_val_cpy2; 
	rsize_t SizeInWords; 
	rsize_t SizeInWordsa; 
	char *Src[5]; 

	hash_reg_val_cpy = hash_reg_val;
	hash_reg_val_cpy2 = hash_reg_val;
	if ( (hash_reg_val & 0x80000000) == 0 )
	{
		if ( hash_reg_val >= 5 || (cur_hash = (char *)hashmap[hash_reg_val].hash_name) == 0 )
			cur_hash = (const char *)"?";
		result = _strdup(cur_hash);
	}
	else
	{
		v2 = 1;
		strlen_2 = 0;
		v4 = 0;
		SizeInWords = 1;
		v5 = 2;
		do
		{
			if ( __ROR__(v5, 1) & hash_reg_val_cpy )		
			{
				ret_str = resolve_hashmap(v2);
				str_len = strlen(ret_str);
				hash_reg_val_cpy = hash_reg_val_cpy2;
				Src[v4] = (char *)ret_str;
				strlen_2 += str_len + 1;
				v2 = SizeInWords;
				++v4;
			}
			++v2;
			v5 = __ROL__(v5, 1);
			SizeInWords = v2;
		}
		while ( v2 < 5 );

		SizeInWordsa = strlen_2;
		new_buf = (char *)malloc( strlen_2 );
		new_buf_cpy = new_buf;
		if ( new_buf )
		{
			memset(new_buf, 0, strlen_2);
			index = 0;
			if ( v4 )
			{
				while ( (!index || !strncat_s(new_buf_cpy, strlen_2, ",", SizeInWordsa)) && 
					!strncat_s(new_buf_cpy, strlen_2, Src[index], SizeInWordsa ) )
				{
					if ( ++index >= v4 )
						goto LABEL_14;
				}
				*new_buf_cpy = 0;
			}
		}
		LABEL_14:
		v12 = 0;
		if ( v4 )
		{
			do
				free(Src[v12++]);
			while ( v12 < v4 );
		}
		result = new_buf_cpy;
	}
	return result;
}


void initialize_event_types( double version ){

	if( version > 2.0 ){

		//Update event filter string tables and counts
		error_rule_struct.RULE_STR_TABLE = (uintptr_t *)&ERROR_STR_TABLE_3;
		error_rule_struct.EVENT_FILTER_COUNT = 3;

		create_process_rule_struct.RULE_STR_TABLE = (uintptr_t *)&CREATE_PROC_STR_TABLE_3;
		create_process_rule_struct.EVENT_FILTER_COUNT = 0x10;

		file_time_rule_struct.RULE_STR_TABLE = (uintptr_t *)&FILE_CREATE_STR_TABLE_3;
		file_time_rule_struct.EVENT_FILTER_COUNT = 7;
		
		network_connect_rule_struct.RULE_STR_TABLE = (uintptr_t *)&NETWORK_CONNECT_STR_TABLE_3;
		network_connect_rule_struct.EVENT_FILTER_COUNT = 0x11;

		service_state_rule_struct.RULE_STR_TABLE = (uintptr_t *)&SERVICE_STATE_STR_TABLE_3;
		service_state_rule_struct.EVENT_FILTER_COUNT = 4;

		process_term_rule_struct.RULE_STR_TABLE = (uintptr_t *)&PROC_TERM_STR_TABLE_3;
		process_term_rule_struct.EVENT_FILTER_COUNT = 4;

		driver_loaded_rule_struct.RULE_STR_TABLE = (uintptr_t *)&DRV_LOADED_STR_TABLE_3;
		driver_loaded_rule_struct.EVENT_FILTER_COUNT = 6;

		image_loaded_rule_struct.RULE_STR_TABLE = (uintptr_t *)&IMG_LOADED_STR_TABLE_3;
		image_loaded_rule_struct.EVENT_FILTER_COUNT = 9;

		create_remote_thread_rule_struct.RULE_STR_TABLE = (uintptr_t *)&CREATE_REMOTE_THREAD_STR_TABLE_3;
		create_remote_thread_rule_struct.EVENT_FILTER_COUNT = 0xb;

		if( version >= 4.0 ){
			create_process_rule_struct.RULE_STR_TABLE = (uintptr_t *)&CREATE_PROC_STR_TABLE_4;
			create_process_rule_struct.EVENT_FILTER_COUNT = 0x14;

			image_loaded_rule_struct.RULE_STR_TABLE = (uintptr_t *)&IMG_LOADED_STR_TABLE_4;
			image_loaded_rule_struct.EVENT_FILTER_COUNT = 0xd;
		}

	} 

	event_type_map[ error_rule_struct.RULE_ID_NUM ] = (PRULE_STRUCT)&error_rule_struct;
	event_type_map[ create_process_rule_struct.RULE_ID_NUM ] = (PRULE_STRUCT)&create_process_rule_struct;
	event_type_map[ file_time_rule_struct.RULE_ID_NUM ] = (PRULE_STRUCT)&file_time_rule_struct;
	event_type_map[ network_connect_rule_struct.RULE_ID_NUM ] = (PRULE_STRUCT)&network_connect_rule_struct;
	event_type_map[ service_state_rule_struct.RULE_ID_NUM ] = (PRULE_STRUCT)&service_state_rule_struct;
	event_type_map[ process_term_rule_struct.RULE_ID_NUM ] = (PRULE_STRUCT)&process_term_rule_struct;
	event_type_map[ driver_loaded_rule_struct.RULE_ID_NUM ] = (PRULE_STRUCT)&driver_loaded_rule_struct;
	event_type_map[ image_loaded_rule_struct.RULE_ID_NUM ] = (PRULE_STRUCT)&image_loaded_rule_struct;
	event_type_map[ create_remote_thread_rule_struct.RULE_ID_NUM ] = (PRULE_STRUCT)&create_remote_thread_rule_struct;

	//Added in schema 3.0
	event_type_map[ raw_access_rule_struct.RULE_ID_NUM ] = (PRULE_STRUCT)&raw_access_rule_struct;
	event_type_map[ proc_accessed_rule_struct.RULE_ID_NUM ] = (PRULE_STRUCT)&proc_accessed_rule_struct;
	event_type_map[ file_created_rule_struct.RULE_ID_NUM ] = (PRULE_STRUCT)&file_created_rule_struct;
	event_type_map[ reg_new_del_rule_struct.RULE_ID_NUM ] = (PRULE_STRUCT)&reg_new_del_rule_struct;
	event_type_map[ reg_modified_rule_struct.RULE_ID_NUM ] = (PRULE_STRUCT)&reg_modified_rule_struct;
	event_type_map[ reg_renamed_rule_struct.RULE_ID_NUM ] = (PRULE_STRUCT)&reg_renamed_rule_struct;
	event_type_map[ file_hash_rule_struct.RULE_ID_NUM ] = (PRULE_STRUCT)&file_hash_rule_struct;
	event_type_map[ sysmon_cfg_state_rule_struct.RULE_ID_NUM ] = (PRULE_STRUCT)&sysmon_cfg_state_rule_struct;
	event_type_map[ pipe_create_rule_struct.RULE_ID_NUM ] = (PRULE_STRUCT)&pipe_create_rule_struct;
	event_type_map[ pipe_connected_rule_struct.RULE_ID_NUM ] = (PRULE_STRUCT)&pipe_connected_rule_struct;

	//Added in schema 4.0
	event_type_map[ wmi_event_rule_struct.RULE_ID_NUM ] = (PRULE_STRUCT)&wmi_event_rule_struct;
	event_type_map[ wmi_event_consumer_rule_struct.RULE_ID_NUM ] = (PRULE_STRUCT)&wmi_event_consumer_rule_struct;
	event_type_map[ wmi_event_consumer_filter_rule_struct.RULE_ID_NUM ] = (PRULE_STRUCT)&wmi_event_consumer_filter_rule_struct;



}