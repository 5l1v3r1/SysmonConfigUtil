#ifndef _MAINHDR_
#define _MAINHDR_

#include <cstdint>
#include "rules.h"

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



void parse_sysmon_rules();
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