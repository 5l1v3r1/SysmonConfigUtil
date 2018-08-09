
#include <windows.h>
#include <stdio.h>
#include "rules.h"
#include "hash.h"


PRULES_STRUCT rule_struct_data;

void parse_sysmon_rules( void *rules_buf_cpy, DWORD regValue_size )
{
	PRULES_STRUCT rule_struct_ptr_cpy; // esi
	unsigned int buf_size; // edx
	unsigned int rules_buf_ptr; // eax
	void **rule_ptr; // esi
	PRULE_STRUCT rule_func_ptr; // ebx
	const wchar_t *inc_exc_str; // eax
	unsigned char *i; // edi
	const wchar_t *rule_modifier_ptr; // eax
	const wchar_t *filter_type = 0; // eax
	unsigned int rule_struct_arr[2] = { 0, 0 }; // [esp+18h] [ebp-230h]
	PRULES_STRUCT rule_struct_ptr = 0; // [esp+2Ch] [ebp-21Ch]

	if ( !ruleEngine(rules_buf_cpy, regValue_size) )
	{
		if ( rules_buf_cpy )
			free((void *)rules_buf_cpy);
		return;
	}

	if ( get_struct_data_wrap( &rule_struct_ptr) )
	{

		if ( get_struct_data_wrap2( rule_struct_ptr, (unsigned int *)&rule_struct_arr) )
		{
			if ( rule_struct_arr[1] )
			{
				wprintf( L"Rule configuration (version %.2f):\n",
					((double)(unsigned __int16)rule_struct_arr[0] + 0.0) * 0.01 + (double)(rule_struct_arr[0] >> 16) + version_stuff[rule_struct_arr[0] >> 47]);
				rule_struct_ptr_cpy = rule_struct_ptr;
				buf_size = rule_struct_ptr_cpy->rule_buf_size;

				if ( buf_size < 8 ){
					if ( rules_buf_cpy )
						free((void *)rules_buf_cpy);
					return;
				}
				rules_buf_ptr = rule_struct_ptr->rules_buf;

				if ( !*(DWORD *)(rules_buf_ptr + 4) || rules_buf_ptr + 8 < rules_buf_ptr || rules_buf_ptr + 8 >= buf_size + rules_buf_ptr || rules_buf_ptr == -8 ){
					if ( rules_buf_cpy )
						free((void *)rules_buf_cpy);
					return;
				}
				rule_ptr = (void **)(rules_buf_ptr + 8);
				do 
				{
					rule_func_ptr = get_rule_func((uint32_t)*rule_ptr);
					if ( rule_func_ptr )
					{
						inc_exc_str = check_include_exclude(rule_ptr[1]);
						wprintf(L" - %-34s onmatch: %s\n", rule_func_ptr->RULE_FUNC, inc_exc_str);
						for ( i = iterate_rule((unsigned char *)rule_ptr, &rule_struct_ptr, 0);
								i;
								i = iterate_rule((unsigned char *)rule_ptr, &rule_struct_ptr, i) )
						{
							int idx = *(DWORD *)i;
							filter_type = (const wchar_t *)( (uintptr_t *)rule_func_ptr->RULE_STR_TABLE[ idx ] );
							if ( *(DWORD *)i < (unsigned int)rule_func_ptr->some_int_0 	&& *filter_type )
							{
								rule_modifier_ptr = get_rule_modifier(*(i + 4));
								wprintf(L"\t%-30s filter: %-12s value: '%s'\n", filter_type, rule_modifier_ptr, i + 16);
							}
						}
					}
					rule_ptr = (void **)iterate_rule_type( (PRULES_STRUCT *)&rule_struct_ptr, (unsigned int*)rule_ptr);

				} while ( rule_ptr );

				return;
			}
		}
	}
		
}

const wchar_t *get_rule_modifier(uint32_t mod_value)
{
	const wchar_t *result;
	switch ( mod_value )
	{
		case 1u:
			result = L"is not";
			break;
		case 2u:
			result = L"contains";
			break;
		case 3u:
			result = L"excludes";
			break;
		case 4u:
			result = L"begin with";
			break;
		case 5u:
			result = L"end with";
			break;
		case 6u:
			result = L"less than";
			break;
		case 7u:
			result = L"more than";
			break;
		case 8u:
			result = L"image";
			break;
		default:
			result = L"is";
			break;
	}
	return result;
}

const wchar_t *check_include_exclude(void *include_bool)
{
	if ( !include_bool )
		return L"exclude";
	if ( include_bool == (void *)1 )
		return L"include";
	return (const wchar_t *)"?";
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

unsigned int iterate_rule_type( PRULES_STRUCT *a1, unsigned int *a2)
{
	PRULES_STRUCT v2; // ecx
	unsigned int v3; // esi
	unsigned int v4; // ecx
	unsigned int v5; // eax
	PRULES_STRUCT v6; // esi
	unsigned int result; // eax

	if ( a2 )
	{
		v6 = *a1;
		v4 = v6->rules_buf;	
		if ( (unsigned int)a2 < v4 )
			return 0;
		v3 = v6->rule_buf_size;
		if ( (unsigned int)a2 >= v3 + v4 )
			return 0;
		v5 = *(DWORD *)(a2 + 2);
		if ( !v5 )
			return 0;
	}
	else
	{
		v2 = *a1;
		v3 = v2->rule_buf_size;
		if ( v3 < 8 )
			return 0;
		v4 = v2->rules_buf;
		if ( !*(DWORD *)(v4 + 1) )
			return 0;
		v5 = 8;
	}
	result = v4 + v5;
	if ( result < v4 || result >= v3 + v4 )
		return 0;
	return result;
}

char ruleEngine(void *rules_buffer, int rule_size)
{
	void *rules_buf_cpy; // ebx
	PRULES_STRUCT rule_struct; // esi
	int rule_size_cpy; // edi
	char result; 

	rules_buf_cpy = rules_buffer;
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
		wprintf(L"RuleEngine: Failed to allocate memory");
		return 0;
	}
	rule_struct->some_num_idx_0 = 1;
	rule_struct->rules_buf = (uintptr_t)rules_buf_cpy;
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


char check_rules(PRULES_STRUCT v1)
{

	PRULES_STRUCT rule_struct_orig; // ebx
	int v3; // esi
	unsigned int v4; // edx
	unsigned int *v5; // eax
	unsigned int v6; // edi
	double v7; // ST0C_8
	char result; // al
	int *v9; // ecx
	int v10; // eax
	int v11; // eax
	unsigned int v12; // edx
	int v13; // edi
	int v14; // eax
	unsigned int v15; // esi
	unsigned int **v16; // eax
	unsigned int **v17; // ecx
	PRULES_STRUCT rule_struct_cpy2; // edi
	unsigned int v19; // esi
	unsigned int v20; // edx
	unsigned int *v21; // ebx
	signed int v22; // eax
	unsigned int v23; // edi
	unsigned int *v24; // ecx
	unsigned int v25; // eax
	PRULES_STRUCT rule_struct_cpy4; // edi
	unsigned int v27; // edx
	unsigned int v28; // esi
	unsigned int v29; // esi
	unsigned int v30; // edi
	unsigned int v31; // eax
	unsigned int v32; // edi
	int v33; // esi
	int *v34; // eax
	unsigned int v35; // edx
	unsigned int v36; // edi
	unsigned int v37; // esi
	DWORD *v38; // ecx
	unsigned int v39; // eax
	unsigned int v40; // edx
	unsigned int v41; // esi
	unsigned int v42; // edi
	unsigned int v43; // eax
	unsigned int v44; // ecx
	unsigned int *v45; // esi
	unsigned int v46; // eax
	unsigned int v47; // esi
	DWORD *v48; // edi
	unsigned int v49; // edx
	unsigned int v50; // esi
	DWORD *v51; // ecx
	unsigned int v52; // eax
	unsigned int v53; // edx
	PRULES_STRUCT rule_struct_cpy3; // esi
	DWORD **v55; // eax
	unsigned int v56; // edx
	unsigned int v57; // esi
	unsigned int v58; // edi
	unsigned int v59; // eax
	unsigned int v60; // eax
	unsigned int v61; // esi
	unsigned int **v62; // edi
	const wchar_t *v63; // [esp+14h] [ebp-30h]
	unsigned int v65; // [esp+28h] [ebp-1Ch]
	unsigned int v66; // [esp+2Ch] [ebp-18h]
	int v67; // [esp+2Ch] [ebp-18h]
	unsigned int **v68; // [esp+30h] [ebp-14h]
	int *v69; // [esp+34h] [ebp-10h]
	DWORD **v70; // [esp+34h] [ebp-10h]
	PRULES_STRUCT rule_struct_cpy; // [esp+38h] [ebp-Ch]
	unsigned int v72; // [esp+3Ch] [ebp-8h]
	unsigned int v73; // [esp+3Ch] [ebp-8h]
	unsigned int v74; // [esp+40h] [ebp-4h]

	rule_struct_orig = v1;
	v3 = 0;
	rule_struct_cpy = v1;
	v4 = v1->rule_buf_size;
	v5 = (unsigned int *)v1->rules_buf;

	if ( !v1 || ( v4 < 8) || ( v6 = *(unsigned int *)v5, !v5[1]) )
	{
		v63 = L"Invalid configuration";
		LABEL_127:
		wprintf(L"Invalid configuration");
		//dbg_msg((int)L"RuleEngine", 0xDu, (int)v63, v64);
		return 0;
	}
	if ( v6 >> 16 != 1 )
	{
		v7 = ((double)(unsigned __int16)v6 + 0.0) * 0.01 + (double)(v6 >> 16) + version_stuff[v6 >> 47];
		wprintf(L"Registry rule version %.2f is incompatible with Sysmon rule version %.2f. Please rebuild your manifest.",v6, v7);
		return 0;
	}
	if ( v5 )
	{
	v9 = (int *)(v5 + 2);
	if ( v5 + 2 >= v5 && v9 < (int *)((char *)v5 + v4) && v5 != (unsigned int *)-8 )
	{
		while ( 1 )
		{
			v10 = *v9;
			if ( *v9 == 255 )
			{
				v10 = 0;
			}
			else if ( v10 < 0 )
			{
				goto LABEL_17;
			}
			if ( v3 < v10 )
				v3 = v10;
			v11 = v9[1];
			if ( v11 && v11 != 1 )
			{
				v63 = L"Invalid data in rules";
				goto LABEL_127;
			}
		LABEL_17:
			v12 = rule_struct_orig->rules_buf;
			if ( (unsigned int)v9 >= v12 )
			{
				v13 = rule_struct_orig->rule_buf_size;
				if ( (unsigned int)v9 < v12 + v13 )
				{
				v14 = v9[2];
				if ( v14 )
				{
					v9 = (int *)(v14 + v12);
					if ( v14 + v12 >= v12 && (unsigned int)v9 < v12 + v13 && v9 )
					continue;
				}
				}
			}
			break;
		}
	}
	}
	v15 = v3 + 1;
	if ( v15 > 0xFFFF || (v16 = (unsigned int **)malloc(8 * v15 + 4), (v68 = v16) == 0) )
	{
		wprintf(L"RuleEngine: Failed to allocate memory");
		return 0;
	}
	memset(v16, 0, 8 * v15 + 4);
	v17 = v68;
	rule_struct_cpy2 = rule_struct_orig;
	*v68 = (unsigned int *)v15;
	v19 = rule_struct_orig->rule_buf_size;
	if ( v19 >= 8
	&& (v20 = rule_struct_orig->rules_buf, *(DWORD *)(v20 + 4))
	&& (v21 = (unsigned int *)(v20 + 8), v65 = v20 + 8, v20 + 8 >= v20)
	&& (unsigned int)v21 < v19 + v20
	&& v20 != -8 )
	{
		while ( 1 )
		{
			v22 = *v21;
			v72 = *v21;
			if ( *v21 == 255 )
			break;
			if ( v22 >= 0 )
			goto LABEL_34;
		LABEL_111:
			v20 = rule_struct_cpy2->rules_buf;
			if ( (unsigned int)v21 >= v20 )
			{
			v19 = rule_struct_cpy2->rule_buf_size;
			if ( (unsigned int)v21 < v19 + v20 )
			{
				v60 = v21[2];
				if ( v60 )
				{
				v21 = (unsigned int *)(v20 + v60);
				v65 = v20 + v60;
				if ( v20 + v60 >= v20 && (unsigned int)v21 < v19 + v20 && v21 )
					continue;
				}
			}
			}
			goto LABEL_117;
		}
		v22 = 0;
		v72 = 0;
		LABEL_34:
		if ( v17[2 * v22 + 1] )
		{
			wprintf(L"Invalid data in rules.");
			// dbg_msg((int)L"RuleEngine", 0xDu, (int)L"Invalid data in rules", v64);
		}
		else
		{
			v74 = 0;
			if ( (unsigned int)v21 >= v20 && (unsigned int)v21 < v19 + v20 )
			{
			if ( v21[3] )
			{
				v23 = (unsigned int)((char *)v21 - v20 + 16);
				v24 = v21 + 4;
				if ( (unsigned int)(v21 + 4) >= v20 && (unsigned int)v24 < v19 + v20 )
				{
				v25 = v21[7];
				if ( !(v25 & 1) && v23 + v25 > v23 && v23 + v25 < v19 && !*((WORD *)v24 + (v25 >> 1) + 7) )
				{
					rule_struct_cpy4 = rule_struct_cpy;
					v27 = rule_struct_cpy->rules_buf;
					while ( 1 )
					{
					v28 = v74;
					if ( *v24 > v74 )
						v28 = *v24;
					v74 = v28;
					if ( (unsigned int)v21 < v27 )
						break;
					v29 = rule_struct_cpy4->rule_buf_size;
					if ( (unsigned int)v21 >= v27 + v29 )
						break;
					if ( (unsigned int)v24 < v27 )
						break;
					if ( (unsigned int)v24 >= v27 + v29 )
						break;
					v30 = v24[2];
					v66 = v30;
					v24 = (unsigned int *)(v30 + v27);
					if ( v30 + v27 < v27 )
						break;
					if ( (unsigned int)v24 >= v27 + v29 )
						break;
					v31 = v24[3];
					if ( v31 & 1 )
						break;
					v32 = v31 + v30;
					if ( v32 <= v66 || v32 >= v29 || *((WORD *)v24 + (v31 >> 1) + 7) )
						break;
					rule_struct_cpy4 = rule_struct_cpy;
					}
				}
				}
			}
			}
			v33 = v74 + 1;
			if ( v74 + 1 <= 0xFFFF )
			{
				v34 = (int *)malloc(8 * v33 + 4);
				v69 = v34;
				if ( v34 )
				{
					memset(v34, 0, 8 * v33 + 4);
					*v69 = v33;
					v68[2 * v72 + 1] = (unsigned int *)v69;
					v68[2 * v72 + 2] = v21;
					v35 = rule_struct_cpy->rules_buf;
					if ( (unsigned int)v21 >= v35 )
					{
					v36 = rule_struct_cpy->rule_buf_size;
					if ( (unsigned int)v21 < v36 + v35 )
					{
						if ( v21[3] )
						{
						v37 = (unsigned int)((char *)v21 - v35 + 16);
						v38 = (DWORD *)v21 + 4;
						if ( (unsigned int)(v21 + 4) >= v35 && (unsigned int)v38 < v36 + v35 )
						{
							v39 = v21[7];
							if ( !(v39 & 1) && v37 + v39 > v37 && v37 + v39 < v36 && !*((WORD *)v38 + (v39 >> 1) + 7) )
							{
							do
							{
								++v69[2 * *v38 + 2];
								v40 = rule_struct_cpy->rules_buf;
								if ( (unsigned int)v21 < v40 )
								break;
								v41 = rule_struct_cpy->rule_buf_size;
								if ( (unsigned int)v21 >= v41 + v40 )
								break;
								if ( !v21[3] )
								break;
								if ( (unsigned int)v38 < v40 )
								break;
								if ( (unsigned int)v38 >= v41 + v40 )
								break;
								v42 = v38[2];
								v38 = (DWORD *)(v40 + v42);
								if ( v40 + v42 < v40 )
								break;
								if ( (unsigned int)v38 >= v41 + v40 )
								break;
								v43 = v38[3];
								if ( v43 & 1 )
								break;
							}
							while ( v42 + v43 > v42 && v42 + v43 < v41 && !*((WORD *)v38 + (v43 >> 1) + 7) );
							}
						}
						}
					}
					}
					v44 = v74;
					v45 = (unsigned int *)(v69 + 2);
					v73 = 0;
					v46 = 0;
					v70 = (DWORD **)v69 + 2;
					while ( 1 )
					{
						v47 = *v45;
						if ( v47 )
						{
							if ( v47 > 0xFFFF || (v48 = (DWORD *)malloc(8 * v47 + 4)) == 0 )
							{
							*v70 = 0;
							break;
							}
							memset(v48, 0, 8 * v47 + 4);
							*v48 = v47;
							*v70 = 0;
							*(v70 - 1) = v48;
							v49 = rule_struct_cpy->rules_buf;
							if ( (unsigned int)v21 >= v49 && (unsigned int)v21 < v49 + rule_struct_cpy->rule_buf_size )
							{
								if ( v21[3] )
								{
									v50 = (unsigned int)((char *)v21 - v49 + 16);
									v51 = (DWORD *)v21 + 4;
									if ( (unsigned int)(v21 + 4) >= v49 )
									{
										v21 = (unsigned int *)v65;
										if ( (unsigned int)v51 < v49 + rule_struct_cpy->rule_buf_size )
										{
											v52 = v51[3];
											if ( !(v52 & 1) )
											{
												v53 = v50 + v52;
												if ( v50 + v52 > v50 )
												{
													rule_struct_cpy3 = rule_struct_cpy;
													if ( v53 < rule_struct_cpy->rule_buf_size && !*((WORD *)v51 + (v52 >> 1) + 7) )
													{
														v55 = (DWORD **)v48 + 2;
														v67 = (int)(v48 + 2);
														while ( 1 )
														{
															if ( *v51 == v73 )
															{
																*v55 = v51;
																v67 = (int)(v55 + 2);
															}
															v56 = rule_struct_cpy3->rules_buf;
															if ( v65 < v56 )
																break;
															v57 = rule_struct_cpy3->rule_buf_size;
															if ( v65 >= v57 + v56 )
																break;
															if ( !*(DWORD *)(v65 + 12) )
																break;
															if ( (unsigned int)v51 < v56 )
																break;
															if ( (unsigned int)v51 >= v57 + v56 )
																break;
															v58 = v51[2];
															v51 = (DWORD *)(v56 + v58);
															if ( v56 + v58 < v56 )
																break;
															if ( (unsigned int)v51 >= v57 + v56 )
																break;
															v59 = v51[3];
															if ( v59 & 1 || v58 + v59 <= v58 || v58 + v59 >= v57 || *((WORD *)v51 + (v59 >> 1) + 7) )
																break;
															v55 = (DWORD **)v67;
															rule_struct_cpy3 = rule_struct_cpy;
														}
													}
												}
											}
										}
									}
								}
							}
							v44 = v74;
							v46 = v73;
						}
						++v46;
						v45 = (unsigned int *)v70 + 2;
						v73 = v46;
						v70 += 2;
						if ( v46 > v44 )
						{
							rule_struct_cpy2 = rule_struct_cpy;
							v17 = v68;
							goto LABEL_111;
						}
					}
				}
			}
			wprintf(L"RuleEngine: Failed to allocate memory");
		}
		v61 = 0;
		if ( *v68 )
		{
			v62 = v68 + 1;
			do
			{
				recursive_count(*v62);
				++v61;
				v62 += 2;
			}
			while ( v61 < (unsigned int)*v68 );
		}
		free(v68);
		result = 0;
	}
	else
	{
		LABEL_117:
			v1->some_num_idx_12 = (unsigned int )v17;
		result = 1;
	}
	return result;
}

void recursive_count(unsigned int *ptr)
{
	unsigned int *v1; // ebx
	unsigned int v2; // esi
	unsigned int **v3; // edi

	v1 = ptr;
	if ( ptr )
	{
		v2 = 0;
		if ( *ptr )
		{
			v3 = (unsigned int **)(ptr + 1);
			do
			{
				recursive_count(*v3);
				++v2;
				v3 += 2;
			}
			while ( v2 < *v1 );
		}
		free(v1);
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

boolean get_struct_data_wrap2( PRULES_STRUCT stack_ptr1, unsigned int *stack_ptr2 ) {

	unsigned int *stack_ptr2_cpy = 0; // ebx
	PRULES_STRUCT ret_ptr; // esi
	unsigned int *ret_ptr_cpy; // ecx

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

PRULE_STRUCT get_rule_func( uint32_t rule_num) {
	int iterator;
	PRULE_STRUCT rule_obj;

	iterator = 0;
	while ( 1 )
	{
		rule_obj = (PRULE_STRUCT)&rule_arr[iterator];
		if ( rule_obj->RULE_FUNC )
		{
			if ( rule_obj->RULE_ID_NUM == rule_num )
				break;
		}
		if ( (unsigned int)++iterator >= 9 )
			return 0;
	}
	return (PRULE_STRUCT)&rule_arr[iterator];
}

wchar_t *resolve_hashmap(unsigned int hash_reg_val)
{
	unsigned int hash_reg_val_cpy; // edx
	unsigned int v2; // ecx
	rsize_t v3; // edi
	unsigned int v4; // ebx
	signed int v5; // esi
	wchar_t *ret_str; // eax
	unsigned int str_len; // kr00_4
	size_t v8; // esi
	wchar_t *new_buf; // eax
	wchar_t *v10; // edi
	unsigned int index; // esi
	unsigned int v12; // esi
	wchar_t *result; // eax
	const wchar_t *v14; // eax
	unsigned int hash_reg_val_cpy2; // [esp+0h] [ebp-24h]
	rsize_t SizeInWords; // [esp+8h] [ebp-1Ch]
	rsize_t SizeInWordsa; // [esp+8h] [ebp-1Ch]
	wchar_t *Src[5]; // [esp+Ch] [ebp-18h]

	hash_reg_val_cpy = hash_reg_val;
	hash_reg_val_cpy2 = hash_reg_val;
	if ( (hash_reg_val & 0x80000000) == 0 )
	{
		if ( hash_reg_val >= 5 || (v14 = (wchar_t *)hashmap[hash_reg_val].hash_name) == 0 )
			v14 = (const wchar_t *)"?";
		result = _wcsdup(v14);
	}
	else
	{
		v2 = 1;
		v3 = 0;
		v4 = 0;
		SizeInWords = 1;
		v5 = 2;
		do
		{
			if ( __ROR__(v5, 1) & hash_reg_val_cpy )		
			{
				ret_str = resolve_hashmap(v2);
				str_len = wcslen(ret_str);
				hash_reg_val_cpy = hash_reg_val_cpy2;
				Src[v4] = (wchar_t *)ret_str;
				v3 += str_len + 1;
				v2 = SizeInWords;
				++v4;
			}
			++v2;
			v5 = __ROL__(v5, 1);
			SizeInWords = v2;
		}
		while ( v2 < 5 );
		v8 = 2 * v3;
		SizeInWordsa = v3;
		new_buf = (wchar_t *)malloc(2 * v3);
		v10 = new_buf;
		if ( new_buf )
		{
			memset(new_buf, 0, v8);
			index = 0;
			if ( v4 )
			{
				while ( (!index || !wcscat_s(v10, SizeInWordsa, L",")) && !wcscat_s(v10, SizeInWordsa, Src[index]) )
				{
					if ( ++index >= v4 )
					goto LABEL_14;
				}
				*v10 = 0;
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
		result = v10;
	}
	return result;
}