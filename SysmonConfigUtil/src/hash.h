#ifndef _SYSMON_HASH_
#define _SYSMON_HASH_

#include <cstdint>

static const wchar_t SHA1[] = L"SHA1";
static const wchar_t MD5[] = L"MD5";
static const wchar_t SHA256[] = L"SHA256";
static const wchar_t IMPHASH[] = L"IMPHASH";

/*
 * Struct for the hashes
 */
typedef struct {
    uintptr_t hash_name;                   
	uint32_t some_int_4;
	uint32_t some_int_8;
	uintptr_t some_func_12;
	uintptr_t some_func_16;
	uintptr_t some_func_20;
	uintptr_t some_func_24;
} HASH_STRUCT, *PHASH_STRUCT;

//Populate hash struct
HASH_STRUCT null_hash_struct = {0,0,0,0,0,0,0};
HASH_STRUCT sha1_hash_struct = { (uintptr_t)&SHA1, 0,0,0,0,0,0 };
HASH_STRUCT md5_hash_struct = { (uintptr_t)&MD5, 0,0,0,0,0,0 };
HASH_STRUCT sha256_hash_struct = { (uintptr_t)&SHA256, 0,0,0,0,0,0 };
HASH_STRUCT imp_hash_struct = { (uintptr_t)&IMPHASH, 0,0,0,0,0,0 };
HASH_STRUCT hashmap[] = {null_hash_struct, sha1_hash_struct, md5_hash_struct, sha256_hash_struct, imp_hash_struct};

#endif