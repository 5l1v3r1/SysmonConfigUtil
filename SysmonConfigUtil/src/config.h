#ifndef CONFIG_H
#define CONFIG_H

#include <string>
#include <unordered_map>
#include <vector>

//Class for managing each event type in the configuration
class sysmon_event_entry {
public:

	sysmon_event_entry(){};
	sysmon_event_entry( std::string passed_str ){ name = passed_str;};

	//Getters & Setters
	std::string get_condition(){ return condition; };
	void set_condition(std::string passed_str ){  condition = passed_str; };

	std::string get_name(){ return name; };
	void set_name(std::string passed_str ){  name = passed_str; };
	
	std::string get_value(){ return value; };
	void set_value(std::string passed_str ){  value = passed_str; };


private:

	//Internal data
	std::string name;
	std::string condition;	
	std::string value;

};

//Class for managing each event type in the configuration
class sysmon_event_type {
public:

	//Constructor & Deconstructors
	sysmon_event_type(){};
	sysmon_event_type( std::string passed_str ){ name = passed_str;};
	virtual ~sysmon_event_type();

	//Getters & Setters
	std::string get_name(){ return name; };

	std::string get_onmatch(){ return onmatch; };
	void set_onmatch(std::string passed_str ){  onmatch = passed_str; };

	//Add to event list
	std::vector<sysmon_event_entry *> get_event_entry_list(){ return event_entry_list; };
	void add_event_entry( sysmon_event_entry *passed_entry ){ event_entry_list.push_back(passed_entry); };

private:

	//Internal data
	std::string name;
	std::string onmatch;
	std::vector<sysmon_event_entry *> event_entry_list;

};

//Class for managing the sysmon configuration
class sysmon_configuration {
public:
	  
	//Constructor & Deconstructors
	sysmon_configuration(){};
	virtual ~sysmon_configuration();

	//Getters & Setters
	std::string get_hash_algorithms(){ return hash_algorithms_node; };
	void set_hash_algorithms(std::string passed_str ){  hash_algorithms_node = passed_str; };

	std::string get_binary_version(){ return binary_version; };
	void set_binary_version(std::string passed_str ) {  binary_version = passed_str; };

	std::vector<sysmon_event_type *> get_event_types(){ return event_type_list; };
	//sysmon_event_type *get_event_type( std::string event_type_str ){ return event_type_map[event_type_str]; };
	void add_event_type( sysmon_event_type *event_type_inst ){ event_type_list.push_back( event_type_inst); };

	//Output the data to XML
	std::string toXml();

protected: 
private:

	//Internal data
	std::string hash_algorithms_node;
	std::string binary_version;
	std::vector<sysmon_event_type *> event_type_list;

};






















#endif