#include <msxml2.h>
#include "config.h"

#import <msxml6.dll>

sysmon_configuration::~sysmon_configuration(){

	for (auto i = event_type_list.begin(); i != event_type_list.end(); i++) {
        sysmon_event_type *an_evt_type = (sysmon_event_type *)*i;
		if( an_evt_type != nullptr )
			delete an_evt_type;
    }

};

sysmon_event_type::~sysmon_event_type(){

    for (auto i = event_entry_list.begin(); i != event_entry_list.end(); i++) {
        sysmon_event_entry *an_evt_entry = (sysmon_event_entry *)*i;
		if( an_evt_entry != nullptr )
			delete an_evt_entry;
    }

};

//Output the XML based on the schema
std::string sysmon_configuration::toXml(){

	std::string retStr;

	//Create the XML
    MSXML2::IXMLDOMDocument2Ptr pXMLDoc;    
    HRESULT hr = pXMLDoc.CreateInstance(__uuidof(MSXML2::DOMDocument60));
    if(FAILED(hr)){
		printf("Failed to create the XML class instance");
		//Uninitialize COM
		::CoUninitialize();
        return retStr;
    }

    if(pXMLDoc->loadXML("<Sysmon></Sysmon>") == VARIANT_FALSE){
        printf("MSXML::DomDocument::load failed. \n");
		printf("Error: %s", pXMLDoc->parseError->Getreason().GetBSTR());
		//Uninitialize COM
		::CoUninitialize();
        return retStr;
    }

    //Get the root element just created    
    MSXML2::IXMLDOMElementPtr pXMLRootElem = pXMLDoc->GetdocumentElement();
	std::string::size_type sz;
	double config_version = std::stod( binary_version, &sz);

	std::string schema_version(binary_version);
	if( config_version < 3.0)
		schema_version.assign("2.01");
	

    //Add schema version attribute
	pXMLRootElem->setAttribute("schemaversion",_variant_t(schema_version.c_str()));

	//Add hash algorithm node 
    MSXML2::IXMLDOMElementPtr hash_algo_node = pXMLDoc->createElement("HashAlgorithms");
	std::string hash_str; 
	if( hash_algorithms_node.compare("?") == 0)
		hash_algorithms_node.assign("MD5,SHA1,IMPHASH");	

	hash_algo_node->Puttext(hash_algorithms_node.c_str());  
	hash_algo_node = pXMLRootElem->appendChild(hash_algo_node);

	//Add event types
    MSXML2::IXMLDOMElementPtr event_filtering_node = pXMLDoc->createElement("EventFiltering");
    event_filtering_node = pXMLRootElem->appendChild(event_filtering_node);

	//Loop through map and add each
	for (auto i = event_type_list.begin(); i != event_type_list.end(); i++) {

		sysmon_event_type *an_evt_type = (sysmon_event_type *)*i;
	
		//Add event type
		MSXML2::IXMLDOMElementPtr event_type_node = pXMLDoc->createElement( an_evt_type->get_name().c_str());
		event_type_node->setAttribute( "onmatch", an_evt_type->get_onmatch().c_str() );
		event_type_node = event_filtering_node->appendChild(event_type_node);

		//Add each child event entry
		std::vector<sysmon_event_entry *>  event_entry_list = an_evt_type->get_event_entry_list();
		for (auto i = event_entry_list.begin(); i != event_entry_list.end(); i++) {

			sysmon_event_entry *an_evt_entry = (sysmon_event_entry *)*i;

			//Add event type
			MSXML2::IXMLDOMElementPtr event_entry_node = pXMLDoc->createElement( an_evt_entry->get_name().c_str());
			if( an_evt_entry->get_condition() != "is" )
				event_entry_node->setAttribute( "condition", an_evt_entry->get_condition().c_str() );

			event_entry_node->Puttext(an_evt_entry->get_value().c_str());  
			event_entry_node = event_type_node->appendChild(event_entry_node);

		}
	
	}

	retStr = pXMLDoc->Getxml();

	return retStr;
}