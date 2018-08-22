
# SysmonConfigUtil 

A native C++ tool for parsing the sysmon configuration to an importable XML format


## Usage

Usage: sysmon_util <options>
        -h      Usage
        -f      File path of dumped binary sysmon rules from registry
        -a      Binary dump is ASCII hex format


## Misc

The binary format expected for the sysmon rules dump was developed from the output from the following command.

reg query HKLM\System\CurrentControlSet\services\SysmonDrv\Parameters -v Rules