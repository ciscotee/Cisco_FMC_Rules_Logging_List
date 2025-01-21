[![published](https://static.production.devnetcloud.com/codeexchange/assets/images/devnet-published.svg)](https://developer.cisco.com/codeexchange/github/repo/ciscotee/CiscoSecureEndpoint-Ansible-CheckStatus)
# Cisco_FMC_Rules_Logging_List
At this time, users would like to list of the settings logging in each rule.
The Code use for List the logging setting in each rule under policy managed by Cisco Secure Firewall Management Center (FMC) 

## Requirements

  > [!IMPORTANT]
  >  -  Create New User with Role "Access Admin" or create new user role with Policies > Access Control permission.
  >  -  Running machine need to access Cisco Secure Firewall Management Center.
  >  -  Running machine need python3 and pip3.
  >  -  Running machine internet access to install module requirement via pip.
  
  ### Create New Folder then paste python code and requirements, the output will export in the same folder.

          ├── Folder
          │   ├── fmc_list_policy.py
          │   ├── requirements.txt
          │   └── fmc_policy_rules.xlsx
          │   └── venv

## Installation
  1. Recommended to run python in virtual environment, access direct to the folder that have code then run.
		
      Windows:

         python -m venv venv
         venv\Script\activate
     
      macOS and Linux:

         python -m venv venv
         source venv/bin/activate
	
  2. Install requirement modules.

           pip install -r requirements.txt

     Validate the modules that mactch with requirements.txt

           pip list
     

         
## Usage
  - Run python code.
  
        python fmc_list_policy.py
    
    It will ask to input FMC host, username, and password. FMC host please enter in https://xxx.xxx.xxx.xxx format.

        Enter FMC Host (IP or FQDN): https://xxx.xxx.xxx.xxx or https://fmcname.domain
        Enter FMC Username:
        Enter FMC Password:
    
  - After it run successful, you will get output in folder with the file-name fmc_policy_rules.xlsx
  

## Code Steps
  - Connect to FMC.
  - Generate Token.
  - Fetching domain UUID.
  - Fetching rules in each policy.
  - List of the logging settings in rules

## Notes
You might get some warning about urllib3 in macOS but it continue to running the code.

