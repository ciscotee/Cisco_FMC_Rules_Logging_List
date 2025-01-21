import requests
import json
import urllib3
import getpass
import pandas as pd

# Suppress SSL/TLS warnings (useful for self-signed certificates)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Function to authenticate and get a token
def get_auth_token(fmc_host, username, password):
    url = f"{fmc_host}/api/fmc_platform/v1/auth/generatetoken"
    headers = {"Content-Type": "application/json"}
    response = requests.post(url, auth=(username, password), headers=headers, verify=False)
    
    if response.status_code == 204:
        return response.headers.get('X-auth-access-token')
    else:
        raise Exception(f"Authentication failed: {response.status_code} {response.text}")

# Function to get all domains (to find correct domain_uuid)
def get_domains(fmc_host, token):
    url = f"{fmc_host}/api/fmc_platform/v1/info/domain"
    headers = {"X-auth-access-token": token}
    response = requests.get(url, headers=headers, verify=False)
    
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Failed to fetch domains: {response.status_code} {response.text}")

# Function to get all policies
def get_access_policies(fmc_host, token, domain_uuid):
    url = f"{fmc_host}/api/fmc_config/v1/domain/{domain_uuid}/policy/accesspolicies"
    headers = {
        "Content-Type": "application/json",
        "X-auth-access-token": token
    }
    
    policies = []
    offset = 0
    limit = 100  # FMC API default or chosen limit per request
    
    while True:
        paginated_url = f"{url}?offset={offset}&limit={limit}"
        response = requests.get(paginated_url, headers=headers, verify=False)
        
        if response.status_code == 200:
            data = response.json()
            items = data.get('items', [])
            policies.extend(items)
            if len(items) < limit:  # No more items to fetch
                break
            offset += limit
        else:
            raise Exception(f"Failed to fetch policies: {response.status_code} {response.text}")
    
    return policies

# Function to get all access control policy rules
def get_access_policy_rules(fmc_host, token, domain_uuid, policy_id):
    url = f"{fmc_host}/api/fmc_config/v1/domain/{domain_uuid}/policy/accesspolicies/{policy_id}/accessrules"
    headers = {
        "Content-Type": "application/json",
        "X-auth-access-token": token
    }
    
    rules = []
    offset = 0
    limit = 1000  # FMC API default or chosen limit per request
    
    while True:
        paginated_url = f"{url}?offset={offset}&limit={limit}"
        response = requests.get(paginated_url, headers=headers, verify=False)
        
        if response.status_code == 200:
            data = response.json()
            items = data.get('items', [])
            rules.extend(items)
            if len(items) < limit:  # No more items to fetch
                break
            offset += limit
        else:
            raise Exception(f"Failed to fetch rules: {response.status_code} {response.text}")
    
    return rules

# Function to get detailed information for a specific rule
def get_rule_details(fmc_host, token, domain_uuid, policy_id, rule_id):
    url = f"{fmc_host}/api/fmc_config/v1/domain/{domain_uuid}/policy/accesspolicies/{policy_id}/accessrules/{rule_id}"
    headers = {
        "Content-Type": "application/json",
        "X-auth-access-token": token
    }
    
    response = requests.get(url, headers=headers, verify=False)
    
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Failed to fetch rule details: {response.status_code} {response.text}")

# Main execution
try:
    # Prompt for FMC Host (IP or FQDN)
    fmc_host = input("Enter FMC Host (IP or FQDN): ")

    # Prompt for FMC Username and Password
    username = input("Enter FMC Username: ")
    password = getpass.getpass("Enter FMC Password: ")

    # Get authentication token
    token = get_auth_token(fmc_host, username, password)
    
    # Fetch and print all available domains
    domains = get_domains(fmc_host, token)
    
    # Create a list to store rule details
    rule_details_list = []

    # Loop through all domains and policies
    for domain in domains.get('items', []):
        domain_uuid = domain['uuid']
        print(f"\nFetching policies for domain: {domain['name']} (UUID: {domain_uuid})")

        # Get all access policies for the domain
        policies = get_access_policies(fmc_host, token, domain_uuid)
        
        # Loop through each policy and fetch its rules
        for policy in policies:
            policy_id = policy['id']
            policy_name = policy['name']  # Fetch policy name
            print(f"Fetching rules for policy: {policy_name} (Policy ID: {policy_id})")
            
            # Get all access policy rules
            rules = get_access_policy_rules(fmc_host, token, domain_uuid, policy_id)

            # Iterate over each rule and fetch its detailed settings
            for idx, rule in enumerate(rules, 1):  # Rule number starts from 1
                rule_id = rule['id']
                rule_details = get_rule_details(fmc_host, token, domain_uuid, policy_id, rule_id)
                
                # Prepare rule details for the Excel output
                rule_data = {
                    'Policy Name': policy_name,  # Add policy name here
                    'Rule Number': idx,
                    'Policy ID': policy_id,
                    'Rule ID': rule_id,
                    'Rule Name': rule_details['name'],
                    'Action': rule_details['action'],
                    'Enabled': rule_details['enabled'],
                    'Log at Beginning': rule_details.get('logBegin', False),
                    'Log at End': rule_details.get('logEnd', False),
                    'Log Intrusion Events': rule_details.get('logFiles', False),
                    'Syslog': rule_details.get('sendEventsToFMC', False)
                }
                rule_details_list.append(rule_data)
                
    # Create a DataFrame and save to an Excel file
    df = pd.DataFrame(rule_details_list)
    output_file = "fmc_policy_rules.xlsx"
    df.to_excel(output_file, index=False, engine='openpyxl')

    print(f"\nPolicy rule details saved to {output_file}")

except Exception as e:
    print(f"Error: {e}")
