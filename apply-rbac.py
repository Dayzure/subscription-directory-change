#!/usr/bin/python
import subprocess, json, sys, os, time
from subprocess import PIPE

def find_user_by_email(email,users_list):
    """ Find user by given e-mail address.
    First look at the UPN directly.
    If the UPN contains #EXT# (a guest/external user), 
    then look at the mail property of the user object
    return the user object id
    """
    for user in users_list:
        compare_value = user['userPrincipalName']
        if "#EXT#" in user['userPrincipalName']:
            compare_value = user['mail']
        if email == compare_value:
            return user['objectId']
    return None

def check_ua_msi_exists(resource_id, tenant_id):
    """ Checks if user assigned msi exists and has same tenant_id as current tenant
    """
    show_ua_msi_result = subprocess.run(["az", "resource", "show", "--id", resource_id, "--query", "properties"], stdout=PIPE, stderr=PIPE, universal_newlines=True)
    if "not found" in show_ua_msi_result.stderr:
        print("found error: ", show_ua_msi_result.stderr)
        return None
    else:
        ua_msi = json.loads(show_ua_msi_result.stdout)
        if ua_msi['tenantId'] == tenant_id:
            print("skipped creating/deleting UA MSI")
            return ua_msi['principalId']
        else:
            # delete the UA MSI as tenants do not match
            subprocess.run(["az", "resource", "delete", "--ids", resource_id], stdout=PIPE, stderr=PIPE, universal_newlines=True)
    return None

def user_assigned_msi_recreate(resource_id, tenant_id):
    """ Checks if user assigned MSI is created
       If not - creates and returns principal ID
       if existing - returns principal ID
    """
    ua_msi_principal_id = check_ua_msi_exists(resource_id, tenant_id)
    if ua_msi_principal_id is not None:
        return ua_msi_principal_id
    else:
        chunks = resource_id.split('/')
        user_assigned_id = { "resourceGroup": None, "name": None }
        user_assigned_id['resourceGroup'] = chunks[4]
        user_assigned_id['name'] = chunks[8]
        create_ua_msi_result = subprocess.run(["az", "identity", "create", "-g", chunks[4], "-n", chunks[8]], stdout=PIPE, stderr=PIPE, universal_newlines=True)
        ua_msi_json = json.loads(create_ua_msi_result.stdout)
        return ua_msi_json['principalId']

def system_assigned_msi_recreate(resource_id, tenant_id):
    """ Check for System Assigned MSI - if it is present and with same tenant id
        If present and has same tenant id - return principal id
        else - update and return prinripal id
    """
    show_sa_msi_result = subprocess.run(["az", "resource", "show", "--id", resource_id, "--query", "identity"], stdout=PIPE, stderr=PIPE, universal_newlines=True)
    if "not found" in show_sa_msi_result.stderr:
        return None
    else:
        sa_msi = json.loads(show_sa_msi_result.stdout)
        if sa_msi['tenantId'] == tenant_id:
            return sa_msi['principalId']
        else:
            create_sa_msi_result = subprocess.run(["az", "resource", "update", "--set", "identity.type='SystemAssigned'", "--ids", resource_id, "--query", "identity"], stdout=PIPE, stderr=PIPE, universal_newlines=True)
            sa_msi = json.loads(create_sa_msi_result.stdout)
            return sa_msi['principalId']
    return None

def extract_principals_from_rbac_assignments(rbacs):
    users_list = []
    service_principals_list = []
    for assignment in rbacs:
        if assignment['scope'] == "/" or "managementGroups" in assignment['scope']:
            continue
        if assignment['principalType'] == "ServicePrincipal":
            # fill the service_principals_list            
            service_principals_list.append(assignment['principalId'])
        elif assignment['principalType'] == "User":
            # fill the users_list
            users_list.append(assignment['principalId'])
        elif assignment['principalType'] == "Group":
            continue
    users = get_assigned_users_from_aad(users_list)
    service_principals = get_assigned_service_principals_from_aad(service_principals_list)
    return {"users": users, "servicePrincipals": service_principals}

def get_assigned_users_from_aad(principals_list):
    if len(principals_list) < 1:
        return []      
    odata_filter = ""
    for principal in principals_list:
        if(len(odata_filter) < 5):
            odata_filter = "objectId eq '{}'".format(principal)
        else:
            odata_filter += " or objectId eq '{}'".format(principal)
    # logger.debug("odata filter: %s", odata_filter)
    # logger.debug("calling az ad user list --filter ...")
    principals_result = subprocess.run(["az", "ad", "user", "list", "--filter", odata_filter], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    # logger.debug(user_result.stdout)
    return json.loads(principals_result.stdout)

def recreate_custom_rbac_roles():
    try:
        with open('rbac_custom_roles.json') as f:
            custom_roles = json.load(f)
            for role in custom_roles:
                new_role_definition = {"Name": None, "IsCustom": True, "Description": None, "Actions": None, "NotActions": None, "DataActions": None, "NotDataActions": None, "AssignableScopes": None}
                new_role_definition['Name'] = role['roleName']
                new_role_definition['Description'] = role['description']
                new_role_definition["Actions"] = role["permissions"][0]["actions"]
                new_role_definition['NotActions'] = role['permissions'][0]['notActions']
                new_role_definition['DataActions'] = role['permissions'][0]['dataActions']
                new_role_definition['NotDataActions'] = role['permissions'][0]['notDataActions']
                new_role_definition['AssignableScopes'] = role['assignableScopes']
                with open('custom-role-def.json', 'w') as f:
                    json.dump(new_role_definition, f)
                create_custom_role_result = subprocess.run(["az", "role", "definition", "create", "--role-definition", "@custom-role-def.json"], stdout=PIPE, stderr=PIPE, universal_newlines=True)
                if len(create_custom_role_result.stderr) > 10:
                    print(create_custom_role_result.stderr)
                os.remove("custom-role-def.json")
            print("Wait 20 seconds for role creation replication ...")
            time.sleep(20)
    except IOError:
        print("No custom roles saved.")

def create_new_assignment(assignment):
    """ Creates new RBAC assigment based on backed-up data
    """
    if assignment['rg-name'] is None:
        #print(assignment)
        result = subprocess.run(["az", "role", "assignment", "create", "--role", assignment['role'], "--assignee-object-id", assignment['assignee-object-id'], "--assignee-principal-type", assignment['assignee-principal-type'], "--scope", assignment['scope']], stdout=PIPE, stderr=PIPE, universal_newlines=True)
    else:
        #print(assignment)
        result = subprocess.run(["az", "role", "assignment", "create", "--role", assignment['role'], "--assignee-object-id", assignment['assignee-object-id'], "--assignee-principal-type", assignment['assignee-principal-type'], "-g", assignment['rg-name'], "--scope", assignment['scope']], stdout=PIPE, stderr=PIPE, universal_newlines=True)
    if len(result.stderr) > 2 :
        print("assignment error: ")
        print(result.stderr)
        print("---------------------")
    else:
        print("assignment result: ")
        print(result.stdout)
        print("---------------------")

def apply_rbac(rbacs, users, tenant_id):
    """ Apply the RBAC permissions
        Loop through saved ones and check for users, system assigned and user assigned MSIs
        custom roles are already re-created at respective levels
    """
    #########################################
    ### dump looks like this              ###
    #########################################    
    # {
    #     "roleName": "Reader",
    #     "managedIdentityReosurceId": null,
    #     "msiType": "[system|user|null]",
    #     "scope": "/subscriptions/8c8ddf2b-cafa-420f-a182-04fb50f51d68",
    #     "principalType": "[Group|User|ServicePrincipal]",
    #     "principalEmail": "[null|user@email.com|service-principal-id]"
    # }
    print("Matching assignments ...")
    users_and_service_principals = extract_principals_from_rbac_assignments(rbacs)
    for assignment in rbacs:
        new_assignment = {"role": assignment['roleName'], "assignee-object-id": None, "assignee-principal-type": None, "rg-name": None, "scope": assignment['scope']}
        if assignment['principalType'] == "ServicePrincipal":
            new_assignment['assignee-principal-type'] = "ServicePrincipal"
            if assignment['msiType'] == "user":
                # handle user assigned MSI
                # print("User Assigned MSI found ...")
                new_assignment['assignee-object-id'] = user_assigned_msi_recreate(assignment['managedIdentityReosurceId'], tenant_id)           
            elif assignment['msiType'] == "system":
                # handle user assigned MSI
                # print("System Assigned MSI found ...")
                new_assignment['assignee-object-id'] = system_assigned_msi_recreate(assignment['managedIdentityReosurceId'], tenant_id)           
            else:
                # handle regular SP
                new_assignment['assignee-principal-type'] = "ServicePrincipal"
                print("Regular Service Principal found ... skipping?")
                continue
        elif assignment['principalType'] == 'User':
            # handle user
            new_assignment['assignee-principal-type'] = "User"
            #print("User assignee found ...")
            user = find_user_by_email(assignment['principalEmail'], users_and_service_principals['users'])
            if user is None:
                print("Could not find user for assignment:")
                print(assignment)
                print("Shall we invite user?")
                continue
            else:
                new_assignment['assignee-object-id'] = user
        else:
            print("We do not handle groups")
            continue
        if "resourceGroups" in assignment['scope']:
            scope_chunks = assignment['scope'].split('/')
            if len(scope_chunks) == 4:
                new_assignment['rg_name'] = scope_chunks[3]
        create_new_assignment(new_assignment)


print("Getting current tenant id ...")
tenant_id_result = subprocess.run(["az", "account", "show", "--query", "tenantId", "-o", "tsv"], stdout=PIPE, stderr=PIPE, universal_newlines=True)
tenant_id = tenant_id_result.stdout.strip()
print(tenant_id)

print("recreating custom RBAC roles...")
recreate_custom_rbac_roles()

print("reading saved rbac assignments ...")
with open('rbac.json') as f:
    rbacs = json.load(f)

apply_rbac(rbacs, users, tenant_id)


##############################################
### az user assigned msi                   ###
##############################################
# az identity create -g shared-resources-rg -n 'ua-msi-migration-path-test'

##############################################
### update system assigned msi             ###
##############################################
# az resource update --set identity.type="SystemAssigned" --ids /subscriptions/8c8ddf2b-cafa-420f-a182-04fb50f51d68/resourceGroups/compute-rg/providers/Microsoft.Compute/virtualMachines/ubnt
