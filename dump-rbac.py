#!/usr/bin/python
import subprocess, json, csv
from distutils import log as logger
logger.set_verbosity(logger.INFO)

def find_object(objectId,objectsList):
  for listItem in objectsList:
    if listItem['id'] == objectId:
        return listItem
  return None

def process_rbac(rbacs):  
    rbacs_list = []
    users_groups_and_service_principals = extract_principals_from_rbac_assignments(rbacs)
    for assignment in rbacs:
        if assignment['scope'] == "/" or "managementGroups" in assignment['scope']:
            logger.info("Ignoring root scope (root management group) and management group scopes")
            continue
        rbac_detail = {"principalEmail": None, "principalType": None, "scope": None, "roleName": None, "managedIdentityReosurceId": None, "msiType": None, "principalId": None}
        rbac_detail['principalType'] = assignment['principalType']
        rbac_detail['roleName'] = assignment['roleDefinitionName']
        rbac_detail['scope'] = assignment['scope']
        rbac_detail['principalId'] = assignment['principalId']
        if assignment['principalType'] == "ServicePrincipal":
            logger.debug("Search for service principal:  %s", assignment['principalId'])
            sp = find_object(assignment['principalId'],users_groups_and_service_principals['servicePrincipals'])
            if sp is not None:
                if sp['servicePrincipalType'] == "ManagedIdentity":
                    if len(sp['alternativeNames']) > 1:
                        rbac_detail['managedIdentityReosurceId'] = sp['alternativeNames'][1]
                    else:
                        rbac_detail['managedIdentityReosurceId'] = sp['alternativeNames'][0]
                    if sp['alternativeNames'][0] == "isExplicit=True":
                        # user assigned
                        rbac_detail['msiType'] = "user"
                    else:
                        # system assigned - we need to create a collection of user assigned MSIs and recreate them
                        # NOTE: before user assigned were introduced, the isExplicit alternative name was not added at all
                        # so a System Assigned MSI is recognized by either totally missing isExplicit name, 
                        # or when this value is present but has value of False
                        rbac_detail['msiType'] = "system"
                    rbac_detail['principalEmail'] = sp['servicePrincipalNames'][0]
                else:
                    # Generally skip populating regular service principals
                    logger.info("Skipping regular service principal assignment")
                    continue
            else:
                logger.info('Found ghost assigment for principal which will be cleaned up... ')
                continue
        elif assignment['principalType'] == "User":
            #logger.debug("Search for user: %s", assignment['principalId'])
            user = find_object(assignment['principalId'],users_groups_and_service_principals['users'])
            if user is not None:
                if user['userType'] == "Member" or user['userType'] is None:
                    # Users created before intorduction of B2B Collaboration are marked with None for user type
                    if user['mail'] is None or len(user['mail']) < 4:
                        # fix for users without email (GitHub #6)
                        rbac_detail['principalEmail'] = user['userPrincipalName']
                    else:
                        rbac_detail['principalEmail'] = user['mail']
                else:           
                    #logger.debug("Users neither member nor none: %s %s", user['userType'], user['userPrincipalName'])         
                    rbac_detail['principalEmail'] = user['otherMails'][0]
            else:
                logger.info("Found ghost assigment for user which will be cleaned up: %s", assignment)
                continue        
        elif assignment['principalType'] == "Group":
            group = find_object(assignment['principalId'],users_groups_and_service_principals['groups'])
            if group is not None:
                rbac_detail["principalEmail"] = group["displayName"]
        rbacs_list.append(rbac_detail)
    return rbacs_list

def write_custom_roles():
    logger.info("Writing custom RBAC roles ...")
    rbac_custom_roles_result = subprocess.run(["az", "role", "definition", "list", "--custom-role-only", "true"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    custom_roles = json.loads(rbac_custom_roles_result.stdout)
    with open('rbac_custom_roles.json', 'w') as f:
        json.dump(custom_roles, f)

def extract_principals_from_rbac_assignments(rbacs):
    users = []
    service_principals = []
    groups = []
    users_list = []
    service_principals_list = []
    groups_list = []
    iusr = 0
    isp = 0
    igrp = 0
    for assignment in rbacs:
        if assignment['scope'] == "/" or "managementGroups" in assignment['scope']:
            continue
        if assignment['principalType'] == "ServicePrincipal":
            # fill the service_principals_list            
            isp +=1
            service_principals_list.append(assignment['principalId'])
            if isp % 15 == 0:
                service_principals += get_assigned_service_principals_from_aad(service_principals_list)
                del service_principals_list[:]
        elif assignment['principalType'] == "User":
            # fill the users_list
            iusr += 1
            users_list.append(assignment['principalId'])
            if iusr % 15 == 0:
                # get this set of users and reset counters and lists
                users += get_assigned_users_from_entra_id(users_list)
                del users_list[:]
        elif assignment['principalType'] == "Group":
            # fill the group_list
            igrp += 1
            groups_list.append(assignment['principalId'])
            if igrp % 15 == 0:
                # get the set of groups and reset counters and lists
                groups += get_assigned_users_or_groups_from_aad(groups_list, "group")
                del groups_list[:]
    users += get_assigned_users_from_entra_id(users_list)
    service_principals += get_assigned_service_principals_from_aad(service_principals_list)
    groups += get_assigned_users_or_groups_from_aad(groups_list, "group")
    return {"users": users, "servicePrincipals": service_principals, "groups": groups}

def get_assigned_users_or_groups_from_aad(principals_list, usergroup):
    if len(principals_list) < 1:
        return []      
    odata_filter = "_"
    for principal in principals_list:
        if(len(odata_filter) < 5):
            odata_filter = "id eq '{}'".format(principal)
        else:
            odata_filter += " or id eq '{}'".format(principal)
    # logger.debug("odata filter: {}", odata_filter)
    # logger.debug(odata_filter)
    # logger.debug("calling az ad user list --filter ...")
    principals_result = subprocess.run(["az", "ad", usergroup, "list", "--filter", odata_filter], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    # logger.debug(user_result.stdout)
    return json.loads(principals_result.stdout)

def get_assigned_users_from_entra_id(principals_list):
    if len(principals_list) < 1:
        return []      
    odata_filter = "_"
    for principal in principals_list:
        if(len(odata_filter) < 5):
            odata_filter = "id eq '{}'".format(principal)
        else:
            odata_filter += " or id eq '{}'".format(principal)
    # logger.debug("odata filter: {}", odata_filter)
    # logger.debug(odata_filter)
    # logger.debug("calling az ad user list --filter ...")
    principals_result = subprocess.run(["az", "rest", "--method", "get", "--uri", "https://graph.microsoft.com/v1.0/users/?$select=id,userPrincipalName,mail,mailNickname,userType&$filter={}".format(odata_filter)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    # logger.debug(principals_result.stdout)
    return json.loads(principals_result.stdout)


def get_assigned_service_principals_from_aad(principals_list):
    if len(principals_list) < 1:
        return []      
    odata_filter = "_"
    for principal in principals_list:
        if(len(odata_filter) < 5):
            odata_filter = "id eq '{}'".format(principal)
        else:
            odata_filter += " or id eq '{}'".format(principal)
    # logger.debug("odata filter: {}", odata_filter)
    # logger.debug(odata_filter)
    # logger.debug("calling az ad sp list --filter ...")
    principals_result = subprocess.run(["az", "ad", "sp", "list", "--all", "--filter", odata_filter], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    # logger.debug(user_result.stdout)
    return json.loads(principals_result.stdout)

def write_groups_csv(rbacs, filename):
    filtered_groups = {}
    # first normalize assignments into unique groups dictionary
    # (GitHub #5)
    for assignment in rbacs:
        if assignment['scope'] == "/" or "managementGroups" in assignment['scope']:
                logger.info("Ignoring root scope (root management group) and management group scopes")
                continue
        if assignment['principalType'] == "Group":
            filtered_groups[assignment['principalId']] = assignment['principalEmail']

    with open(filename, 'w') as csvfile:
        fieldnames = ['GroupName', 'GroupObjectId', 'NewGroupObjectId']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        for k,v in filtered_groups.items():
                writer.writerow({'GroupName': v, 'GroupObjectId':k, 'NewGroupObjectId':' '})

write_custom_roles()

logger.info("Getting rbac assignments ...")
rbac_result = subprocess.run(["az", "role", "assignment", "list", "--all"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
rbacs = json.loads(rbac_result.stdout)

logger.info("Matching assignments ...")
extract_principals_from_rbac_assignments(rbacs)

rbacs_list = process_rbac(rbacs)
with open('rbac.json', 'w') as f:
    json.dump(rbacs_list, f)

write_groups_csv(rbacs_list, "groups_mapping.csv")
