#!/usr/bin/python
import subprocess, json
from subprocess import PIPE

def find_object(objectId,objectsList):
  for listItem in objectsList:
    if listItem['objectId'] == objectId:
        return listItem
  return None

def process_rbac(rbacs, users, sps):
    rbacs_list = []
    for assignment in rbacs:
        if assignment['scope'] == "/" or "managementGroups" in assignment['scope']:
            print("Ignoring root scope (root management group) and management group scopes")
            continue
        rbac_detail = {"principalEmail": None, "principalType": None, "scope": None, "roleName": None, "managedIdentityReosurceId": None, "msiType": None}
        rbac_detail['principalType'] = assignment['principalType']
        rbac_detail['roleName'] = assignment['roleDefinitionName']
        rbac_detail['scope'] = assignment['scope']
        if assignment['principalType'] == "ServicePrincipal":
            #print("Search for service principal: ", assignment['principalId'])
            sp = find_object(assignment['principalId'],sps)
            if sp is not None:
                if sp['servicePrincipalType'] == "ManagedIdentity":
                    rbac_detail['managedIdentityReosurceId'] = sp['alternativeNames'][1]
                    if sp['alternativeNames'][0] == "isExplicit=False":
                        # system assigned
                        rbac_detail['msiType'] = "system"
                    elif sp['alternativeNames'][0] == "isExplicit=True":
                        # user assigned - we need to create a collection of user assigned MSIs and recreate them
                        rbac_detail['msiType'] = "user"
                rbac_detail['principalEmail'] = sp['servicePrincipalNames'][0]
            else:
                print('Found ghost assigment for principal which will be cleaned up... ')
                continue
        elif assignment['principalType'] == "User":
            #print("Search for user: ", assignment['principalId'])
            user = find_object(assignment['principalId'],users)
            if user is not None:
                if user['userType'] == "Member":
                    rbac_detail['principalEmail'] = user['mail']
                else:
                    rbac_detail['principalEmail'] = user['otherMails'][0]
            else:
                print('Found ghost assigment for user which will be cleaned up: ', assignment)
                continue        
        elif assignment['principalType'] == "Group":
            print("Groups are not yet supported...")
            continue
        rbacs_list.append(rbac_detail)
    return rbacs_list

def write_custom_roles():
    print("Writing custom RBAC roles ...")
    rbac_custom_roles_result = subprocess.run(["az", "role", "definition", "list", "--custom-role-only", "true"], stdout=PIPE, stderr=PIPE, universal_newlines=True)
    custom_roles = json.loads(rbac_custom_roles_result.stdout)
    with open('rbac_custom_roles.json', 'w') as f:
        json.dump(custom_roles, f)

write_custom_roles()

print("Getting users ...")
user_result = subprocess.run(["az", "ad", "user", "list"], stdout=PIPE, stderr=PIPE, universal_newlines=True)

print("Getting service principals ...")
sp_result = subprocess.run(["az", "ad", "sp", "list", "--all"], stdout=PIPE, stderr=PIPE, universal_newlines=True)

print("Getting rbac assignments ...")
rbac_result = subprocess.run(["az", "role", "assignment", "list", "--all"], stdout=PIPE, stderr=PIPE, universal_newlines=True)

print("Getting parsing results ...")
users =  json.loads(user_result.stdout)
sps = json.loads(sp_result.stdout)
rbacs = json.loads(rbac_result.stdout)

print("Matching assignments ...")
rbacs_list = process_rbac(rbacs, users, sps)
with open('rbac.json', 'w') as f:
    json.dump(rbacs_list, f)