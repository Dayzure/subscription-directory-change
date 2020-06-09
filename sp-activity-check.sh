#!/bin/bash
function check_sp_activities () {
    echo "Checking for Service Principal assignments on your resources"
    echo "--------------------------------------------"
    spassignments=$(az role assignment list --all --query "[?principalType == 'ServicePrincipal'].principalId" | jq -r ".[]" | sort | uniq)

    echo " "
    echo "Looping over service principal assignments:"
    echo "--------------------------------------------------------"

    for sp in $spassignments; do
        spName=$(az ad sp show --id $sp --query "[appDisplayName,servicePrincipalType,alternativeNames]" -o tsv | xargs | sed 's/ /, /g')
        echo "(Only the top 1) activity for ${sp} (${spName})"
        az monitor activity-log list --caller $sp --max-events 1 --offset $1d --query "[].{caller:caller, resourceGroup:resourceGroup, operation:operationName.localizedValue, category:category.value, provider:resourceProvider.value, resourceType:resourceType.value, resource:resourceId}"
        echo "---------------------------------------------------------------------"
    done 
    
}

if [ "$1" != "" ]; then
    check_sp_activities $1
else
    echo "Missing days param"
    echo "Usage: sp-activity-check.sh <number of days to look behind>"
    echo "example: "
    echo "./sp-activity-check.sh 30"
fi