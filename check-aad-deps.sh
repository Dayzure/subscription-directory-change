#!/bin/bash
function check_directory_dependencies() {
    echo "Checking for graph extension on Azure CLI..."
    echo "--------------------------------------------"
    PATTERN='resource-graph'
    string=$(az extension list | grep 'resource-graph')
    if [[ $string == *"resource-graph"* ]]; 
    then
        # az extension update --name resource-graph
        echo 'Graph extension is already installed...'
    else
        echo 'Installing az graph extension. Hold on a second...'
        az extension add --name resource-graph 
    fi
    echo " "
    echo "Azure resources with known Azure AD Tenant dependencies:"
    echo "--------------------------------------------------------"
    subscriptionId=$(az account show --query id | sed -e 's/^"//' -e 's/"$//')
    az graph query -q 'resources | where type != "microsoft.azureactivedirectory/b2cdirectories" | where  identity <> "" or properties.tenantId <> "" or properties.encryptionSettingsCollection.enabled == true | project name, type, kind, identity, tenantId, properties.tenantId' --subscriptions $subscriptionId --output table

    echo " "
    echo "Azure SQL Servers with Azrue AD Authentication"
    echo "----------------------------------------------"
    az sql server ad-admin list --ids $(az graph query -q 'resources | where type == "microsoft.sql/servers" | project id' -o tsv | cut -f1)

    # for resourceId in $(az graph query -q 'resources | where type == "microsoft.sql/servers" | project id' -o tsv | cut -f1)
    #   do 
    #      az sql server ad-admin list --ids $resourceId -o table
    #   done
    
    echo "RBAC role assignments:"
    echo "----------------------"
    az role assignment list --all -o table
}

function generate_report()
{
    subscriptionId=$(az account show --query id | sed -e 's/^"//' -e 's/"$//')
    repHeader='<!doctype html><html lang="en"><head><link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.4.1/css/bootstrap.min.css" integrity="sha384-Vkoo8x4CGsO3+Hhxv8T/Q5PaXtkKtu6ug5TOeNV6gBiFeWPGFN9MuhOf23Q9Ifjh" crossorigin="anonymous"><script src="https://code.jquery.com/jquery-3.4.1.slim.min.js" integrity="sha384-J6qa4849blE2+poT4WnyKhv5vZF5SrPo0iEjwBvKU7imGFAV0wwj1yYfoRSJoZ+n" crossorigin="anonymous"></script><script src="https://cdn.jsdelivr.net/npm/popper.js@1.16.0/dist/umd/popper.min.js" integrity="sha384-Q6E9RHvbIyZFJoft+2mJbHaEWldlvI9IOYy5n3zV9zzTtmI3UksdQRVvoxMfooAo" crossorigin="anonymous"></script><script src="https://stackpath.bootstrapcdn.com/bootstrap/4.4.1/js/bootstrap.min.js" integrity="sha384-wfSDF2E50Y2D1uUdj0O3uMBJnjuUD4Ih7YwaYd1iqfktj0Uod8GCExl3Og8ifwB6" crossorigin="anonymous"></script><title>Azure AD Tenant dependencies report</title></head><body><div class="d-flex flex-column flex-md-row align-items-center p-3 px-md-4 mb-3 bg-white border-bottom shadow-sm"><h5 class="my-0 mr-md-auto font-weight-normal">Tenant Dependencies</h5><nav class="my-2 my-md-0 mr-md-3"><a class="p-2 text-dark" href="#">Documentation</a><a class="p-2 text-dark" href="#">GitHub Repository</a></nav></div><div class="container"><table class="table table-hover table-sm"><thead><tr><th scope="col">Name</th><th scope="col">Type</th><th scope="col">Kind</th><th scope="col">Identity</th><th scope="col">Tenant ID</th><th scope="col">Tenant ID (prop)</th></tr></thead><tbody>'
    repFooter='</tbody></table></div><script src="https://code.jquery.com/jquery-3.4.1.slim.min.js" integrity="sha384-J6qa4849blE2+poT4WnyKhv5vZF5SrPo0iEjwBvKU7imGFAV0wwj1yYfoRSJoZ+n" crossorigin="anonymous"></script><script src="https://cdn.jsdelivr.net/npm/popper.js@1.16.0/dist/umd/popper.min.js" integrity="sha384-Q6E9RHvbIyZFJoft+2mJbHaEWldlvI9IOYy5n3zV9zzTtmI3UksdQRVvoxMfooAo" crossorigin="anonymous"></script><script src="https://stackpath.bootstrapcdn.com/bootstrap/4.4.1/js/bootstrap.min.js" integrity="sha384-wfSDF2E50Y2D1uUdj0O3uMBJnjuUD4Ih7YwaYd1iqfktj0Uod8GCExl3Og8ifwB6" crossorigin="anonymous"></script></body></html>'
    subscriptionId=$(az account show --query id | sed -e 's/^"//' -e 's/"$//')
    resources=$(az graph query -q 'resources | where type != "microsoft.azureactivedirectory/b2cdirectories" | where  identity <> "" or properties.tenantId <> "" or properties.encryptionSettingsCollection.enabled == true | project name, type, kind, identity, tenantId, properties.tenantId' --subscriptions $subscriptionId | jq -c '.[]')

    report=$repHeader

    for row in $resources; do
        _jq() {
            echo ${row} | jq -r ${1}
        }
        trow="<tr><th scope='row'>"
        trow+=$(_jq '.name')
        trow+="</th><td>"
        trow+=$(_jq '.type')
        trow+="</td><td>"
        trow+=$(_jq '.kind')
        trow+="</td><td>"
        trow+=$(_jq '.identity')
        trow+="</td><td>"
        trow+=$(_jq '.tenantId')
        trow+="</td><td>"
        trow+=$(_jq '.properties_tenantId')
        trow+="</td></tr>"
        report+="$trow"
    done
    report+=$repFooter
    reportFileName = "report-${subscriptionId}.html"
    echo "$report" > $reportFileName
    echo "Download report from '/clouddrive/dirchange-${subscriptionId}/${reportFileName}'"
}

check_directory_dependencies
generate_report

python dump-rbac.py