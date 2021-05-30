#!/bin/bash
# Add the following after calling the unified agent in a github-action.yml file from the WhiteSource Field Tookit
#         chmod +x ./ghissue-eua.sh
#          ./ghissue-eua.sh

APIURL=https://saas.whitesourcesoftware.com
WS_PROJECTTOKEN=$(jq -r '.projects | .[] | .projectToken' ./whitesource/scanProjectDetails.json)
echo "productName" $WS_PRODUCTNAME
echo "projectName" $WS_PROJECTNAME
echo "projectToken" $WS_PROJECTTOKEN

### Get ProjectID
PROJECTID=$(curl --request POST $APIURL'/api/v1.3' --header 'Content-Type: application/json' --header 'Accept-Charset: UTF-8'  --data-raw '{   'requestType' : 'getOrganizationEffectiveUsageAnalysis',   'userKey' : '$WS_USERKEY',   'orgToken': '$WS_APIKEY','format' : 'json'}' | jq '.products[] | select(.productName=='\"$WS_PRODUCTNAME\"') | .projects[] | select(.projectName=='\"$WS_PROJECTNAME\"') | .projectId ')
echo "PROJECTID:"$PROJECTID

### Get CVE by Red Shield
for redshieldvuln in $(curl --request POST $APIURL'/api/v1.3' --header 'Content-Type: application/json' --header 'Accept-Charset: UTF-8'  --data-raw '{   'requestType' : 'getProjectSecurityAlertsByVulnerabilityReport',   'userKey' : '$WS_USERKEY',   'projectToken': '$WS_PROJECTTOKEN', 'format' : 'json'}' | jq '.alerts[] | select(.euaShield=="RED") | .vulnerabilityId')
do
echo "REDSHIELD"$redshieldvuln

## Get Github issue number by CVE
GHISSUE=$(gh issue list -S $redshieldvuln --json number --jq '.[] | .number ')
echo "GHISSUE:"$GHISSUE

LIBNAME=$(curl --request POST $APIURL'/api/v1.3' --header 'Content-Type: application/json' --header 'Accept-Charset: UTF-8'  --data-raw '{   'requestType' : 'getProjectSecurityAlertsByVulnerabilityReport',   'userKey' : '$WS_USERKEY',   'projectToken': '$WS_PROJECTTOKEN', 'format' : 'json'}' | jq '.alerts[] | select(.vulnerabilityId=='\"$reshieldvuln\"') | .libraryName')

### Get keyUuid - requires productName and projectName
KEYUUID=$(curl --request POST $APIURL'/api/v1.3' --header 'Content-Type: application/json' --header 'Accept-Charset: UTF-8'  --data-raw '{   'requestType' : 'getOrganizationEffectiveUsageAnalysis',   'userKey' : '$WS_USERKEY',   'orgToken': '$WS_APIKEY','format' : 'json'}' | jq -r '.products[] | select(.productName=='\"$WS_PRODUCTNAME\"') | .projects[] | select(.projectName=='\"$WS_PROJECTNAME\"') | .libraries[] | select(.name=='\"$LIBNAME\"') | .keyUuid')
echo "KEYUIID:" $KEYUUID


### Construct Link
EUALINK="$APIURL/Wss/WSS.html#!libraryVulnerabilities;uuid=$KEYUUID;project=$PROJECTID"
echo $EUALINK
done
#gh issue comment $GHISSUE --body "$EUALINK"
