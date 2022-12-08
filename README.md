# ms-openhack-containers-2022

Open Hack Containers

Components:
Trip Viewer WebApp (.NET Core): Your customers use this web application to review their driving scores and trips. The trips are being simulated against the APIs within the OpenHack environment. --> Dockerfile_1
Trip API (Go): The mobile application sends the vehicle’s on-board diagnostics (OBD) trip data to this API to be stored. ==> Dockerfile_4
Points of Interest API (.NET Core): This API is used to collect the points of the trip when a hard stop or hard acceleration was detected. ==>Dockerfile_3
User Profile API (NodeJS): This API is used by the application to read the user’s profile information. --> Dockerfile_2
User API (Java): This API is used by the application to create and modify the users. --> Dockerfile_0
SQL database: mcr.microsoft.com/mssql/server:2017-latest  You can pull it using `docker pull mcr.microsoft.com/mssql/server:2017-latest`

Challenge 1 (POI / SQL) :

Run SQL Container : 
Super Admin User is: SA
Retrieve the SQL Server Image
docker pull mcr.microsoft.com/mssql/server:2017-latest (x86, x64)
docker pull mcr.microsoft.com/azure-sql-edge:latest (ARM)
Run the SQL container
MSSQL_SA_PASSWORD=NoSugarNoHack007!
docker run -e "ACCEPT_EULA=Y" -e "MSSQL_SA_PASSWORD=$MSSQL_SA_PASSWORD"  -p 1433:1433 --name sql1 --hostname sql1  -d  mcr.microsoft.com/mssql/server:2017-latest
Connect from outside the container
sudo apt-get install mssql-tools
sqlcmd -S localhost,1433 -U SA -P "$MSSQL_SA_PASSWORD"
Connect inside the container
docker exec -it sql1 "bash"
/opt/mssql-tools/bin/sqlcmd -S localhost -U SA -P NoSugarNoHack007!
Create DB
CREATE DATABASE mydrivingDB;
SELECT Name from sys.databases;
GO
docker inspect sql1
(az login --scope https://management.core.windows.net//.default) -->az acr login -n registrynhi6414 
docker pull registrynhi6414.azurecr.io/dataload:1.0
You can use this command to load data into the SQL container: docker run -e SQLFQDN=$(docker inspect sql1 --format='{{range $k,$v := .NetworkSettings.Networks}}{{$v.IPAddress}}{{end}}') -e SQLUSER=SA -e SQLPASS=$MSSQL_SA_PASSWORD -e SQLDB=mydrivingDB registrynhi6414.azurecr.io/dataload:1.0
Alternatively, you can run the following commands separately to get the IP address of the sql1 container and use it to load the data:
To get the IP address, you can use the following command: docker inspect sql1 --format='{{range $k,$v := .NetworkSettings.Networks}}{{$v.IPAddress}}{{end}}'
docker run --network host -e SQLFQDN=172.17.0.2,1433 -e SQLUSER=SA -e SQLPASS=$MSSQL_SA_PASSWORD -e SQLDB=mydrivingDB registrynhi6414.azurecr.io/dataload:1.0
docker run --network host -e SQLFQDN="host.docker.internal,1433" -e SQLUSER=SA -e SQLPASS=$MSSQL_SA_PASSWORD -e SQLDB=mydrivingDB registrynhi6414.azurecr.io/dataload:1.0 ==> https://github.com/microsoft/msphpsql/issues/302#issuecomment-1002810115

Microsoft SQL Server - Ubuntu based images by Microsoft | Docker Hub
Troubleshoot
docker exec -t sql1 cat /var/opt/mssql/log/errorlog | grep connection
sqlcmd -S sql1,1433 -U SA
https://github.com/microsoft/msphpsql/issues/302#issuecomment-1002810115
C:\Windows\System32\drivers\etc\hosts shows:

Added by Docker Desktop
192.168.1.98 host.docker.internal
192.168.1.98 gateway.docker.internal

Building the POI image
git clone git@github.com:Microsoft-OpenHack/containers_artifacts.git
cd containers_artifacts/src/poi
cp ../../dockerfiles/Dockerfile_3 Dockerfile
We need to update the environment variables in Dockerfile (starting with ENV) with the appropriate ones
in containers_artifacts/src/poi/web/Dockerfile set ASPNETCORE_ENVIRONMENT="Local"
docker build -t poi .
docker run -p 8080:80 -e SQL_SERVER=172.17.0.2  poi | or docker run -p 8080:80 -e SQL_SERVER=host.docker.internal poi
Open the url localhost:8080/api/poi/ in your browser to ensure the POI service works as expected
Push POI images
docker tag poi registrynhi6414.azurecr.io/tripviewer2/poi
az acr login --name registrynhi6414
docker push registrynhi6414.azurecr.io/tripviewer/poi

Build / Push Trip image
cd containers_artifacts/src/trips
cp ../../dockerfiles/Dockerfile_4 Dockerfile
docker build -t registrynhi6414.acr.io/trips .
docker push registrynhi6414.acr.io/tripviewer/trips
Build / Push TripViewer image
cd containers_artifacts/src/tripviewer
cp ../../dockerfiles/Dockerfile_1 Dockerfile
docker build -t registrynhi6414.azurecr.io/tripviewer .
docker push registrynhi6414.acr.io/tripviewer/tripviewer
Build / Push UserProfile image
cd containers_artifacts/src/userprofile
cp ../../dockerfiles/Dockerfile_x Dockerfile_2
docker build -t registrynhi6414.azurecr.io/userprofile .
docker push registrynhi6414.acr.io/tripviewer/userprofile
Build / Push User API image
cd containers_artifacts/src/user-java
cp ../../dockerfiles/Dockerfile_0 Dockerfile
docker build -t registrynhi6414.azurecr.io/user-java .
docker push registrynhi6414.acr.io/tripviewer/user-java

# Challenge 2 (AKS / TripView & APIs) :

-AKS Creation using the Azure Portal (ACR attached, UAI properly provisioned)
Check cluster creation
az aks get-credentials --resource-group teamResources --name aks-team5
kubectl cluster-info 
kubectl get nodes -o wide
Create secret
kubectl create secret generic sql-password --from-literal=SQL_PASSWORD=NoSugarNoHack007! --dry-run=client -o yaml > db_secret.yaml
kubectl apply -f db_secret.yaml 
k get secrets
kubectl get secret sql-password -o jsonpath='{.data.*}' | base64 -d
Create Deployments
kubectl create deployment poi --image=registrynhi6414.azurecr.io/tripviewer/poi  --replicas=3 --port=80 --dry-run=client -o yaml > poi_deployment.yaml
Check cluster creation
az aks get-credentials --resource-group teamResources --name aks-team5
kubectl cluster-info 
kubectl get nodes -o wide
Add Env. var : https://kubernetes.io/docs/tasks/inject-data-application/define-environment-variable-container/
Register the secret in the deployment file : Secrets | Kubernetes
k apply -f poi_deployment.yaml 
k apply -f trips_deployment.yaml 
k apply -f tripviewer_deployment.yaml 
k apply -f user-java_deployment.yaml 
k apply -f userprofile_deployment.yaml 
k get po
k get deploy
Create services
kubectl create service clusterip poi --tcp=80:80 --dry-run=client -o yaml > poi_svc.yaml
 kubectl  expose  deployment poi --name=poi --type=ClusterIP --port=80 --target-port=80  --dry-run=client -o yaml

kubectl create service clusterip trips --tcp=80:80 --dry-run=client -o yaml > trips_svc.yaml
kubectl expose deployment trips --name=trips --type=ClusterIP --port=80 --target-port=80 --dryn-run=client -o yaml

kubectl create service clusterip user-java --tcp=80:80 --dry-run=client -o yaml > user-java_svc.yaml
kubectl expose deployment user-java--name=user-java --type=ClusterIP --port=80 --target-port=80 --dryn-run=client -o yaml

kubectl create service clusterip userprofile --tcp=80:80 --dry-run=client -o yaml > userprofile_svc.yaml
kubectl expose deployment userprofile--name=userprofile --type=ClusterIP --port=80 --target-port=80 --dryn-run=client -o yaml

kubectl create service clusterip tripviewer --tcp=80:80 --dry-run=client -o yaml > tripviewer_svc.yaml

Connect to TripViewer Pod
k get po -l app=tripviewer
k exec -it tripviewer-879fd9fff-p9648 -- sh
kubectl port-forward service/tripviewer 8442:80
kubectl port-forward service/poi 8081:80

# Challenge 3 (AKS / RBAC) :

-AKS Cluster creation (Westus)
IP - Subnet IP availability = 250 IPs max
-Authentication using Azure Active directory / Authorization using both kubernetes RBAC and Azure RBAC (recommended)
-
Check cluster creation
az aks get-credentials --resource-group teamResources --name AKS-OPTeam5
kubectl cluster-info 
kubectl get nodes -o wide
Create two Azure AD Group for Admin / User
kubectl apply -f cluster-role.yaml

# Challenge 4 AKS / Ingress + KV ) :

-AKS Cluster creation (Westus)
Create Ingress Controller
Create an ingress controller in Azure Kubernetes Service (AKS) - Azure Kubernetes Service | Microsoft Learn
NAMESPACE=ingress
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
helm repo update

helm install ingress-nginx ingress-nginx/ingress-nginx \
--create-namespace \
--namespace $NAMESPACE \
--set controller.service.annotations."service\.beta\.kubernetes\.io/azure-load-balancer-health-probe-request-path"=/healthz

k get svc -n $NAMESPACE 
service_ip=$(k get service ingress-nginx-controller -n $NAMESPACE -o jsonpath="{.status.loadBalancer.ingress[*].ip}") 

az aks list -g teamResources
managed_rg=MC_teamResources_aks-team5_westeurope
public_ip_id=$(az network public-ip list -g $managed_rg --query "[?ipAddress!=null]|[?contains(ipAddress, '$service_ip')].[id]" --output tsv) echo $public_ip_id
Define & apply the ingress rules :
kubectl apply -f ingress-tripviewer.yaml

DNS Zone
In the Azure portal, go to All services / Public IP addresses / kubernetes-xxxx - Configuration ( the Ingress Controller IP) , (you will also find this PIP in AKS MC_ RG) then there is a field "DNS name label (optional)" ==> An "A record" that starts with the specified label and resolves to this public IP address will be registered with the Azure-provided DNS servers. Example: team5rocks.westeurope.cloudapp.azure.com
team5rocks.westus.cloudapp.azure.com

Enable secret store CSI Driver on AKS (Configuration section)
Check provisionning done : kubectl get pods -n kube-system -l 'app in (secrets-store-csi-driver, secrets-store-provider-azure)'
Create Azure Keyvault
az keyvault create --name "kv-team5" --resource-group "teamResources" --location "WestUS"
Add the secret in the KV
az keyvault secret set --name SQL-PASSWORD --vault-name kv-team5 --value NoSugarNoHack007! 
Create Managed Identity to access the KV from AKS 
az aks identity show -n AKS-OPTeam5 -g teamResources  -o yaml
az aks show -n AKS-OPTeam5 -g teamResources --query addonProfiles.azureKeyvaultSecretsProvider.identity.clientId -o tsv
==> e25c17dc-e129-4a5a-9749-398039fdbd47
az aks update -n AKS-OPTeam5 -g teamResources --enable-managed-identity
az keyvault set-policy -n kv-team5 --secret-permissions get --spn e25c17dc-e129-4a5a-9749-398039fdbd47
Using the Azure Key Vault Provider | Azure Key Vault Provider for Secrets Store CSI Driver
secrets-store-csi-driver-provider-azure/v1alpha1_secretproviderclass_secrets.yaml at master · Azure/secrets-store-csi-driver-provider-azure (github.com)
k get secretproviderclass


# Challenge 5 AKS Observability :

xxx

# Challenge 6 AKS security:



Do not allow privileged containers in Kubernetes cluster" By default, Docker containers are “unprivileged” and cannot, for example, run a Docker daemon inside a Docker container. This is because by default a container is not allowed to access any devices, but a “privileged” container is given access to all devices (see the documentation on cgroups devices).
When the operator executes docker run --privileged, Docker will enable access to all devices on the host as well as set some configuration in AppArmor or SELinux to allow the container nearly all the same access to the host as processes running outside containers on the host.
See also this blog

https://learn.microsoft.com/en-us/azure/aks/policy-reference?source=recommendations
https://store.policy.core.windows.net/kubernetes/container-no-privilege/v2/template.yaml
https://github.com/open-policy-agent/gatekeeper-library/tree/master/library/pod-security-policy/privileged-containers/samples/psp-privileged-container
https://github.com/open-policy-agent/gatekeeper-library/tree/master/library/general

azure-arc/setup-aks.md at master · ezYakaEagle442/azure-arc (github.com)


https://github.com/ezYakaEagle442/azure-arc/blob/master/app/root-pod-privileged.yaml
https://github.com/ezYakaEagle442/azure-arc/blob/master/app/dark-registry_deployment.yaml
https://github.com/ezYakaEagle442/azure-arc/blob/master/app/Dockerfile_root-demo

# Try to deploy a "bad" 
Pod k apply -f app/root-pod.yaml 

# You should see the error below Error from server 
([denied by azurepolicy-container-no-privilege-dc2585889397ecb73d135643b3e0e0f2a6da54110d59e676c2286eac3c80dab5] Privileged container is not allowed: root-demo, securityContext: {"privileged": true}): error when creating "root-demo-pod.yaml": admission webhook "validation.gatekeeper.sh" denied the request: [denied by azurepolicy-container-no-privilege-dc2585889397ecb73d135643b3e0e0f2a6da54110d59e676c2286eac3c80dab5] Privileged container is not allowed: root-demo, securityContext: {"privileged": true} 

Deploy and configure an Azure Kubernetes Service (AKS) cluster with workload identity (preview) - Azure Kubernetes Service | Microsoft Learn
-az extension add --name aks-preview
-az feature register --namespace "Microsoft.ContainerService" --name "EnableWorkloadIdentityPreview"
-az feature show --namespace "Microsoft.ContainerService" --name "EnableWorkloadIdentityPreview" (Check Registration Status)
-az provider register --namespace Microsoft.ContainerService
-az aks update -g teamResources -n AKS-OPTeam5 --enable-oidc-issuer --enable-workload-identit


Managed Identity SQL (Tutorial: Use a managed identity to access Azure SQL Database - Windows - Azure AD - Microsoft Entra | Microsoft Learn)
CREATE USER [id-trip-sql] FROM EXTERNAL PROVIDER
ALTER ROLE db_owner ADD MEMBER [id-trip-sql]
