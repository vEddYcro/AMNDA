# AMNDA Verification Laboratory Cookbook

**Resource Group:** AMNDAVerif | **Region:** eastus  
**Based on:** AMNDA: An adaptive multi-layer, lifecycle-aware defense architecture for multi-stage cyberattacks with Azure-based validation

---

## Key Resource Reference

| Resource | Value |
|---|---|
| Subscription ID | `<YOUR_SUBSCRIPTION_ID>` |
| Tenant ID | `<YOUR_TENANT_ID>` |
| Resource Group | `AMNDAVerif` |
| VNet | `VNET-AMNDA` (10.0.0.0/16) |
| Log Analytics Workspace | `LAW-AMNDA` |
| LAW Resource ID | `/subscriptions/<YOUR_SUBSCRIPTION_ID>/resourceGroups/AMNDAVerif/providers/Microsoft.OperationalInsights/workspaces/LAW-AMNDA` |
| LAW GUID | `<YOUR_LAW_GUID>` |
| Firewall | `FW-AMNDA` — public IP `<YOUR_FIREWALL_PUBLIC_IP>`, private IP `10.0.5.4` |
| VM1-Edge | `10.0.1.4` — Subnet-Edge — internet-facing via firewall DNAT |
| VM2-App | `10.0.2.4` — Subnet-App — internal only |
| VM3-Internal | `10.0.3.4` — Subnet-Internal — internal only |
| CA Policy ID | `<YOUR_CA_POLICY_ID>` (AMNDA-MFA-Enforcement) |
| Admin Username | `<YOUR_ADMIN_USERNAME>` |

---

## Architecture Map

| AMNDA State | Adversarial Stage | Azure Layer | Playbook |
|---|---|---|---|
| s₀ | Reconnaissance / Port Scan | Azure Firewall + IIS on VM1-Edge | — |
| s₁ | Initial Access / Credential Abuse | Entra ID Conditional Access | PLB-S1-IdentityTighten |
| s₂ | Privilege Escalation | PIM + Defender for Cloud | PLB-S2-PrivilegeRestrict |
| s₃ | Lateral Movement | NSG micro-segmentation + UEBA | PLB-S3-SegmentationTighten |
| s₄ | Persistence / C2 | MDE host isolation | PLB-S4-HostIsolation |

---

## Global Variables

Run this block at the start of every Cloud Shell session. All commands reference these variables.

```bash
# Auth
az login  # skip if already authenticated via Cloud Shell
az account set --subscription "<YOUR_SUBSCRIPTION_ID>"

# Global vars
RG="AMNDAVerif"
LOCATION="eastus"
VNET="VNET-AMNDA"
LAW="LAW-AMNDA"
ADMIN_USER="<YOUR_ADMIN_USERNAME>"
ADMIN_PASS="<YOUR_ADMIN_PASSWORD>"
IMAGE="Win2022Datacenter"
SIZE="Standard_D2s_v3"
NW_RG="NetworkWatcherRG"
SUBSCRIPTION=$(az account show --query id -o tsv)

# Derived IDs
LAW_ID=$(az monitor log-analytics workspace show \
  --resource-group "$RG" --workspace-name "$LAW" \
  --query id -o tsv)
LAW_GUID=$(az monitor log-analytics workspace show \
  --resource-group "$RG" --workspace-name "$LAW" \
  --query customerId -o tsv)
FW_ID=$(az network firewall show --resource-group "$RG" --name FW-AMNDA --query id -o tsv)
FW_IP="<YOUR_FIREWALL_PUBLIC_IP>"

# Tenant domain (needed for user operations)
DOMAIN=$(az rest --method get \
  --url "https://graph.microsoft.com/v1.0/domains" \
  --query "value[?isDefault].id" -o tsv)

# PrivAdmin object ID (needed for Scenario C)
PRIV_USER_ID=$(az ad user show --id "privadmin@${DOMAIN}" --query id -o tsv)

# CA policy ID
CA_POLICY_ID="<YOUR_CA_POLICY_ID>"

# VM internal IPs
VM2_IP=$(az vm show --resource-group "$RG" --name VM2-App --show-details --query privateIps -o tsv)

echo "All variables set."
echo "LAW_GUID: $LAW_GUID | FW_IP: $FW_IP | DOMAIN: $DOMAIN | VM2_IP: $VM2_IP"
```

> **⚠ WARNING:** VMs and Azure Firewall incur cost while running. Deallocate VMs between sessions:
> `az vm deallocate --resource-group $RG --name <VM_NAME>`

---

## Phase 0 — Network Foundation

### Step 0.1 — Create Resource Group

```bash
az group create --name "$RG" --location "$LOCATION"
az group show --name "$RG" --query "{name:name,state:properties.provisioningState}"
```

### Step 0.2 — Create VNet and Subnets

```bash
az network vnet create \
  --resource-group "$RG" --name "$VNET" \
  --address-prefixes 10.0.0.0/16 --location "$LOCATION"

for SUBNET_NAME SUBNET_PREFIX in \
  "Subnet-Edge" "10.0.1.0/24" \
  "Subnet-App" "10.0.2.0/24" \
  "Subnet-Internal" "10.0.3.0/24" \
  "Subnet-Management" "10.0.4.0/24"; do
  az network vnet subnet create \
    --resource-group "$RG" --vnet-name "$VNET" \
    --name "$SUBNET_NAME" --address-prefixes "$SUBNET_PREFIX"
done
```

---

## Phase 1 — Baseline Infrastructure

### Step 1.1 — Deploy Three Virtual Machines

VM1-Edge is public-facing (via firewall DNAT — no direct public IP). VM2-App and VM3-Internal are internal.

```bash
# VM1-Edge — Subnet-Edge, no direct public IP (firewall DNAT handles access)
az vm create \
  --resource-group "$RG" --name VM1-Edge \
  --image "$IMAGE" --size "$SIZE" \
  --admin-username "$ADMIN_USER" --admin-password "$ADMIN_PASS" \
  --vnet-name "$VNET" --subnet Subnet-Edge \
  --public-ip-address "" --nsg "" \
  --location "$LOCATION"

# VM2-App — Subnet-App, internal only
az vm create \
  --resource-group "$RG" --name VM2-App \
  --image "$IMAGE" --size "$SIZE" \
  --admin-username "$ADMIN_USER" --admin-password "$ADMIN_PASS" \
  --vnet-name "$VNET" --subnet Subnet-App \
  --public-ip-address "" --nsg "" \
  --location "$LOCATION"

# VM3-Internal — Subnet-Internal, internal only
az vm create \
  --resource-group "$RG" --name VM3-Internal \
  --image "$IMAGE" --size "$SIZE" \
  --admin-username "$ADMIN_USER" --admin-password "$ADMIN_PASS" \
  --vnet-name "$VNET" --subnet Subnet-Internal \
  --public-ip-address "" --nsg "" \
  --location "$LOCATION"

# Install Azure Monitor Agent on all VMs
for VM in VM1-Edge VM2-App VM3-Internal; do
  az vm extension set \
    --resource-group "$RG" --vm-name "$VM" \
    --name AzureMonitorWindowsAgent \
    --publisher Microsoft.Azure.Monitor \
    --version 1.0 --enable-auto-upgrade true
done
```

### Step 1.2 — Configure the Identity Layer (Entra ID)

```bash
# Get tenant domain
DOMAIN=$(az rest --method get \
  --url "https://graph.microsoft.com/v1.0/domains" \
  --query "value[?isDefault].id" -o tsv)
echo "Tenant domain: $DOMAIN"

# Create three standard test users
for N in 1 2 3; do
  az ad user create \
    --display-name "Test User $N" \
    --user-principal-name "testuser${N}@${DOMAIN}" \
    --password "<TEMP_PASSWORD>" \
    --force-change-password-next-sign-in false
done

# Create privileged admin (used in Scenario C)
az ad user create \
  --display-name "PrivAdmin" \
  --user-principal-name "privadmin@${DOMAIN}" \
  --password "<ADMIN_PASSWORD>" \
  --force-change-password-next-sign-in false

PRIV_USER_ID=$(az ad user show --id "privadmin@${DOMAIN}" --query id -o tsv)
echo "PRIV_USER_ID: $PRIV_USER_ID"
```

### Step 1.3 — Create Log Analytics Workspace

```bash
az monitor log-analytics workspace create \
  --resource-group "$RG" \
  --workspace-name "$LAW" \
  --location "$LOCATION" \
  --sku PerGB2018 \
  --retention-time 30

LAW_ID=$(az monitor log-analytics workspace show \
  --resource-group "$RG" --workspace-name "$LAW" \
  --query id -o tsv)
LAW_GUID=$(az monitor log-analytics workspace show \
  --resource-group "$RG" --workspace-name "$LAW" \
  --query customerId -o tsv)
echo "LAW_ID: $LAW_ID"
echo "LAW_GUID: $LAW_GUID"
```

### Step 1.4 — Deploy Microsoft Sentinel

```bash
az extension add --name sentinel
az extension update --name sentinel --allow-preview True

az sentinel onboarding-state create \
  --resource-group "$RG" \
  --workspace-name "$LAW" \
  --name default \
  --customer-managed-key false
```

### Step 1.5 — Enable Defender Plans

Enable via portal: **Microsoft 365 Admin Center → Billing → Purchase services**. Activate 30-day free trials for:
- Microsoft Entra ID P2
- Microsoft Defender for Endpoint Plan 2
- Microsoft Defender for Cloud — Servers plan
- Microsoft Sentinel

### Step 1.6 — Connect Data Connectors in Sentinel

```bash
SUBSCRIPTION=$(az account show --query id -o tsv)
BASE="https://management.azure.com/subscriptions/$SUBSCRIPTION/resourceGroups/$RG/providers/Microsoft.OperationsManagement/solutions"
API="?api-version=2015-11-01-preview"

az rest --method put \
  --url "$BASE/AzureActivity($LAW)$API" \
  --body '{
    "location":"eastus",
    "plan":{"name":"AzureActivity","publisher":"Microsoft","product":"OMSGallery/AzureActivity","promotionCode":""},
    "properties":{"workspaceResourceId":"'$LAW_ID'"}
  }'
```

**Microsoft Defender XDR connector** — required for s₄ MDE alert streaming:

**portal.azure.com → Microsoft Sentinel → LAW-AMNDA → Data connectors → Microsoft Defender XDR → Install → Open connector page**

Under **Connect events**, enable:
- **Microsoft Defender Alerts:** AlertInfo, AlertEvidence
- **Microsoft Defender for Endpoint:** DeviceInfo, DeviceFileEvents (optional, useful for metrics)

> **⚠ NOTE:** The "Connect incidents & alerts" section will show a warning that the workspace is onboarded to the Unified Security Operations Platform, which disables the traditional incident sync. This is expected. MDE alerts stream via the unified platform to security.microsoft.com. The Defender XDR event tables (AlertInfo, AlertEvidence) still populate in Log Analytics and can be queried from Sentinel.

### Step 1.7 — Configure Entra ID Diagnostic Settings

**portal.azure.com → Entra ID → Monitoring → Diagnostic settings → + Add diagnostic setting**

- Name: `AMNDA-EntraID-Diag`
- Categories: SigninLogs, AuditLogs
- Destination: LAW-AMNDA

### Step 1.8 — Configure Azure Activity Log Collection

**portal.azure.com → Monitor → Activity log → Export Activity Logs → + Add diagnostic setting**

- Name: `AMNDA-ActivityLog-Diag`
- Categories: Administrative, Security, Policy, Alert
- Destination: LAW-AMNDA

### Step 1.9 — Create Data Collection Rules (DCRs)

**DCR 1 — Windows Security Events** (required for s₃ lateral movement detection):

**portal.azure.com → Microsoft Sentinel → LAW-AMNDA → Content hub → search "Windows Security Events" → Install → Manage → Windows Security Events via AMA → Open connector page → + Create data collection rule**

- Rule name: `DCR-AMNDA-SecurityEvents-Sentinel`
- Resource group: AMNDAVerif
- Resources: VM1-Edge, VM2-App, VM3-Internal
- Collect: All Security Events

**DCR 2 — Heartbeat / Performance Counters**:

**Monitor → Data Collection Rules → + Create**

- Rule name: `DCR-AMNDA-Heartbeat`
- Platform: Windows
- Resources: VM1-Edge, VM2-App, VM3-Internal
- Data source: Performance Counters (Basic)
- Destination: LAW-AMNDA

```bash
# Capture Heartbeat DCR ID after creation
DCR_HB_ID=$(az monitor data-collection rule show \
  --resource-group "$RG" --name "DCR-AMNDA-Heartbeat" \
  --query id -o tsv)
echo "DCR_HB_ID: $DCR_HB_ID"
```

### Step 1.10 — Associate Heartbeat DCR with VMs

```bash
for VM in VM1-Edge VM2-App VM3-Internal; do
  VM_ID=$(az vm show --resource-group "$RG" --name "$VM" --query id -o tsv)
  az monitor data-collection rule association create \
    --name "AMNDA-Heartbeat-$VM" \
    --resource "$VM_ID" \
    --data-collection-rule-id "$DCR_HB_ID"
  echo "Heartbeat DCR associated to $VM"
done
```

### Step 1.11 — Verify Telemetry Ingestion

Wait 15–30 minutes after association, then verify all tables are populated:

```bash
# Heartbeat
az monitor log-analytics query --workspace "$LAW_GUID" \
  --analytics-query "Heartbeat | summarize LastHeartbeat=max(TimeGenerated) by Computer | order by LastHeartbeat desc" \
  --timespan PT1H

# SecurityEvent
az monitor log-analytics query --workspace "$LAW_GUID" \
  --analytics-query "SecurityEvent | summarize Count=count() by Computer | order by Count desc" \
  --timespan PT1H

# SigninLogs
az monitor log-analytics query --workspace "$LAW_GUID" \
  --analytics-query "SigninLogs | summarize Count=count() by ResultType | order by Count desc" \
  --timespan PT1H

# AuditLogs
az monitor log-analytics query --workspace "$LAW_GUID" \
  --analytics-query "AuditLogs | summarize Count=count() by OperationName | order by Count desc" \
  --timespan PT1H
```

---

## Phase 2 — AMNDA Defensive Layers

### Layer 1: Edge Defense (s₀) — Azure Firewall

#### Deploy Azure DDoS Protection Standard

> **⚠ WARNING:** DDoS Protection Standard costs approximately $2,944/month. Enable it only for the active test window and delete it immediately afterward.

DDoS Protection Standard is an architectural component of the s₀ edge defense layer as defined in Section 4 of the paper. It operates at the platform level and does not generate telemetry that flows into Sentinel — it cannot be used as a detection signal or analytics rule source. Its role in the lab is to demonstrate that the AMNDA edge layer is fully instantiated using Azure-native services.

```bash
az network ddos-protection create \
  --resource-group "$RG" \
  --name DDoS-AMNDA \
  --location "$LOCATION"

DDOS_ID=$(az network ddos-protection show \
  --resource-group "$RG" --name DDoS-AMNDA --query id -o tsv)

# Associate with VNet
az network vnet update \
  --resource-group "$RG" --name "$VNET" \
  --ddos-protection true \
  --ddos-protection-plan "$DDOS_ID"

# Verify
az network ddos-protection show \
  --resource-group "$RG" --name DDoS-AMNDA \
  --query "{Name:name,State:provisioningState,Location:location}"

az network vnet show \
  --resource-group "$RG" --name "$VNET" \
  --query "{DDoSEnabled:enableDdosProtection,DDoSPlan:ddosProtectionPlan.id}"
```

**Delete after the test window:**

The `az network ddos-protection delete` CLI command may fail depending on the CLI version. Use PowerShell instead:

```powershell
# Disassociate from VNet first
$vnet = Get-AzVirtualNetwork -ResourceGroupName "AMNDAVerif" -Name "VNET-AMNDA"
$vnet.DdosProtectionPlan = $null
$vnet.EnableDdosProtection = $false
Set-AzVirtualNetwork -VirtualNetwork $vnet

# Then delete the plan
Remove-AzDdosProtectionPlan -ResourceGroupName "AMNDAVerif" -Name "DDoS-AMNDA"
```

#### Deploy Azure Firewall

```bash
# AzureFirewallSubnet is a mandatory name — minimum /26
az network vnet subnet create \
  --resource-group "$RG" --vnet-name "$VNET" \
  --name AzureFirewallSubnet --address-prefixes 10.0.5.0/26

az network public-ip create \
  --resource-group "$RG" --name PIP-FW-AMNDA \
  --sku Standard --allocation-method Static

az network firewall create \
  --resource-group "$RG" --name FW-AMNDA \
  --location "$LOCATION" --sku AZFW_VNet --tier Standard

az network firewall ip-config create \
  --firewall-name FW-AMNDA --resource-group "$RG" \
  --name FW-Config \
  --public-ip-address PIP-FW-AMNDA \
  --vnet-name "$VNET"

FW_ID=$(az network firewall show --resource-group "$RG" --name FW-AMNDA --query id -o tsv)
FW_IP=$(az network public-ip show --resource-group "$RG" --name PIP-FW-AMNDA --query ipAddress -o tsv)
echo "FW_ID: $FW_ID | FW_IP: $FW_IP"
```

#### Enable Firewall Diagnostic Logging → Sentinel

```bash
az monitor diagnostic-settings create \
  --resource "$FW_ID" \
  --name FW-AMNDA-Diag \
  --workspace "$LAW_ID" \
  --logs '[{"category":"AzureFirewallNetworkRule","enabled":true},{"category":"AzureFirewallApplicationRule","enabled":true}]'

# Verify
az monitor diagnostic-settings show \
  --resource "$FW_ID" --name FW-AMNDA-Diag \
  --query "{Name:name,Workspace:workspaceId,NetworkRule:logs[0].enabled,AppRule:logs[1].enabled}"
```

#### Configure Firewall Rules

The s₀ detection relies on DNAT'd traffic passing through the firewall and being logged as `AzureFirewallNetworkRule`. Only traffic with an active DNAT rule is forwarded into the VNet and logged. The firewall must have DNAT rules for all ports you intend to scan.

**Step 1 — Add DNAT rules and network/application rules via REST API** (the CLI `az network firewall nat-rule create` uses a deprecated API version; use REST directly):

```bash
az rest --method PUT \
  --url "https://management.azure.com${FW_ID}?api-version=2024-10-01" \
  --body "$(az rest --method GET --url "https://management.azure.com${FW_ID}?api-version=2024-10-01" | python3 -c "
import sys,json
fw=json.load(sys.stdin)

# NAT rule collection
fw['properties']['natRuleCollections'] = [{
  'name': 'AMNDA-DNAT-Rules',
  'properties': {
    'priority': 100,
    'action': {'type': 'Dnat'},
    'rules': [
      {'name':'DNAT-RDP-To-VM1-Edge','protocols':['TCP'],'sourceAddresses':['*'],'destinationAddresses':['<YOUR_FIREWALL_PUBLIC_IP>'],'destinationPorts':['3389'],'translatedAddress':'10.0.1.4','translatedPort':'3389'},
      {'name':'DNAT-HTTP-To-VM1-Edge','protocols':['TCP'],'sourceAddresses':['*'],'destinationAddresses':['<YOUR_FIREWALL_PUBLIC_IP>'],'destinationPorts':['80'],'translatedAddress':'10.0.1.4','translatedPort':'80'},
      {'name':'DNAT-Port-443','protocols':['TCP'],'sourceAddresses':['*'],'destinationAddresses':['<YOUR_FIREWALL_PUBLIC_IP>'],'destinationPorts':['443'],'translatedAddress':'10.0.1.4','translatedPort':'443'},
      {'name':'DNAT-Port-22','protocols':['TCP'],'sourceAddresses':['*'],'destinationAddresses':['<YOUR_FIREWALL_PUBLIC_IP>'],'destinationPorts':['22'],'translatedAddress':'10.0.1.4','translatedPort':'22'},
      {'name':'DNAT-Port-21','protocols':['TCP'],'sourceAddresses':['*'],'destinationAddresses':['<YOUR_FIREWALL_PUBLIC_IP>'],'destinationPorts':['21'],'translatedAddress':'10.0.1.4','translatedPort':'21'},
      {'name':'DNAT-Port-8080','protocols':['TCP'],'sourceAddresses':['*'],'destinationAddresses':['<YOUR_FIREWALL_PUBLIC_IP>'],'destinationPorts':['8080'],'translatedAddress':'10.0.1.4','translatedPort':'8080'},
      {'name':'DNAT-Port-25','protocols':['TCP'],'sourceAddresses':['*'],'destinationAddresses':['<YOUR_FIREWALL_PUBLIC_IP>'],'destinationPorts':['25'],'translatedAddress':'10.0.1.4','translatedPort':'25'},
      {'name':'DNAT-Port-110','protocols':['TCP'],'sourceAddresses':['*'],'destinationAddresses':['<YOUR_FIREWALL_PUBLIC_IP>'],'destinationPorts':['110'],'translatedAddress':'10.0.1.4','translatedPort':'110'},
      {'name':'DNAT-Port-143','protocols':['TCP'],'sourceAddresses':['*'],'destinationAddresses':['<YOUR_FIREWALL_PUBLIC_IP>'],'destinationPorts':['143'],'translatedAddress':'10.0.1.4','translatedPort':'143'},
      {'name':'DNAT-Port-3306','protocols':['TCP'],'sourceAddresses':['*'],'destinationAddresses':['<YOUR_FIREWALL_PUBLIC_IP>'],'destinationPorts':['3306'],'translatedAddress':'10.0.1.4','translatedPort':'3306'},
      {'name':'DNAT-Port-5985','protocols':['TCP'],'sourceAddresses':['*'],'destinationAddresses':['<YOUR_FIREWALL_PUBLIC_IP>'],'destinationPorts':['5985'],'translatedAddress':'10.0.1.4','translatedPort':'5985'},
      {'name':'DNAT-Port-5986','protocols':['TCP'],'sourceAddresses':['*'],'destinationAddresses':['<YOUR_FIREWALL_PUBLIC_IP>'],'destinationPorts':['5986'],'translatedAddress':'10.0.1.4','translatedPort':'5986'},
      {'name':'DNAT-Port-445','protocols':['TCP'],'sourceAddresses':['*'],'destinationAddresses':['<YOUR_FIREWALL_PUBLIC_IP>'],'destinationPorts':['445'],'translatedAddress':'10.0.1.4','translatedPort':'445'},
      {'name':'DNAT-Port-135','protocols':['TCP'],'sourceAddresses':['*'],'destinationAddresses':['<YOUR_FIREWALL_PUBLIC_IP>'],'destinationPorts':['135'],'translatedAddress':'10.0.1.4','translatedPort':'135'},
      {'name':'DNAT-Port-139','protocols':['TCP'],'sourceAddresses':['*'],'destinationAddresses':['<YOUR_FIREWALL_PUBLIC_IP>'],'destinationPorts':['139'],'translatedAddress':'10.0.1.4','translatedPort':'139'},
      {'name':'DNAT-Port-53','protocols':['TCP'],'sourceAddresses':['*'],'destinationAddresses':['<YOUR_FIREWALL_PUBLIC_IP>'],'destinationPorts':['53'],'translatedAddress':'10.0.1.4','translatedPort':'53'},
      {'name':'DNAT-Port-23','protocols':['TCP'],'sourceAddresses':['*'],'destinationAddresses':['<YOUR_FIREWALL_PUBLIC_IP>'],'destinationPorts':['23'],'translatedAddress':'10.0.1.4','translatedPort':'23'},
      {'name':'DNAT-Port-8443','protocols':['TCP'],'sourceAddresses':['*'],'destinationAddresses':['<YOUR_FIREWALL_PUBLIC_IP>'],'destinationPorts':['8443'],'translatedAddress':'10.0.1.4','translatedPort':'8443'},
      {'name':'DNAT-Port-4444','protocols':['TCP'],'sourceAddresses':['*'],'destinationAddresses':['<YOUR_FIREWALL_PUBLIC_IP>'],'destinationPorts':['4444'],'translatedAddress':'10.0.1.4','translatedPort':'4444'},
      {'name':'DNAT-Port-9090','protocols':['TCP'],'sourceAddresses':['*'],'destinationAddresses':['<YOUR_FIREWALL_PUBLIC_IP>'],'destinationPorts':['9090'],'translatedAddress':'10.0.1.4','translatedPort':'9090'},
      {'name':'DNAT-Port-7070','protocols':['TCP'],'sourceAddresses':['*'],'destinationAddresses':['<YOUR_FIREWALL_PUBLIC_IP>'],'destinationPorts':['7070'],'translatedAddress':'10.0.1.4','translatedPort':'7070'},
      {'name':'DNAT-Port-6379','protocols':['TCP'],'sourceAddresses':['*'],'destinationAddresses':['<YOUR_FIREWALL_PUBLIC_IP>'],'destinationPorts':['6379'],'translatedAddress':'10.0.1.4','translatedPort':'6379'},
      {'name':'DNAT-Port-27017','protocols':['TCP'],'sourceAddresses':['*'],'destinationAddresses':['<YOUR_FIREWALL_PUBLIC_IP>'],'destinationPorts':['27017'],'translatedAddress':'10.0.1.4','translatedPort':'27017'},
      {'name':'DNAT-Port-5432','protocols':['TCP'],'sourceAddresses':['*'],'destinationAddresses':['<YOUR_FIREWALL_PUBLIC_IP>'],'destinationPorts':['5432'],'translatedAddress':'10.0.1.4','translatedPort':'5432'}
    ]
  }
}]

# Network rule collection — allows inbound scan traffic to firewall IP
fw['properties']['networkRuleCollections'] = [{
  'name': 'AMNDA-NetworkRules',
  'properties': {
    'priority': 200,
    'action': {'type': 'Allow'},
    'rules': [{
      'name': 'Allow-Inbound-Scan',
      'protocols': ['TCP','UDP'],
      'sourceAddresses': ['*'],
      'destinationAddresses': ['<YOUR_FIREWALL_PUBLIC_IP>'],
      'destinationPorts': ['1-1024']
    }]
  }
}]

# Application rule collection — allows outbound internet from VMs
fw['properties']['applicationRuleCollections'] = [{
  'name': 'AMNDA-Allow-Outbound',
  'properties': {
    'priority': 300,
    'action': {'type': 'Allow'},
    'rules': [{
      'name': 'Allow-Internet',
      'protocols': [{'protocolType':'Http','port':80},{'protocolType':'Https','port':443}],
      'targetFqdns': ['*'],
      'sourceAddresses': ['10.0.0.0/16']
    }]
  }
}]

print(json.dumps(fw))
")"
```

**Step 2 — Apply route table to Subnet-Edge** (forces VM1-Edge outbound through firewall):

```bash
az network route-table create \
  --resource-group "$RG" --name RT-AMNDA --location "$LOCATION"

az network route-table route create \
  --resource-group "$RG" --route-table-name RT-AMNDA \
  --name Route-To-Firewall \
  --address-prefix 0.0.0.0/0 \
  --next-hop-type VirtualAppliance \
  --next-hop-ip-address 10.0.5.4

az network vnet subnet update \
  --resource-group "$RG" --vnet-name "$VNET" \
  --name Subnet-Edge --route-table RT-AMNDA
```

**Step 3 — Deploy IIS on VM1-Edge** (required for s₀ — the web service is what generates DNAT'd traffic through the firewall):

RDP into VM1-Edge via `<YOUR_FIREWALL_PUBLIC_IP>:3389` (<YOUR_ADMIN_USERNAME> / <YOUR_ADMIN_PASSWORD>), then in PowerShell:

```powershell
Install-WindowsFeature -Name Web-Server -IncludeManagementTools
Start-Service W3SVC
```

Verify from outside: `curl http://<YOUR_FIREWALL_PUBLIC_IP>` should return the IIS default page.

> **ℹ NOTE:** IIS on VM1-Edge is required for s₀ simulation. Azure Firewall only logs traffic that passes through it via DNAT rules. Direct scans against the firewall's public IP without a DNAT rule are handled at the NIC level and not forwarded into the VNet, so they do not appear in `AzureFirewallNetworkRule` logs. The IIS service on port 80 with a DNAT rule ensures scan traffic is forwarded to VM1-Edge and logged.

**Step 4 — Apply WAF (Application Gateway)**:

```bash
az network vnet subnet create \
  --resource-group "$RG" --vnet-name "$VNET" \
  --name Subnet-AGW --address-prefixes 10.0.6.0/24

az network public-ip create \
  --resource-group "$RG" --name PIP-AGW-AMNDA \
  --sku Standard --allocation-method Static

az network application-gateway waf-policy create \
  --resource-group "$RG" --name WAF-Policy-AMNDA --location "$LOCATION"

az network application-gateway create \
  --resource-group "$RG" --name AGW-AMNDA \
  --location "$LOCATION" --sku WAF_v2 --capacity 2 \
  --vnet-name "$VNET" --subnet Subnet-AGW \
  --public-ip-address PIP-AGW-AMNDA \
  --waf-policy WAF-Policy-AMNDA \
  --priority 100
```

### Layer 2: Identity Governance (s₁) — Conditional Access

#### Create Lab Security Group and Conditional Access Policy

```bash
# Create security group scoped to lab users only
az rest --method post \
  --url "https://graph.microsoft.com/v1.0/groups" \
  --headers "Content-Type=application/json" \
  --body '{
    "displayName": "AMNDA-Lab-Users",
    "mailEnabled": false,
    "mailNickname": "AMNDA-Lab-Users",
    "securityEnabled": true
  }'

GROUP_ID="<YOUR_GROUP_ID>"  # save from output above

# Add test users to group
for UPN in testuser1 testuser2 testuser3 privadmin; do
  USER_ID=$(az ad user show --id "${UPN}@${DOMAIN}" --query id -o tsv)
  az rest --method post \
    --url "https://graph.microsoft.com/v1.0/groups/$GROUP_ID/members/\$ref" \
    --headers "Content-Type=application/json" \
    --body "{\"@odata.id\":\"https://graph.microsoft.com/v1.0/directoryObjects/$USER_ID\"}"
  echo "Added $UPN"
done

# Create CA policy in report-only mode (PLB-S1 will switch it to enabled)
az rest --method post \
  --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  --headers "Content-Type=application/json" \
  --body '{
    "displayName": "AMNDA-MFA-Enforcement",
    "state": "enabledForReportingButNotEnforced",
    "conditions": {
      "users": {"includeGroups": ["'$GROUP_ID'"]},
      "applications": {"includeApplications": ["All"]}
    },
    "grantControls": {
      "operator": "OR",
      "builtInControls": ["mfa"]
    }
  }'

CA_POLICY_ID="<YOUR_CA_POLICY_ID>"
```

### Layer 3: Segmentation (s₂–s₃) — NSGs

```bash
# Create NSGs
for SUBNET in Edge App Internal; do
  az network nsg create \
    --resource-group "$RG" --name "NSG-$SUBNET" --location "$LOCATION"
done

# NSG-App: deny RDP inbound from Edge and Internal subnets
az network nsg rule create \
  --resource-group "$RG" --nsg-name NSG-App \
  --name Deny-RDP-Inbound --priority 1000 \
  --direction Inbound --access Deny --protocol Tcp \
  --source-address-prefixes 10.0.1.0/24 10.0.3.0/24 \
  --destination-port-ranges 3389

# NSG-Internal: deny RDP inbound from Edge and App subnets
az network nsg rule create \
  --resource-group "$RG" --nsg-name NSG-Internal \
  --name Deny-RDP-Inbound --priority 1000 \
  --direction Inbound --access Deny --protocol Tcp \
  --source-address-prefixes 10.0.1.0/24 10.0.2.0/24 \
  --destination-port-ranges 3389

# NSG-App: allow HTTPS from Edge (legitimate service traffic)
az network nsg rule create \
  --resource-group "$RG" --nsg-name NSG-App \
  --name Allow-HTTPS-from-Edge --priority 900 \
  --direction Inbound --access Allow --protocol Tcp \
  --source-address-prefixes 10.0.1.0/24 \
  --destination-port-ranges 443

# Associate NSGs with subnets
for SUBNET in Edge App Internal; do
  az network vnet subnet update \
    --resource-group "$RG" --vnet-name "$VNET" \
    --name "Subnet-$SUBNET" \
    --network-security-group "NSG-$SUBNET"
done
```

> **ℹ NOTE on NSG-Edge:** NSG-Edge has no custom rules — only Azure default rules apply. This is intentional; inbound access to VM1-Edge is controlled by the Azure Firewall DNAT rules, not NSG rules.

> **ℹ NOTE on DenyAllInbound-AMNDA:** The rule `DenyAllInbound-AMNDA` at priority 100 on NSG-App is added automatically by PLB-S3 when Scenario D fires. Do not pre-create it.

> **ℹ NOTE on Temp-Allow-RDP-for-S3-Test:** A temporary allow rule at priority 800 is required for Scenario D (see Phase 4). It should be removed after the scenario completes. The lab currently shows this rule in NSG-App — remove it between sessions: `az network nsg rule delete --resource-group $RG --nsg-name NSG-App --name Temp-Allow-RDP-for-S3-Test`

### Layer 4: AI-Driven Detection and UEBA

Enable Sentinel UEBA: **portal.azure.com → Microsoft Sentinel → LAW-AMNDA → Configuration → Settings → Set UEBA** — enable all available data sources.

---

## Phase 2 — Sentinel Analytics Rules

### AMNDA-S0: Port Scanning Detection

| Setting | Value |
|---|---|
| Severity | Medium |
| Run every | 5 minutes |
| Lookup last | 30 minutes |
| Threshold | > 0 results |
| Suppression | 30 minutes |
| Entity mapping | IP → Address → SourceIP |

```kusto
AzureDiagnostics
| where ResourceType == "AZUREFIREWALLS"
| where Category == "AzureFirewallNetworkRule"
| where isnotempty(msg_s)
| where msg_s contains "was DNAT"
| parse msg_s with "TCP request from " SourceIP ":" SourcePort " to " DestIP ":" DestPort " was DNAT" *
| where isnotempty(SourceIP)
| summarize DistinctPorts = dcount(DestPort) by SourceIP, bin(TimeGenerated, 5m)
| where DistinctPorts >= 15
```

> **ℹ NOTE:** The threshold is `>= 15` distinct ports. The lab has 24 DNAT rules configured. An nmap SYN scan targeting those 24 ports will exceed this threshold. The parse is anchored to `"TCP request from "` to unambiguously match the DNAT log format (`TCP request from <IP>:<Port> to <IP>:<Port> was DNAT'ed to ...`). The original generic `* "from "` parse pattern failed because Azure Firewall DNAT logs use a different format than standard allow/deny logs.

### AMNDA-S0: Excessive Inbound Requests

| Setting | Value |
|---|---|
| Severity | Medium |
| Run every | 5 minutes |
| Lookup last | 5 minutes |
| Threshold | > 0 results |
| Suppression | 10 minutes |
| Entity mapping | IP → Address → SourceIP |

```kusto
AzureDiagnostics
| where ResourceType == "AZUREFIREWALLS"
| where Category == "AzureFirewallNetworkRule"
| where isnotempty(msg_s)
| where msg_s contains "was DNAT"
| parse msg_s with "TCP request from " SourceIP ":" SourcePort " to " DestIP ":" DestPort " was DNAT" *
| where isnotempty(SourceIP)
| summarize RequestCount = count() by SourceIP, bin(TimeGenerated, 5m)
| where RequestCount > 100
```

### AMNDA-S1: Multiple Failed Logins

| Setting | Value |
|---|---|
| Severity | Medium |
| Run every | 10 minutes |
| Lookup last | 10 minutes |
| Threshold | > 0 results |
| Suppression | 10 minutes |
| Entity mapping | Account → Name → AccountName; IP → Address → IPAddress |
| Status | Disabled between runs (re-enable before Scenario B) |

```kusto
SigninLogs
| where ResultType != "0"
| where ResultType !in ("50074", "50076")
| summarize FailureCount = count() by IPAddress, UserPrincipalName, bin(TimeGenerated, 30m)
| where FailureCount >= 5
| extend AccountName = tostring(split(UserPrincipalName, '@')[0])
| extend AccountUPNSuffix = tostring(split(UserPrincipalName, '@')[1])
```

> **ℹ NOTE:** ResultType exclusions `50074` and `50076` filter out MFA prompts and MFA required errors respectively, which are not credential abuse signals. The lab-verified version uses a 30-minute bin to capture distributed brute-force attempts.

### AMNDA-S2: Privilege Escalation

| Setting | Value |
|---|---|
| Severity | High |
| Run every | 5 minutes |
| Lookup last | 20 minutes |
| Threshold | > 0 results |
| Suppression | Off |
| Entity mapping | Account → Name → AccountName; Account → AadUserId → AccountObjectId |
| Status | Disabled between runs (re-enable before Scenario C) |

```kusto
AuditLogs
| where OperationName == "Add member to role"
| mv-expand prop = TargetResources[0].modifiedProperties
| where prop.displayName == "Role.DisplayName"
| extend RoleName = tostring(prop.newValue)
| where RoleName contains "Admin"
| project TimeGenerated, InitiatedBy, TargetResources, RoleName
| extend AccountName = tostring(TargetResources[0].userPrincipalName)
| extend AccountUPNSuffix = tostring(split(AccountName, '@')[1])
| extend AccountObjectId = tostring(TargetResources[0].id)
| extend InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName)
```

### AMNDA-S3: Lateral Movement Detected

| Setting | Value |
|---|---|
| Severity | High |
| Run every | 5 minutes |
| Lookup last | 15 minutes |
| Threshold | > 0 results |
| Suppression | 15 minutes |
| Entity mapping | Host → HostName → TargetComputer; IP → Address → SourceIP |
| Status | Disabled between runs (re-enable before Scenario D) |

```kusto
SecurityEvent
| where EventID == 4624
| where LogonType == 10
| where IpAddress != "" and IpAddress != "127.0.0.1"
| summarize ConnectionCount = count() by SourceIP = IpAddress, TargetComputer = Computer, bin(TimeGenerated, 15m)
| where ConnectionCount >= 1
```

---

## Phase 3 — Orchestration Logic (Logic Apps Playbooks)

### Step 3.1 — Grant Required Permissions

Define the helper function and run one-time Sentinel SP setup before creating any playbooks:

```bash
assign_sentinel_role() {
  local LOGIC_APP_NAME=$1
  local IDENTITY=$(az logic workflow show \
    --resource-group "$RG" --name "$LOGIC_APP_NAME" \
    --query "identity.principalId" -o tsv)
  az role assignment create \
    --assignee "$IDENTITY" \
    --role "Microsoft Sentinel Responder" \
    --scope "/subscriptions/$SUBSCRIPTION/resourceGroups/$RG"
}

# One-time: grant Sentinel SP permission to execute playbooks
SENTINEL_SP=$(az ad sp list \
  --display-name "Azure Security Insights" \
  --query "value[?appId=='98785600-1bb7-4fb9-b9fa-19afe2c8a360'].id" -o tsv)

az role assignment create \
  --assignee "$SENTINEL_SP" \
  --role "Microsoft Sentinel Automation Contributor" \
  --scope "/subscriptions/$SUBSCRIPTION/resourceGroups/$RG"

az role assignment create \
  --assignee "$SENTINEL_SP" \
  --role "Logic App Contributor" \
  --scope "/subscriptions/$SUBSCRIPTION/resourceGroups/$RG"
```

### Step 3.2 — PLB-S1-IdentityTighten (Implements C₁)

Activates MFA enforcement by switching the CA policy from report-only to enabled when credential abuse is detected (s₁).

**Create via Sentinel → Configuration → Automation → + Create → Playbook with incident trigger**, name it `PLB-S1-IdentityTighten`, then replace the full workflow JSON in Code view:

```json
{
  "definition": {
    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
    "contentVersion": "1.0.0.0",
    "triggers": {
      "Microsoft_Sentinel_incident": {
        "type": "ApiConnectionWebhook",
        "inputs": {
          "host": {"connection": {"name": "@parameters('$connections')['azuresentinel']['connectionId']"}},
          "body": {"callback_url": "@{listCallbackUrl()}"},
          "path": "/incident-creation"
        }
      }
    },
    "actions": {
      "HTTP_1": {
        "runAfter": {},
        "type": "Http",
        "inputs": {
          "uri": "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/<YOUR_CA_POLICY_ID>",
          "method": "PATCH",
          "body": {"state": "disabled"},
          "authentication": {"type": "ManagedServiceIdentity", "audience": "https://graph.microsoft.com"}
        }
      },
      "HTTP": {
        "runAfter": {"HTTP_1": ["Succeeded"]},
        "type": "Http",
        "inputs": {
          "uri": "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/<YOUR_CA_POLICY_ID>",
          "method": "PATCH",
          "body": {"state": "enabled"},
          "authentication": {"type": "ManagedServiceIdentity", "audience": "https://graph.microsoft.com"}
        }
      }
    },
    "outputs": {},
    "parameters": {"$connections": {"type": "Object", "defaultValue": {}}}
  },
  "parameters": {
    "$connections": {
      "type": "Object",
      "value": {
        "azuresentinel": {
          "id": "/subscriptions/<YOUR_SUBSCRIPTION_ID>/providers/Microsoft.Web/locations/eastus/managedApis/azuresentinel",
          "connectionId": "/subscriptions/<YOUR_SUBSCRIPTION_ID>/resourceGroups/AMNDAVerif/providers/Microsoft.Web/connections/azuresentinel-PLB-S1-IdentityTighten",
          "connectionName": "azuresentinel-PLB-S1-IdentityTighten",
          "connectionProperties": {"authentication": {"type": "ManagedServiceIdentity"}}
        }
      }
    }
  }
}
```

> **ℹ NOTE:** PLB-S1 first disables then re-enables the CA policy. This is a toggle pattern to force the policy state to `enabled` regardless of current state, working around Graph API idempotency behavior.

```bash
assign_sentinel_role PLB-S1-IdentityTighten

# Grant Conditional Access Administrator role to managed identity
LOGIC_IDENTITY=$(az logic workflow show \
  --resource-group "$RG" --name PLB-S1-IdentityTighten \
  --query "identity.principalId" -o tsv)

CA_ADMIN_ROLE_ID=$(az rest --method get \
  --url "https://graph.microsoft.com/v1.0/directoryRoles" \
  --query "value[?displayName=='Conditional Access Administrator'].id" -o tsv)

az rest --method post \
  --url "https://graph.microsoft.com/v1.0/directoryRoles/$CA_ADMIN_ROLE_ID/members/\$ref" \
  --headers "Content-Type=application/json" \
  --body "{\"@odata.id\":\"https://graph.microsoft.com/v1.0/directoryObjects/$LOGIC_IDENTITY\"}"
```

**Automation rule — Auto-S1-IdentityTighten:**

**Sentinel → Configuration → Automation → Automation rules → + Create (Standard)**

- Name: Auto-S1-IdentityTighten
- Trigger: When incident is created
- Condition: Analytics rule name → Contains → AMNDA-S1: Multiple Failed Logins
- Action: Run playbook → PLB-S1-IdentityTighten
- Order: 1

### Step 3.3 — PLB-S2-PrivilegeRestrict (Implements C₂)

Disables the compromised user account when privilege escalation is detected (s₂).

Create via Sentinel, name `PLB-S2-PrivilegeRestrict`, replace JSON in Code view:

```json
{
  "definition": {
    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
    "contentVersion": "1.0.0.0",
    "triggers": {
      "Microsoft_Sentinel_incident": {
        "type": "ApiConnectionWebhook",
        "inputs": {
          "host": {"connection": {"name": "@parameters('$connections')['azuresentinel']['connectionId']"}},
          "body": {"callback_url": "@{listCallbackUrl()}"},
          "path": "/incident-creation"
        }
      }
    },
    "actions": {
      "Entities_-_Get_Accounts": {
        "runAfter": {},
        "type": "ApiConnection",
        "inputs": {
          "host": {"connection": {"name": "@parameters('$connections')['azuresentinel']['connectionId']"}},
          "method": "post",
          "body": "@triggerBody()?['object']?['properties']?['relatedEntities']",
          "path": "/entities/account"
        }
      },
      "For_each_account": {
        "foreach": "@body('Entities_-_Get_Accounts')?['Accounts']",
        "actions": {
          "Disable_User": {
            "runAfter": {},
            "type": "Http",
            "inputs": {
              "method": "PATCH",
              "uri": "https://graph.microsoft.com/v1.0/users/@{encodeURIComponent(concat(items('For_each_account')?['accountName'],'@',items('For_each_account')?['upnSuffix']))}",
              "body": {"accountEnabled": false},
              "authentication": {"type": "ManagedServiceIdentity", "audience": "https://graph.microsoft.com"}
            }
          }
        },
        "runAfter": {"Entities_-_Get_Accounts": ["Succeeded"]},
        "type": "Foreach"
      }
    },
    "outputs": {},
    "parameters": {"$connections": {"type": "Object", "defaultValue": {}}}
  },
  "parameters": {
    "$connections": {
      "type": "Object",
      "value": {
        "azuresentinel": {
          "id": "/subscriptions/<YOUR_SUBSCRIPTION_ID>/providers/Microsoft.Web/locations/eastus/managedApis/azuresentinel",
          "connectionId": "/subscriptions/<YOUR_SUBSCRIPTION_ID>/resourceGroups/AMNDAVerif/providers/Microsoft.Web/connections/azuresentinel-PLB-S2-PrivilegeRestrict",
          "connectionName": "azuresentinel-PLB-S2-PrivilegeRestrict",
          "connectionProperties": {"authentication": {"type": "ManagedServiceIdentity"}}
        }
      }
    }
  }
}
```

```bash
assign_sentinel_role PLB-S2-PrivilegeRestrict

LOGIC_IDENTITY=$(az logic workflow show \
  --resource-group "$RG" --name PLB-S2-PrivilegeRestrict \
  --query "identity.principalId" -o tsv)

# Grant Graph API permissions
GRAPH_SP=$(az ad sp show --id 00000003-0000-0000-c000-000000000000 --query id -o tsv)

ROLE_ID=$(az ad sp show --id 00000003-0000-0000-c000-000000000000 \
  --query "appRoles[?value=='User.ReadWrite.All'].id" -o tsv)
az rest --method post \
  --url "https://graph.microsoft.com/v1.0/servicePrincipals/$GRAPH_SP/appRoleAssignments" \
  --headers "Content-Type=application/json" \
  --body "{\"principalId\":\"$LOGIC_IDENTITY\",\"resourceId\":\"$GRAPH_SP\",\"appRoleId\":\"$ROLE_ID\"}"

ENABLE_ROLE=$(az ad sp show --id 00000003-0000-0000-c000-000000000000 \
  --query "appRoles[?value=='User.EnableDisableAccount.All'].id" -o tsv)
az rest --method POST \
  --url "https://graph.microsoft.com/v1.0/servicePrincipals/$GRAPH_SP/appRoleAssignments" \
  --body "{\"principalId\":\"$LOGIC_IDENTITY\",\"resourceId\":\"$GRAPH_SP\",\"appRoleId\":\"$ENABLE_ROLE\"}"

# Assign Privileged Authentication Administrator via portal:
# Entra ID → Roles and administrators → Privileged Authentication Administrator → + Add assignments → PLB-S2-PrivilegeRestrict
# Then grant admin consent: Entra ID → Enterprise applications → PLB-S2-PrivilegeRestrict → Permissions → Grant admin consent
```

**Automation rule — Auto-S2-PrivilegeRestrict:**

- Name: Auto-S2-PrivilegeRestrict
- Trigger: When incident is created
- Condition: Analytics rule name → Contains → AMNDA-S2: Privilege Escalation
- Action: Run playbook → PLB-S2-PrivilegeRestrict
- Order: 2

### Step 3.4 — PLB-S3-SegmentationTighten (Implements C₃)

Adds a DenyAll inbound NSG rule to NSG-App when lateral movement is detected (s₃).

Create via Sentinel, name `PLB-S3-SegmentationTighten`, replace JSON in Code view:

```json
{
  "definition": {
    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
    "contentVersion": "1.0.0.0",
    "triggers": {
      "Microsoft_Sentinel_incident": {
        "type": "ApiConnectionWebhook",
        "inputs": {
          "host": {"connection": {"name": "@parameters('$connections')['azuresentinel']['connectionId']"}},
          "body": {"callback_url": "@{listCallbackUrl()}"},
          "path": "/incident-creation"
        }
      }
    },
    "actions": {
      "HTTP": {
        "runAfter": {},
        "type": "Http",
        "inputs": {
          "uri": "https://management.azure.com/subscriptions/<YOUR_SUBSCRIPTION_ID>/resourceGroups/AMNDAVerif/providers/Microsoft.Network/networkSecurityGroups/NSG-App/securityRules/DenyAllInbound-AMNDA?api-version=2023-05-01",
          "method": "PUT",
          "body": {
            "properties": {
              "priority": 100,
              "direction": "Inbound",
              "access": "Deny",
              "protocol": "*",
              "sourceAddressPrefix": "*",
              "destinationAddressPrefix": "*",
              "sourcePortRange": "*",
              "destinationPortRange": "*"
            }
          },
          "authentication": {"type": "ManagedServiceIdentity", "audience": "https://management.azure.com"}
        }
      }
    },
    "outputs": {},
    "parameters": {"$connections": {"type": "Object", "defaultValue": {}}}
  },
  "parameters": {
    "$connections": {
      "type": "Object",
      "value": {
        "azuresentinel": {
          "id": "/subscriptions/<YOUR_SUBSCRIPTION_ID>/providers/Microsoft.Web/locations/eastus/managedApis/azuresentinel",
          "connectionId": "/subscriptions/<YOUR_SUBSCRIPTION_ID>/resourceGroups/AMNDAVerif/providers/Microsoft.Web/connections/azuresentinel-PLB-S3-SegmentationTighten",
          "connectionName": "azuresentinel-PLB-S3-SegmentationTighten",
          "connectionProperties": {"authentication": {"type": "ManagedServiceIdentity"}}
        }
      }
    }
  }
}
```

```bash
assign_sentinel_role PLB-S3-SegmentationTighten

LOGIC_IDENTITY=$(az logic workflow show \
  --resource-group "$RG" --name PLB-S3-SegmentationTighten \
  --query "identity.principalId" -o tsv)

az role assignment create \
  --assignee "$LOGIC_IDENTITY" \
  --role "Network Contributor" \
  --scope "/subscriptions/$SUBSCRIPTION/resourceGroups/$RG"
```

**Automation rule — Auto-S3-SegmentationTighten:**

- Name: Auto-S3-SegmentationTighten
- Trigger: When incident is created
- Condition: Analytics rule name → Contains → AMNDA-S3: Lateral Movement Detected
- Action: Run playbook → PLB-S3-SegmentationTighten
- Order: 3

### Step 3.5 — PLB-S4-HostIsolation (Implements C₄)

Fully isolates a VM via MDE when malware/persistence artifacts are detected (s₄).

> **ℹ NOTE:** The Logic App uses the `Entities - Get Hosts` action to iterate over host entities from the incident and extracts `MdatpDeviceId` from `additionalData`.

Create via Sentinel, name `PLB-S4-HostIsolation`, replace JSON in Code view:

```json
{
  "definition": {
    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
    "contentVersion": "1.0.0.0",
    "triggers": {
      "Microsoft_Sentinel_incident": {
        "type": "ApiConnectionWebhook",
        "inputs": {
          "host": {"connection": {"name": "@parameters('$connections')['azuresentinel']['connectionId']"}},
          "body": {"callback_url": "@{listCallbackUrl()}"},
          "path": "/incident-creation"
        }
      }
    },
    "actions": {
      "Entities_-_Get_Hosts": {
        "runAfter": {},
        "type": "ApiConnection",
        "inputs": {
          "host": {"connection": {"name": "@parameters('$connections')['azuresentinel']['connectionId']"}},
          "method": "post",
          "body": "@triggerBody()?['object']?['properties']?['relatedEntities']",
          "path": "/entities/host"
        }
      },
      "For_each_host": {
        "foreach": "@body('Entities_-_Get_Hosts')?['Hosts']",
        "actions": {
          "Isolate_Machine": {
            "runAfter": {},
            "type": "Http",
            "inputs": {
              "method": "POST",
              "uri": "https://api.securitycenter.microsoft.com/api/machines/@{encodeURIComponent(items('For_each_host')?['additionalData']?['MdatpDeviceId'])}/isolate",
              "body": {
                "Comment": "Isolated by AMNDA PLB-S4 playbook",
                "IsolationType": "Full"
              },
              "authentication": {"type": "ManagedServiceIdentity", "audience": "https://api.securitycenter.microsoft.com"}
            }
          }
        },
        "runAfter": {"Entities_-_Get_Hosts": ["Succeeded"]},
        "type": "Foreach"
      }
    },
    "outputs": {},
    "parameters": {"$connections": {"type": "Object", "defaultValue": {}}}
  },
  "parameters": {
    "$connections": {
      "type": "Object",
      "value": {
        "azuresentinel": {
          "id": "/subscriptions/<YOUR_SUBSCRIPTION_ID>/providers/Microsoft.Web/locations/eastus/managedApis/azuresentinel",
          "connectionId": "/subscriptions/<YOUR_SUBSCRIPTION_ID>/resourceGroups/AMNDAVerif/providers/Microsoft.Web/connections/azuresentinel-PLB-S4-HostIsolation",
          "connectionName": "azuresentinel-PLB-S4-HostIsolation",
          "connectionProperties": {"authentication": {"type": "ManagedServiceIdentity"}}
        }
      }
    }
  }
}
```

```bash
assign_sentinel_role PLB-S4-HostIsolation

LOGIC_IDENTITY=$(az logic workflow show \
  --resource-group "$RG" --name PLB-S4-HostIsolation \
  --query "identity.principalId" -o tsv)
echo "PLB-S4 Identity: $LOGIC_IDENTITY"

# Grant Machine.Isolate permission to managed identity
WDATP_SP=$(az ad sp show --id fc780465-2017-40d4-a0c5-307022471b92 --query id -o tsv)
ISOLATE_ROLE=$(az ad sp show --id fc780465-2017-40d4-a0c5-307022471b92 \
  --query "appRoles[?value=='Machine.Isolate'].id" -o tsv)

az rest --method POST \
  --url "https://graph.microsoft.com/v1.0/servicePrincipals/$WDATP_SP/appRoleAssignments" \
  --headers "Content-Type=application/json" \
  --body "{\"principalId\":\"$LOGIC_IDENTITY\",\"resourceId\":\"$WDATP_SP\",\"appRoleId\":\"$ISOLATE_ROLE\"}"
```

**Automation rule — Auto-S4-HostIsolation:**

- Name: Auto-S4-HostIsolation
- Trigger: When incident is created
- Condition: Title → Contains → Malware OR EICAR OR quarantined
- Action: Run playbook → PLB-S4-HostIsolation
- Order: 4

> **ℹ NOTE on unified SOC platform:** The lab tenant uses the Microsoft Defender Unified Security Operations Platform. MDE alerts appear in security.microsoft.com and do not automatically create incidents in Sentinel's classic incident queue. The Auto-S4 automation rule triggers when an incident is created in Sentinel. To bridge this gap, the Microsoft Defender XDR connector must be installed and AlertInfo/AlertEvidence tables enabled. The MDE malware alert creates an incident in the unified platform which, when the XDR connector is active, also creates a corresponding Sentinel incident that triggers Auto-S4. The incident may show as "Informational" severity and may not appear in the standard Sentinel workspace incident view — verify via security.microsoft.com and the Logic App run history.

---

## Phase 4 — Simulated Multi-Stage Attack

### Pre-Simulation Checklist

Before each simulation run, restore all analytics rules and automation rules for the scenario being tested. Rules are disabled by default between runs to prevent false positives.

```bash
# Verify analytics rules enabled status
az sentinel alert-rule list \
  --resource-group "$RG" --workspace-name "$LAW" \
  --query "[].{Name:displayName,Enabled:enabled}" \
  --output table 2>/dev/null

# Verify Logic Apps are enabled
az logic workflow list --resource-group "$RG" \
  --query "[].{Name:name,State:state}" --output table

# Get VM2 internal IP
VM2_IP=$(az vm show --resource-group "$RG" --name VM2-App --show-details --query privateIps -o tsv)
echo "VM2_IP: $VM2_IP"
```

---

### Scenario A — External Reconnaissance (s₀)

**Expected trigger:** AMNDA-S0: Port Scanning Detection and/or AMNDA-S0: Excessive Inbound Requests  
**No automated playbook response for s₀ — detection only.**

**Enable rules:**
```bash
# S0 rules should already be enabled (they are always-on)
az sentinel alert-rule list --resource-group "$RG" --workspace-name "$LAW" \
  --query "[?contains(displayName,'AMNDA-S0')].{Name:displayName,Enabled:enabled}" --output table 2>/dev/null
```

**Run simulation from Kali Linux:**

```bash
# Port scan — hits all 24 DNAT ports, generates multi-port DNAT log entries
sudo nmap -sS -p 80,443,22,21,8080,25,110,143,3306,5985,5986,445,135,139,53,23,8443,4444,9090,7070,6379,27017,5432,3389 <YOUR_FIREWALL_PUBLIC_IP>

# Excessive requests — flood port 80 with 200 HTTP requests
for i in $(seq 1 200); do curl -s http://<YOUR_FIREWALL_PUBLIC_IP> > /dev/null; done
```

**Verify traffic logged:**
```bash
az monitor log-analytics query \
  --workspace "$LAW_GUID" \
  --analytics-query "AzureDiagnostics | where ResourceType == 'AZUREFIREWALLS' | where Category == 'AzureFirewallNetworkRule' | where isnotempty(msg_s) | where msg_s contains 'was DNAT' | parse msg_s with 'TCP request from ' SourceIP ':' SourcePort ' to ' DestIP ':' DestPort ' was DNAT' * | where isnotempty(SourceIP) | summarize Count=count(), DistinctPorts=dcount(DestPort) by SourceIP | order by Count desc" \
  --timespan PT30M
```

**Check for incidents (wait 5–15 minutes after scan):**
```bash
az sentinel incident list \
  --resource-group "$RG" --workspace-name "$LAW" \
  --query "[?contains(title,'AMNDA-S0')].{Title:title,Severity:severity,Status:status,Created:createdTimeUtc}" \
  --output table
```

---

### Scenario B — Initial Access / Credential Abuse (s₁)

**Expected trigger:** AMNDA-S1: Multiple Failed Logins  
**Expected response:** PLB-S1 switches CA policy from report-only to enabled.

**Enable rules and playbook:**
```bash
# Re-enable PLB-S1 and PLB-S2 (disabled after previous run)
az logic workflow update --resource-group "$RG" --name PLB-S1-IdentityTighten --state Enabled
az logic workflow update --resource-group "$RG" --name PLB-S2-PrivilegeRestrict --state Enabled
# Also re-enable analytics rules via portal: Sentinel → Analytics → AMNDA-S1 → Enable
```

**Run simulation:** Perform 5+ failed login attempts to https://portal.azure.com using `testuser1@<DOMAIN>` with incorrect passwords.

**Verify:**
```bash
# Check for incident
az sentinel incident list --resource-group "$RG" --workspace-name "$LAW" \
  --query "[?contains(title,'AMNDA-S1')].{Title:title,Severity:severity,Created:createdTimeUtc}" \
  --output table

# Verify CA policy switched to enabled by PLB-S1
az rest --method get \
  --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/$CA_POLICY_ID" \
  --query "{Name:displayName,State:state}"
# Expected: "State": "enabled"
```

---

### Scenario C — Privilege Escalation (s₂)

**Expected trigger:** AMNDA-S2: Privilege Escalation  
**Expected response:** PLB-S2 disables the privadmin account.

**Setup:**
```bash
PRIV_ROLE_ID=$(az rest --method get \
  --url "https://graph.microsoft.com/v1.0/directoryRoles" \
  --query "value[?displayName=='Privileged Role Administrator'].id" -o tsv)

# Re-enable privadmin if previously disabled
az ad user update --id "privadmin@${DOMAIN}" --account-enabled true
```

**Run simulation:**
```bash
# Simulate unexpected role assignment — let automation rule trigger PLB-S2 automatically
az rest --method post \
  --url "https://graph.microsoft.com/v1.0/directoryRoles/$PRIV_ROLE_ID/members/\$ref" \
  --body "{\"@odata.id\":\"https://graph.microsoft.com/v1.0/users/$PRIV_USER_ID\"}"
```

**Verify:**
```bash
az sentinel incident list --resource-group "$RG" --workspace-name "$LAW" \
  --query "[?contains(title,'AMNDA-S2')].{Title:title,Severity:severity,Created:createdTimeUtc}" \
  --output table

az ad user show --id "privadmin@$DOMAIN" \
  --query "{DisplayName:displayName,AccountEnabled:accountEnabled}"
# Expected: "AccountEnabled": false
```

---

### Scenario D — Lateral Movement (s₃)

**Expected trigger:** AMNDA-S3: Lateral Movement Detected  
**Expected response:** PLB-S3 adds DenyAllInbound-AMNDA rule at priority 100 to NSG-App.

> **ℹ NOTE:** NSG-App has `Deny-RDP-Inbound` at priority 1000 which blocks RDP from Edge subnet. EventID 4624 requires a **successful** logon, so this rule must be temporarily overridden. Add the temp rule before running the scenario, remove it after PLB-S3 fires.

**Step 1 — Add temporary RDP allow rule:**
```bash
az network nsg rule create \
  --resource-group "$RG" --nsg-name NSG-App \
  --name Temp-Allow-RDP-for-S3-Test --priority 800 \
  --direction Inbound --access Allow --protocol Tcp \
  --source-address-prefixes 10.0.1.0/24 \
  --destination-port-ranges 3389
```

**Step 2 — RDP into VM1-Edge via firewall, then laterally to VM2-App:**
```bash
# From Kali
xfreerdp /v:<YOUR_FIREWALL_PUBLIC_IP> /u:<YOUR_ADMIN_USERNAME> /p:<YOUR_ADMIN_PASSWORD> /cert:ignore
# From VM1-Edge Run dialog (Win+R)
# mstsc /v:<VM2_IP>
```

**Step 3 — Wait for incident, verify NSG tightening:**
```bash
az sentinel incident list --resource-group "$RG" --workspace-name "$LAW" \
  --query "[?contains(title,'AMNDA-S3')].{Title:title,Severity:severity,Status:status,Created:createdTimeUtc}" \
  --output table

az network nsg rule list --resource-group "$RG" --nsg-name NSG-App \
  --query "[?access=='Deny'].{Name:name,Priority:priority,Access:access}" --output table
# Expected: DenyAllInbound-AMNDA at priority 100
```

**Step 4 — Remove temp rule after scenario:**
```bash
az network nsg rule delete --resource-group "$RG" --nsg-name NSG-App \
  --name Temp-Allow-RDP-for-S3-Test
```

> **ℹ NOTE:** NSG rules apply to new connections only. An already-established RDP session will not be disconnected when DenyAllInbound-AMNDA is applied. This is expected Azure platform behavior.

---

### Scenario E — Persistence / Malware (s₄)

**Expected trigger:** MDE malware alert → Sentinel incident  
**Expected response:** PLB-S4 isolates VM1-Edge via MDE.

**Create EICAR test file on VM1-Edge** (RDP in via <YOUR_FIREWALL_PUBLIC_IP>:3389, then PowerShell):
```powershell
Set-Content -Path "C:\Users\<YOUR_ADMIN_USERNAME>\Desktop\eicar.com" -Value "X5O!P%@AP[4\PZX54(P^)7CC)7}`$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!`$H+H*"
```

Defender for Endpoint will detect and quarantine the file immediately.

**Monitor for incident** (MDE alert → unified platform → Sentinel via XDR connector, allow 5–15 minutes):
```bash
az sentinel incident list --resource-group "$RG" --workspace-name "$LAW" \
  --query "[?contains(title,'Malware') || contains(title,'EICAR') || contains(title,'quarantined')].{Title:title,Severity:severity,Status:status,Created:createdTimeUtc}" \
  --output table
```

**Verify isolation:**
```bash
MDATP_DEVICE_ID=$(az rest --method get \
  --url "https://api.securitycenter.microsoft.com/api/machines" \
  --resource "https://api.securitycenter.microsoft.com" \
  --query "value[?computerDnsName=='vm1-edge'].id" -o tsv)

az rest --method get \
  --url "https://api.securitycenter.microsoft.com/api/machines/$MDATP_DEVICE_ID" \
  --resource "https://api.securitycenter.microsoft.com" \
  --query "{Hostname:computerDnsName,IsolationStatus:isolationStatus}"
# Expected: "IsolationStatus": "Isolated"
```

**Un-isolate after verification:**
```bash
az rest --method post \
  --url "https://api.securitycenter.microsoft.com/api/machines/$MDATP_DEVICE_ID/unisolate" \
  --resource "https://api.securitycenter.microsoft.com" \
  --headers "Content-Type=application/json" \
  --body '{"Comment": "Unisolate after S4 verification"}'
```

---

## Phase 5 — Metrics Collection

All incident and alert queries in this phase run in **Advanced Hunting** (`security.microsoft.com → Hunting → Advanced Hunting`). Infrastructure state checks (NSG, account, CA policy, Logic App runs) remain in the CLI.

---

### 5.1 — Incident Detection Latency

Detection latency = `FirstActivityTime → CreatedTime` (how long before the platform created an incident).  
Containment latency = `CreatedTime → ClosedTime` (how long the playbook took to act and close).

```kusto
SecurityIncident
| where Title contains "AMNDA"
| where isnotempty(FirstActivityTime)
| extend DetectionLatencySec  = datetime_diff('second', CreatedTime, FirstActivityTime)
| extend ContainmentLatencySec = iff(isnotempty(ClosedTime),
    datetime_diff('second', ClosedTime, CreatedTime), int(null))
| project Title, Severity, Status,
          FirstActivityTime, CreatedTime, ClosedTime,
          DetectionLatencySec, ContainmentLatencySec
| order by CreatedTime desc
```

> **ℹ NOTE:** Field names are `FirstActivityTime`, `CreatedTime`, `ClosedTime` — confirmed from table schema. `ClosedTime` is only populated once the incident is closed; run this after each scenario has fully resolved.

---

### 5.2 — Alert Timeline per Scenario

Cross-reference each AMNDA alert with its firing time and source rule. Useful for mapping `AlertInfo.Timestamp` against your simulation run time to confirm detection occurred within the analytics rule window.

```kusto
AlertInfo
| where Title contains "AMNDA"
| project Timestamp, Title, Severity, ServiceSource, DetectionSource, AttackTechniques
| order by Timestamp desc
```

---

### 5.3 — Logic App Enforcement Latency

Playbook run duration is not queryable via Advanced Hunting — use the CLI.

```bash
for PLB in PLB-S1-IdentityTighten PLB-S2-PrivilegeRestrict PLB-S3-SegmentationTighten PLB-S4-HostIsolation; do
  echo "=== $PLB ==="
  RUN=$(az rest --method GET \
    --url "https://management.azure.com/subscriptions/$SUBSCRIPTION/resourceGroups/$RG/providers/Microsoft.Logic/workflows/$PLB/runs?api-version=2016-06-01&\$top=1" \
    --query "value[0].{Status:properties.status,Start:properties.startTime,End:properties.endTime}" \
    -o json)
  echo "$RUN"
  echo "$RUN" | python3 -c "
import sys, json, re
from datetime import datetime
r = json.load(sys.stdin)
if r.get('Start') and r.get('End'):
    def parse(s):
        s = re.sub(r'(\.\d{6})\d+Z$', r'\1Z', s)
        return datetime.strptime(s, '%Y-%m-%dT%H:%M:%S.%fZ' if '.' in s else '%Y-%m-%dT%H:%M:%SZ')
    print(f'  Duration: {(parse(r[\"End\"]) - parse(r[\"Start\"])).total_seconds():.1f}s')
else:
    print('  (no completed run found or still running)')
"
done
```

---

### 5.4 — s₀ Evidence: Firewall Scan Detection

```kusto
AzureDiagnostics
| where ResourceType == "AZUREFIREWALLS"
| where Category == "AzureFirewallNetworkRule"
| where isnotempty(msg_s)
| where msg_s contains "was DNAT"
| parse msg_s with "TCP request from " SourceIP ":" SourcePort " to " DestIP ":" DestPort " was DNAT" *
| where isnotempty(SourceIP)
| summarize RequestCount = count(), DistinctPorts = dcount(DestPort) by SourceIP, bin(TimeGenerated, 5m)
| order by TimeGenerated desc
```

---

### 5.5 — s₁ Evidence: Failed Login Attempts

```kusto
SigninLogs
| where ResultType != "0"
| where ResultType !in ("50074", "50076")
| summarize FailureCount = count() by IPAddress, UserPrincipalName, bin(TimeGenerated, 30m)
| where FailureCount >= 5
| extend AccountName = tostring(split(UserPrincipalName, '@')[0])
| extend AccountUPNSuffix = tostring(split(UserPrincipalName, '@')[1])
| order by FailureCount desc
```

---

### 5.6 — s₂ Evidence: Privilege Escalation Events

```kusto
AuditLogs
| where OperationName == "Add member to role"
| mv-expand prop = TargetResources[0].modifiedProperties
| where prop.displayName == "Role.DisplayName"
| extend RoleName = tostring(prop.newValue)
| where RoleName contains "Admin"
| extend AccountName = tostring(TargetResources[0].userPrincipalName)
| extend AccountUPNSuffix = tostring(split(AccountName, '@')[1])
| extend AccountObjectId = tostring(TargetResources[0].id)
| extend InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, InitiatedByUser, AccountName, RoleName, AccountObjectId
| order by TimeGenerated desc
```

---

### 5.7 — s₃ Evidence: Lateral Movement Detection

```kusto
SecurityEvent
| where EventID == 4624
| where LogonType == 10
| where IpAddress != "" and IpAddress != "127.0.0.1"
| summarize ConnectionCount = count()
    by SourceIP = IpAddress, TargetComputer = Computer, bin(TimeGenerated, 15m)
| where ConnectionCount >= 1
| order by TimeGenerated desc
```

---

### 5.8 — NSG Attack Surface: Before/After Enforcement

Run before Scenario D (baseline) and again after PLB-S3 fires (confirm `DenyAllInbound-AMNDA` at priority 100).

```bash
az network nsg rule list --resource-group "$RG" --nsg-name NSG-App \
  --query "[].{Name:name,Priority:priority,Access:access,Direction:direction}" \
  --output table
```

---

### 5.9 — Account and Policy Status: Containment Verification

```bash
# privadmin — should be disabled after Scenario C
az ad user show --id "privadmin@$DOMAIN" \
  --query "{DisplayName:displayName,AccountEnabled:accountEnabled}"

# CA policy — should be 'enabled' after Scenario B
az rest --method get \
  --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/$CA_POLICY_ID" \
  --query "{Name:displayName,State:state}"
```

---

## Cleanup

After validation is complete, clean up to stop billing.

```bash
# Delete all resources (irreversible)
az group delete --name "$RG" --yes --no-wait

# To stop VM billing without deleting
az vm deallocate --resource-group "$RG" --name VM1-Edge
az vm deallocate --resource-group "$RG" --name VM2-App
az vm deallocate --resource-group "$RG" --name VM3-Internal

# Remove test users
for N in 1 2 3; do az ad user delete --id "testuser${N}@${DOMAIN}"; done
az ad user delete --id "privadmin@${DOMAIN}"
```

---

