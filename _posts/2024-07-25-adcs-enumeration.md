---
title: ADCS Enumeration
date: 2024-07-25 00:00:00 +0800
categories:
  - ADCS
tags:
  - Red-Teaming
---
# Active Directory Certificate Services
Active Directory Certificate Services (ADCS) is Microsoft's implementation of certificate-based PKI. These certificates can be used for a huge number of things in an Active Directory environment. From code signing, to user/service authentication, etc. 

One thing to note is that Active Directory Certificate services is completely separate from Active Directory Domain Services (AD DS), but can integrate with it. In order to do that, an admin would need to install ADCS separately and setup a Certificate Authority (CA) server. This can be the same server as the DC or a separate server.

From my testing, ADCS appears to be quite common in medium to large enterprise environments. Despite it's prevalence, there is a huge knowledge GAP in securing ADCS, and on almost every internal assessment I've been on where ADCS was used, it was misconfigured.

Credit goes to the original researchers over at Spectre Ops. If you haven't yet read the white paper "Certified Pre-Owned" that opened the flood gates on this area of security, I'd highly recommend it. It's quite a lengthy read, but absolutely essential if you're doing a lot of internal assessments and/or red team engagements today.

Certified Pre-Owned White Paper:
https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf

In this blog post we will narrow our focus down to ADCS enumeration. How to identify the misconfigurations. In future blog posts we'll dive into the specific techniques we can use to abuse them.

## Domain Privilege Escalation Overview (ESC) - Overview
The white paper identifies a number of domain privilege escalation paths that arise from various ADCS misconfigurations. Here's a quick overview...

#### ESC1
Enrollee can request cert for ANY user (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT + Client Authentication/Smart Card Logon EKU)

#### ESC2
Enrollee can request cert for ANY user (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT + Any Purpose EKU or no EKU)

#### ESC3
Request an enrollment agent certificate (Application Policy - Certificate Request Agent) and use it to request a cert on behalf of ANY user (Certificate Request Agent EKU)

#### ESC4
Vulnerable ACLs (GenericWrite) over ADCS Certificate Templates

#### ESC5
Poor Access Control (GenericWrite) on CA Server Computer Object

#### ESC7
Vulnerable Certificate Authority Access Control Roles (ManageCA and ManageCertificate)

#### ESC 8 
NTLM Relay ANY domain computer to ADCS HTTP Endpoints

#### ESC11
NTLM Relay ANY domain computer to ADCS ICertPassage Remote Protocol (ICPR) RPC Endpoints


NOTE: This blog post will only focus on enumerating the misconfigurations above that are still abusable at the time of writing (7/25/2024). These are of course subject to change over time as Microsoft releases new patches and mitigations. I will aim to keep this up-to-date as much as possible.

## Other Certificate Based Abuses - Overview

#### Cross Forest Trust Abuse
If we can abuse a cross forest trust, we may be able to utilize any compromised certificates to move laterally across forests.

#### On-Prem to Cloud
If we compromise a Root CA and the target uses Microsoft Azure with certificate-based authentication enabled, we may be able to utilize it to move laterally from on-prem to cloud.

#### CertPotato
 Elevate our privileges to `NT AUTHORITY\SYSTEM` from virtual and network service accounts of a domain-joined machine (for example from a webshell on a Windows server) using ADCS

## Patched by Microsoft
Here is a quick list of some of the previous ADCS related abuses that were since patched by Microsoft.

- ESC6
	- Vulnerable EDITF_ATTRIBUTESUBJECTALTNAME2 setting on CA allowing requesting certs for ANY user

- ESC9
	- If CT_FLAG_NO_SECURITY_EXTENSION (0x80000) is set on a specific template the szOID_NTDS_CA_SECURITY_EXT security extension will not be embedded.

- ESC10
	- ESC10 Case 1: 
		Weak Certificate Mappings – StrongCertificateBindingEnforcement set to 0 in registry.

	- ESC10 Case 2:
		Weak Certificate Mappings - CertificateMappingMethods set to 4 in registry

- Certifried: CVE-2022–26923
	- Updating the dNSHostName property of a controller computer account to impersonate ANY target computer account


## ADCS Enumeration Commands
### Checking if ADCS is in use in the target environment

```
# Look for ADCS containers using the AD Module 
Get-ADObject -Filter * -SearchBase 'CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,DC=cb,DC=corp' 

ls 'AD:\CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,DC=cb,DC=corp' 

# Based on ObjectClass 
Get-ADObject -LDAPFilter '(objectclass=certificationAuthority)' -SearchBase 'CN=Configuration,DC=cb,DC=corp' | fl *
```
- Bloodhound, PowerView, your favorite AD enumeration tools can typically also do this

### Enumerating Certificates and Certificate Stores

Examine a certificate
```
certutil -v -dump -p <password> C:\ADCS\Certs\protecteduser.pfx
```

Enumerate the current User / LocalMachine "My" CertStore for any saved certificates.
- This requires admin privileges.
```
certutil -store My
``` 

To enumerate the current user's "My" Personal CertStore, we use the same command appending the `-user` argument.
```
certutil -user -store My
```

Enumerate certstores 
- Simpler than using certutil
```
CertifyKit.exe list
```

 CertifyKit's `list` argument by default lists all certificates stored in the current user's "My" CertStore. To specifically enumerate the Local Machine "My" CertStore we can use this:
```
CertifyKit.exe list /storename:my /storelocation:localmachine
```

PowerShell CertStore Enumeration
```
Get-ChildItem Cert:\CurrentUser\ -Recurse
Get-ChildItem Cert:\LocalMachine\ -Recurse
```
- NOTE: It is possible to enumerate other User CertStore if we have Local Admin access to the machine.

## Enumerating Certificate Templates

Enumerate Certificate Authorities (CAs)
```
Certify.exe cas /domain:protectedcb.corp
```

Enumerate Templates
```
Certify.exe find /domain:protectedcb.corp
```

Enumerate access control information for PKI objects
```
Certify.exe pkiobjects
```

Enumerate Templates. Filter for enrolleeSuppliesSubject.
```
Certify.exe find /enrolleeSuppliesSubject /domain:protectedcb.corp
```


Certipy enumeration  (username/password)
```
certipy find -u <username> -p <password> -dc-ip 172.16.67.1 -stdout
```
- Can add `-vunerable` flag to show vulnerabilities.
  
Certipy enumeration (rc4)
```
certipy find -u protecteduser@protectedcb.corp -hashes 'aad3b435b51404eeaad3b435b51404ee:97d563550d309648ecae42657767f6a0' -dc-ip 172.22.87.1 -stdout
```
- Can add `-vunerable` flag to show vulnerabilities.

### ESC1
Enrollee can request cert for ANY user (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT + Client Authentication/Smart Card Logon EKU)
![](../assets/images/Pasted%20image%2020240723001103.png)
- We need all 3 of these with Enrollment Rights for a user we control.
### ESC2
Enrollee can request cert for ANY user (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT + Any Purpose EKU or no EKU)
![](../assets/images/Pasted%20image%2020240723001855.png)
- Same requirements as ESC1 except that EKU is "Any Purpose".
### ESC3
Request an enrollment agent certificate (Application Policy - Certificate Request Agent) and use it to request a cert on behalf of ANY user (Certificate Request Agent EKU)

Template 1
![](../assets/images/Pasted%20image%2020240723002840.png)
- Can request a certificate for Template 1.
  
Template 2
![](../assets/images/Pasted%20image%2020240723002910.png)
- Can use the new certificate to request a cert on behalf of any user via Template 2.
### ESC4
Vulnerable ACLs (GenericWrite) over ADCS Certificate Templates
![](../assets/images/Pasted%20image%2020240723002419.png)
![](../assets/images/Pasted%20image%2020240723002454.png)

OR using Standin
```
StandIn_v13_Net45.exe --adcs --filter SecureUpdate
```
![](../assets/images/Pasted%20image%2020240723002540.png)
### ESC5
Poor Access Control (GenericWrite) on CA Server Computer Object

```
C:\ADCS\Tools\Get-RBCD-Threaded.exe -d cb.corp
```

- NOTE: This can also be enumerated via AD PowerShell, PowerSploit, Bloodhound, whatever you prefer.
![](../assets/images/Pasted%20image%2020240723005311.png)
### ESC7
Vulnerable Certificate Authority Access Control Roles (ManageCA and ManageCertificate)
![](../assets/images/Pasted%20image%2020240723010115.png)
 - ManageCA and ManageCertificate rights for a user we control.
 
![](../assets/images/Pasted%20image%2020240723010207.png)
- And an enabled template that we have enrollment rights for.
### ESC8
NTLM Relay ANY domain computer to ADCS HTTP Endpoints
![](../assets/images/Pasted%20image%2020240723005622.png)
- Requires these permissions + an ADCS HTTP endpoint, which should be accessible by default.
### ESC11
NTLM Relay ANY domain computer to ADCS ICertPassage Remote Protocol (ICPR) RPC Endpoints
![](../assets/images/Pasted%20image%2020240723005711.png)

### Cross Forest Trust Abuse
Enumerate Trusts
```
Get-ADTrust -Filter * -Server internalcb.corp
```

Enumerate the Trusted Root Certification Authorities Root store on the DC.
```
certutil -store -enterprise Root
```

### On-Prem to Cloud
Search for any potential cloud users in the AD environment.
```
Get-ADUser -Filter * -Server cb.corp | select SamAccountName
```
- NOTE: It's a bit trickier if the AD environment is not hybrid joined to cloud. In that case, additional enumeration may be needed.

We can also attempt to identify the org's valid Azure tenant and perform initial recon.
```
Invoke-AADIntReconAsOutsider -DomainName defcorphq.onmicrosoft.com
```
- NOTE: We can attempt guess the tenant name or use OSINT techniques such as Google dorking, scraping LinkedIn, etc. 

And then test for valid users (email) using a tool such as o365creeper.
### Validate email IDs
Save the potential users to a text file (emails.txt).
```
admin@defcorphq.onmicrosoft.com
root@defcorphq.onmicrosoft.com
test@defcorphq.onmicrosoft.com
contact@defcorphq.onmicrosoft.com
```

Run the tool.
```
C:\Python27\python.exe C:\AzAD\Tools\o365creeper\o365creeper.py -f C:\AzAD\Tools\emails.txt -o C:\AzAD\Tools\validemails.txt
```

### CertPotato
 Elevate our privileges to `NT AUTHORITY\SYSTEM` from virtual and network service accounts of a domain-joined machine (for example from a webshell on a Windows server) using ADCS

Webshell running as a Microsoft virtual account.
![](../assets/images/Pasted%20image%2020240723011504.png)

Auth will fall back to using the machine account when connecting over the network (e.g. to an SMB share).

Reference:
https://sensepost.com/blog/2022/certpotato-using-adcs-to-privesc-from-virtual-and-network-service-accounts-to-local-system/

## Abuse
In the next ADCS post we'll dive into some abuse techniques we could weapons against these misconfigurations once they are identified.