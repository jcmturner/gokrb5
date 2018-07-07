# Active Directory Test Environment Setup Notes


## Claims
* Needs Windows 2012
### Enable Claims
* Administrative Tools > Group Policy Management
  * Forest > Domains > DOMAIN.COM > Default Domain Policy (right click, Edit)
  * Compute Configuration > Policies > Administrative Templates > System > KDC
    * Edit "KDC Support for claims"
    * Set to "Enabled" with the option "Always provide claims"
    
### Configure Claims Values
* Administrative Tools > Active Directory Administrative Center
  * Dynamic Access Control > Claim Types > New

| Display name | Attribute | Type |
| -------------|-----------|------|
| username | sAMAccountName | string |
| msTSAllowLogon | msTSAllowLogon | boolean |
| sAMAccountType | sAMAccountType | Integer |
| objectClass | objectClass | multi-valued unsigned integer |
| ou | ou | multi-valued string |
| postalAddress | postalAddress | multi-valued string |

### Inspect Values
```
Get-ADUser -Filter 'Name -like "*test*1*" -properties *
```
    