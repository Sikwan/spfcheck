SPFChecker

version: 0.1b

Description:
This package is used to validate SPF or SenderID for your emails. It is your job to gather the sending domain and ip,
once this is done you can use this package to validate it.

Usage:

```
from sikwan.spfcheck import SPFCheck


sc = SPFCheck()
print sc.verify(ip, domain)

```
