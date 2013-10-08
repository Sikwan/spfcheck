SPFChecker

version: 0.1.4dev

Description:
This package is used to validate SPF or SenderID for your emails. It is your job to gather the sending domain and ip,
once this is done you can use this package to validate it.

Usage:

```
from sikwan.spfcheck import SPFCheck


sc = SPFCheck()
print sc.verify(ip, domain, version=1)

```


Changelog:

* 0.1.4dev : Hotfix remove all rule from includes.
