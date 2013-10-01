SPFChecker

version: 0.1.2dev

Description:
This package is used to validate SPF or SenderID for your emails. It is your job to gather the sending domain and ip,
once this is done you can use this package to validate it.

Usage:

- Instatiate the class sikwan.spfchecker.SPFCheck (You can pass a logger to the class if you want verbose mode)

- Use SPFCheck.verify(ip, domain, version). (Note that version is by default to 1 for SPF, use 2 for SenderId)
