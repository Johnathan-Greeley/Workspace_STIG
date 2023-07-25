# $language = "python3"
# $interface = "1.0"

# Network device stigger for IOS XE Network NDM Switch - ver 3 rev 0


import os, datetime, SecureCRT, array, sys, re, html, string
from datetime import date
from collections import OrderedDict

strFilePath = "\\\\tsclient\\Z\\STIG\\IOS-XE Switches\\"
#strFilePath = 'c:\\STIGS\\'

# sys.path.append(strFilePath)
# from StigVuln import *

# create a global variable that will cache device commands and outputs
CommandCache = []
strAppVersion = "AutoStigXE_Switch_Ver 0.1"


# Use python dictionary to convert netmasks to CIDR
Nets = {
    "255.255.255.255": "/32",
    "255.255.255.254": "/31",
    "255.255.255.252": "/30",
    "255.255.255.248": "/29",
    "255.255.255.240": "/28",
    "255.255.255.224": "/27",
    "255.255.255.192": "/26",
    "255.255.255.128": "/25",
    "255.255.255.0": "/24",
    "255.255.0.0": "/16",
    "255.0.0.0": "/8",
}


class Stig:
    def __init__(self):
        self.vulid = "undefined"
        self.devicetype = "undefined"
        self.finding = "undefined"
        self.status = "Open"
        self.severity = "default"
        self.comments = ""


class Command:
    def __init__(self):
        self.command = "undefined"
        self.output = "undefined"
        self.devicename = "undefined"
        self.status = 0

class IntStatus:
    def __init__(self):
        self.interface = "undefined"
        self.description = "undefined"
        self.vlan = "undefined"        

strVulnVersion = "Apr-23-2021"

# ----- NDM STIGS ----------------------------------------------------------------------------------------  

def V220518(devicetype, devicename):
    # Legacy IDs: V-101369; SV-110473
    # V-220518 - CAT II - The Cisco switch must be configured to limit the number of concurrent management sessions to an organization-defined number.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = "V-220518"
    check.status = "Open"
    strModel = "unknown"
    strModelVersion = "unknown"

    strCommand = "show inventory | i PID"
    strResult = ExecCommand(strCommand, devicename)

    intStart = strResult.splitlines()[1].find(" ")
    intEnd = strResult.splitlines()[1].find(" ", intStart + 1)
    strModel = str(strResult.splitlines()[1][intStart:intEnd]).strip()
    
    strCommand = "show ver | beg Ports.Model"
    strResult = ExecCommand(strCommand, devicename)
    if len(strResult.splitlines()) > 2:
        strModelVersion = strResult.splitlines()[3][32:46]
        
    strCommand = "sh run | i http.secure-server"
    strTemp = ExecCommand(strCommand, devicename)
    if strModel.find("C9300") > -1:
        check.status = "Not_Applicable"
        check.finding = strTemp + "\r" + strResult
        check.comments = (
            "V-220518 - NA - Catalyst 9300 switches no longer have the session-limit command."
        )
    else:
        strCommand = "sh run | i \line.vty.*.*|session-limit"
        strResult = ExecCommand(strCommand, devicename)
        if strResult.find("session-limit", len(devicename) + len(strCommand)) > -1:
            check.status = "NotAFinding"
        check.finding = strTemp + "\r" + strResult
        check.comments = (
            "V-220518 - CAT II - NAF as long as the VTY lines have session-limit >=2"
        )
    return check


def V220519(devicetype, devicename):
    # Legacy IDs: V-101371; SV-110475
    # V-220519 - CAT II - The Cisco switch must be configured to automatically audit account creation.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = "V-220519"
    check.status = "Open"
    strCommand = "sh run | sec log.config"
    strResult = ExecCommand(strCommand, devicename)
    check.comments = "V-220519 - CAT II - OPEN - no logging"
    check.finding = strResult
    if strResult.find("log config", len(devicename) + len(strCommand)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-220519 - CAT II - NAF - Logging enabled"
    return check


def V220520(devicetype, devicename):
    # Legacy IDs: V-96199; SV-105337
    # V220520 - CAT II - The Cisco switch must be configured to automatically audit account modification.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = "V-220520"
    check.status = "Open"
    strCommand = "sh run | sec log.config"
    strResult = ExecCommand(strCommand, devicename)
    check.finding = strResult
    check.comments = "V220520 - CAT II - OPEN - no logging"
    check.finding = strResult
    if strResult.find("log config", len(devicename) + len(strCommand)) > -1:
        check.status = "NotAFinding"
        check.comments = "V220520 - CAT II - NAF - Logging enabled"
    return check


def V220521(devicetype, devicename):
    # Legacy IDs: V-96201; SV-105339
    # V-220521 - CAT II - The Cisco switch must be configured to automatically audit account disabling actions.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = "V-220521"
    check.status = "Open"
    strCommand = "sh run | sec log.config"
    strResult = ExecCommand(strCommand, devicename)
    check.finding = strResult
    check.comments = "V-220521 - CAT II - OPEN - no logging"
    check.finding = strResult
    if strResult.find("log config", len(devicename) + len(strCommand)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-220521 - CAT II - NAF - Logging enabled"
    return check


def V220522(devicetype, devicename):
    # Legacy IDs: V-96203; SV-105341
    # V-220522 - CAT II - The Cisco switch must be configured to automatically audit account removal actions.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = "V-220522"
    check.status = "Open"
    strCommand = "sh run | sec log.config"
    strResult = ExecCommand(strCommand, devicename)
    check.finding = strResult
    check.comments = "V-220522 - CAT II - OPEN - no logging"
    check.finding = strResult
    if strResult.find("log config", len(devicename) + len(strCommand)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-220522 - CAT II - NAF - Logging enabled"
    return check


def V220523(devicetype, devicename):
    # Legacy IDs: V-96205; SV-105343
    # V-220523 - CAT II - The Cisco switch must be configured to enforce approved authorizations for controlling the flow of management information within the device based on control policies.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = "V-220523"
    check.status = "Open"
    check.comments = "V-220523 - OPEN - ACLs were not found."
    strACLName = "Not found"
    intCount = 0
    strCommand = "sh run | i vty..|access-class"
    strResult = str(ExecCommand(strCommand, devicename))
    for line in strResult.splitlines():
        if (
            line.find("access-class") > -1
            and intCount > 0
            and line.find("ip http") == -1
        ):
            intStart = line.find(" ", line.find("access-class") + 1)
            intEnd = line.find(" ", intStart + 1)
            strACLName = line[intStart:intEnd]
            break
        intCount = intCount + 1
    strTemp = strResult
    #crt.Dialog.MessageBox("ACL Name is: " + strACLName)
    if strACLName != "Not found":
        strCommand = "sh ip access-lists " + strACLName
        strResult = ExecCommand(strCommand, devicename)
        if len(strResult) > 3:
            check.status = "NotAFinding"
            check.comments = "V-220523 - NAF - ACL in place"
        check.finding = strTemp + "\r" + strResult
    else:
        check.finding = strResult
    return check


def V220524(devicetype, devicename):
    # Legacy IDs: V-96207; SV-105345
    # V-220524 - CAT II - The Cisco switch must be configured to enforce the limit of three consecutive invalid logon attempts, after which time it must lock out the user account from accessing the device for 15 minutes.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = "V-220524"
    check.status = "Open"
    strCommand = "sh run | i login.block"
    strResult = ExecCommand(strCommand, devicename)
    check.finding = strResult
    check.comments = "!V-220524 - CAT II - ****NOTE AS OF 11/1/2019 THIS IS OPEN / FINDING - BE SURE TO FIX THIS!! *** \r !V-220524 - CAT II - FIX ACTION: conf t - login block-for 900 attempts 3 within 120"
    if strResult.find("block-for", len(devicename) + len(strCommand)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-220524 - CAT II - NAF - Configured to limit the number of failed logon attempts"
    return check


def V220525(devicetype, devicename):
    # Legacy IDs: V-96209; SV-105347
    # V-220525 - CAT II - The Cisco switch must be configured to display the Standard Mandatory DoD Notice and Consent Banner before granting access to the device.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = "V-220525"
    check.status = "Open"
    strCommand = "show run | beg banner"
    if devicetype == "NXOS":
        strCommand = "show run | beg banner next 10"
    strResult = ExecCommand(strCommand, devicename)
    for line in strResult.splitlines():
        # Look for key words that are supposed to be in the banner string
        if str(line).find("USG-authorized", 0) > 5:
            check.status = "NotAFinding"
    if check.status == "NotAFinding":
        check.comments = "Not a finding.  Correct banner in place"
    else:
        check.comments = "Open issue - could not find matching configuration."
    check.finding = strResult
    return check


def V220526(devicetype, devicename):
    # Legacy IDs: V-96217; SV-105355
    # V-220526 - CAT II - The Cisco switch must be configured to protect against an individual falsely denying having performed organization-defined actions to be covered by non-repudiation.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = "V-220526"
    check.status = "Open"
    strCommand = "sh run | i userinfo|logging.enable"
    # if devicetype == "NXOS":
    #    strCommand = "sh run | i \"aaa authentic\""
    strResult = ExecCommand(strCommand, devicename)
    check.finding = strResult
    check.comments = "V-220526 - CAT II - OPEN - Logging not configured."
    if strResult.find("logging enable", len(devicename) + len(strCommand)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-220526 - CAT II - NAF - ACS logs all attempts (successful/unsuccessful) to escalate privilege to any device using TACACS"
    return check


def V220527(devicetype, devicename):
    # Legacy IDs: V-96221; SV-105359
    # V-220527 - CAT II - The Cisco switch must be configured to generate audit records when successful/unsuccessful attempts to log on with access privileges occur.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = "V-220527"
    check.status = "Open"
    strCommand = "sh run | i login.on-*"
    # if devicetype == "NXOS":
    #    strCommand = "sh run | i \"aaa authentic\""
    strResult = ExecCommand(strCommand, devicename)
    check.finding = strResult
    check.comments = "V-220527 - Make sure its applied"
    strResult = ExecCommand(strCommand, devicename)
    check.finding = strResult
    check.comments = "V-220527 - CAT II - OPEN - Logging not configured."
    if strResult.find("login on-success log", len(devicename) + len(strCommand)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-220527 - CAT II - NAF - Audit records generated correctly."
    return check


def V220528(devicetype, devicename):
    # Legacy IDs: V-96223; SV-105361
    # V-220528 - CAT II -  The Cisco switch must produce audit records containing information to establish when (date and time) the events occurred.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = "V-220528"
    check.status = "Open"
    strCommand = "sh run | i service.timestamp"
    strResult = ExecCommand(strCommand, devicename)
    check.finding = strResult
    check.comments = "V-220528 - CAT II - Open - no timestamps configured"
    if strResult.find("service timestamps log", len(devicename) + len(strCommand)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-220528 - CAT II - NAF - Timestamps configured correctly."
    return check


def V220529(devicetype, devicename):
    # Legacy IDs: V-96225; SV-105363
    # V-220529 - CAT II -  The Cisco switch must produce audit records containing information to establish where the events occurred.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = "V-220529"
    check.status = "Open"
    strCommand = "sh ip access-lists | i .log*"
    # if devicetype == "NXOS":
    #    strCommand = "sh run | i \"aaa authentic\""
    strResult = ExecCommand(strCommand, devicename)
    check.finding = strResult
    check.comments = "V-220529 - CAT II - OPEN - No ACLs with logging"
    if strResult.find("log", len(devicename) + len(strCommand)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-220529 - CAT II - NAF - ACL lambdaogging configured."
    return check


def V220530(devicetype, devicename):
    # Legacy IDs: V-96227; SV-105365
    # V-220530 - CAT II - The Cisco switch must be configured to generate audit records containing the full-text recording of privileged commands.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = "V-220530"
    check.status = "Open"
    strCommand = "sh run | i logging.enable|log.config"
    # if devicetype == "NXOS":
    #    strCommand = "sh run | i \"aaa authentic\""
    strResult = ExecCommand(strCommand, devicename)
    check.finding = strResult
    check.comments = "V-220530 - CAT II - OPEN - No Log config"
    if (
        strResult.find("log config", len(devicename) + len(strCommand)) > -1
        and strResult.find("logging enable", len(devicename) + len(strCommand)) > -1
    ):
        check.status = "NotAFinding"
        check.comments = "V-220530 - CAT II - NAF - Logging configured."
    return check


def V220531(devicetype, devicename):
    # Legacy IDs: V-96231; SV-105369
    # V-220531 - CAT II - The Cisco switch must be configured to protect audit information from unauthorized modification.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = "V-220531"
    check.status = "Open"
    strCommand = "sh run all | i file.privilege"
    # if devicetype == "NXOS":
    #    strCommand = "sh run | i \"aaa authentic\""
    strResult = ExecCommand(strCommand, devicename)
    check.finding = strResult
    check.comments = "V-220531 - CAT II - Open - non-standard config.  Please note that IOS 15.x does not support the file privilege feature."
    if strResult.find("file privilege 15", len(devicename) + len(strCommand)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-220531 - CAT II - NAF - file privilege 15 configured."
    return check


def V220532(devicetype, devicename):
    # Legacy IDs: V-96233; SV-105371
    # V-220532 - CAT II - The Cisco switch must be configured to protect audit information from unauthorized deletion.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = "V-220532"
    check.status = "Open"
    strCommand = "sh run all | i file.privilege"
    # if devicetype == "NXOS":
    #    strCommand = "sh run | i \"aaa authentic\""
    strResult = ExecCommand(strCommand, devicename)
    check.finding = strResult
    check.comments = "V-220532 - CAT II - Open - non standard config.  Please note that IOS 15.x does not support the file privilege feature."
    if strResult.find("file privilege 15", len(devicename) + len(strCommand)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-220532 - CAT II - NAF - file privilege 15 configured."
    return check


def V220533(devicetype, devicename):
    # Legacy IDs: V-96237; SV-105375
    # V-220533 - CAT II - The Cisco switch must be configured to limit privileges to change the software resident within software libraries.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = "V-220533"
    check.status = "Open"
    strCommand = "sh run all | i file.privilege"
    # if devicetype == "NXOS":
    #    strCommand = "sh run | i \"aaa authentic\""
    strResult = ExecCommand(strCommand, devicename)
    check.finding = strResult
    check.comments = "V-220533 - CAT II - Open.  Please note that IOS 15.x does not support the file privilege feature."
    if strResult.find("file privilege 15", len(devicename) + len(strCommand)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-220533 - CAT II - NAF - file privilege 15 configured."
    return check


def V220534(devicetype, devicename):
    # Legacy IDs: V-96239; SV-105377
    # V-220534 - CAT I - The Cisco switch must be configured to prohibit the use of all unnecessary and nonsecure functions and services.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = "V-220534"
    check.status = "NotAFinding"
    strCommand = "sh run | i boot.server|identd|finger|http|dns|tcp-small"
    strResult = ExecCommand(strCommand, devicename)
    check.finding = strResult
    check.comments = "V-220534 - CAT I - NAF - no unnecessary services configured"
    if (
        strResult.find("boot network", len(devicename) + len(strCommand)) > -1
        or strResult.find("ip boot server", len(devicename) + len(strCommand)) > -1
        or strResult.find("ip dns server", len(devicename) + len(strCommand)) > -1
        or strResult.find("rcp-enable", len(devicename) + len(strCommand)) > -1
        or strResult.find("rsh-enable", len(devicename) + len(strCommand)) > -1
    ):
        check.status = "Open"
        check.comments = "V-220534 - CAT I - Open - unecessary services enabled."
    return check


def V220535(devicetype, devicename):
    # Legacy IDs: V-96243; SV-105381
    # V-220535 - CAT II -  The Cisco switch must be configured with only one local account to be used as the account of last resort in the event the authentication server is unavailable.    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = "V-220535"
    strCommand = "sh run | i ^username"
    if devicetype == "NXOS":
        strCommand = "show run | i username.*.password"
    check.comments = ""
    strResult = ExecCommand(strCommand, devicename)
    check.finding = strResult
    check.status = "NotAFinding"
    strUserAuthLocalAccounts = [
        "admin",
        "admin1"
        
    ]
    strConfiguredAccounts = []
    finding = []
    # Create a list of configured accounts
    for line in strResult.splitlines():
        if line[0:10].find("username ") > -1:
            strConfiguredAccounts.append(line.split(" ")[1])
    #
    # Check if each configured account is in the authorized list.
    for account in strConfiguredAccounts:
        ismatch = "Open"
        for authaccount in strUserAuthLocalAccounts:
            if account.strip() == authaccount.strip():
                ismatch = "NotAFinding"
                check.comments = (
                    check.comments + "Authorized user found:" + account + "\r"
                )
                break
        finding.append(ismatch)
    #
    # Loop through the findings.  If there's any unknown users mark the Vuln as open
    for obj in finding:
        if str(obj) == "Open":
            check.status = "Open"
    #
    if check.status == "Open":
        check.comments = "V220535: More than one local user account found.  Please review finding details. "
    else:
        check.comments = (
            check.comments + "Account creation authorized by CS, created by ORG"
        )
    return check


def V220536(devicetype, devicename):
    # Legacy IDs: V-96249; SV-105387
    # V-220536 - CAT II - The Cisco switch must be configured to implement replay-resistant authentication mechanisms for network access to privileged accounts.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = "V-220536"
    check.status = "Open"
    strCommand = "sh run all | i ssh.ver|encryption.aes"
    strResult = ExecCommand(strCommand, devicename)
    check.finding = strResult
    check.comments = "V-220536 - CAT II - OPEN - missing configurations"
    if strResult.find("ip ssh version 2", len(devicename) + len(strCommand)) > -1 and (
        strResult.find("aes128-cbc", len(devicename) + len(strCommand)) > -1
        or strResult.find("aes192-cbc", len(devicename) + len(strCommand)) > -1
        or strResult.find("aes192-ctr", len(devicename) + len(strCommand)) > -1
    ):
        check.status = "NotAFinding"
        check.comments = "V-220536 - CAT II - NAF - Secure configuration verified."
    return check


def V220537(devicetype, devicename):
    # Legacy IDs: V-96253; SV-105391
    # V-220537 - CAT II -  The Cisco switch must be configured to enforce a minimum 15-character password length.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = "V-220537"
    check.status = "Open"
    strCommand = "sh aaa common-criteria policy all"
    strResult = ExecCommand(strCommand, devicename)
    check.finding = strResult
    check.comments = "V-220537 - NOTE:  *** Make sure its applied ***"
    if len(strResult.splitlines()) > 2:
        check.status = "NotAFinding"
        check.comments = "V-220537 - CAT II - NAF - common criteria policy configured."
    return check


def V220538(devicetype, devicename):
    # Legacy IDs: V-96255; SV-105393
    # V-220538 - CAT II -  The Cisco switch must be configured to enforce password complexity by requiring that at least one upper-case character be used.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = "V-220538"
    check.status = "Open"
    strCommand = "sh aaa common-criteria policy all"
    strResult = ExecCommand(strCommand, devicename)
    check.finding = strResult
    check.comments = "V-220538 - NOTE:  *** Make sure its applied ***"
    if len(strResult.splitlines()) > 2:
        check.status = "NotAFinding"
        check.comments = "V-220538 - NAF - common criteria policy configured."
    return check


def V220539(devicetype, devicename):
    # Legacy IDs: V-96257; SV-105395
    # V-220539 - CAT II -  The Cisco switch must be configured to enforce password complexity by requiring that at least one lower-case character be used.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = "V-220539"
    check.status = "Open"
    strCommand = "sh aaa common-criteria policy all"
    strResult = ExecCommand(strCommand, devicename)
    check.finding = strResult
    check.comments = "V-220539 - NOTE:  *** Make sure its applied ***"
    if len(strResult.splitlines()) > 2:
        check.status = "NotAFinding"
        check.comments = "V-220539 - NAF - common criteria policy configured."
    return check


def V220540(devicetype, devicename):
    # Legacy IDs: V-96259; SV-105397
    # V-220540 - CAT II - The Cisco switch must be configured to enforce password complexity by requiring that at least one numeric character be used.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = "V-220540"
    check.status = "Open"
    strCommand = "sh aaa common-criteria policy all"
    strResult = ExecCommand(strCommand, devicename)
    check.finding = strResult
    check.comments = "V-220540 - NOTE:  *** Make sure its applied ***"
    if len(strResult.splitlines()) > 2:
        check.status = "NotAFinding"
        check.comments = "V-220540 - NAF - common criteria policy configured."
    return check


def V220541(devicetype, devicename):
    # Legacy IDs: V-96261; SV-105399
    # V-220541 - CAT II -  The Cisco switch must be configured to enforce password complexity by requiring that at least one special character be used.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = "V-220541"
    check.status = "Open"
    strCommand = "sh aaa common-criteria policy all"
    strResult = ExecCommand(strCommand, devicename)
    check.finding = strResult
    check.comments = "V-220541 - NOTE:  *** Make sure its applied ***"
    if len(strResult.splitlines()) > 2:
        check.status = "NotAFinding"
        check.comments = "V-220541 - NAF - common criteria policy configured."
    return check


def V220542(devicetype, devicename):
    # Legacy IDs: V-96263; SV-105401
    # V-220542 - CAT II -  The Cisco switch must be configured to require that when a password is changed, the characters are changed in at least eight of the positions within the password.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = "V-220542"
    check.status = "Open"
    strCommand = "sh aaa common-criteria policy all"
    strResult = ExecCommand(strCommand, devicename)
    check.finding = strResult
    check.comments = "V-220542 - NOTE:  *** Make sure its applied ***"
    if len(strResult.splitlines()) > 2:
        check.status = "NotAFinding"
        check.comments = "V-220542 - NAF - common criteria policy configured."
    return check


def V220543(devicetype, devicename):
    # Legacy IDs: V-96265; SV-105403
    # V-220543 - CAT I -  The Cisco switch must only store cryptographic representations of passwords.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = "V-220543"
    check.status = "Open"
    strCommand = "sh run | i service.password"
    strResult = ExecCommand(strCommand, devicename)
    check.finding = strResult
    check.comments = "V-220543 - CAT 1 - password encryption must be configured"
    if strResult.find("service password-", len(devicename) + len(strCommand)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-220543 - NAF - Password encryption configured."
    return check


def V220544(devicetype, devicename):
    # Legacy IDs: V-96271; SV-105409
    # V-220544 - CAT I -  The Cisco switch must be configured to terminate all network connections associated with device management after 10 minutes of inactivity.
    # The network element must timeout management connections for administrative access after 10 minutes or less of inactivity.
    check = Stig()
    check.vulid = "V-220544"
    strCommand = "sh run all | i vty.0.4|exec-t"
    if devicetype == "NXOS":
        strCommand = "show run | i timeout prev 1"
    # We're going to start with reverse logic, assume all config lines are good.  We'll look at every on and if it's > 10 min we'll fail this vuln
    check.status = "NotAFinding"
    strResult = ExecCommand(strCommand, devicename)
    for line in strResult.splitlines():
        # Look for exec-timeout operand in the string, then split the string into individual operands....
        if str(line).find("exec-timeout", 0) > -1:
            # we know we have a timeout config line.  split the operands via spaces
            lstOperands = line.strip().split(" ")
            # Lets check the second operans, it should hold the current timeout value
            # MsgBox = crt.Dialog.MessageBox
            if len(lstOperands) > 2:
                # MsgBox(str(len(line.strip().split(" "))) + '\r' + (line))
                strTimeout = lstOperands[1]
            else:
                # MsgBox(str(len(line.strip().split(" "))) + '\r' + (line))
                strTimeout = lstOperands[1]
            if int(strTimeout) > 10:
                check.status = "Open"
    if check.status == "NotAFinding":
        check.comments = "Not a finding.  Timeout less than or equal to 10"
    else:
        check.comments = "Open issue - could not find matching configuration."
    check.finding = strResult
    return check


def V220545(devicetype, devicename):
    # Legacy IDs: V-96285; SV-105423
    # V-220545 - CAT II -  The Cisco switch must be configured to automatically audit account enabling actions.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = "V-220545"
    check.status = "Open"
    strCommand = "sh run | i archive|log.config|logging.enable"
    strResult = ExecCommand(strCommand, devicename)
    check.finding = strResult
    check.comments = "V-220545 - Archive logging is required"
    if (
        strResult.find("archive", len(devicename) + len(strCommand)) > -1
        and strResult.find("log config", len(devicename) + len(strCommand)) > -1
        and strResult.find("logging enable", len(devicename) + len(strCommand)) > -1
    ):
        check.status = "NotAFinding"
        check.comments = "V-220545 - CAT II - NAF - Archive logging configured"
    return check


def V220546(devicetype, devicename):
    # Legacy IDs: V-96291; SV-105429
    # V-220546 - CAT II -  The Cisco switch must be configured to audit the execution of privileged functions.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = "V-220546"
    check.status = "Open"
    strCommand = "sh run | i logging.u"
    strResult = ExecCommand(strCommand, devicename)
    check.finding = strResult
    strCommand = "sh run | i archive|log.config|logging.enable"
    strResult = strResult + "\r" + ExecCommand(strCommand, devicename)
    check.finding = strResult
    check.comments = "V-220546 - CAT II - Logging required"
    if strResult.find("log config", len(devicename) + len(strCommand)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-220546 - CAT II - NAF - Logging configured."
    return check


def V220547(devicetype, devicename):
    # Legacy IDs: V-96297; SV-105435
    # V-220547 - CAT II - The Cisco switch must be configured to allocate audit record storage capacity in accordance with organization-defined audit record storage requirements.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = "V-220547"
    check.status = "Open"
    strCommand = "sh run | i logging.buffered"
    strResult = ExecCommand(strCommand, devicename)
    check.finding = strResult
    check.comments = (
        "V-220547 - OPEN - suggest adding logging buffered 1000000 informational"
    )
    if strResult.find("logging buffered", len(devicename) + len(strCommand)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-220547 - CAT II - NAF - ACS manages Authentication."
    return check


def V220548(devicetype, devicename):
    # Legacy IDs: V-96301; SV-105439
    # V-220548 - CAT II - The Cisco switch must be configured to generate an alert for all audit failure events.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = "V-220548"
    check.status = "Open"
    strCommand = "show logging | i Trap|Logging.to"
    strResult = ExecCommand(strCommand, devicename)
    check.finding = strResult
    check.comments = (
        "V220548 - NOTE **** AS OF 11/1/19 THIS IS A FINDING!! PLEASE REMEDIATE"
    )
    if strResult.find("Logging to ", len(devicename) + len(strCommand)) > -1 and (
        strResult.find("debugging", len(devicename) + len(strCommand)) > -1
        or strResult.find("critical", len(devicename) + len(strCommand)) > -1
        or strResult.find("warnings", len(devicename) + len(strCommand)) > -1
        or strResult.find("notifications", len(devicename) + len(strCommand)) > -1
        or strResult.find("informational", len(devicename) + len(strCommand)) > -1
    ):
        check.status = "NotAFinding"
        check.comments = "V-220548 - CAT II - NAF - ext sorce manages Authentication."
    return check


def V220549(devicetype, devicename):
    # Legacy IDs: V-96303; SV-105441
    # V-220549 - CAT II -  The Cisco switch must be configured to synchronize its clock with the primary and secondary time sources using redundant authoritative time sources.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = "V-220549"
    check.status = "Open"
    strCommand = "sh run | i ntp.server"
    if devicetype == "NXOS":
        strCommand = "sh run | i ntp.server"
    strResult = ExecCommand(strCommand, devicename)
    check.finding = strResult
    serverCount = 0
    for line in strResult.splitlines():
        if line.find(devicename) == -1 and line.find("server") > -1:
            serverCount += 1
    check.comments = "Found " + str(serverCount) + " NTP servers."
    if serverCount >= 2:
        check.status = "NotAFinding"
    return check


def V220550(devicetype, devicename):
    # Legacy IDs: V-96305; SV-105443
    # V-220550 - CAT II - The Cisco switch must record time stamps for audit records that meet a granularity of one second for a minimum degree of precision.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = "V-220550"
    check.status = "Open"
    strCommand = "sh run | i service.timestamps"
    strResult = ExecCommand(strCommand, devicename)
    check.finding = strResult
    check.comments = "V-220550 - Missing timestamps"
    if (
        strResult.find("service timestamps log ", len(devicename) + len(strCommand))
        > -1
    ):
        check.status = "NotAFinding"
        check.comments = "V-220550 - CAT II - NAF - Timestamps configured"
    return check


def V220551(devicetype, devicename):
    # Legacy IDs: V-96307; SV-105445
    # V-220551 - CAT II -  The Cisco switch must be configured to record time stamps for log records that can be mapped to Coordinated Universal Time (UTC) or Greenwich Mean Time (GMT).
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = "V-220551"
    check.status = "Open"
    check.comments = "V-220551 - CAT II - Open - Timezone and timestamps required"
    strCommand = "sh run | i timezone|timestamps"
    strResult = ExecCommand(strCommand, devicename)
    check.finding = strResult
    check.comments = "V-220551 - Timestamps must use Zulu time"
    if (
        strResult.find("service timestamps log", len(devicename) + len(strCommand)) > -1
        and strResult.find("clock timezone", len(devicename) + len(strCommand))
        > -1
    ):
        check.status = "NotAFinding"
        check.comments = "V-220551 - CAT II - NAF - Timezone and timestamps configured"
    return check


def V220552(devicetype, devicename):
    # Legacy IDs: V-96317; SV-105455
    # V-220552 - CAT II - The Cisco switch must be configured to authenticate SNMP messages using a FIPS-validated Keyed-Hash Message Authentication Code (HMAC).
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = "V-220552"
    check.status = "Not_Reviewed"
    strCommand = "sh run | i snmp-server|snmp.user "
    strResult = ExecCommand(strCommand, devicename)
    check.finding = strResult
    check.comments = "V-220552 authenticate SNMP messages using a FIPS-validated Keyed-Hash Message Authentication Code (HMAC)."
    strCommand = "sh run | i snmp-server.group"
    strResult = ExecCommand(strCommand, devicename)
    check.finding = strResult
    for line in strResult.splitlines():
        if line.find("v3") == -1 or line.find(devicename) == -1:
            check.status = "NotAFinding"
            check.comments = "NAF SNMP version 3 is in use"
    return check


def V220553(devicetype, devicename):
    # Legacy IDs: V-96319; SV-105457
    # V-220553 - CAT II - The Cisco switch must be configured to encrypt SNMP messages using a FIPS 140-2 approved algorithm.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = "V-220553"
    check.status = "Open"
    strCommand = "sh run | i v3|version.3"
    strResult = ExecCommand(strCommand, devicename)
    check.finding = strResult
    check.comments = "V-220553 - NAF - paste output"
    if strResult.find("v3", len(devicename) + len(strCommand)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-220553 - SNMP v3 is in use."
    return check


def V220554(devicetype, devicename):
    # Legacy IDs: V-96321; SV-105459
    # V-220554 - CAT II -  The Cisco switch must be configured to authenticate Network Time Protocol (NTP) sources using authentication that is cryptographically based.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = "V-220554"
    check.status = "Open"
    strCommand = "sh run | in ntp authentication"
    if devicetype == "NXOS":
        strCommand = 'sh run | in "ntp authentication"'
    strResult = ExecCommand(strCommand, devicename)
    check.finding = strResult
    check.comments = (
        "V-220554 - COMMENTS: MD5 no higher encryption - Downgrades it to a CATIII"
    )

    if strResult.find("md5", len(devicename + "#" + strCommand)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-220554 - MD5 NTP authentication enabled."
    return check


def V220555(devicetype, devicename):
    # Legacy IDs: V-96327; SV-105465
    # V-V-220555 - CAT I - The Cisco switch must be configured to use FIPS-validated Keyed-Hash Message Authentication Code (HMAC) to protect the integrity of remote maintenance sessions.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = "V-220555"
    check.status = "Open"
    strCommand = "sh run all | i ssh.version|server.a"
    strResult = ExecCommand(strCommand, devicename)
    check.finding = strResult
    check.comments = "V-220555 - The Cisco switch must be configured to use FIPS-validated Keyed-Hash Message Authentication Code (HMAC) to protect the integrity of remote maintenance sessions.\r Add the command ip ssh server algorithm mac hmac-sha1-96"
    if (
        strResult.find("ip ssh version 2", len(devicename) + len(strCommand)) > -1
        and (
            strResult.find("hmac-sha1-96", len(devicename) + len(strCommand)) > -1
            or strResult.find("hmac-sha2-256", len(devicename) + len(strCommand))
        )
        > -1
    ):
        check.status = "NotAFinding"
        check.comments = (
            "V-220555 - CAT II - NAF - FIPS-validated Keyed-Hash is being used."
        )
    return check


def V220556(devicetype, devicename):
    # Legacy IDs: V-96329; SV-105467
    # V-220556 -  CAT I - The Cisco switch must be configured to implement cryptographic mechanisms to protect the confidentiality of remote maintenance sessions.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = "V-220556"
    check.status = "Open"
    strCommand = "sh run all | i ssh.version|server.a"
    strResult = ExecCommand(strCommand, devicename)
    check.finding = strResult
    check.comments = "V-220556 -  The Cisco switch must be configured to implement cryptographic mechanisms to protect the confidentiality of remote maintenance sessions."
    if (
        strResult.find("ip ssh version 2", len(devicename) + len(strCommand)) > -1
        and strResult.find("encryption aes", len(devicename) + len(strCommand)) > -1
    ):
        check.status = "NotAFinding"
        check.comments = "V-220556 - CAT II - NAF - Specified cryptographic mechanisms are being used."
    return check


# def V220557(devicetype, devicename):
    # Legacy IDs: V-96331; SV-105469
    # V-220557 -  CAT II - The Cisco switch must be configured to implement cryptographic mechanisms to protect the confidentiality of remote maintenance sessions.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    # check = Stig()
    # check.vulid = "V-220557"
    # check.status = "Open"
    # check.comments = "V-220557 - OPEN - Cisco switch not configured to protect against known types of DoS attacks on the route processor."
    
    # strCommand = "show inventory | i PID"
    # strResult = ExecCommand(strCommand, devicename)

    # intStart = strResult.splitlines()[1].find(" ")
    # intEnd = strResult.splitlines()[1].find(" ", intStart + 1)
    # strModel = str(strResult.splitlines()[1][intStart:intEnd]).strip()

    # strCommand = "sh run | in system.*.policy"
    # strResult = ExecCommand(strCommand, devicename)
    # check.finding = strResult
    # if strModel.find("C9300") > -1 or strModel.find("C3850") > -1:
        # check.status = "NotAFinding"
        # check.comments = (
            # "V-220557 - NAF - Catalyst 9300 and 3850 series switches have the copp-system-policy always configured and applied."
        # )
    # else:
        # if strModel.find("C2960") > -1:
            # strCommand = "sh run | i copp"
            # strResult = ExecCommand(strCommand, devicename)
            # check.finding = strResult
            # if strResult.find("copp", len(devicename) + len(strCommand)) > -1:
                # check.status = "NotAFinding"
                # check.comments = (
                # "V-220557 - NAF - Catalyst 2960 series switches have CoPP in use "
                # )
        # else:
            # strCommand = "sh run | i CoPP"
            # strResult = ExecCommand(strCommand, devicename)
            # check.finding = strResult
            # check.comments = "V-220557 - OPEN - CoPP must be configured"
            # if strResult.find("CoPP", len(devicename) + len(strCommand)) > -1:
                # check.status = "NotAFinding"
                # check.comments = "V-220557 - CAT II - NAF - CoPP is in use."
    # return check


def V220558(devicetype, devicename):
    # Legacy IDs: V-96333; SV-105471
    # V-220558 - CAT II -The Cisco switch must be configured to generate log records when administrator privileges are modified.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = "V-220558"
    check.status = "Open"
    strCommand = "sh run | i logging.user|archive|log.config|logging.enable"
    strResult = ExecCommand(strCommand, devicename)
    check.finding = strResult
    check.comments = "V-220558 - CThe Cisco switch must be configured to generate log records when administrator privileges are modified"
    if (
        strResult.find("archive", len(devicename) + len(strCommand)) > -1
        and strResult.find("logging enable", len(devicename) + len(strCommand)) > -1
    ):
        check.status = "NotAFinding"
        check.comments = "V-220558 - CAT II - NAF - archive logging is enabled"
    return check


def V220559(devicetype, devicename):
    # Legacy IDs: V-96335; SV-105473
    # V-220559 - The Cisco switch must be configured to generate log records when administrator privileges are deleted.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = "V-220559"
    check.status = "Open"
    strCommand = "sh run | i logging.user|archive|log.config|logging.enable"
    strResult = ExecCommand(strCommand, devicename)
    check.finding = strResult
    check.comments = "V-220559 - The Cisco switch must be configured to generate log records when administrator privileges are deleted."
    if (
        strResult.find("archive", len(devicename) + len(strCommand)) > -1
        and strResult.find("logging enable", len(devicename) + len(strCommand)) > -1
    ):
        check.status = "NotAFinding"
        check.comments = "V-220559 - CAT II - NAF - archive logging is enabled"
    return check


def V220560(devicetype, devicename):
    # Legacy IDs: V-96337; SV-105475
    # V-220560 - CAT II -  The Cisco switch must be configured to generate audit records when successful/unsuccessful logon attempts occur.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = "V-220560"
    check.status = "Open"
    strCommand = "sh run | i login.on"
    strResult = ExecCommand(strCommand, devicename)
    check.finding = strResult
    check.comments = (
        "V-220560 - NOTE:  ensure there is logging"
    )
    if (
        strResult.find("on-failure", len(devicename) + len(strCommand)) > -1
        and strResult.find("on-success", len(devicename) + len(strCommand)) > -1
    ):
        check.status = "NotAFinding"
        check.comments = "V-220560 - CAT II - NAF -  Audit records generated when successful/unsuccessful logon attempts occur"
    return check


def V220561(devicetype, devicename):
    # Legacy IDs: V-96339; SV-105477
    # V-220561 - CAT II -  The Cisco switch must be configured to generate log records for privileged activities.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = "V-220561"
    check.status = "Open"
    strCommand = "sh run | i logging.user|archive|log.config|logging.enable"
    strResult = ExecCommand(strCommand, devicename)
    check.finding = strResult
    check.comments = "V-220561 - The Cisco switch must be configured to generate log records for privileged activities"
    if (
        strResult.find("archive", len(devicename) + len(strCommand)) > -1
        and strResult.find("logging enable", len(devicename) + len(strCommand)) > -1
    ):
        check.status = "NotAFinding"
        check.comments = "V-220561 - CAT II - NAF - archive logging is enabled"
    return check


def V220563(devicetype, devicename):
    # Legacy IDs: V-96343; SV-105481
    # V-220563 - CAT II - The Cisco switch must be configured to generate log records when concurrent logons from different workstations occur
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = "V-220563"
    check.status = "Open"
    strCommand = "sh run | i login.on-success"
    strResult = ExecCommand(strCommand, devicename)
    check.finding = strResult
    check.comments = "V-220563 - CAT II - NAF - paste output"
    if strResult.find("login on-success log", len(devicename) + len(strCommand)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-220563 - CAT II - NAF - Login on-success log is configured."
    return check


def V220564(devicetype, devicename):
    # Legacy IDs: V-96345; SV-105483
    # V-220564 - CAT II - The Cisco switch must be configured to off-load log records onto a different system than the system being audited.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = "V-220564"
    check.status = "Open"
    strCommand = "sh run | i logging.host|logging.trap"
    strResult = ExecCommand(strCommand, devicename)
    check.finding = strResult
    check.comments = (
        "V-220564 - NOTE:  Make sure its applied! PLEASE REMEDIATE"
    )
    if (
        strResult.find("logging host", len(devicename) + len(strCommand)) > -1
        and strResult.find("logging trap", len(devicename) + len(strCommand)) > -1
    ):
        check.status = "NotAFinding"
        check.comments = "V-220564 - CAT II - NAF - Login on-success log is configured."
    return check


def V220565(devicetype, devicename):
    # Legacy IDs: V-96351; SV-105489
    # V-220565 - CAT I - The Cisco switch must be configured to use an authentication server for the purpose of authenticating users prior to granting administrative access.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = "V-220565"
    check.status = "Open"
    strCommand = "sh run | sec aaa.group|server-private"
    strResult = ExecCommand(strCommand, devicename)
    check.finding = strResult
    check.comments = "V-220565 - NAF - paste output"
    if (
        strResult.find("aaa group", len(devicename) + len(strCommand)) > -1
        and strResult.find("server-private", len(devicename) + len(strCommand)) > -1
    ) or (
        strResult.find("aaa group", len(devicename) + len(strCommand)) > -1
        and strResult.find("server name", len(devicename) + len(strCommand)) > -1
    ):
        check.status = "NotAFinding"
        check.comments = (
            "V-220565 - CAT II - NAF - Authentication server(s) is configured."
        )
    return check


def V220566(devicetype, devicename):
    # Legacy IDs: V-96359; SV-105497
    # V-220566 - CAT II -  The Cisco switch must be configured to support organizational requirements to conduct backups of the configuration when changes occur.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = "V-220566"
    check.status = "Open"
    strCommand = "sh event manager policy registered"
    strResult = ExecCommand(strCommand, devicename)
    check.finding = strResult
    check.comments = (
        "V-220566 - NOTE:  Make sure its applied! PLEASE REMEDIATE"
    )
    if strResult.find("applet", len(devicename) + len(strCommand)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-220566 - CAT II - NAF - Applet configured and registered."
    return check


def V220567(devicetype, devicename):
    # Legacy IDs: V-96363; SV-105501
    # V-220567 - CAT II -  The Cisco switch must be configured to obtain its public key certificates from an appropriate certificate policy through an approved service provider.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = "V-220567"
    check.status = "NotAFinding"
    strCommand = "show run | i crypto.pki|enroll"
    strResult = ExecCommand(strCommand, devicename)
    strCommand = "show crypto pki certificates"
    strResult = strResult + ExecCommand(strCommand, devicename)
    check.finding = strResult
    check.comments = "V-220567 - COMMENT:  ORG does not use PKI Authentication"
    return check


def V220568(devicetype, devicename):
    # Legacy IDs: V-96365; SV-105503
    # V-220568 - CAT I - The Cisco switch must be configured to send log data to a syslog server for the purpose of forwarding alerts to the administrators and the ISSO.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = "V-220568"
    check.status = "Open"
    strCommand = "sh run | i logging.host|logging.trap.no"
    strResult = ExecCommand(strCommand, devicename)
    check.finding = strResult
    check.comments = (
        "V-220568 - NOTE: Make sure its applied PLEASE REMEDIATE"
    )
    if strResult.find("logging host", len(devicename) + len(strCommand)) > -1:
        check.status = "NotAFinding"
        check.comments = (
            "V-220568 - CAT I - NAF - Remote system logging server(s) in place.."
        )
    return check


def V220569(devicetype, devicename):
    # Legacy IDs: V-96369; SV-105507
    # V-220569 - CAT I - The Cisco switch must be running an IOS release that is currently supported by Cisco Systems.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = "V-220569"
    check.status = "Open"
    strModel = "unknown"
    strModelVersion = "unknown"

    strCommand = "show inventory | i PID"
    strResult = ExecCommand(strCommand, devicename)

    intStart = strResult.splitlines()[1].find(" ")
    intEnd = strResult.splitlines()[1].find(" ", intStart + 1)
    strModel = str(strResult.splitlines()[1][intStart:intEnd]).strip()

    strTemp = strResult
    if strModel.find("ASR") > -1 or strModel.find("ISR4") > -1:
        strCommand = "show ver | i IOS"
        strResult = ExecCommand(strCommand, devicename)
        intStart = strResult.splitlines()[1].find(
            " ", strResult.splitlines()[1].find("Version") + 1
        )
        intEnd = strResult.splitlines()[1].find("\r", intStart)
        strModelVersion = strResult.splitlines()[1][intStart:]
        if removechar(strModelVersion) >= removechar("16.09.04"):
            check.status = "NotAFinding"
            check.comments = (
                "NAF: As of 1/16/2020 ASR/ISR devices should have code level 16.9.4.  This device has "
                + strModelVersion
            )
        else:
            check.status = "Open"
            check.comments = (
                "OPEN: As of 1/16/2020 ASR/ISR devices should have code level 16.9.4.  This device has "
                + strModelVersion
            )

    if strModel.find("CISCO39") > -1:
        strCommand = "show ver | i IOS"
        strResult = ExecCommand(strCommand, devicename)
        intStart = strResult.splitlines()[1].find(
            " ", strResult.splitlines()[1].find("Version") + 1
        )
        intEnd = strResult.splitlines()[1].find(",", intStart)
        strModelVersion = strResult.splitlines()[1][intStart:intEnd]
        if removechar(strModelVersion) >= removechar("15.7(3)M5"):
            check.status = "NotAFinding"
            check.comments = (
                "NAF: As of 1/16/2020 ISRG2 devices should have code level 15.7(3)M5.  This device has "
                + strModelVersion
            )
        else:
            check.status = "Open"
            check.comments = (
                "OPEN: As of 1/16/2020 ISRG2 devices should have code level 15.7(3)M5.  This device has "
                + strModelVersion
            )

    if strModel.find("C650") > -1:
        strCommand = "show ver | i IOS"
        strResult = ExecCommand(strCommand, devicename)
        intStart = strResult.splitlines()[1].find(
            " ", strResult.splitlines()[1].find("Version") + 1
        )
        intEnd = strResult.splitlines()[1].find(",", intStart)
        strModelVersion = strResult.splitlines()[1][intStart:intEnd]
        if removechar(strModelVersion) >= removechar("15.1(2)SY14"):
            check.status = "NotAFinding"
            check.comments = (
                "NAF: As of 10/17/2019 Cisco recomends 6500 series devices should have code level 15.1(2)SY14.  This device has "
                + strModelVersion
            )
        else:
            check.status = "Open"
            check.comments = (
                "OPEN: As of 10/17/2019 Cisco recomends 6500 series devices should have code level 15.1(2)SY14.  This device has "
                + strModelVersion
            )
    strTemp = strTemp + strResult
    if devicetype == "NXOS":
        strCommand = "show ver | i System:|system:|NXOS:|Chassis|chassis"
        strResult = ExecCommand(strCommand, devicename)
        if len(strResult.splitlines()) > 2:
            if len(strResult.splitlines()[1]) > 8:
                strModelVersion = strResult.splitlines()[1][
                    strResult.splitlines()[1].find("version")
                    + 8 : len(strResult.splitlines()[1])
                ]
        if strModel.find("N9K") > -1:
            if removechar(strModelVersion) >= removechar("70376"):
                check.status = "NotAFinding"
                check.comments = (
                    "NAF: As of 1/16/2020 Nexus 9K series switches should have code level 7.0(3)I7(6).  This device has "
                    + strModelVersion
                )
            else:
                check.status = "Open"
                check.comments = (
                    "OPEN: As of 1/16/2020 Nexus 9K series switches should have code level 7.0(3)I7(6).  This device has "
                    + strModelVersion
                )

        if strModel.find("N5K") > -1:
            if removechar(strModelVersion) >= removechar("73511"):
                check.status = "NotAFinding"
                check.comments = (
                    "NAF: As of 1/16/2020 Nexus 5K series switches should have code level 7.3(5)N1(1).  This device has "
                    + strModelVersion
                )
            else:
                check.status = "Open"
                check.comments = (
                    "OPEN: As of 1/16/2020 Nexus 5K series switches should have code level 7.0(3)I7(6).  This device has "
                    + strModelVersion
                )

        if strModel.find("N3K") > -1:
            if removechar(strModelVersion) >= removechar("70376"):
                check.status = "NotAFinding"
                check.comments = (
                    "NAF: As of 1/16/2020 Nexus 3K series switches should have code level 7.0(3)I7(6).  This device has "
                    + strModelVersion
                )
            else:
                check.status = "Open"
                check.comments = (
                    "OPEN: As of 1/16/2020 Nexus 3K series switches should have code level 7.0(3)I7(6).  This device has "
                    + strModelVersion
                )
    else:
        strCommand = "show ver | beg Ports.Model"
        strResult = ExecCommand(strCommand, devicename)
        if len(strResult.splitlines()) > 2:
            strModelVersion = strResult.splitlines()[3][32:46]
        if strModel.find("9300") > -1:
            if removechar(strModelVersion) >= removechar("17.03.05"):
                check.status = "NotAFinding"
                check.comments = (
                    "NAF: As of 4/1/2022 Cat 9300 series switches should have code level 17.03.05.  This device has "
                    + strModelVersion
                )
            else:
                check.status = "Open"
                check.comments = (
                    "OPEN: As of 4/1/2022 Cat 9300 series switches should have code level 17.03.05.  This device has "
                    + strModelVersion
                )
        if strModel.find("3850") > -1 or strModel.find("3650") > -1:
            if removechar(strModelVersion) >= removechar("16.12.7"):
                check.status = "NotAFinding"
                check.comments = (
                    "NAF: As of 2/3/2022 Cat 3850 and 3650 series switches should have code level 16.12.7.  This device has "
                    + strModelVersion
                )
            else:
                check.status = "Open"
                check.comments = (
                    "OPEN: As of 2/3/2022 Cat 3850 and 3650 series switches should have code level 16.12.7.  This device has "
                    + strModelVersion
                )
        if (
            strModel.find("3750") > -1
            or strModel.find("3560") > -1
            or strModel.find("2960") > -1
        ):
            if removechar(strModelVersion) >= removechar("15.02(4)E09"):
                check.status = "NotAFinding"
                check.comments = (
                    "NAF: As of 1/16/2020 Cat 3750, 3560, and 2960 series switches should have code level 15.02(4)E9.  This device has "
                    + strModelVersion
                )
            else:
                check.status = "Open"
                check.comments = (
                    "OPEN: As of 1/16/2020 Cat 3750, 3560, and 2960 series switches should have code level 15.02(4)E9.  This device has "
                    + strModelVersion
                )

        # if strModel.find("ASR"):
        #    strModelVersion = strResult.splitlines()[1][strResult.splitlines()[1].find("version")+8:len(strResult.splitlines()[1])]
    strResult = strTemp + "\r" + strResult
    check.finding = strResult
    return check

# ----- L2S STIGS ----------------------------------------------------------------------------------------    
        
#def V220648(devicetype, devicename):
    # V-220648 - The Cisco switch must be configured to disable non-essential capabilities.
#    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
#    check.vulid = "V-220648"
#    check.status = "NotAFinding"
#    check.comments = "V-220648 - NAF as a non-essential features are NOT enabled"
#    strCommand = (
#        "sh run | i boot.server|identd|finger|http|dns|tcp-small|rcmd|udp-small|pad"
#    )
#    strResult = ExecCommand(strCommand, devicename)
#    if (
#        strResult.find("boot network", len(devicename) + len(strCommand)) > -1
#        or strResult.find("ip boot server", len(devicename) + len(strCommand)) > -1
#        or strResult.find("ip dns server", len(devicename) + len(strCommand)) > -1
#        or strResult.find("rcp-enable", len(devicename) + len(strCommand)) > -1
#        or strResult.find("rsh-enable", len(devicename) + len(strCommand)) > -1
#    ):
#        check.status = "Open"
#        check.comments = "V-220648 - OPEN as a non-essential features is enabled"
#    check.finding = strResult + "\r"
#    return check


def V220649(devicetype, devicename):
    # V-220649 - The Cisco switch must uniquely identify all network-connected endpoint devices before establishing any connection..
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = "V-220649"
    check.status = "Not_Applicable"
    check.comments = (
        "V-220649 - Not applicable - There are no end-user devices in the datacenter."
    )
    #
    return check


def V220650(devicetype, devicename):
    # V-220650 - The Cisco switch must authenticate all VLAN Trunk Protocol (VTP) messages with a hash function using the most secured cryptographic algorithm available.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = "V-220650"
    check.status = "NotAFinding"
    check.comments = "V-220650 - Not running VTP."

    strTemp = ""

    strCommand = "show vtp status"
    strResult = ExecCommand(strCommand, devicename)
    strTemp = strResult
    if strResult.find("Off", len(devicename) + len(strCommand)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-220650 - Running VTP, but in transparent mode."
    else:
        strCommand = "show vtp pass"
        strResult = ExecCommand(strCommand, devicename)
        strTemp = strTemp + "\r" + strResult
        if strResult.find("Password", len(devicename) + len(strCommand)) == -1:
            check.status = "Open"
            check.comments = (
                "V-220650 - Open - Participating in VTP, but without a password configured."
            )
        else:
            check.status = "NotAFinding"
            check.comments = (
                "V-220650 - NAF - Participating in VTP with a password configured."
            )
    check.finding = strTemp
    return check


def V220651(devicetype, devicename):
    # V-220651 - The Cisco switch must manage excess bandwidth to limit the effects of packet flooding types of denial of service (DoS) attacks.    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = "V-220651"
    check.status = "NotAFinding"
    strCommand = "show policy-map interface"
    strResult = ExecCommand(strCommand, devicename)
    check.finding = strResult
    check.comments = "V-220651 - NAF - Datacenter switches only connect to servers."
    return check


#def V220652(devicetype, devicename):
    # V-220652 - The Cisco switch must be configured for authorized users to select a user session to capture.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
#    check = Stig()
#    check.vulid = "V-220652"
#    check.status = "NotAFinding"
#    strCommand = "show monitor session all"
#    strResult = ExecCommand(strCommand, devicename)
#    check.finding = strResult
#    check.comments = "V-220652 - NAF - Feature is supported on Cisco devices.  In addition, Datacenter switches #only connect to servers."
#    return check


#def V220653(devicetype, devicename):
    # V-220653 - The Cisco switch must be configured for authorized users to remotely view, in real time, all #content related to an established user session from a component separate from The Cisco switch.
#    check = Stig()
#    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
#    check.vulid = "V-220653"
#    check.status = "NotAFinding"
#    strCommand = "show run | sec monitor.session"
#    strResult = ExecCommand(strCommand, devicename)
#    check.finding = strResult
#    check.comments = "V-220653 - NAF - Datacenter switches only connect to servers.  In addition, all NXOS switches #are capable of this function."
#    return check


#def V220654(devicetype, devicename):
    # V-220654 - The Cisco switch must authenticate all endpoint devices before establishing any connection.
#    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
#    check.vulid = "V-220654"
#    check.status = "NotAFinding"
#    strCommand = "show run | i interface.Ether|dot1x|aaa.authentication.dot1x|aaa.group.server.radius|#aaa.authentication.dot1x"
#    strResult = ExecCommand(strCommand, devicename)
#    check.finding = strResult
#    check.comments = "V-220654 - NAF - Datacenter switches only connect to servers.  In addition, all NXOS switches #are capable of this function."
#    return check


def V220655(devicetype, devicename):
    # V-220655 - The Cisco switch must have Root Guard enabled on all switch ports connecting to access layer switches and hosts.
    check = Stig()
    MsgBox = crt.Dialog.MessageBox
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = "V-220655"
    check.status = "NotAFinding"
    # Find all the root ports.
    strCommand = "show spanning-tree | i Root.FWD"
    rootPorts = []
    trunkPorts = []
    strResult = ExecCommand(strCommand, devicename)
    strTemp = strResult
    for line in strResult.splitlines():
        port = line[0 : line.find(" ")]
        isfound = False
        if line.find("#") == -1 and line.find("show") == -1:
            for portname in rootPorts:
                if portname == port:
                    isfound = True
            if isfound == False:
                rootPorts.append(port)
    check.comments = "Found the following root ports: "
    for port in rootPorts:
        check.comments = check.comments + ", " + port
    # Find all trunk ports
    strCommand = "show int trunk | i trunking | exc not-trunking"
    strResult = ExecCommand(strCommand, devicename)
    # Now lets find all trunking ports that aren't root ports
    for line in strResult.splitlines():
        port = line[0 : line.find(" ")]
        isfound = False
        for portname in rootPorts:
            if portname == port:
                isfound = True
        if isfound == False:
            if line.find("#") == -1 and line.find("show") == -1:
                trunkPorts.append(port)
    strTemp = strTemp + "\r" + strResult
    if len(trunkPorts) == 0:
        check.comments = check.comments + "\r" + "All trunking ports are root ports."
        check.status = "NotAFinding"
    else:
        strResult = ""
        # Check all non-root trunk ports for root guard
        for port in trunkPorts:
            strCommand = "show run int " + port
            portconfig = ExecCommand(strCommand, devicename)
            if portconfig.find("UL") == -1 and portconfig.find("DL") == -1:
                if portconfig.find("guard root") == -1:
                    check.status = "Open"
                    check.comments = (
                        check.comments
                        + "\r Interface "
                        + port
                        + " is not configured with root guard.  This may not be a finding if this is facing infrastructure devices."
                    )
                else:
                    check.comments = (
                        check.comments
                        + "\r Interface "
                        + port
                        + " is configured correctly."
                    )
            else:
                check.comments = (
                    check.comments
                    + "\r Interface "
                    + port
                    + " is does not require root guard."
                )
            strTemp = strTemp + portconfig
    check.finding = strTemp
    # check.comments = "V-220655 - NAF - Datacenter switches only connect to servers."
    return check


def V220656(devicetype, devicename):
    # V-220656 - The Cisco switch must have BPDU Guard enabled on all user-facing or untrusted access switch ports.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = "V-220656"
    check.status = "Not_Applicable"
    strCommand = "show run | i interface.Eth|bpduguard"
    strResult = ExecCommand(strCommand, devicename)
    check.finding = strResult
    check.comments = "V-220656 - Not Applicable - Datacenter switches only connect to trusted infrastructure devices."
    return check


def V220657(devicetype, devicename):
    # V-220657 -  The Cisco switch must have STP Loop Guard enabled.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = "V-220657"
    check.status = "Open"
    check.comments = (
        "V-220657 - OPEN - The Cisco switch must have STP Loop Guard enabled."
    )
    strCommand = "show run | i loopguard"
    strResult = ExecCommand(strCommand, devicename)
    if strResult.find("loopguard default", len(devicename) + len(strCommand)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-220657 - NAF  The Cisco switch has STP Loop Guard enabled."
    check.finding = strResult + "\r"
    return check


def V220658(devicetype, devicename):
    # V-220658 - The Cisco switch must have Unknown Unicast Flood Blocking (UUFB) enabled.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = "V-220658"
    check.status = "Not_Applicable"
    strCommand = "show run | i block"
    strResult = ExecCommand(strCommand, devicename)
    check.finding = strResult
    check.comments = "V-220658 - Not Applicable - Datacenter switches only connect to trusted infrastructure devices."
    return check


def V220659(devicetype, devicename):
    # V-220659 - The Cisco switch must have DHCP snooping for all user VLANs to validate DHCP messages from untrusted sources.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = "V-220659"
    check.status = "Not_Applicable"
    strCommand = "show run | i dhcp.snoop"
    strResult = ExecCommand(strCommand, devicename)
    check.finding = strResult
    check.comments = "V-220659 - Not Applicable - Datacenter switches only connect to trusted infrastructure devices."
    return check


def V220660(devicetype, devicename):
    # V-220660 - The Cisco switch must have IP Source Guard enabled on all user-facing or untrusted access switch ports.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = "V-220660"
    check.status = "Not_Applicable"
    strCommand = "show run | i verify.*.dhcp.snoop"
    strResult = ExecCommand(strCommand, devicename)
    check.finding = strResult
    check.comments = "V-220660 - Not Applicable - Datacenter switches only connect to trusted infrastructure devices."
    return check


def V220661(devicetype, devicename):
    # V-220661 - The Cisco switch must have Dynamic Address Resolution Protocol (ARP) Inspection (DAI) enabled on all user VLANs.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = "V-220661"
    check.status = "Not_Applicable"
    strCommand = "show run | i arp.inspection.vlan"
    strResult = ExecCommand(strCommand, devicename)
    check.finding = strResult
    check.comments = "V-220661 - Not Applicable - Datacenter switches only connect to trusted infrastructure devices."
    return check


def V220662(devicetype, devicename):
    # V-220662 - The Cisco switch must have Storm Control configured on all host-facing switchports.
    check = Stig()
    MsgBox = crt.Dialog.MessageBox
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = "V-220662"
    check.status = "NotAFinding"
    # Find all the root ports.
    strCommand = "show spanning-tree | i Root.FWD"
    rootPorts = []
    trunkPorts = []
    strResult = ExecCommand(strCommand, devicename)
    strTemp = strResult
    for line in strResult.splitlines():
        port = line[0 : line.find(" ")]
        isfound = False
        if line.find("#") == -1 and line.find("show") == -1:
            for portname in rootPorts:
                if portname == port:
                    isfound = True
            if isfound == False:
                rootPorts.append(port)
    check.comments = "Found the following root ports: "
    for port in rootPorts:
        check.comments = check.comments + ", " + port
    # Find all trunk ports
    strCommand = "show int trunk | i trunking | exc not-trunking"
    strResult = ExecCommand(strCommand, devicename)
    # Now lets find all trunking ports that aren't root ports
    for line in strResult.splitlines():
        port = line[0 : line.find(" ")]
        isfound = False
        for portname in rootPorts:
            if portname == port:
                isfound = True
        if isfound == False:
            if line.find("#") == -1 and line.find("show") == -1:
                trunkPorts.append(port)
    strTemp = strTemp + "\r" + strResult
    if len(trunkPorts) == 0:
        check.comments = check.comments + "\r" + "All trunking ports are root ports."
        check.status = "NotAFinding"
    else:
        strResult = ""
        # Check all non-root trunk ports for root guard
        for port in trunkPorts:
            strCommand = "show run int " + port
            portconfig = ExecCommand(strCommand, devicename)
            if portconfig.find("UL") == -1 and portconfig.find("DL") == -1:
                if portconfig.find("storm-control") == -1:
                    check.status = "Open"
                    check.comments = (
                        check.comments
                        + "\r Interface "
                        + port
                        + " is not configured with storm control.  This may not be a finding if this is facing infrastructure devices."
                    )
                else:
                    check.comments = (
                        check.comments
                        + "\r Interface "
                        + port
                        + " is configured correctly."
                    )
            else:
                check.comments = (
                    check.comments
                    + "\r Interface "
                    + port
                    + " does not require storm control."
                )
            strTemp = strTemp + portconfig
    check.finding = strTemp
    return check


def V220663(devicetype, devicename):
    # V-220663 - The Cisco switch must have IGMP or MLD Snooping configured on all VLANs.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = "V-220663"
    check.status = "Open"
    check.comments = "V-220663 - Open - The Cisco switch must have IGMP or MLD Snooping configured on all VLANs."
    strCommand = "show run all | i igmp.snooping$"
    strResult = ExecCommand(strCommand, devicename)
    if (
        strResult.find("ip igmp snooping", len(devicename) + len(strCommand)) > -1
        and strResult.find("ip igmp snooping", len(devicename) + len(strCommand)) > -1
    ):
        check.status = "NotAFinding"
        check.comments = "V-220663 - NAF  The Cisco switch has IGMP or MLD snooping is enabled globally."
    check.finding = strResult
    return check


def V220664(devicetype, devicename):
    # V-220664 - Rule Title: The Cisco switch must implement Rapid STP where VLANs span multiple switches with redundant links.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = "V-220664"
    check.status = "Open"
    check.comments = "V-220664 - Open - The Cisco switch must implement Rapid STP where VLANs span multiple switches with redundant links."
    strCommand = "show spanning-tree summary | i mode"
    strResult = ExecCommand(strCommand, devicename)
    if (
        strResult.find("rapid", len(devicename) + len(strCommand)) > -1
        or strResult.find("mst", len(devicename) + len(strCommand)) > -1
    ):
        check.status = "NotAFinding"
        check.comments = "V-220664 - NAF  The Cisco switch has RPVST enabled."
    check.finding = strResult
    return check


def V220665(devicetype, devicename):
    # V-220665 - Rule Title: The Cisco switch must enable Unidirectional Link Detection (UDLD) to protect against one-way connections.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = "V-220665"
    check.status = "Open"
    check.comments = "V-220665 - Open - The Cisco switch must enable Unidirectional Link Detection (UDLD) to protect against one-way connections.\r"
    strCommand = "show run | i udld"
    strResult = ExecCommand(strCommand, devicename)
    if (
        strResult.find("enable", len(devicename) + len(strCommand)) > -1
        or strResult.find("aggressive", len(devicename) + len(strCommand)) > -1
    ):
        check.status = "NotAFinding"
        check.comments = "V-220665 - NAF - The Cisco switch has UDLD feature enabled and running on all fiber attached ports.\r"
    check.finding = strResult
    return check


def V220666(devicetype, devicename):
    # V-220666 - The Cisco switch must have all trunk links enabled statically
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = "V-220666"
    check.status = "Open"
    check.comments = "V-220666 - Open - The Cisco switch ports must have nonegotiate configured."
    strCommand = "show interfaces switchport | i Negotiation"
    strResult = ExecCommand(strCommand, devicename)
    if strResult.find("On", len(devicename) + len(strCommand)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-220666 - NAF  As there are no dynamic ports"
    check.finding = strResult
    return check


def V220667(devicetype, devicename):
    # V-220667 -The Cisco switch must have all disabled switch ports assigned to an unused VLAN.
    MsgBox = crt.Dialog.MessageBox
    check = Stig()
    Interfaces = []
    strTemp = ""
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = "V-220667"
    check.status = "NotAFinding"
    check.comments = "V-220667 - NAF - The Cisco switch has all disabled switch ports assigned to an unused VLAN.\r"

    # Lets get a list of all disabled ports
    # strCommand = "show interface status | i disabled | exc Po"
    strCommand = "show interface status | inc sfpAbsent|disabled|xcvrAbsen"
    strResult = ExecCommand(strCommand, devicename)
    # Lets get a port info
    for currentline in strResult.splitlines():
        InterfaceInfo = IntStatus()
        if (
            currentline.find("Eth") > -1 or currentline.find("Po") > -1
        ) and currentline.find("#") == -1:
            InterfaceInfo.interface = currentline[0:12].strip()
            InterfaceInfo.description = currentline[14:33].strip()
            InterfaceInfo.vlan = currentline[43:50].strip()
            Interfaces.append(InterfaceInfo)
    # Now we'll make sure all ports are in vlan 666
    for Interface in Interfaces:
        if Interface.interface.find("undefined") == -1:
            if (
                Interface.vlan.find("666") == -1
                and Interface.vlan.find("2299") == -1
                and Interface.vlan.find("2195")
            ):
                check.status = "Open"
                strTemp = (
                    strTemp
                    + " "
                    + Interface.interface
                    + " ("
                    + Interface.description
                    + ")"
                    + " is disabled but assigned to VLAN "
                    + Interface.vlan
                    + "; "
                )
    if check.status == "Open":
        check.comments = "V-220667 - OPEN because " + strTemp + "\r"
    check.finding = strResult
    return check


def V220668(devicetype, devicename):
    # V-220668 - The Cisco switch must not have the default VLAN assigned to any host-facing switch ports.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = "V-220668"
    check.status = "Open"
    check.comments = "V-220668 - Open - The Cisco switch must not have the default VLAN assigned to any host-facing switch ports."
    strCommand = "show spanning-tree vlan 1"
    strResult = ExecCommand(strCommand, devicename)
    if strResult.find("does not exist", len(devicename) + len(strCommand)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-220668 - NAF  No host-facing ports are assigned to VLAN1"
    check.finding = strResult
    return check


def V220669(devicetype, devicename):
    # V-220669 - The Cisco switch must have the default VLAN pruned from all trunk ports that do not require it.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = "V-220669"
    check.status = "Open"
    check.comments = "V-220669 - Open - The Cisco switch must have the default VLAN pruned from all trunk ports that do not require it."
    strCommand = "show spanning-tree vlan 1"
    strResult = ExecCommand(strCommand, devicename)
    if strResult.find("does not exist", len(devicename) + len(strCommand)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-220669 - NAF VLAN1 is not in use or trunked"
    check.finding = strResult
    return check


def V220670(devicetype, devicename):
    # V-220670 - The Cisco switch must not use the default VLAN for management traffic.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = "V-220670"
    check.status = "Open"
    check.comments = "V-220670 - Open - The Cisco switch must not use the default VLAN for management traffic."
    strCommand = "show spanning-tree vlan 1"
    strResult = ExecCommand(strCommand, devicename)
    strCommand = "show run int vlan 1"
    strResult = strResult + "\r" + ExecCommand(strCommand, devicename)
    if (
        strResult.find("does not exist", len(devicename) + len(strCommand)) > -1
        and strResult.find("no ip address", len(devicename) + len(strCommand)) > -1
    ):
        check.status = "NotAFinding"
        check.comments = "V-220670 - NAF VLAN1 is not being used for management."
    check.finding = strResult
    return check


def V220671(devicetype, devicename):
    # V-220671 - The Cisco switch must have all user-facing or untrusted ports configured as access switch ports.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = "V-220671"
    check.status = "Not_Applicable"
    strCommand = "sh int status | ex trunk|666|disabled"
    strResult = ExecCommand(strCommand, devicename)
    check.finding = strResult
    check.comments = "V-220671 - Not Applicable - Datacenter switches only connect to trusted infrastructure devices."
    return check


def V220672(devicetype, devicename):
    # V-220672 - The native VLAN must be assigned to a VLAN ID other than the default VLAN for all 802.1q trunk links.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = "V-220672"
    check.status = "NotAFinding"
    check.comments = "V-220672 - NAF - The native VLAN on trunk links is other than the default VLAN for all 802.1q trunk links."

    Interfaces = []
    strTemp = ""
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    intCount = 0
    bolContinue = True
    # Lets get a list of all trunk ports
    strCommand = "show int trunk"
    strResult = ExecCommand(strCommand, devicename)
    # Lets get a port info
    for currentline in strResult.splitlines():
        InterfaceInfo = IntStatus()
        if (currentline.find("--------")) > -1:
            intCount = intCount + 1
        if (
            (currentline.find("Eth") > -1 or currentline.find("Po") > -1)
            and currentline.find("#") == -1
            and intCount <= 2
        ):
            InterfaceInfo.interface = currentline[0:12].strip()
            InterfaceInfo.vlan = currentline[14:22].strip()
            Interfaces.append(InterfaceInfo)
    # Now we'll make sure all ports are not in VLAN 1
    for Interface in Interfaces:
        if Interface.interface.find("undefined") == -1:
            if Interface.vlan == "1":
                check.status = "Open"
                strTemp = (
                    strTemp
                    + " "
                    + Interface.interface
                    + "'s native VLAN appears to be assigned to default vlan "
                    + Interface.vlan
                    + "; "
                )
    if check.status == "Open":
        check.comments = "V-220672 - OPEN because " + strTemp + "\r"
    check.finding = strResult
    return check


def V220673(devicetype, devicename):
    # V-220673 - The Cisco switch must not have any switchports assigned to the native VLAN.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = "V-220673"
    check.status = "Open"
    check.comments = "V-220673 - Open - The Cisco switch must not have any switchports assigned to the native VLAN."
    strCommand = "sh int status | in connected.2172"
    strResult = ExecCommand(strCommand, devicename)
    if strResult.find("", len(devicename) + len(strCommand)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-220673 - NAF Native VLAN 200 is not in use by access ports."
    check.finding = strResult
    return check    

# def Vtemplate(devicetype, devicename):
#    #Info about Vulnerability.
#    check = Stig()
#    #The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
#    check = Stig()
#    check.vulid = "V-3012"
#    check.status = "Not_Reviewed"
#    strCommand = "sh run| i aaa authentic"
#    #if devicetype == "NXOS":
#    #    strCommand = "sh run | i \"aaa authentic\""
#    strResult = ExecCommand(strCommand, devicename)
#    check.finding = strResult
#    #Time to check the results of the command...   save check status to check.status and commants to check.comments
#    #if len(strResult1.splitlines()) < 3 and len(strResult2.splitlines()) < 3:
# 	#	check.status = "NotAFinding"
# 	#	check.comments = "NAF - There are no community or user accounts."
#    #if strResult.find("logging level", len(devicename + "#" + strCommand)) > -1:
#    #        check.status = "NotAFinding"
#    #        check.comments = "NXOS logging enabled."
#    #
#    return check
# ----------------------------------------------------------------------------------------
def IsItInt(s):
    try:
        int(s)
        return True
    except ValueError:
        return False


def RemoveDup(duplicate):
    final_list = []
    for num in duplicate:
        if num not in final_list:
            final_list.append(num)
    return final_list


def removechar(x):
    # crt.Dialog.MessageBox("X is: " + x)
    Output = re.sub("\D", "", x)
    # crt.Dialog.MessageBox("Ouput is: " + str(Output))
    return Output


def ExecCommand(strCommand, strDeviceName):
    if strDeviceName.find(".") > -1:
        strPrompt = "#"
    else:
        strPrompt = strDeviceName + "#"
    MsgBox = crt.Dialog.MessageBox
    # MsgBox(strPrompt)
    strResult = ""
    mycmd = Command()
    mycmd.command = strCommand
    mycmd.devicename = strDeviceName
    # Check the command cache in case we've already tried this command for this device
    for cmd in CommandCache:
        if cmd.command == mycmd.command and cmd.devicename == mycmd.devicename:
            mycmd.output = cmd.output
    # if we've not run this command, lets run it and add to the cache
    if mycmd.output == "undefined":
        crt.Screen.WaitForStrings(["#", ">"], 1)
        crt.Screen.Send(strCommand + "\r")
        # crt.Screen.WaitForStrings(["#",">"],2)
        strResult = crt.Screen.ReadString(strPrompt, 30)
        # MsgBox("try 1:\r" + strResult)
        if len(strResult) < len(strDeviceName):
            crt.Screen.WaitForStrings(["#", ">"], 1)
            crt.Screen.Send("\x03" + "\r")
            strResult = crt.Screen.ReadString(strPrompt, 10)
            crt.Screen.WaitForStrings(["#", ">"], 5)
            crt.Screen.Send(strCommand + "\r")
            # crt.Screen.WaitForStrings(["#",">"],5)
            strResult = crt.Screen.ReadString(strPrompt, 110)
            # MsgBox("FAILed 1, try 2:\r" + strResult)
        # The hostname is stripped in SecureCRT.   Adding it back for if we know a hostname already.
        if strDeviceName.find(".") > -1:
            strResult = strResult.strip().replace(strDeviceName, "")
        else:
            strResult = strPrompt + strResult.replace("\r", "") + strPrompt
        mycmd.output = strResult
        # MsgBox(strResult)
        if mycmd.output.find("Invalid") == -1:
            CommandCache.append(mycmd)
    if len(mycmd.output) > 0:
        mycmd.status = 1
    # MsgBox("Final result\r" + mycmd.output)
    if len(mycmd.output) > 4096:
        mycmd.output = mycmd.output[0:4095]
    return mycmd.output


def Main():
    strCommand0 = "term len 0"
    strCommand1 = "show ip int br | exc unass"
    strCommand2 = "show run | i location"
    MsgBox = crt.Dialog.MessageBox
    strPrompt = "#"
    strStigTemplateName = "Stigtemplate-XE-Switch-NDM-L2S-v2r6_07_Jun_2023.ckl"
    #
    # Lets load the template into memory
    objStigTemplateFile = open(strFilePath + strStigTemplateName, "r", encoding="utf-8")
    strStigTemplate = objStigTemplateFile.read()
    #

    #strUser = crt.Dialog.Prompt("Enter your Username:", "AutoStig Script", "")
    #strPasswd = crt.Dialog.Prompt("Enter your Password:", "AutoStig  Script", "", True)
    # strUser = ""       # uncomment for testing
    # strPasswd = ""  # uncomment for testing
    # Open Hosts file
    strStigDevielist = strFilePath + "hosts.txt", "r"
    strStigDevielist = crt.Dialog.FileOpenDialog(
        title="   ----------Please select a file containing Stig targets----------",
        filter="Text Files (*.txt)|*.txt||",
    )
    objHostsFile = open(strStigDevielist)
    today = date.today()
    strDateTime = str(today.strftime("%b-%d-%Y"))
    strLogFile = (
        strFilePath + "scriptoutput-StigCheck-XE-switch-NDM-L2S-v3r4-" + str(today) + ".csv"
    )
    intTotalHosts = 0
    intTotalInterfaces = 0
    # We only get here if we were able to successfully open commands file.
    # Iterate over each host in our host list...
    objLogFile = open(strLogFile, "a")
    objLogFile.write(
        "Date,Hostname,CommonName,DeviceName,VulnID,Status,Finding,Comments,,\n"
    )
    strCKL = ""
    for strHost in objHostsFile:
        # for strHost in arrHosts:
        # Replace newline character appended to hostname.
        strHost = strHost.replace("\n", "")
        strDeviceType = "IOS"
        # Get date and time for use in log file naming.
        # Create log file name and path
        intTotalHosts += 1
        strInterfaces = []
        stigList = []
        strCommonName = "undefined"
        strConnectString = (
            #"/SSH2 /L " + strUser + " /PASSWORD " + strPasswd + " " + strHost
            "/SSH2 " + " " + strHost
        )
        # strConnectString = "/TELNET " + strHost
        # Only operate on non-blank values.
        if (
            strHost != ""
            #and strPasswd != ""
            #and strUser != ""
            and strHost.find("#") == -1
        ):
            strCKL = strStigTemplate
            # Try to open log file.
            # objLogFile = open(strLogFile,'a')
            # Try to connect to host and run command.
            try:
                crt.Session.Connect(strConnectString, False)
            except ScriptError:
                error = crt.GetLastErrorMessage()
                objLogFile.write("Error accessing host " + strHost + " " + error + "\r")
                # Enable the Synchronous property so we don't miss data.
            if crt.Session.Connected:
                crt.Screen.Synchronous = True
                crt.Screen.WaitForStrings(["#", ">"], 15)
                # Send the command to the remote.
                ExecCommand("term len 0" + "\r", strHost)
                crt.Screen.WaitForStrings(["#", ">"], 15)
                # Send the command to the remote.
                ExecCommand("term width 400" + "\r", strHost)
                #
                #
                # Get the common readable name off of devices
                strResult = ExecCommand("show run | i location" + "\r", strHost)
                if len(str(strResult).splitlines()) > 2:
                    for line in strResult.splitlines():
                        if str(line).find("location", 0) > 5:
                            if len(line[line.rfind(" ", 0) : len(line)]) > 11:
                                strCommonName = line[line.rfind(" ", 0) : len(line)]
                # MsgBox(strResult.splitlines()[-1])
                strDeviceName = strResult.splitlines()[-1]
                strDeviceName = strDeviceName.replace("#", "")
                if strCommonName == "undefined":
                    strCommonName = strDeviceName
                #
                # Lets find out if it's a Nexus or IOS Device
                strResult = ExecCommand(
                    "show ver | i IOS|NXOS|NX-OS|System.version" + "\r", strHost
                )
                if (
                    str(strResult).find(
                        "NXOS",
                        len(strHost + "#show ver | i IOS|NXOS|NX-OS|System.version"),
                    )
                    > -1
                    or str(strResult).find(
                        "NX-OS",
                        len(strHost + "#show ver | i IOS|NXOS|NX-OS|System.version"),
                    )
                    > -1
                ):
                    strDeviceType = "NXOS"
                #
                #
                # Begin Vulnerability checks
                #
                # Cisco IOS XE Switch NDM Security Technical Implementation Guide
                # Version 2, Release: 2 Benchmark Date: 27 Oct 2021
                #                  
                stigList.append(V220518(strDeviceType, strDeviceName.strip()))
                stigList.append(V220519(strDeviceType, strDeviceName.strip()))
                stigList.append(V220520(strDeviceType, strDeviceName.strip()))
                stigList.append(V220521(strDeviceType, strDeviceName.strip()))
                stigList.append(V220522(strDeviceType, strDeviceName.strip()))
                stigList.append(V220523(strDeviceType, strDeviceName.strip()))
                stigList.append(V220524(strDeviceType, strDeviceName.strip()))
                stigList.append(V220525(strDeviceType, strDeviceName.strip()))
                stigList.append(V220526(strDeviceType, strDeviceName.strip()))
                #stigList.append(V220527(strDeviceType, strDeviceName.strip()))
                stigList.append(V220528(strDeviceType, strDeviceName.strip()))
                stigList.append(V220529(strDeviceType, strDeviceName.strip()))
                stigList.append(V220530(strDeviceType, strDeviceName.strip()))
                stigList.append(V220531(strDeviceType, strDeviceName.strip()))
                stigList.append(V220532(strDeviceType, strDeviceName.strip()))
                stigList.append(V220533(strDeviceType, strDeviceName.strip()))
                stigList.append(V220534(strDeviceType, strDeviceName.strip()))
                stigList.append(V220535(strDeviceType, strDeviceName.strip()))
                #stigList.append(V220536(strDeviceType, strDeviceName.strip()))
                stigList.append(V220537(strDeviceType, strDeviceName.strip()))
                stigList.append(V220538(strDeviceType, strDeviceName.strip()))
                stigList.append(V220539(strDeviceType, strDeviceName.strip()))
                stigList.append(V220540(strDeviceType, strDeviceName.strip()))
                stigList.append(V220541(strDeviceType, strDeviceName.strip()))
                stigList.append(V220542(strDeviceType, strDeviceName.strip()))
                stigList.append(V220543(strDeviceType, strDeviceName.strip()))
                stigList.append(V220544(strDeviceType, strDeviceName.strip()))
                stigList.append(V220545(strDeviceType, strDeviceName.strip()))
                #stigList.append(V220546(strDeviceType, strDeviceName.strip()))
                stigList.append(V220547(strDeviceType, strDeviceName.strip()))
                stigList.append(V220548(strDeviceType, strDeviceName.strip()))
                stigList.append(V220549(strDeviceType, strDeviceName.strip()))
                #stigList.append(V220550(strDeviceType, strDeviceName.strip()))
                #stigList.append(V220551(strDeviceType, strDeviceName.strip()))
                stigList.append(V220552(strDeviceType, strDeviceName.strip()))
                stigList.append(V220553(strDeviceType, strDeviceName.strip()))
                stigList.append(V220554(strDeviceType, strDeviceName.strip()))
                stigList.append(V220555(strDeviceType, strDeviceName.strip()))
                stigList.append(V220556(strDeviceType, strDeviceName.strip()))
                # stigList.append(V220557(strDeviceType, strDeviceName.strip()))
                #stigList.append(V220558(strDeviceType, strDeviceName.strip()))
                stigList.append(V220559(strDeviceType, strDeviceName.strip()))
                stigList.append(V220560(strDeviceType, strDeviceName.strip()))
                stigList.append(V220561(strDeviceType, strDeviceName.strip()))
                #stigList.append(V220563(strDeviceType, strDeviceName.strip()))
                #stigList.append(V220564(strDeviceType, strDeviceName.strip()))
                stigList.append(V220565(strDeviceType, strDeviceName.strip()))
                stigList.append(V220566(strDeviceType, strDeviceName.strip()))
                stigList.append(V220567(strDeviceType, strDeviceName.strip()))
                stigList.append(V220568(strDeviceType, strDeviceName.strip()))
                stigList.append(V220569(strDeviceType, strDeviceName.strip()))
                #
                # Cisco IOS XE Switch L2S Security Technical Implementation Guide
                # Version 2, Release: 2 Benchmark Date: 27 Oct 2021
                #                
                #stigList.append(V220648(strDeviceType, strDeviceName.strip()))
                stigList.append(V220649(strDeviceType, strDeviceName.strip()))
                stigList.append(V220650(strDeviceType, strDeviceName.strip()))
                stigList.append(V220651(strDeviceType, strDeviceName.strip()))
                #stigList.append(V220652(strDeviceType, strDeviceName.strip()))
                #stigList.append(V220653(strDeviceType, strDeviceName.strip()))
                #stigList.append(V220654(strDeviceType, strDeviceName.strip()))
                stigList.append(V220655(strDeviceType, strDeviceName.strip()))
                stigList.append(V220656(strDeviceType, strDeviceName.strip()))
                stigList.append(V220657(strDeviceType, strDeviceName.strip()))
                stigList.append(V220658(strDeviceType, strDeviceName.strip()))
                stigList.append(V220659(strDeviceType, strDeviceName.strip()))
                stigList.append(V220660(strDeviceType, strDeviceName.strip()))
                stigList.append(V220661(strDeviceType, strDeviceName.strip()))
                stigList.append(V220662(strDeviceType, strDeviceName.strip()))
                stigList.append(V220663(strDeviceType, strDeviceName.strip()))
                stigList.append(V220664(strDeviceType, strDeviceName.strip()))
                stigList.append(V220665(strDeviceType, strDeviceName.strip()))
                stigList.append(V220666(strDeviceType, strDeviceName.strip()))
                stigList.append(V220667(strDeviceType, strDeviceName.strip()))
                stigList.append(V220668(strDeviceType, strDeviceName.strip()))
                stigList.append(V220669(strDeviceType, strDeviceName.strip()))
                stigList.append(V220670(strDeviceType, strDeviceName.strip()))
                stigList.append(V220671(strDeviceType, strDeviceName.strip()))
                stigList.append(V220672(strDeviceType, strDeviceName.strip()))
                stigList.append(V220673(strDeviceType, strDeviceName.strip()))
                #
                # Time to save info to the log file
                for obj in stigList:
                    # strFindingDetails = obj.finding.replace(',', ".")
                    # strFindingDetails = strFindingDetails.replace("\"", "")
                    # strComments = obj.comments.replace(',', ".")
                    # strComments = strComments.replace('\"', "")
                    strFindingDetails = html.escape(obj.finding)
                    strFindingDetails.replace("\b", " ")
                    strComments = html.escape(obj.comments)
                    objLogFile.write(
                        strDateTime
                        + ","
                        + strHost
                        + ","
                        + strCommonName.strip()
                        + ","
                        + strDeviceName.strip()
                        + ","
                        + obj.vulid
                        + ","
                        + obj.status
                        + ',"'
                        + strFindingDetails
                        + '"'
                        + ","
                        + '"'
                        + strComments
                        + '"'
                        + ",,\n"
                    )
                    # Lets update the template with vulnerability data too
                    #
                    # Output the finding details
                    #
                    # OK, lets find the section that matches our vulnerability
                    index = strCKL.find(obj.vulid)
                    if index > -1:
                        #
                        # Output the finding status
                        if index >= -1:
                            intInsert = strCKL.find("<STATUS>", index) + len("<STATUS>")
                            # We have to remove the default status 'not reviewed'
                            temp = (
                                strCKL[:intInsert]
                                + str(obj.status)
                                + strCKL[intInsert + len("Not_Reviewed") :]
                            )
                            strCKL = temp
                        #
                        # Output the finding details
                        if index >= -1:
                            intInsert = strCKL.find("<FINDING_DETAILS>", index) + len(
                                "<FINDING_DETAILS>"
                            )
                            temp = (
                                strCKL[:intInsert]
                                + str(strFindingDetails)
                                + strCKL[intInsert:]
                            )
                            strCKL = temp
                        #
                        # Output the finding Comments
                        if index >= -1:
                            intInsert = strCKL.find("<COMMENTS>", index) + len(
                                "<COMMENTS>"
                            )
                            temp = (
                                strCKL[:intInsert]
                                + str(strComments)
                                + strCKL[intInsert:]
                            )
                            # "\r\r" + strAppVersion + "/" + strVulnVersion +
                            strCKL = temp
                #
                # Now that vulnerability infos are updated, time to set hostname and IP in the stig
                intInsert = strCKL.find("<HOST_NAME>") + len("<HOST_NAME>")
                temp = strCKL[:intInsert] + str(strDeviceName) + strCKL[intInsert:]
                strCKL = temp
                intInsert = strCKL.find("<HOST_IP>") + len("<HOST_IP>")
                temp = strCKL[:intInsert] + str(strHost) + strCKL[intInsert:]
                strCKL = temp
                #
                # Create a CKL file based on Stig data
                strCKLFile = (
                    strCommonName + "AAA" + strDateTime + ".ckl"
                )
                objCKLFile = open(strFilePath + strCKLFile, "w", encoding="utf-8")
                objCKLFile.write(strCKL)
                objCKLFile.close()
            # Disconnect to move on to next host.
        crt.Session.Disconnect()

    # objLogFile = open(strLogFile,'a')
    # To show we did something, even if there's no drops.
    objLogFile.write(
        strDateTime + ",Total Hosts Checked: " + str(intTotalHosts) + ",,\n"
    )
    objLogFile.close()
    # Close hostname file.
    objHostsFile.close()


Main()
