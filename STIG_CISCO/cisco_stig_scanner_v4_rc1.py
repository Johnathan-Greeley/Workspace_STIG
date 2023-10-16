# $language = "python3"
# $interface = "1.0"

'''
This is a fork of the autostig scripts
Starting with Version 4
Moving all Vul checks into one script
By Johnathan  A. Greeley
As of 2023-OCT-02, all check for IOS XE SWITCH, IOS XE Router & NXOS are imported.
They have been tested and seam to work.
Next step is to refactor all imported vuls.
'''

import os, datetime, SecureCRT, array, sys, re, string, csv, inspect, time, xml.sax.saxutils
from datetime import date
from collections import OrderedDict
from packaging import version
import xml.etree.ElementTree as ET

today = date.today()
strDateTime = str(today.strftime("%b-%d-%Y"))

t1 = time.perf_counter()
# create a global variable that will cache device commands and outputs
# CommandCache = []


class Stig:
    def __init__(self):
        self.vulid = ""
        self.device_type = ""
        self.finding = ""
        self.status = "Open"
        self.severity = "default"
        self.comments = ""


class Command:
    def __init__(self):
        self.command = "undefined"
        self.output = "undefined"
        self.device_name = "undefined"
        self.status = 0


class IntStatus:
    def __init__(self):
        self.interface = "undefined"
        self.description = "undefined"
        self.vlan = "undefined"

class IntTrans:
    def __init__(self):
        self.interface = "undefined"
        self.transtype = "none"
        self.devicename = "undefined"

class Commandcache:
    def __init__(self):
        self.cache = {}

    def add(self, device_name, command, output):
        self.cache[(device_name, command)] = output

    def get(self, device_name, command):
        return self.cache.get((device_name, command))


command_cache = Commandcache()
stored_username = ""
stored_password = ""

# ----- NDM STIGS ----------------------------------------------------------------------------------------


def V220518(device_type, device_name):
    """
    V-220518 - CAT II - The Cisco switch must be configured to limit the number of concurrent management sessions to an organization-defined number.
    logic updated 2023-SEP-05 by Johnathan Greeley, removed module lookup and changes command.
    """
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"

    # Run the command to check for session limit and vty line configuration
    command = "show run | s ^line.(vty|con)"
    result = exec_command(command, device_name)

    # Check if session limit is set
    if "session-limit" in result:
        session_limit = re.search(r"session-limit (\d+)", result)
        if session_limit and int(session_limit.group(1)) < 2:
            check.status = "NotAFinding"
            check.finding = result
            check.comments = "V-220518 - CAT II - NAF as long as the VTY lines have session-limit >=2"
        else:
            check.status = "Open"
            check.finding = result
            check.comments = "V-220518 - CAT II - Session limit is not set to less than 2."
    else:
        # Extract vty line configurations using regex
        vty_configs = re.findall(r"line vty (\d+) (\d+)([\s\S]*?)(?=line vty|\Z)", result)

        # Check if only vty 0 to 4 are open and all other lines are closed
        is_valid = True
        for start, end, config in vty_configs:
            if int(start) <= 4:
                if "no exec" in config:
                    is_valid = False
                    break
            else:
                if "no exec" not in config:
                    is_valid = False
                    break

        if is_valid:
            check.status = "NotAFinding"
            check.finding = result
            check.comments = "V-220518 - CAT II - NAF as only vty 0 to 4 are open and all other lines are closed."
        else:
            check.status = "Open"
            check.finding = result
            check.comments = "V-220518 - CAT II - VTY lines configuration is not as expected."

    return check




def V220519(device_type, device_name):
    """
    V-220519 - CAT II - The Cisco switch must be configured to automatically audit account creation.
    updated command to "show run | s ^archive" by Johnathan Greeley 2023-SEP-05
    """
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"

    command = "show run | s ^archive"
    result = exec_command(command, device_name)

    # Default comments and finding
    check.comments = "V-220519 - CAT II - OPEN - no logging"
    check.finding = result

    # Check if "log config" is present in the result
    if re.search(r'log config', result[len(device_name) + len(command):]):
        check.status = "NotAFinding"
        check.comments = "V-220519 - CAT II - NAF - Logging enabled"

    return check


def V220520(device_type, device_name):
    """
    V220520 - CAT II - The Cisco switch must be configured to automatically audit account modification.
    updated command to "show run | s ^archive" by Johnathan Greeley 2023-SEP-05
    """
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"

    command = "show run | s ^archive"
    result = exec_command(command, device_name)

    # Default comments and finding
    check.comments = "V220520 - CAT II - OPEN - no logging"
    check.finding = result

    # Check if "log config" is present in the result
    if re.search(r'log config', result[len(device_name) + len(command):]):
        check.status = "NotAFinding"
        check.comments = "V220520 - CAT II - NAF - Logging enabled"

    return check


def V220521(device_type, device_name):
    """
    V-220521 - CAT II - The Cisco switch must be configured to automatically audit account disabling actions.
    updated command to "show run | s ^archive" by Johnathan Greeley 2023-SEP-05
    """
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"

    command = "show run | s ^archive"
    result = exec_command(command, device_name)

    # Default comments and finding
    check.comments = "V-220521 - CAT II - OPEN - no logging"
    check.finding = result

    # Check if "log config" is present in the result
    if re.search(r'log config', result[len(device_name) + len(command):]):
        check.status = "NotAFinding"
        check.comments = "V-220521 - CAT II - NAF - Logging enabled"

    return check


def V220522(device_type, device_name):
    """
    V-220522 - CAT II - The Cisco switch must be configured to automatically audit account removal actions.
    updated command to "show run | s ^archive" by Johnathan Greeley 2023-SEP-05
    """
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"

    command = "show run | s ^archive"
    result = exec_command(command, device_name)

    # Default comments and finding
    check.comments = "V-220522 - CAT II - OPEN - no logging"
    check.finding = result

    # Check if "log config" is present in the result
    if re.search(r'log config', result[len(device_name) + len(command):]):
        check.status = "NotAFinding"
        check.comments = "V-220522 - CAT II - NAF - Logging enabled"

    return check


def V220523(device_type, device_name):
    """
    V-220523 - CAT II - The Cisco switch must be configured to enforce approved authorizations for controlling the flow of management information within the device based on control policies.
    Updated by Johnathan Greeley 2023-SEP-05, used "show run | s ^line.(vty|con)" to use from command cach
    """
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"
    check.comments = "V-220523 - OPEN - ACLs were not found."

    acl_name = "Not found"
    command = "show run | s ^line.(vty|con)"
    result = str(exec_command(command, device_name))

    lines = result.splitlines()
    skip_next = False
    for count, line in enumerate(lines):
        if "line con 0" in line:
            skip_next = True
        elif "line vty" in line:
            if "no exec" in lines[count + 1]:
                skip_next = True
            else:
                skip_next = False
        elif "access-class" in line and not skip_next and "ip http" not in line:
            acl_name = re.search(r'access-class (\S+)', line).group(1)
            break

    temp = result

    if acl_name != "Not found":
        command = f"sh ip access-lists {acl_name}"
        result = exec_command(command, device_name)

        if len(result) > 3:
            check.status = "NotAFinding"
            check.comments = "V-220523 - NAF - ACL in place"

        check.finding = f"{temp}\r{result}"
    else:
        check.finding = result

    return check
    
    
def V220524(device_type, device_name):
    """
    V-220524 - CAT II - The Cisco switch must be configured to enforce the limit of three consecutive invalid logon attempts, after which time it must lock out the user account from accessing the device for 15 minutes.
    """
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"

    command = "sh run | i login.block"
    result = exec_command(command, device_name)

    check.finding = result
    check.comments = "!V-220524 - CAT II - ****NOTE AS OF 11/1/2019 THIS IS OPEN / FINDING - BE SURE TO FIX THIS!! *** \r !V-220524 - CAT II - FIX ACTION: conf t - login block-for 900 attempts 3 within 120"

    # Search for "block-for" in the result
    if re.search(r'block-for', result):
        check.status = "NotAFinding"
        check.comments = "V-220524 - CAT II - NAF - Configured to limit the number of failed logon attempts"

    return check    


def V220525(device_type, device_name):
    """
    V-220525 - CAT II - The Cisco switch must be configured to display the Standard Mandatory DoD Notice and Consent Banner before granting access to the device.
    """
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"

    command = "show banner login"
    result = exec_command(command, device_name)

    # Look for key words that are supposed to be in the banner string
    if re.search(r'USG-authorized', result):
        check.status = "NotAFinding"
        check.comments = "Not a finding.  Correct banner in place"
    else:
        check.comments = "Open issue - could not find matching configuration."

    check.finding = result

    return check


def V220526(device_type, device_name):
    """
    V-220526 - CAT II - The Cisco switch must be configured to protect against an individual falsely denying having performed organization-defined actions to be covered by non-repudiation.
    updated command to "show run | s ^archive" by Johnathan Greeley 2023-SEP-05
    """
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"

    command = "show run | s ^archive"
    result = exec_command(command, device_name)

    # Look for key words that are supposed to be in the configuration
    if re.search(r'logging enable', result):
        check.status = "NotAFinding"
        check.comments = "V-220526 - CAT II - NAF - ACS logs all attempts (successful/unsuccessful) to escalate privilege to any device using TACACS"
    else:
        check.comments = "V-220526 - CAT II - OPEN - Logging not configured."

    check.finding = result

    return check


def V220528(device_type, device_name):
    """
    V-220528 - CAT II - The Cisco switch must produce audit records containing information to establish when (date and time) the events occurred.
    """
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"

    command = "sh run | i service.timestamp"
    result = exec_command(command, device_name)

    # Look for key words that are supposed to be in the configuration
    if re.search(r'service timestamps log', result):
        check.status = "NotAFinding"
        check.comments = "V-220528 - CAT II - NAF - Timestamps configured correctly."
    else:
        check.comments = "V-220528 - CAT II - Open - no timestamps configured."

    check.finding = result

    return check


def V220529(device_type, device_name):
    """
    V-220529 - CAT II - The Cisco switch must produce audit records containing information to establish where the events occurred.
    Updated by Johnathan Greeley 2023-SEP-05
    added -input to the command to line up better with what the Vul is asking for
    """
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"

    command = "sh ip access-lists | i .log-input*"
    result = exec_command(command, device_name)

    # Look for key words that are supposed to be in the configuration
    if re.search(r'log', result):
        check.status = "NotAFinding"
        check.comments = "V-220529 - CAT II - NAF - ACL logging configured."
    else:
        check.comments = "V-220529 - CAT II - OPEN - No ACLs with logging."

    check.finding = result

    return check


def V220530(device_type, device_name):
    """
    V-220530 - CAT II - The Cisco switch must be configured to generate audit records containing the full-text recording of privileged commands.
    updated command to "show run | s ^archive" by Johnathan Greeley 2023-SEP-05
    """
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"

    command = "show run | s ^archive"
    result = exec_command(command, device_name)

    # Look for key words that are supposed to be in the configuration
    if re.search(r'log config', result) and re.search(r'logging enable', result):
        check.status = "NotAFinding"
        check.comments = "V-220530 - CAT II - NAF - Logging configured."
    else:
        check.comments = "V-220530 - CAT II - OPEN - No Log config."

    check.finding = result

    return check


def V220531(device_type, device_name):
    """
    V-220531 - CAT II - The Cisco switch must be configured to protect audit information from unauthorized modification.
    """
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"

    command = "sh run all | i file.privilege"
    result = exec_command(command, device_name)

    # Look for key words that are supposed to be in the configuration
    if re.search(r'file privilege 15', result):
        check.status = "NotAFinding"
        check.comments = "V-220531 - CAT II - NAF - file privilege 15 configured."
    else:
        check.comments = (
            "V-220531 - CAT II - Open - non-standard config. "
            "Please note that IOS 15.x does not support the file privilege feature."
        )

    check.finding = result

    return check    

    
def V220532(device_type, device_name):
    """
    Legacy IDs: V-96233; SV-105371
    V-220532 - CAT II - The Cisco switch must be configured to protect audit information from unauthorized deletion.
    """
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"

    command = "sh run all | i file.privilege"
    result = exec_command(command, device_name)

    check.finding = result
    check.comments = (
        "V-220532 - CAT II - Open - non-standard config. "
        "Please note that IOS 15.x does not support the file privilege feature."
    )

    if "file privilege 15" in result[len(device_name) + len(command):]:
        check.status = "NotAFinding"
        check.comments = "V-220532 - CAT II - NAF - file privilege 15 configured."

    return check    


def V220533(device_type, device_name):
    """
    V-220533 - CAT II - The Cisco switch must be configured to limit privileges to change the software resident within software libraries.
    """
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"

    command = "sh run all | i file.privilege"
    result = exec_command(command, device_name)

    check.finding = result
    check.comments = (
        "V-220533 - CAT II - Open. "
        "Please note that IOS 15.x does not support the file privilege feature."
    )

    if "file privilege 15" in result[len(device_name) + len(command):]:
        check.status = "NotAFinding"
        check.comments = "V-220533 - CAT II - NAF - file privilege 15 configured."

    return check

def V220534(device_type, device_name):
    """
    V-220534 - CAT I - The Cisco switch must be configured to disable unnecessary services.
    Update by Johnathan Greeley 2023-SEP-05, command updated, looking for all the service listed in vul
    """
    check = Stig()
    check.vulid = format_vulid()
    check.status = "NotAFinding"

    command = "show run | i ^ip.(boot|dns|identd|finger|http|rcmd)|^boot.network|^service.(config|finger|pad|call|tcp-small|udp-small)"
    result = exec_command(command, device_name)

    check.finding = result
    check.comments = "V-220534 - CAT I - NAF - no unnecessary services configured"

    # Use regex to find any of the unnecessary services
    unnecessary_services = [
        "boot network",
        "ip boot server",
        "ip bootp server",
        "ip dns server",
        "ip identd",
        "ip finger",
        "ip http server",
        "ip rcmd rcp-enable",
        "ip rcmd rsh-enable",
        "service config",
        "service finger",
        "service tcp-small-servers",
        "service udp-small-servers",
        "service pad",
        "service call-home"
    ]
    for service in unnecessary_services:
        # Check if service is found and not preceded by 'no'
        if re.search(rf'(?<!no ){service}', result):
            check.status = "Open"
            check.comments = f"V-220534 - CAT I - Open - {service} service enabled."
            break

    return check


def V220535(device_type, device_name):
    """
    V-220535 - CAT II - The Cisco switch must be configured to have only one local user account.
    """
    check = Stig()
    check.vulid = format_vulid()
    command = "sh run | i ^username"
    check.comments = ""
    temp = exec_command(command, device_name)

    # Replace password and secret with ***REMOVED***
    result = ""
    for line in temp.splitlines():
        if "secret" in line:
            clean = line[:line.find("secret")] + "-----***REMOVED***-----"
        elif "password" in line:
            clean = line[:line.find("password")] + "-----***REMOVED***-----"
        else:
            clean = line
        result += "\n" + clean

    check.finding = result
    check.status = "NotAFinding"

    # Create a list of configured accounts
    configured_accounts = [line.split(" ")[1] for line in result.splitlines() if "username " in line[:10]]

    # Check if there's more than one user account
    if len(configured_accounts) > 1:
        check.status = "Open"
        check.comments = "V220535: More than one local user account found. Please review finding details."
    else:
        check.comments = "Only one local account"

    return check


def V220537(device_type, device_name):
    """
    V-220537 - CAT II - The Cisco switch must be configured to enforce a minimum 15-character password length.
    Updated by Johnathan Greeley 2023-SEP-05, check output for what VUL is asking for.
    """
    REQUIRED_MIN_LENGTH = 15
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh aaa common-criteria policy all"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-220537 - NOTE:  *** As of 11/1/19 THIS IS A FINDING!!! ***"

    # Check if the result has more than two lines
    if len(result.splitlines()) > 2:
        for line in result.splitlines():
            if "Minimum length:" in line:
                min_length = int(line.split(":")[1].strip())
                if min_length >= REQUIRED_MIN_LENGTH:
                    check.status = "NotAFinding"
                    check.comments = f"V-220537 - CAT II - NAF - Minimum length is configured to {min_length}."
                else:
                    check.comments = f"V-220537 - CAT II - Minimum length is configured to {min_length}. The required minimum length is {REQUIRED_MIN_LENGTH}. This is a finding."
                break

    return check
    
    
def V220538(device_type, device_name):
    """
    V-220538 - CAT II - The Cisco switch must be configured to enforce password complexity by requiring 
    that at least one upper-case character be used.
    Updated by Johnathan Greeley 2023-SEP-05, check output for what VUL is asking for.
    """
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh aaa common-criteria policy all"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-220538 - NOTE:  *** As of 11/1/19 THIS IS A FINDING!!! ***"

    # Check if the result has more than two lines
    if len(result.splitlines()) > 2:
        # Extract the "Upper Count" value from the result
        upper_count = None
        for line in result.splitlines():
            if "Upper Count:" in line:
                upper_count = int(line.split(":")[1].strip())
                break

        # Check if the "Upper Count" value is 1 or higher
        if upper_count is not None and upper_count >= 1:
            check.status = "NotAFinding"
            check.comments = f"V-220538 - NAF - Upper Count is configured to {upper_count}. The minimum to not be a finding is 1."
        else:
            check.comments = f"V-220538 - Upper Count is configured to {upper_count}. It should be 1 or higher."

    return check

    
def V220539(device_type, device_name):
    """
    V-220539 - CAT II - The Cisco switch must be configured to enforce password complexity by requiring that at least one lower-case character be used.
    Updated by Johnathan Greeley 2023-SEP-05, check output for what VUL is asking for.
    """
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh aaa common-criteria policy all"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-220539 - NOTE:  *** As of 11/1/19 THIS IS A FINDING!!! ***"

    # Check if the result has more than two lines
    if len(result.splitlines()) > 2:
        # Extract the Lower Count value
        lower_count = None
        for line in result.splitlines():
            if "Lower Count:" in line:
                lower_count = int(line.split(":")[1].strip())
                break

        # Check if the Lower Count is 1 or higher
        if lower_count is not None and lower_count >= 1:
            check.status = "NotAFinding"
            check.comments = f"V-220539 - NAF - common criteria policy configured. Lower Count is configured to {lower_count}."
        else:
            check.comments = "V-220539 - Lower Count is not configured to 1 or higher."

    return check



def V220540(device_type, device_name):
    """
    V-220540 - CAT II - The Cisco switch must be configured to enforce password complexity by requiring that at least one numeric character be used.
    Updated by Johnathan Greeley 2023-SEP-05, check output for what VUL is asking for.
    """
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh aaa common-criteria policy all"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-220540 - NOTE:  *** As of 11/1/19 THIS IS A FINDING!!! ***"

    # Check if the result has more than two lines
    if len(result.splitlines()) > 2:
        # Extract the Numeric Count value from the result
        numeric_count = None
        for line in result.splitlines():
            if "Numeric Count:" in line:
                numeric_count = int(line.split(":")[1].strip())
                break

        # Check if Numeric Count is 1 or higher
        if numeric_count is not None and numeric_count >= 1:
            check.status = "NotAFinding"
            check.comments = f"V-220540 - NAF - common criteria policy configured. Numeric Count is configured to {numeric_count}."
        else:
            check.comments = f"V-220540 - Numeric Count is configured to {numeric_count} which is below the minimum requirement."

    return check



def V220541(device_type, device_name):
    """
    V-220541 - CAT II - The Cisco switch must be configured to enforce password complexity by requiring that at least one special character be used.
    Updated by Johnathan Greeley 2023-SEP-05, check output for what VUL is asking for.
    """
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh aaa common-criteria policy all"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-220541 - NOTE:  *** As of 11/1/19 THIS IS A FINDING!!! ***"

    # Check if the result has more than two lines
    if len(result.splitlines()) > 2:
        # Extract the Special Count value
        special_count = None
        for line in result.splitlines():
            if "Special Count:" in line:
                special_count = int(line.split(":")[1].strip())
                break

        # Check if the Special Count value is 1 or higher
        if special_count is not None and special_count >= 1:
            check.status = "NotAFinding"
            check.comments = f"V-220541 - NAF - common criteria policy configured. Special Count is configured to {special_count}."
        else:
            check.comments = "V-220541 - NOTE: Special Count is not configured to 1 or higher."

    return check


def V220542(device_type, device_name):
    """
    V-220542 - CAT II - The Cisco switch must be configured to require that when a password is changed, 
    the characters are changed in at least eight of the positions within the password.
    Updated by Johnathan Greeley 2023-SEP-05, check output for what VUL is asking for.
    """
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh aaa common-criteria policy all"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-220542 - NOTE:  *** As of 11/1/19 THIS IS A FINDING!!! ***"

    # Check if the result has more than two lines
    if len(result.splitlines()) > 2:
        # Extract the number of character changes from the result
        char_changes = None
        for line in result.splitlines():
            if "Number of character changes" in line:
                char_changes = int(line.split()[-1])
                break

        # Check if the number of character changes is 8 or higher
        if char_changes is not None and char_changes >= 8:
            check.status = "NotAFinding"
            check.comments = f"V-220542 - NAF - common criteria policy configured. The Number of character changes is configured to {char_changes}."

    return check
    
    
def V220543(device_type, device_name):
    """
    V-220543 - CAT I - The Cisco switch must only store cryptographic representations of passwords.
    """
    # Create a Stig object and set the vulnerability ID
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"

    # Execute the command and store the result
    command = "sh run | i service.password"
    result = exec_command(command, device_name)

    # Check if the result contains the "service password-" string
    if re.search(r'service password-', result):
        check.status = "NotAFinding"
        check.comments = "V-220543 - NAF - Password encryption configured."
    else:
        check.comments = "V-220543 - CAT 1 - password encryption must be configured"

    check.finding = result

    return check
    
import re

def V220544(device_type, device_name):
    """
    V-220544 - CAT I - The Cisco switch must be configured to terminate all network connections associated with device management after 5 minutes of inactivity.
    Updated by Johnathan Greeley on 2023-SEP-05
    """
    # Create a Stig object and set the vulnerability ID
    check = Stig()
    check.vulid = format_vulid()

    # Execute the command and store the result
    command = "show run | s ^line.(vty|con)"
    result = exec_command(command, device_name)

    # Assume all config lines are good. If any line has a timeout > 5 min, set status to "Open"
    check.status = "NotAFinding"
    skip_next = False
    for line in result.splitlines():
        if "no exec" in line:
            skip_next = True
            continue
        if skip_next and "line vty" in line:
            skip_next = False
            continue
        # Look for session-timeout and exec-timeout operands in the string
        match_session = re.search(r'session-timeout (\d+)', line)
        match_exec = re.search(r'exec-timeout (\d+) (\d+)', line)
        if match_session:
            timeout_minutes = int(match_session.group(1))
            if timeout_minutes > 5:
                check.status = "Open"
                break
        if match_exec:
            timeout_minutes = int(match_exec.group(1))
            if timeout_minutes > 5:
                check.status = "Open"
                break

    # Set comments based on the check status
    if check.status == "NotAFinding":
        check.comments = "Not a finding. Timeout less than or equal to 5"
    else:
        check.comments = "Open issue - found configuration with timeout greater than 5 minutes."

    check.finding = result

    return check


def V220545(device_type, device_name):
    """
    V-220545 - CAT II - The Cisco switch must be configured to automatically audit account enabling actions.
    updated command to "show run | s ^archive" by Johnathan Greeley 2023-SEP-05
    """
    # Create a Stig object and set the vulnerability ID
    check = Stig()
    check.vulid = format_vulid()

    # Execute the command and store the result
    command = "show run | s ^archive"
    result = exec_command(command, device_name)

    # Set the initial status and comments
    check.status = "Open"
    check.comments = "V-220545 - Archive logging is required"

    # Check if the result contains the required configuration
    if re.search(r'(?s)archive.*log config.*logging enable', result):
        check.status = "NotAFinding"
        check.comments = "V-220545 - CAT II - NAF - Archive logging configured"

    check.finding = result

    return check


def V220546(device_type, device_name):
    """
    V-220546 - CAT II - The Cisco switch must be configured to audit the execution of privileged functions.
    """
    # Create a Stig object and set the vulnerability ID
    check = Stig()
    check.vulid = format_vulid()

    # Set the initial status and comments
    check.status = "Open"
    check.comments = "V-220546 - CAT II - Logging required"

    # Execute the command and store the result
    command = "sh run | i ^archive"
    result = exec_command(command, device_name)

    # Append the result of the second command execution to the first result
    result += "\r" + exec_command(command, device_name)

    # Check if the result contains the required configuration
    if re.search(r'log config', result):
        check.status = "NotAFinding"
        check.comments = "V-220546 - CAT II - NAF - Logging configured."

    check.finding = result

    return check


def V220547(device_type, device_name):
    """
    V-220547 - CAT II - The Cisco switch must be configured to allocate audit record storage capacity in accordance with organization-defined audit record storage requirements.
    updated by Johnathan Greeley 2023-SEP-07
    """
    # Create a Stig object and set the vulnerability ID
    check = Stig()
    check.vulid = format_vulid()

    # Execute the command and store the result
    command = "sh run | i ^logging.buffered"
    result = exec_command(command, device_name)

    # Use regex to search for the required configuration
    match = re.search(r'logging buffered (\d+) informational', result)
    if match:
        buffer_size = match.group(1)
        check.status = "NotAFinding"
        check.comments = f"V-220547 - CAT II - NAF - logging buffer configured to {buffer_size}."
    else:
        check.comments = "V-220547 - OPEN - suggest adding logging buffered 1000000 informational"

    check.finding = result

    return check



def V220548(device_type, device_name):
    """
    V-220548 - CAT II - The Cisco switch must be configured to generate an alert for all audit failure events.
    updated by Johnathan Greeley 2023-SEP-07
    """
    # Create a Stig object and set the vulnerability ID
    check = Stig()
    check.vulid = format_vulid()

    # Set the initial status and comments
    check.status = "Open"
    check.comments = "V220548 - NOTE **** AS OF 11/1/19 THIS IS A FINDING!! PLEASE REMEDIATE"

    # Execute the command and store the result
    command = "show logging | i Trap|Logging.to"
    result = exec_command(command, device_name)

    # Check if the result contains the required configuration
    if "Logging to" in result and re.search(r"(debugging|critical|warnings|notifications|informational)", result):
        check.status = "NotAFinding"
        check.comments = "V-220548 - CAT II - NAF - logging trap is configured."

    check.finding = result

    return check


def V220549(device_type, device_name):
    """
    V-220549 - CAT II - The Cisco switch must be configured to synchronize its clock with the primary and secondary time sources using redundant authoritative time sources.
    updated by Johnathan Greeley 2023-SEP-07
    """
    # Create a Stig object and set the vulnerability ID
    check = Stig()
    check.vulid = format_vulid()

    # Set the initial status
    check.status = "Open"

    # Execute the command and store the result
    command = "show ntp associations detail | i configured,"
    result = exec_command(command, device_name)

    # Extract all IP addresses (NTP servers) from the result
    ntp_servers = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", result)

    # Count the number of valid peers
    valid_peers = sum(1 for line in result.splitlines() if ("'*' sys.peer" in line) or ("candidate" in line and "valid" in line))

    # Update the comments with the number of NTP servers and valid peers found
    check.comments = f"Found {len(ntp_servers)} configured NTP servers and {valid_peers} valid peers."

    # Check the conditions for findings
    if len(ntp_servers) >= 2:
        if valid_peers >= 1:
            check.status = "NotAFinding"
        else:
            check.comments += " Only one valid peer at this time."

    check.finding = result

    return check



def V220552(device_type, device_name):
    """
    V-220552 - CAT II - The Cisco switch must be configured to authenticate SNMP messages using a FIPS-validated Keyed-Hash Message Authentication Code (HMAC).
    Updated by Johnathan Greeley 2023-SEP-07
    """
    # Create a Stig object and set the vulnerability ID
    check = Stig()
    check.vulid = format_vulid()

    # Set the initial status
    check.status = "NotAFinding"

    # Execute the first command and store the result
    command1 = "sh run | i snmp-server.(group|host|user|view)"
    result1 = exec_command(command1, device_name)

    # Execute the second command and store the result
    command2 = "show snmp user"
    result2 = exec_command(command2, device_name)

    # Combine the results for the finding
    check.finding = result1 + "\n" + result2
    check.comments = "V-220552 authenticate SNMP messages using a FIPS-validated Keyed-Hash Message Authentication Code (HMAC)."

    # Check each line of the first command's result for the required strings
    for line in result1.splitlines():
        if "snmp-server group" in line and "v3" not in line:
            check.status = "Open"
            check.comments = "Finding: SNMP group not using version 3."
            return check
        elif "snmp-server host" in line and "version 3" not in line:
            check.status = "Open"
            check.comments = "Finding: SNMP host not using version 3."
            return check

    # Check for active users and their settings from the second command's result
    users = re.findall(r"User name: (\S+)", result2)
    for user in users:
        user_data = re.search(rf"User name: {user}.*?Authentication Protocol: (\S+).*?Privacy Protocol: (\S+)", result2, re.DOTALL)
        if user_data:
            auth_protocol, privacy_protocol = user_data.groups()
            if not (auth_protocol == "SHA" and privacy_protocol.startswith("AES")):
                check.status = "Open"
                check.comments = f"Finding: User {user} not using SHA for Authentication and AES for Privacy."
                return check

    return check


def V220553(device_type, device_name):
    """
    V-220553 - CAT II - The Cisco switch must be configured to encrypt SNMP messages using a FIPS 140-2 approved algorithm.
    Updated by Johnathan Greeley 2023-SEP-08
    """
    # Create a Stig object and set the vulnerability ID
    check = Stig()
    check.vulid = format_vulid()

    # Set the initial status
    check.status = "NotAFinding"

    # Execute the first command and store the result
    command1 = "sh run | i snmp-server.(group|host|user|view)"
    result1 = exec_command(command1, device_name)

    # Execute the second command and store the result
    command2 = "show snmp user"
    result2 = exec_command(command2, device_name)

    # Combine the results for the finding
    check.finding = result1 + "\n" + result2
    check.comments = "V-220553 - The Cisco switch must be configured to encrypt SNMP messages using a FIPS 140-2 approved algorithm."

    # Check each line of the first command's result for the required strings
    for line in result1.splitlines():
        if "snmp-server group" in line and "v3" not in line:
            check.status = "Open"
            check.comments = "Finding: SNMP group not using version 3."
            return check
        elif "snmp-server host" in line and "version 3" not in line:
            check.status = "Open"
            check.comments = "Finding: SNMP host not using version 3."
            return check

    # Check for active users and their settings from the second command's result
    if "no active users" not in result2:
        users = re.findall(r"User name: (\S+)", result2)
        for user in users:
            user_data = re.search(rf"User name: {user}.*?Privacy Protocol: (\S+)", result2, re.DOTALL)
            if user_data:
                privacy_protocol = user_data.group(1)
                if not privacy_protocol.startswith("AES"):
                    check.status = "Open"
                    check.comments = f"Finding: User {user} not using AES for Privacy."
                    return check

    return check


def V220554(device_type, device_name):
    """
    V-220554 - CAT II - The Cisco switch must be configured to authenticate Network Time Protocol (NTP) sources using authentication that is cryptographically based.
    updated by Johnathan Greeley on 2023-SEP-08
    """

    # Initialize Stig check
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"

    # Define command to be executed
    command = "show ntp associations detail | i configured,"

    # Execute command
    result = exec_command(command, device_name)
    check.finding = result  # Save the result to check.finding

    # Define the authentication methods
    auth_methods = ["cmac-aes-128", "hmac-sha1", "hmac-sha2-256", "md5", "sha1", "sha2"]

    # Check for the presence of "configured," and "authenticated" on the same line
    if "configured," in result and "authenticated" in result:
        # Check for the presence of one of the specified authentication methods on the same line
        if any(method in result for method in auth_methods):
            check.status = "NotAFinding"
            check.comments = "V-220554 - NTP authentication is properly configured and authenticated using one of the specified methods."
        else:
            check.comments = "V-220554 - NTP is configured and authenticated but not using one of the specified methods."
    else:
        check.comments = "V-220554 - NTP is not properly configured or authenticated."

    return check


def V220555(device_type, device_name):
    """
    V-V-220555 - CAT I - The Cisco switch must be configured to use FIPS-validated Keyed-Hash Message Authentication Code (HMAC) to protect the integrity of remote maintenance sessions.
    """

    # Initialize Stig object
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"

    # Execute command and get result
    command = "show run all | i ^ip.ssh.(version|server.algorithm.)"
    result = exec_command(command, device_name)

    # Update check findings and comments
    check.finding = result
    check.comments = "V-220555 - The Cisco switch must be configured to use FIPS-validated Keyed-Hash Message Authentication Code (HMAC) to protect the integrity of remote maintenance sessions.\r Add the command ip ssh server algorithm mac hmac-sha1-96"

    # Check if the result contains required strings using regex
    if re.search(r"ip ssh version 2", result) and re.search(r"hmac-sha2", result):
        check.status = "NotAFinding"
        check.comments = "V-220555 - CAT II - NAF - FIPS-validated Keyed-Hash is being used."

    return check

def V220556(device_type, device_name):
    """
    V-220556 -  CAT I - The Cisco switch must be configured to implement cryptographic mechanisms to protect the confidentiality of remote maintenance sessions.
    """

    # Initialize Stig object
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"

    # Execute command and get result
    command = "show run all | i ^ip.ssh.(version|server.algorithm.)"
    result = exec_command(command, device_name)

    # Update check findings and comments
    check.finding = result
    check.comments = "V-220556 -  The Cisco switch must be configured to implement cryptographic mechanisms to protect the confidentiality of remote maintenance sessions."

    # Check if the result contains required strings using regex
    if re.search(r"ip ssh version 2", result) and (re.search(r"encryption aes128", result) or re.search(r"encryption aes192", result) or re.search(r"encryption aes256", result)):
        check.status = "NotAFinding"
        check.comments = "V-220556 - CAT II - NAF - Specified cryptographic mechanisms are being used."

    return check
def V220558(device_type, device_name):
    """
    V-220558 - CAT II -The Cisco switch must be configured to generate log records when administrator privileges are modified.
    """

    # Initialize Stig object
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"

    # Execute command and get result
    command = "sh run | i logging.user|archive|log.config|logging.enable"
    result = exec_command(command, device_name)

    # Update check findings and comments
    check.finding = result
    check.comments = "V-220558 - The Cisco switch must be configured to generate log records when administrator privileges are modified."

    # Check if the result contains required strings using regex
    if re.search(r"archive", result) and re.search(r"logging enable", result):
        check.status = "NotAFinding"
        check.comments = "V-220558 - CAT II - NAF - archive logging is enabled."

    return check


def V220559(device_type, device_name):
    """
    V-220559 - The Cisco switch must be configured to generate log records when administrator privileges are deleted.
    """

    # Initialize Stig object
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"

    # Execute command and get result
    command = "sh run | i logging.user|archive|log.config|logging.enable"
    result = exec_command(command, device_name)

    # Update check findings and comments
    check.finding = result
    check.comments = "V-220559 - The Cisco switch must be configured to generate log records when administrator privileges are deleted."

    # Check if the result contains required strings using regex
    if re.search(r"archive", result) and re.search(r"logging enable", result):
        check.status = "NotAFinding"
        check.comments = "V-220559 - CAT II - NAF - archive logging is enabled."

    return check


def V220560(device_type, device_name):
    """
    V-220560 - CAT II -  The Cisco switch must be configured to generate audit records when successful/unsuccessful logon attempts occur.
    """

    # Initialize Stig object
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"

    # Execute command and get result
    command = "sh run | i login.on"
    result = exec_command(command, device_name)

    # Update check findings and comments
    check.finding = result
    check.comments = "V-220560 - NOTE:  AS OF 11/1/19 THIS IS A FINDING - PLEASE REMEDIATE"

    # Check if the result contains required strings using regex
    if re.search(r"on-failure", result) and re.search(r"on-success", result):
        check.status = "NotAFinding"
        check.comments = "V-220560 - CAT II - NAF -  Audit records generated when successful/unsuccessful logon attempts occur."

    return check


def V220561(device_type, device_name):
    """
    V-220561 - CAT II -  The Cisco switch must be configured to generate log records for privileged activities.
    updated command to "show run | s ^archive" by Johnathan Greeley 2023-SEP-05
    """

    # Initialize Stig object
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"

    # Execute command and get result
    command = "show run | s ^archive"
    result = exec_command(command, device_name)

    # Update check findings and comments
    check.finding = result
    check.comments = "V-220561 - The Cisco switch must be configured to generate log records for privileged activities"

    # Check if the result contains required strings using regex
    if re.search(r"archive", result) and re.search(r"logging enable", result):
        check.status = "NotAFinding"
        check.comments = "V-220561 - CAT II - NAF - archive logging is enabled"

    return check


def V220563(device_type, device_name):
    """
    V-220563 - CAT II - The Cisco switch must be configured to generate log records when concurrent logons from different workstations occur.
    """

    # Initialize Stig object
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"

    # Execute command and get result
    command = "sh run | i login.on"
    result = exec_command(command, device_name)

    # Update check findings and comments
    check.finding = result
    check.comments = "V-220563 - CAT II - NAF - paste output"

    # Check if the result contains required string using regex
    if re.search(r"login on-success log", result):
        check.status = "NotAFinding"
        check.comments = "V-220563 - CAT II - NAF - Login on-success log is configured."

    return check


def V220564(device_type, device_name):
    """
    V-220564 - CAT II - The Cisco switch must be configured to off-load log records onto a different system than the system being audited.
    """

    # Initialize Stig object
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"

    # Execute command and get result
    command = "sh run | i logging.host|logging.trap"
    result = exec_command(command, device_name)

    # Update check findings and comments
    check.finding = result
    check.comments = "V-220564 - NOTE:  AS OF 11/1/19 THIS IS A FINDING!!!! PLEASE REMEDIATE"

    # Check if the result contains required strings using regex
    if re.search(r"logging host", result) and re.search(r"logging trap", result):
        check.status = "NotAFinding"
        check.comments = "V-220564 - CAT II - NAF - Login on-success log is configured."

    return check


def V220565(device_type, device_name):
    """
    V-220565 - CAT I - The Cisco switch must be configured to use an authentication server for the purpose of authenticating users prior to granting administrative access.
    """

    # Initialize Stig object
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"

    # Execute commands and get results
    command1 = "show tacacs | i Server.(name|address|Status)"
    result1 = exec_command(command1, device_name)

    command2 = "show run | i ^line.(con|vty)|login.authentication|^aaa.authentication|^aaa group server tacacs|server-private"
    result2 = exec_command(command2, device_name)

    # Extract server name from command1 output
    server_name_match = re.search(r"Server name: (\S+?)_", result1)
    server_name = server_name_match.group(1) if server_name_match else None

    # Check if server status is Alive
    if "Server Status: Alive" not in result1:
        check.comments = f"{server_name} is not active"

    # Check for server name in command2 output
    if server_name:
        if all(keyword in result2 for keyword in [server_name, "aaa authentication login", "aaa authentication enable", "aaa group server"]):
            check.status = "NotAFinding"
            check.comments = f"V-220565 - CAT II - NAF - {server_name} is configured correctly."
        else:
            check.comments = f"V-220565 - CAT II - {server_name} is not configured correctly."

    # Check for login authentication value
    login_auth_matches = re.findall(r"aaa authentication login (\S+) group", result2)
    for login_auth_value in login_auth_matches:
        if f"login authentication {login_auth_value}" in result2:
            check.comments += f"\nValue {login_auth_value} is using TACACS."
        else:
            check.status = "Open"
            check.comments += f"\nValue {login_auth_value} is not using TACACS."

    # Check if the authentication source is tied to TACACS
    auth_sources = re.findall(r"aaa authentication login (\S+) local", result2)
    for source in auth_sources:
        if f"login authentication {source}" in result2:
            check.status = "Open"
            check.comments += f"\nValue {source} is not using TACACS."

    # Clean up the result2 output
    result2_cleaned = re.sub(r"(server-private \d+\.\d+\.\d+\.\d+ key) .*", r"\1 ***removed***", result2)
    
    # Combine the results from both commands for the findings
    check.finding = f"{result1}\n\n{result2_cleaned}"

    return check



def V220566(device_type, device_name):
    """
    V-220566 - CAT II -  The Cisco switch must be configured to support organizational requirements to conduct backups of the configuration when changes occur.
    """

    # Initialize Stig object
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"

    # Execute command and get result
    command = "sh event manager policy registered"
    result = exec_command(command, device_name)

    # Update check findings and comments
    check.finding = result
    check.comments = "V-220566 - NOTE:  AS OF 11/1/19 THIS IS A FINDING!!!! PLEASE REMEDIATE"

    # Check if the result contains required strings using regex
    if re.search(r"applet", result):
        check.status = "NotAFinding"
        check.comments = "V-220566 - CAT II - NAF - Applet configured and registered."

    return check


def V220567(device_type, device_name):
    """
    Update to confirm 2FA
    V-220567 - CAT II - The Cisco switch must be configured to obtain its public key certificates from an appropriate certificate policy through an approved service provider.
    """

    # Initialize Stig object
    check = Stig()
    check.vulid = format_vulid()
    check.status = "NotAFinding"

    # Execute command and get result
    command = "show run | i ^crypto.pki.(trustpoint|certificate|)|enrollment"
    result = exec_command(command, device_name)

    # Store the command output in check.finding
    check.finding = result

    # Parse the result to generate comments
    comments = []
    findings_detected = False
    lines = result.split('\n')
    for i, line in enumerate(lines):
        if "self-signed" in line:
            comments.append(f"Finding: {line} - Any line with 'self-signed' is a finding/open.")
            findings_detected = True
        elif "enrollment selfsigned" in line:
            comments.append(f"Finding: {line} - Any line with 'selfsigned' is a finding/open.")
            findings_detected = True
        elif "enrollment terminal" in line:
            # Find the preceding crypto pki trustpoint line
            for j in range(i, -1, -1):
                ca_match = re.match(r"crypto pki trustpoint (\S+)", lines[j])
                if ca_match:
                    ca_name = ca_match.group(1)
                    comments.append(f"Note: {line} - This means that CA '{ca_name}' is used for terminal access.")
                    break

    # Update check comments based on findings
    if findings_detected:
        check.status = "Open"
        comments.append("Self-signed certificates are being used for terminal access. They should be removed.")
    else:
        comments.append("No self-signed certificates are used for terminal access.")

    check.comments = "\n".join(comments)

    return check
    
    
def V220568(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"

    command = "show logging | i Trap|Logging.to"
    result = exec_command(command, device_name)

    check.finding = result

    if result.count("Logging to") >= 2:
        check.status = "NotAFinding"
        check.comments = "V-220568 - CAT I - NAF - Remote system logging server(s) in place.."
    else:
        check.comments = "V-220568 - NOTE: AS OF 11/1/19 THIS IS A FINDING!!! PLEASE REMEDIATE"

    return check



def V220569(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"

    command = "show ver | i ^Cisco IOS Software,|^Cisco IOS XE Software,|^cisco."
    result = exec_command(command, device_name)

    model = re.search(r'cisco\s+([A-Za-z0-9\-]+)', result).group(1)
    model_version = re.search(r'Version\s+([\d\.]+)', result).group(1)

    checks = [
        {"model_str": ["ASR", "ISR"], "version": "16.09.04", "device": "ASR/ISR"},
        {"model_str": ["CISCO39"], "version": "15.7(3)M5", "device": "ISRG2"},
        {"model_str": ["C650"], "version": "15.1(2)SY14", "device": "6500 series"},
        {"model_str": ["9300", "9500"], "version": "17.03.05", "device": "Cat 9300"},
        {"model_str": ["3850", "3650"], "version": "16.12.9", "device": "Cat 3850 and 3650"},
        {"model_str": ["3750"], "version": "15.02(4)E09", "device": "Cat 3750, 3560, and 2960"},
    ]

    for check_item in checks:
        if any(model_str in model for model_str in check_item["model_str"]):
            if version.parse(model_version) >= version.parse(check_item["version"]):
                check.status = "NotAFinding"
                check.comments = (
                    f"NAF: As of 1/16/2020 {check_item['device']} devices should have code level {check_item['version']}.  This device has "
                    + model_version
                )
            else:
                check.status = "Open"
                check.comments = (
                    f"OPEN: As of 1/16/2020 {check_item['device']} devices should have code level {check_item['version']}.  This device has "
                    + model_version
                )

    check.finding = result
    return check





# ----- L2S STIGS ----------------------------------------------------------------------------------------


def V220649(device_type, device_name):
    """
    V-220649 - The Cisco switch must uniquely identify all network-connected endpoint devices before establishing any connection.
    """
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Not_Applicable"
    check.comments = "V-220649 - Not applicable - There are no end-user devices in the datacenter."
    
    return check


def V220650(device_type, device_name):
    """
    V-220650 - The Cisco switch must authenticate all VLAN Trunk Protocol (VTP) messages with a hash function using the most secured cryptographic algorithm available.
    """
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "NotAFinding"
    check.comments = "V-220650 - Not running VTP."

    command = "show vtp status"
    result = exec_command(command, device_name)
    if "Off" in result[len(device_name) + len(command):]:
        check.status = "NotAFinding"
        check.comments = "V-220650 - Running VTP, but in transparent mode."
    else:
        command = "show vtp pass"
        result += "\r" + exec_command(command, device_name)
        if "Password" not in result[len(device_name) + len(command):]:
            check.status = "Open"
            check.comments = "V-220650 - Open - Participating in VTP, but without a password configured."
        else:
            check.status = "NotAFinding"
            check.comments = "V-220650 - NAF - Participating in VTP with a password configured."

    check.finding = result
    return check


def V220651(device_type, device_name):
    """
    V-220651 - The Cisco switch must manage excess bandwidth to limit the effects of packet flooding types of denial of service (DoS) attacks.
    """
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "NotAFinding"
    command = "show policy-map interface"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-220651 - NAF - Datacenter switches only connect to servers."
    return check


def V220655(device_type, device_name):
    """
    V-220655 - The Cisco switch must have Root Guard enabled on all switch ports connecting to access layer switches and hosts.
    """
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "NotAFinding"

    # Find all the root ports.
    command = "show spanning-tree | i Root.FWD"
    result = exec_command(command, device_name)
    temp = result

    root_ports = [line.split()[0] for line in result.splitlines() if line.find("#") == -1 and line.find("show") == -1]

    check.comments = "Found the following root ports: " + ", ".join(root_ports)

    # Find all trunk ports
    command = "show int trunk | i trunking | exc not-trunking"
    result = exec_command(command, device_name)
    temp += "\r" + result

    trunk_ports = [line.split()[0] for line in result.splitlines() if line.find("#") == -1 and line.find("show") == -1 and line.split()[0] not in root_ports]

    if not trunk_ports:
        check.comments += "\rAll trunking ports are root ports."
        check.status = "NotAFinding"
    else:
        result = ""
        # Check all non-root trunk ports for root guard
        for port in trunk_ports:
            command = "show run int " + port
            port_config = exec_command(command, device_name)
            if "UL" not in port_config and "DL" not in port_config:
                if "guard root" not in port_config:
                    check.status = "Open"
                    check.comments += f"\rInterface {port} is not configured with root guard. This may not be a finding if this is facing infrastructure devices."
                else:
                    check.comments += f"\rInterface {port} is configured correctly."
            else:
                check.comments += f"\rInterface {port} does not require root guard."
            temp += port_config

    check.finding = temp
    return check


def V220656(device_type, device_name):
    """
    V-220656 - The Cisco switch must have BPDU Guard enabled on all user-facing or untrusted access switch ports.
    """
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Not_Applicable"

    command = "show run | i interface.Eth|bpduguard"
    result = exec_command(command, device_name)

    check.finding = result
    check.comments = "V-220656 - Not Applicable - Datacenter switches only connect to trusted infrastructure devices."

    return check


def V220657(device_type, device_name):
    """
    V-220657 - The Cisco switch must have STP Loop Guard enabled.
    """
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    check.comments = "V-220657 - OPEN - The Cisco switch must have STP Loop Guard enabled."

    command = "show run | i loopguard"
    result = exec_command(command, device_name)

    if "loopguard default" in result[len(device_name) + len(command):]:
        check.status = "NotAFinding"
        check.comments = "V-220657 - NAF  The Cisco switch has STP Loop Guard enabled."

    check.finding = f"{result}\r"

    return check


def V220658(device_type, device_name):
    """
    V-220658 - The Cisco switch must have Unknown Unicast Flood Blocking (UUFB) enabled.
    """
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Not_Applicable"
    
    command = "show run | i block.unicast|^interface|switchport.access"
    result = exec_command(command, device_name)
    
    check.finding = result
    check.comments = "V-220658 - Not Applicable - Datacenter switches only connect to trusted infrastructure devices."
    
    return check


def V220659(device_type, device_name):
    """
    V-220659 - The Cisco switch must have DHCP snooping for all user VLANs to validate DHCP messages from untrusted sources.
    """
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Not_Applicable"
    
    command = "show run | i ^ip.dhcp.snooping"
    result = exec_command(command, device_name)
    
    check.finding = result
    check.comments = "V-220659 - Not Applicable - Datacenter switches only connect to trusted infrastructure devices."
    
    return check



def V220660(device_type, device_name):
    """
    V-220660 - The Cisco switch must have IP Source Guard enabled on all user-facing or untrusted access switch ports.
    """
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Not_Applicable"
    
    command = "show run | i ip.verify.source|^interface|switchport.access"
    result = exec_command(command, device_name)
    
    check.finding = result
    check.comments = "V-220660 - Not Applicable - Datacenter switches only connect to trusted infrastructure devices."
    
    return check

def V220661(device_type, device_name):
    """
    V-220661 - The Cisco switch must have Dynamic Address Resolution Protocol (ARP) Inspection (DAI) enabled on all user VLANs.
    """
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Not_Applicable"
    
    command = "show run | i arp.inspection.vlan"
    result = exec_command(command, device_name)
    
    check.finding = result
    check.comments = "V-220661 - Not Applicable - Datacenter switches only connect to trusted infrastructure devices."
    
    return check



def V220662(device_type, device_name):
    # V-220662 - The Cisco switch must have Storm Control configured on all host-facing switchports.
    check = Stig()
    MsgBox = crt.Dialog.MessageBox
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = "V-220662"
    check.status = "NotAFinding"
    # Find all the root ports.
    command= "show spanning-tree | i Root.FWD"
    rootPorts = []
    trunkPorts = []
    result= exec_command(command, device_name)
    temp= result
    for line in result.splitlines():
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
    command= "show int trunk | i trunking | exc not-trunking"
    result= exec_command(command, device_name)
    # Now lets find all trunking ports that aren't root ports
    for line in result.splitlines():
        port = line[0 : line.find(" ")]
        isfound = False
        for portname in rootPorts:
            if portname == port:
                isfound = True
        if isfound == False:
            if line.find("#") == -1 and line.find("show") == -1:
                trunkPorts.append(port)
    temp= temp + "\r" + result
    if len(trunkPorts) == 0:
        check.comments = check.comments + "\r" + "All trunking ports are root ports."
        check.status = "NotAFinding"
    else:
        result = ""
        # Check all non-root trunk ports for root guard
        for port in trunkPorts:
            command= "show run int " + port
            portconfig = exec_command(command, device_name)
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
            temp= temp + portconfig
    check.finding = temp
    return check


def V220663(device_type, device_name):
    # V-220663 - The Cisco switch must have IGMP or MLD Snooping configured on all VLANs.
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"
    check.comments = "V-220663 - Open - The Cisco switch must have IGMP or MLD Snooping configured on all VLANs."

    command = "show run all | i igmp.snooping$"
    result = exec_command(command, device_name)

    if "ip igmp snooping" in result[len(device_name) + len(command):]:
        check.status = "NotAFinding"
        check.comments = "V-220663 - NAF  The Cisco switch has IGMP or MLD snooping is enabled globally."

    check.finding = result
    return check


def V220664(device_type, device_name):
    # V-220664 - Rule Title: The Cisco switch must implement Rapid STP where VLANs span multiple switches with redundant links.
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"
    check.comments = "V-220664 - Open - The Cisco switch must implement Rapid STP where VLANs span multiple switches with redundant links."

    command = "show spanning-tree summary | i mode"
    result = exec_command(command, device_name)

    if "rapid" in result or "mst" in result:
        check.status = "NotAFinding"
        check.comments = "V-220664 - NAF  The Cisco switch has RPVST enabled."

    check.finding = result
    return check


def V220665(device_type, device_name):
    # V-220665 - Rule Title: The Cisco switch must enable Unidirectional Link Detection (UDLD) to protect against one-way connections.
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"
    check.comments = "V-220665 - Open - The Cisco switch must enable Unidirectional Link Detection (UDLD) to protect against one-way connections.\r"

    command = "show run | i ^udld"
    result = exec_command(command, device_name)

    if "enable" in result or "aggressive" in result:
        check.status = "NotAFinding"
        check.comments = "V-220665 - NAF - The Cisco switch has UDLD feature enabled and running on all fiber attached ports.\r"

    check.finding = result
    return check



def V220666(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()
    check.status = "NotAFinding"
    check.comments = "The Cisco switch ports must have nonegotiate off on all trunks."

    command = "show interfaces switchport | i ^Negotiation|^Name:"
    result = exec_command(command, device_name)

    findings = re.findall(r"Name: (.+?)\nNegotiation of Trunking: On", result)

    if findings:
        check.status = "Open"
        check.comments += "\nThe following interfaces are set to On:\n" + "\n".join(findings)
        check.comments += "\n\nPlease add the following configuration to correct the findings:\n"
        for interface in findings:
            check.comments += f"\ninterface {interface}\nswitchport nonegotiate\n!"

    check.finding = result
    return check


def V220667(device_type, device_name):
    # there is an issue writing comments when dealing with trunk and dis port configs but is mark open
    check = Stig()
    check.vulid = format_vulid()
    check.status = "NotAFinding"
    check.comments = "V-220667 - NAF - The Cisco switch has all disabled switch ports assigned to an unused VLAN.\r"

    command1 = "show interface status | inc sfpAbsent|disabled|xcvrAbsen"
    result1 = exec_command(command1, device_name)

    pattern1 = r"(\w+/[\d/]+)\s+([\w\s/]+)\s+disabled\s+(\w+)"
    matches1 = re.findall(pattern1, result1)
    disabled_ports = {match[0]: match[2] for match in matches1}
    unused_vlans = [vlan for port, vlan in disabled_ports.items() if vlan.isdigit()]

    command2 = "show interfaces trunk"
    result2 = exec_command(command2, device_name)

    pattern2 = r"(\w+/[\d/]+)\s+([\d,-]+)"
    matches2 = re.findall(pattern2, result2)
    trunk_ports = {match[0]: match[1] for match in matches2}

    findings_str = ""

    # Check for disabled ports that are set as trunks
    for port, vlan in disabled_ports.items():
        if vlan == "trunk":
            findings_str += f"Port {port} is disabled but set as a trunk\n"

    # Check for unused VLANs allowed on trunk ports
    for unused_vlan in unused_vlans:
        for port, vlans in trunk_ports.items():
            allowed_vlans = []
            for vlan in vlans.split(','):
                if '-' in vlan:
                    start, end = map(int, vlan.split('-'))
                    allowed_vlans.extend(range(start, end+1))
                else:
                    allowed_vlans.append(int(vlan))
            if int(unused_vlan) in allowed_vlans:
                findings_str += f"Port {port} is allowing unused vlan {unused_vlan}\n"

    if findings_str:
        check.status = "Open"
        check.comments = "V-220667 - OPEN because of the below findings:\n{}\r".format(findings_str)

    check.finding = result1 + "\n" + result2
    return check




def V220668(device_type, device_name):
    # V-220668 - The Cisco switch must not have the default VLAN assigned to any host-facing switch ports.
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"
    check.comments = "V-220668 - Open - The Cisco switch must not have the default VLAN assigned to any host-facing switch ports."

    command = "show spanning-tree vlan 1"
    result = exec_command(command, device_name)

    if "does not exist" in result[len(device_name) + len(command):]:
        check.status = "NotAFinding"
        check.comments = "V-220668 - NAF  No host-facing ports are assigned to VLAN1"

    check.finding = result
    return check


def V220669(device_type, device_name):
    # The Cisco switch must have the default VLAN pruned from all trunk ports that do not require it.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has. We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    check.comments = "V-220669 - Open - The Cisco switch must have the default VLAN pruned from all trunk ports that do not require it."

    command = "show spanning-tree vlan 1"
    result = exec_command(command, device_name)

    # Using regex to find the string "does not exist" in the result
    if re.search("does not exist", result[len(device_name) + len(command):]):
        check.status = "NotAFinding"
        check.comments = "V-220669 - NAF VLAN1 is not in use or trunked"

    check.finding = result
    return check

def V220670(device_type, device_name):
    # The Cisco switch must not use the default VLAN for management traffic.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has. We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    check.comments = "V-220670 - Open - The Cisco switch must not use the default VLAN for management traffic."

    command1 = "show spanning-tree vlan 1"
    command2 = "show run int vlan 1"
    result = exec_command(command1, device_name) + "\r" + exec_command(command2, device_name)

    # Using regex to find the strings "does not exist" and "no ip address" in the result
    if re.search("does not exist", result[len(device_name) + len(command2):]) and re.search("no ip address", result[len(device_name) + len(command2):]):
        check.status = "NotAFinding"
        check.comments = "V-220670 - NAF VLAN1 is not being used for management."

    check.finding = result
    return check


def V220671(device_type, device_name):
    # The Cisco switch must have all user-facing or untrusted ports configured as access switch ports.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has. We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Not_Applicable"

    command = "sh int status | ex trunk|666|disabled"
    result = exec_command(command, device_name)

    check.finding = result
    check.comments = "V-220671 - Not Applicable - Datacenter switches only connect to trusted infrastructure devices."

    return check


def V220672(device_type, device_name):
    # The native VLAN must be assigned to a VLAN ID other than the default VLAN for all 802.1q trunk links.
    check = Stig()
    check.vulid = format_vulid()
    check.status = "NotAFinding"
    check.comments = "V-220672 - NAF - The native VLAN on trunk links is other than the default VLAN for all 802.1q trunk links."

    interfaces = []
    temp = ""
    int_count = 0

    # Get a list of all trunk ports
    command = "show int trunk"
    result = exec_command(command, device_name)

    # Get port info
    for current_line in result.splitlines():
        interface_info = IntStatus()
        if "--------" in current_line:
            int_count += 1
        if ("Eth" in current_line or "Po" in current_line) and "#" not in current_line and int_count <= 2:
            interface_info.interface = current_line[0:12].strip()
            interface_info.vlan = current_line[14:22].strip()
            interfaces.append(interface_info)

    # Ensure all ports are not in VLAN 1
    for interface in interfaces:
        if "undefined" not in interface.interface and interface.vlan == "1":
            check.status = "Open"
            temp += f" {interface.interface}'s native VLAN appears to be assigned to default vlan {interface.vlan}; "

    if check.status == "Open":
        check.comments = f"V-220672 - OPEN because {temp}\r"
    check.finding = result

    return check


def V220673(device_type, device_name):
    # The Cisco switch must not have any switchports assigned to the native VLAN.
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"
    check.comments = "V-220673 - Open - The Cisco switch must not have any switchports assigned to the native VLAN."

    command = "sh int status | in connected.2172"
    result = exec_command(command, device_name)

    if "" in result[len(device_name) + len(command):]:
        check.status = "NotAFinding"
        check.comments = "V-220673 - NAF Native VLAN 200 is not in use by access ports."

    check.finding = result

    return check


# ----- SW RTR STIGS ---------------------------------------------------------------------------------

def V220986(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"
    command = "show platform hardware fed switch active qos queue stats internal cpu policer"
    result = exec_command(command, device_name)
    
    # Extract lines between the start and end markers
    lines = result.split('\n')
    start_idx = lines.index("QId PlcIdx  Queue Name                Enabled   Rate     Rate      Drop(Bytes)  Drop(Frames)")
    end_idx = lines.index("* NOTE: CPU queue policer rates are configured to the closest hardware supported value")
    relevant_lines = lines[start_idx + 1:end_idx]
    check.finding = result
    # Check if each line that starts with a number has "Yes" in it
    is_cpp_in_place = all('Yes' in line for line in relevant_lines if line.startswith(tuple('0123456789')))
    
    # Additional comments
    additional_comments = "The Core switch is below the Firewall/boundary for the site so some protection is in place. " \
                          "Servers and Workstations are running HBSS/AESS thus giving a layer of protection."
    
    check.comments = f"Cpp is in place and adds some protection on the core switch: {is_cpp_in_place}. {additional_comments}"
    
    return check

def V220987(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()
    check.status = "NotAFinding"
    check.comments = "Checking Routing Protocol and Authentication."

    # First command
    command = "show ip proto | i Routing.Protoc"
    result = exec_command(command, device_name)
    check.finding += result

    if "Routing Protocol is" in result:
        if "eigrp" in result:
            # Run the second command
            command = "show ip eigrp interfaces detail | i Authen|^(T|V|G|I)"
            result = exec_command(command, device_name)
            check.finding += result
            
            if "Authentication mode is not set" in result:
                check.status = "Open"
                check.comments += "\nAuthentication mode is not set in EIGRP interfaces."
            else:
                check.status = "NotAFinding"
                check.comments += "\nEIGRP interfaces have authentication set."
        else:
            check.status = "Open"
            check.comments += "\nRouting Protocol is not EIGRP."
    else:
        check.status = "Not_Applicable"
        check.comments += "\nRouting Protocol is not set."

    return check
    
def V220988(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()
    check.status = "NotAFinding"
    check.comments = "Checking Routing Protocol and Keys."

    # First command
    command = "show ip proto | i Routing.Protoc"
    result = exec_command(command, device_name)
    check.finding += result

    if "Routing Protocol is" in result:
        if "eigrp" in result:
            # Run the second command
            command = "show ip eigrp interfaces detail | i Authen|^(T|V|G|I)"
            result = exec_command(command, device_name)
            check.finding += result
            
            if "Authentication mode is not set" in result:
                check.status = "Open"
                check.comments += "\nAuthentication mode is not set in EIGRP interfaces."
            else:
                check.status = "Not_Applicable"
                check.comments += "\nEIGRP interfaces have authentication set HMAC not Keys."
        else:
            check.status = "Open"
            check.comments += "\nRouting Protocol is not EIGRP.Configs need to be reviewed"
    else:
        check.status = "Not_Applicable"
        check.comments += "\nRouting Protocol is not set."

    return check    

def V220989(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()
    check.status = "NotAFinding"
    check.comments = "Checking Routing Protocol and Keys."

    # First command
    command = "show ip proto | i Routing.Protoc"
    result = exec_command(command, device_name)
    check.finding += result

    if "Routing Protocol is" in result:
        if "eigrp" in result:
            # Run the second command
            command = "show ip eigrp interfaces detail | i Authen|^(T|V|G|I)"
            result = exec_command(command, device_name)
            check.finding += result
            
            if "Authentication mode is not set" in result:
                check.status = "Open"
                check.comments += "\nAuthentication mode is not set in EIGRP interfaces."
            else:
                check.status = "Not_Applicable"
                check.comments += "\nEIGRP interfaces have authentication set HMAC not Keys."
        else:
            check.status = "Open"
            check.comments += "\nRouting Protocol is not EIGRP.Configs need to be reviewed"
    else:
        check.status = "Not_Applicable"
        check.comments += "\nRouting Protocol is not set."

    return check    
    
    
def V220990(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()
    check.status = "NotAFinding"
    check.comments = "Checking Routing Protocol and Keys."

    # First command
    command = "show ip proto | i Routing.Protoc"
    result = exec_command(command, device_name)
    check.finding += result

    if "Routing Protocol is" in result:
        if "eigrp" in result:
            # Run the second command
            command = "show ip eigrp interfaces detail | i Authen|^(T|V|G|I)"
            result = exec_command(command, device_name)
            check.finding += result
            
            if "Authentication mode is not set" in result:
                check.status = "Open"
                check.comments += "\nAuthentication mode is not set in EIGRP interfaces."
            else:
                check.status = "Not_Applicable"
                check.comments += "\nEIGRP interfaces have authentication set HMAC not Keys."
        else:
            check.status = "Open"
            check.comments += "\nRouting Protocol is not EIGRP.Configs need to be reviewed"
    else:
        check.status = "Not_Applicable"
        check.comments += "\nRouting Protocol is not set."

    return check

def V220991(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()
    check.status = "NotAFinding"
    check.comments = "The Cisco switch ports must not have interfaces in a down state."

    command = "show int des | ex admin|up"
    result = exec_command(command, device_name)

    # Use regular expression to find interfaces with "down" status
    findings = re.findall(r"(?m)^(\S+)\s+down\s+down", result)

    if findings:
        check.status = "Open"
        check.comments += "\nThe following interfaces are in a down state:\n" + "\n".join(findings)
        check.comments += "\n\nPlease investigate why these interfaces are down."

    check.finding = result
    return check

def V220994(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()
    check.status = "NotAFinding"
    check.comments = "V-220994 - The Cisco switch must have boot options set correctly."

    # Define the command to run
    command = "show run | i boot(-start|-end|.network)|^cns"

    # Execute the command and get the result
    result = exec_command(command, device_name)

    # Count the number of lines in the result
    line_count = len(result.strip().split("\n"))

    # Check if the result has more than 2 lines
    if line_count > 2:
        check.status = "Open"
        check.comments += f"\nThe device has extra boot options:\n{result}"

    # Storing the complete result, including the device name and prompt
    check.finding = result
    return check
    
def V220995(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"  # Default status
    command = "show platform hardware fed switch active qos queue stats internal cpu policer"
    result = exec_command(command, device_name)
    
    # Extract lines between the start and end markers
    lines = result.split('\n')
    start_idx = lines.index("QId PlcIdx  Queue Name                Enabled   Rate     Rate      Drop(Bytes)  Drop(Frames)")
    end_idx = lines.index("* NOTE: CPU queue policer rates are configured to the closest hardware supported value")
    relevant_lines = lines[start_idx + 1:end_idx]
    
    # Check if each line that starts with a number has "Yes" in it
    is_cpp_in_place = all('Yes' in line for line in relevant_lines if line.startswith(tuple('0123456789')))
    
    if is_cpp_in_place:
        check.status = "NotAFinding"
        check.comments = "CPP is in place and configured correctly."
    else:
        check.comments = "CPP does not appear to be configured correctly."
    check.finding = result
    return check

def V220996(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"  # Default status
    command = "show platform hardware fed switch active qos queue stats internal cpu policer"
    result = exec_command(command, device_name)
    
    # Extract lines between the start and end markers
    lines = result.split('\n')
    start_idx = lines.index("QId PlcIdx  Queue Name                Enabled   Rate     Rate      Drop(Bytes)  Drop(Frames)")
    end_idx = lines.index("* NOTE: CPU queue policer rates are configured to the closest hardware supported value")
    relevant_lines = lines[start_idx + 1:end_idx]
    
    # Check if each line that starts with a number has "Yes" in it
    is_cpp_in_place = all('Yes' in line for line in relevant_lines if line.startswith(tuple('0123456789')))
    
    if is_cpp_in_place:
        check.status = "NotAFinding"
        check.comments = ("CPP is in place and configured correctly. \n"
                          "From DISA ticket: 'Yes the CoPP meets the controls. \n"
                          "We currently have an open ticket to update the STIGS in the near future.' \n"
                          "DISA ticket URL: \n"
                          "https://services.disa.mil/sp?id=ticket&table=sc_req_item&sys_id=8ff611fb47efa150484fbaba436d43c7 \n")
    else:
        check.comments = "CPP does not appear to be configured correctly."
    check.finding = result
    return check

def V220997(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"  # Default status
    command = "show platform hardware fed switch active qos queue stats internal cpu policer"
    result = exec_command(command, device_name)
    
    # Extract lines between the start and end markers
    lines = result.split('\n')
    start_idx = lines.index("QId PlcIdx  Queue Name                Enabled   Rate     Rate      Drop(Bytes)  Drop(Frames)")
    end_idx = lines.index("* NOTE: CPU queue policer rates are configured to the closest hardware supported value")
    relevant_lines = lines[start_idx + 1:end_idx]
    
    # Check if each line that starts with a number has "Yes" in it
    is_cpp_in_place = all('Yes' in line for line in relevant_lines if line.startswith(tuple('0123456789')))
    
    if is_cpp_in_place:
        check.status = "NotAFinding"
        check.comments = ("CPP is in place and configured correctly. \n"
                          "From DISA ticket: 'Yes the CoPP meets the controls. \n"
                          "We currently have an open ticket to update the STIGS in the near future.' \n"
                          "DISA ticket URL: \n"
                          "https://services.disa.mil/sp?id=ticket&table=sc_req_item&sys_id=8ff611fb47efa150484fbaba436d43c7 \n")
    else:
        check.comments = "CPP does not appear to be configured correctly."
    check.finding = result
    return check
    

def V220998(device_type, device_name):
    # Create an object of the Stig class and set default values
    check = Stig()
    check.vulid = format_vulid()
    check.status = "NotAFinding"  

    # The command to execute
    command = "show run | i gratuitous-arps"
    
    # Execute the command and store the result
    result = exec_command(command, device_name)
    
    # Store the command output in check.finding
    check.finding = result

    # Check if 'no ip gratuitous-arps' is NOT in the result
    if "no ip gratuitous-arps" not in result:
        check.status = "Open"
        check.comments = "Gratuitous arps are NOT disabled globally"
    else:
        check.comments = "Gratuitous arps are disabled globally"

    return check


def V220999(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()
    check.status = "NotAFinding"
    check.comments = "V-220999 - IP directed broadcast command must not be found on any interface."

    # Define the command to run
    command = "show run all | i ip directed-broadcast"

    # Execute the command and get the result
    result = exec_command(command, device_name)

    # Count the number of lines in the result
    line_count = len(result.strip().split("\n"))

    # Check if the result has more than 2 lines
    if line_count > 2:
        check.status = "Open"
        check.comments += "IP directed broadcast command found, look at findings"

    # Storing the complete result, including the device name and prompt
    check.finding = result
    return check


def V221000(device_type, device_name):
    # Create an object of the Stig class and set default values
    check = Stig()
    check.vulid = format_vulid()
    check.status = "NotAFinding"

    # The command to execute
    command = "show run | i ^interface|no.ip.(redirects|unreachables|proxy-arp)|ip.address.*.255"

    # Execute the command and store the result
    result = exec_command(command, device_name)

    # Store the command output in check.finding
    check.finding = result

    # Initialize data structures
    interface_data = {}
    missing_unreachables = []
    config_needed = []
    current_interface = None

    # Process each line of the output
    for line in result.strip().split('\n'):
        if "interface" in line:
            current_interface = line.strip()
        elif "ip address" in line:
            # Initialize an empty list of settings for the current interface
            interface_data[current_interface] = []
        elif "no ip" in line:
            # Only add the setting if the current interface has been initialized (i.e., it has an IP address)
            if current_interface in interface_data:
                interface_data[current_interface].append(line.strip())

    # Check if any interface is missing "no ip unreachables"
    for interface, settings in interface_data.items():
        if "no ip unreachables" not in settings:
            check.status = "Open"
            missing_unreachables.append(interface)

    # Generate the configuration needed for each interface
    for interface, settings in interface_data.items():
        missing_settings = [s for s in ["no ip redirects", "no ip unreachables", "no ip proxy-arp"] if s not in settings]
        if missing_settings:
            config_needed.append(f"{interface}\n\t" + "\n\t".join(missing_settings) + "\nexit\n!")

    # Update check.comments based on the findings
    if missing_unreachables:
        check.comments = f"The following interfaces are missing 'no ip unreachables' command\n" + "\n".join(missing_unreachables)
    else:
        check.comments = "'no ip unreachables' command found on all L3 interfaces"

    if config_needed:
        check.comments += "\n\nConfiguration needed:\n" + "\n".join(config_needed)

    return check    


def V221001(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()
    check.status = "NotAFinding"
    check.comments = "V-221001 - IP mask-reply command must not be found on any interface."

    # Define the command to run
    command = "show run all | i ip mask-reply"

    # Execute the command and get the result
    result = exec_command(command, device_name)

    # Count the number of lines in the result
    line_count = len(result.strip().split("\n"))

    # Check if the result has more than 2 lines
    if line_count > 2:
        check.status = "Open"
        check.comments += "IP mask-replay command found, look at findings"

    # Storing the complete result, including the device name and prompt
    check.finding = result
    return check


def V221002(device_type, device_name):
    # Create an object of the Stig class and set default values
    check = Stig()
    check.vulid = format_vulid()
    check.status = "NotAFinding"

    # The command to execute
    command = "show run | i ^interface|no.ip.(redirects|unreachables|proxy-arp)|ip.address.*.255"

    # Execute the command and store the result
    result = exec_command(command, device_name)

    # Store the command output in check.finding
    check.finding = result

    # Initialize data structures
    interface_data = {}
    missing_redirects = []
    config_needed = []
    current_interface = None

    # Process each line of the output
    for line in result.strip().split('\n'):
        if "interface" in line:
            current_interface = line.strip()
        elif "ip address" in line:
            # Initialize an empty list of settings for the current interface
            interface_data[current_interface] = []
        elif "no ip" in line:
            # Only add the setting if the current interface has been initialized (i.e., it has an IP address)
            if current_interface in interface_data:
                interface_data[current_interface].append(line.strip())

    # Check if any interface is missing "no ip redirects"
    for interface, settings in interface_data.items():
        if "no ip redirects" not in settings:
            check.status = "Open"
            missing_redirects.append(interface)

    # Generate the configuration needed for each interface
    for interface, settings in interface_data.items():
        missing_settings = [s for s in ["no ip redirects", "no ip unreachables", "no ip proxy-arp"] if s not in settings]
        if missing_settings:
            config_needed.append(f"{interface}\n\t" + "\n\t".join(missing_settings) + "\nexit\n!")

    # Update check.comments based on the findings
    if missing_redirects:
        check.comments = f"The following interfaces are missing 'no ip redirects' command\n" + "\n".join(missing_redirects)
    else:
        check.comments = "no ip redirects command found on all L3 interfaces"

    if config_needed:
        check.comments += "\n\nConfiguration needed:\n" + "\n".join(config_needed)

    return check


    
def V221003(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"  # Default status
    command = "show platform hardware fed switch active qos queue stats internal cpu policer"
    result = exec_command(command, device_name)
    
    # Extract lines between the start and end markers
    lines = result.split('\n')
    start_idx = lines.index("QId PlcIdx  Queue Name                Enabled   Rate     Rate      Drop(Bytes)  Drop(Frames)")
    end_idx = lines.index("* NOTE: CPU queue policer rates are configured to the closest hardware supported value")
    relevant_lines = lines[start_idx + 1:end_idx]
    
    # Check if each line that starts with a number has "Yes" in it
    is_cpp_in_place = all('Yes' in line for line in relevant_lines if line.startswith(tuple('0123456789')))
    
    if is_cpp_in_place:
        check.status = "NotAFinding"
        check.comments = "CPP is in place and configured correctly."
    else:
        check.comments = "CPP does not appear to be configured correctly."
    check.finding = result
    return check
    

def V221004(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()
    check.status = "NotAFinding"

    os_acl_list = [
        "AutoConf-4.0-Acl-Default", "CoPP_CRITICAL", "CoPP_DEFAULT", "CoPP_IMPORTANT",
        "CoPP_NORMAL", "CoPP_UNDESIRABLE", "IP-Adm-V4-Int-ACL-global", "implicit_deny",
        "implicit_permit", "meraki-fqdn-dns", "preauth_v4", "sl_def_acl"
    ]

    command = "show ip access-lists | i deny.*.log|IP access list|deny"
    result = exec_command(command, device_name)

    custom_acl_issues = {}
    os_acl_present = []

    is_standard = False  # Initialize flag for standard or extended ACL

    for line in result.split("\n"):
        if "IP access list" in line:
            acl_name = line.split("IP access list")[1].strip()
            is_standard = "Standard" in line  # Set flag based on ACL type

        elif "deny" in line:
            if acl_name in os_acl_list:
                os_acl_present.append(acl_name)
            else:
                log_check = "log" if is_standard else "log-input"
                if log_check not in line:
                    if acl_name not in custom_acl_issues:
                        custom_acl_issues[acl_name] = []
                    custom_acl_issues[acl_name].append(line.strip())

    if custom_acl_issues:
        check.status = "Open"
        check.comments = "Following Access control lists have the following deny lines without appropriate logging:\n"
        for acl, issues in custom_acl_issues.items():
            nested_issues = "\n  ".join(issues)
            check.comments += f"{acl}:\n  {nested_issues}\n"

    else:
        check.comments = "All access lists have the appropriate logging as needed."

    # Add list of OS ACLs to comments
    check.comments += "\nThe following access lists are a part of the IOS and can't be updated:\n" + '\n'.join(set(os_acl_present))
    check.finding = result
    return check


def V221005(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()
    check.status = "NotAFinding"

    os_acl_list = [
        "AutoConf-4.0-Acl-Default", "CoPP_CRITICAL", "CoPP_DEFAULT", "CoPP_IMPORTANT",
        "CoPP_NORMAL", "CoPP_UNDESIRABLE", "IP-Adm-V4-Int-ACL-global", "implicit_deny",
        "implicit_permit", "meraki-fqdn-dns", "preauth_v4", "sl_def_acl"
    ]

    command = "show ip access-lists | i deny.*.log|IP access list|deny"
    result = exec_command(command, device_name)

    custom_acl_issues = {}
    os_acl_present = []

    is_standard = False  # Initialize flag for standard or extended ACL

    for line in result.split("\n"):
        if "IP access list" in line:
            acl_name = line.split("IP access list")[1].strip()
            is_standard = "Standard" in line  # Set flag based on ACL type

        elif "deny" in line:
            if acl_name in os_acl_list:
                os_acl_present.append(acl_name)
            else:
                log_check = "log" if is_standard else "log-input"
                if log_check not in line:
                    if acl_name not in custom_acl_issues:
                        custom_acl_issues[acl_name] = []
                    custom_acl_issues[acl_name].append(line.strip())

    if custom_acl_issues:
        check.status = "Open"
        check.comments = "Following Access control lists have the following deny lines without appropriate logging:\n"
        for acl, issues in custom_acl_issues.items():
            nested_issues = "\n  ".join(issues)
            check.comments += f"{acl}:\n  {nested_issues}\n"

    else:
        check.comments = "All access lists have the appropriate logging as needed."

    # Add list of OS ACLs to comments
    check.comments += "\nThe following access lists are a part of the IOS and can't be updated:\n" + '\n'.join(set(os_acl_present))
    check.finding = result
    return check



def V221006(device_type, device_name):
    # Create an object of the Stig class and set default values
    check = Stig()
    check.vulid = format_vulid()
    check.status = "NotAFinding"

    # The command to execute
    command = "show run | s line aux 0"

    # Execute the command and store the result
    result = exec_command(command, device_name)

    # Store the command output in check.finding
    check.finding = result

    # Check for the presence of "line aux" and "no exec" in the result
    if "line aux" not in result or "no exec" not in result:
        check.status = "Open"
        check.comments = "Line Aux is on and needs to be off"
    else:
        check.comments = "Line Aux is disabled"

    return check    


def V221007(device_type, device_name):
    """
   Add a command or command to show its location based off configuration.
    """
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Not_Applicable"
    check.comments = "This is not a perimeter device the FIREWALLS above are the perimeter."
    
    return check

def V221008(device_type, device_name):
    """
   Add a command or command to show its location based off configuration.
    """
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Not_Applicable"
    check.comments = "This is not a perimeter device the FIREWALLS above are the perimeter."
    
    return check

def V221009(device_type, device_name):
    """
   Add a command or command to show its location based off configuration.
    """
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Not_Applicable"
    check.comments = "This is not a perimeter device the FIREWALLS above are the perimeter."
    
    return check

def V221010(device_type, device_name):
    """
   Add a command or command to show its location based off configuration.
    """
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Not_Applicable"
    check.comments = "This is not a perimeter device the FIREWALLS above are the perimeter."
    
    return check

def V221011(device_type, device_name):
    """
   Add a command or command to show its location based off configuration.
    """
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Not_Applicable"
    check.comments = "This is not a perimeter device the FIREWALLS above are the perimeter."
    
    return check

def V221012(device_type, device_name):
    """
   Add a command or command to show its location based off configuration.
    """
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Not_Applicable"
    check.comments = "This is not a perimeter device the FIREWALLS above are the perimeter."
    
    return check

def V221013(device_type, device_name):
    """
   Add a command or command to show its location based off configuration.
    """
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Not_Applicable"
    check.comments = "This is not a perimeter device the FIREWALLS above are the perimeter."
    
    return check

def V221014(device_type, device_name):
    """
   Add a command or command to show its location based off configuration.
    """
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Not_Applicable"
    check.comments = "This is not a perimeter device the FIREWALLS above are the perimeter."
    
    return check

def V221015(device_type, device_name):
    """
   Add a command or command to show its location based off configuration.
    """
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Not_Applicable"
    check.comments = "This is not a perimeter device the FIREWALLS above are the perimeter."
    
    return check

def V221016(device_type, device_name):
    """
   Add a command or command to show its location based off configuration.
    """
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Not_Applicable"
    check.comments = "This is not a perimeter device the FIREWALLS above are the perimeter."
    
    return check

def V221017(device_type, device_name):
    """
   Add a command or command to show its location based off configuration.
    """
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Not_Applicable"
    check.comments = "This is not a perimeter device the FIREWALLS above are the perimeter."
    
    return check

    
def V221018(device_type, device_name):
    # Create an object of the Stig class and set default values
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Not_Applicable"

    # The command to execute
    command = "show run | i ^interface|no.ip.(redirects|unreachables|proxy-arp)|ip.address.*.255"

    # Execute the command and store the result
    result = exec_command(command, device_name)

    # Store the command output in check.finding
    check.finding = result

    # Initialize data structures
    interface_data = {}
    missing_proxy_arp = []
    config_needed = []
    current_interface = None

    # Process each line of the output
    for line in result.strip().split('\n'):
        if "interface" in line:
            current_interface = line.strip()
        elif "ip address" in line:
            # Initialize an empty list of settings for the current interface
            interface_data[current_interface] = []
        elif "no ip" in line:
            # Only add the setting if the current interface has been initialized (i.e., it has an IP address)
            if current_interface in interface_data:
                interface_data[current_interface].append(line.strip())

    # Check if any interface is missing "no ip proxy-arp"
    for interface, settings in interface_data.items():
        if "no ip proxy-arp" not in settings:
            check.status = "Open"
            missing_proxy_arp.append(interface)

    # Generate the configuration needed for each interface
    for interface, settings in interface_data.items():
        missing_settings = [s for s in ["no ip redirects", "no ip unreachables", "no ip proxy-arp"] if s not in settings]
        if missing_settings:
            config_needed.append(f"{interface}\n\t" + "\n\t".join(missing_settings) + "\nexit\n!")

    # Update check.comments based on the findings
    check.comments = "This is not a perimeter device; the FIREWALLS above are the perimeter.\n"
    
    if missing_proxy_arp:
        check.comments += f"The following interfaces are missing 'no ip proxy-arp' command\n" + "\n".join(missing_proxy_arp)
    else:
        check.comments += "'no ip proxy-arp' command found on all L3 interfaces"

    if config_needed:
        check.comments += "\n\nConfiguration needed:\n" + "\n".join(config_needed)

    return check


def V221019(device_type, device_name):
    """
   Add a command or command to show its location based off configuration.
    """
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Not_Applicable"
    check.comments = "This is not a perimeter device the FIREWALLS above are the perimeter."
    
    return check


def V221020(device_type, device_name):
    
    check = Stig()
    # The vulnerability ID MUST match what the stig file has. We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Not_Applicable"
    # The command to execute
    command = "show run | i ^line.vty|access-class*.*.SSH|access.list.*.SSH"
    
    # Execute the command and store the result
    result = exec_command(command, device_name)
    
    # Update the finding with the additional information
    check.finding = f"No out of band network but SSH to the device is locked down\r\n{result}"
    
    check.comments = "There is no OOBM network in SWA nor any plans to stand one up at this time."
    
    return check


def V221021(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()  # Automatically format the vulnerability ID
    check.status = "Not_Applicable"  # Default status
    
    # Send the command 'show ip bgp' to the device
    command = "show ip bgp"
    result = exec_command(command, device_name)

    # Check for "% BGP not active" in the output
    if "% BGP not active" in result:
        check.status = "Not_Applicable"
        check.comments = f"No active BGP process on {device_name}"
    else:
        check.status = "Open"
        check.comments = f"BGP is active on {device_name} please review"

    check.finding = result  # Store the result as the finding

    return check


def V221022(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()  # Automatically format the vulnerability ID
    check.status = "Not_Applicable"  # Default status
    
    # Send the command 'show ip bgp' to the device
    command = "show ip bgp"
    result = exec_command(command, device_name)

    # Check for "% BGP not active" in the output
    if "% BGP not active" in result:
        check.status = "Not_Applicable"
        check.comments = f"No active BGP process on {device_name}"
    else:
        check.status = "Open"
        check.comments = f"BGP is active on {device_name}; please review"

    check.finding = result  # Store the result as the finding

    return check

def V221023(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()  # Automatically format the vulnerability ID
    check.status = "Not_Applicable"  # Default status
    
    # Send the command 'show ip bgp' to the device
    command = "show ip bgp"
    result = exec_command(command, device_name)

    # Check for "% BGP not active" in the output
    if "% BGP not active" in result:
        check.status = "Not_Applicable"
        check.comments = f"No active BGP process on {device_name}"
    else:
        check.status = "Open"
        check.comments = f"BGP is active on {device_name}; please review"

    check.finding = result  # Store the result as the finding

    return check

def V221024(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()  # Automatically format the vulnerability ID
    check.status = "Not_Applicable"  # Default status
    
    # Send the command 'show ip bgp' to the device
    command = "show ip bgp"
    result = exec_command(command, device_name)

    # Check for "% BGP not active" in the output
    if "% BGP not active" in result:
        check.status = "Not_Applicable"
        check.comments = f"No active BGP process on {device_name}"
    else:
        check.status = "Open"
        check.comments = f"BGP is active on {device_name}; please review"

    check.finding = result  # Store the result as the finding

    return check

def V221025(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()  # Automatically format the vulnerability ID
    check.status = "Not_Applicable"  # Default status
    
    # Send the command 'show ip bgp' to the device
    command = "show ip bgp"
    result = exec_command(command, device_name)

    # Check for "% BGP not active" in the output
    if "% BGP not active" in result:
        check.status = "Not_Applicable"
        check.comments = f"No active BGP process on {device_name}"
    else:
        check.status = "Open"
        check.comments = f"BGP is active on {device_name}; please review"

    check.finding = result  # Store the result as the finding

    return check

def V221026(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()  # Automatically format the vulnerability ID
    check.status = "Not_Applicable"  # Default status
    
    # Send the command 'show ip bgp' to the device
    command = "show ip bgp"
    result = exec_command(command, device_name)

    # Check for "% BGP not active" in the output
    if "% BGP not active" in result:
        check.status = "Not_Applicable"
        check.comments = f"No active BGP process on {device_name}"
    else:
        check.status = "Open"
        check.comments = f"BGP is active on {device_name}; please review"

    check.finding = result  # Store the result as the finding

    return check

def V221027(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()  # Automatically format the vulnerability ID
    check.status = "Not_Applicable"  # Default status
    
    # Send the command 'show ip bgp' to the device
    command = "show ip bgp"
    result = exec_command(command, device_name)

    # Check for "% BGP not active" in the output
    if "% BGP not active" in result:
        check.status = "Not_Applicable"
        check.comments = f"No active BGP process on {device_name}"
    else:
        check.status = "Open"
        check.comments = f"BGP is active on {device_name}; please review"

    check.finding = result  # Store the result as the finding

    return check

def V221028(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()  # Automatically format the vulnerability ID
    check.status = "Not_Applicable"  # Default status
    
    # Send the command 'show ip bgp' to the device
    command = "show ip bgp"
    result = exec_command(command, device_name)

    # Check for "% BGP not active" in the output
    if "% BGP not active" in result:
        check.status = "Not_Applicable"
        check.comments = f"No active BGP process on {device_name}"
    else:
        check.status = "Open"
        check.comments = f"BGP is active on {device_name}; please review"

    check.finding = result  # Store the result as the finding

    return check

def V221029(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()  # Automatically format the vulnerability ID
    check.status = "Not_Applicable"  # Default status
    
    # Send the command 'show ip bgp' to the device
    command = "show ip bgp"
    result = exec_command(command, device_name)

    # Check for "% BGP not active" in the output
    if "% BGP not active" in result:
        check.status = "Not_Applicable"
        check.comments = f"No active BGP process on {device_name}"
    else:
        check.status = "Open"
        check.comments = f"BGP is active on {device_name}; please review"

    check.finding = result  # Store the result as the finding

    return check

def V221030(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()  # Automatically format the vulnerability ID
    check.status = "Not_Applicable"  # Default status
    
    # Send the command 'show ip bgp' to the device
    command = "show ip bgp"
    result = exec_command(command, device_name)

    # Check for "% BGP not active" in the output
    if "% BGP not active" in result:
        check.status = "Not_Applicable"
        check.comments = f"No active BGP process on {device_name}"
    else:
        check.status = "Open"
        check.comments = f"BGP is active on {device_name}; please review"

    check.finding = result  # Store the result as the finding

    return check

def V221031(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()  # Automatically format the vulnerability ID
    check.status = "Not_Applicable"  # Default status
    
    # Send the command 'show ip bgp' to the device
    command = "show ip bgp"
    result = exec_command(command, device_name)

    # Check for "% BGP not active" in the output
    if "% BGP not active" in result:
        check.status = "Not_Applicable"
        check.comments = f"No active BGP process on {device_name}"
    else:
        check.status = "Open"
        check.comments = f"BGP is active on {device_name}; please review"

    check.finding = result  # Store the result as the finding

    return check

def V221032(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()  # Automatically format the vulnerability ID
    check.status = "Not_Applicable"  # Default status
    
    # Send the command 'show ip bgp' to the device
    command = "show ip bgp"
    result = exec_command(command, device_name)

    # Check for "% BGP not active" in the output
    if "% BGP not active" in result:
        check.status = "Not_Applicable"
        check.comments = f"No active BGP process on {device_name}"
    else:
        check.status = "Open"
        check.comments = f"BGP is active on {device_name}; please review"

    check.finding = result  # Store the result as the finding

    return check
    
    
def V221033(device_type, device_name):
    
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Not_Applicable"  # Initialize as Not_Applicable, to be updated based on findings

    # Check MPLS configuration
    command_mpls = "show mpls forwarding-table"
    result_mpls = exec_command(command_mpls, device_name)

    # Initialize flags to determine the status of MPLS and VRF
    mpls_flag = False
    vrf_flag = False

    # Parse the MPLS output to see if any line starts with a number
    for line in result_mpls.split('\n'):
        if line and line[0].isdigit():
            mpls_flag = True
            break

    # Check VRF configuration
    command_vrf = "show ip vrf detail | i RT:|^VRF"
    result_vrf = exec_command(command_vrf, device_name)

    # Parse the VRF output to see if it has "VRF" and "RD" in the same line
    for line in result_vrf.split('\n'):
        if "VRF" in line and "RD" in line:
            if "<not set>" not in line:
                vrf_flag = True
            break

    # Update the finding and comments based on the flags
    if mpls_flag:
        check.finding += f"\nMPLS Output:\n{result_mpls}"
        check.comments += "MPLS is configured on this device and needs to be reviewed."
        check.status = "Open"
    else:
        check.finding += f"\nMPLS Output:\n{result_mpls}"
        check.comments += "MPLS is not configured on this device."

    if vrf_flag:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs configured on this device, please review."
        check.status = "Open"
    else:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs are not configured on this device."

    return check


def V221034(device_type, device_name):
    """
    Checks MPLS and VRF configurations on the Cisco switch.
    """
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Not_Applicable"  # Initialize as Not_Applicable, to be updated based on findings

    # Check MPLS configuration
    command_mpls = "show mpls forwarding-table"
    result_mpls = exec_command(command_mpls, device_name)

    # Initialize flags to determine the status of MPLS and VRF
    mpls_flag = False
    vrf_flag = False

    # Parse the MPLS output to see if any line starts with a number
    for line in result_mpls.split('\n'):
        if line and line[0].isdigit():
            mpls_flag = True
            break

    # Check VRF configuration
    command_vrf = "show ip vrf detail | i RT:|^VRF"
    result_vrf = exec_command(command_vrf, device_name)

    # Parse the VRF output to see if it has "VRF" and "RD" in the same line
    for line in result_vrf.split('\n'):
        if "VRF" in line and "RD" in line:
            if "<not set>" not in line:
                vrf_flag = True
            break

    # Update the finding and comments based on the flags
    if mpls_flag:
        check.finding += f"\nMPLS Output:\n{result_mpls}"
        check.comments += "MPLS is configured on this device and needs to be reviewed."
        check.status = "Open"
    else:
        check.finding += f"\nMPLS Output:\n{result_mpls}"
        check.comments += "MPLS is not configured on this device."

    if vrf_flag:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs configured on this device, please review."
        check.status = "Open"
    else:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs are not configured on this device."

    return check

def V221035(device_type, device_name):
    """
    Checks MPLS and VRF configurations on the Cisco switch.
    """
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Not_Applicable"  # Initialize as Not_Applicable, to be updated based on findings

    # Check MPLS configuration
    command_mpls = "show mpls forwarding-table"
    result_mpls = exec_command(command_mpls, device_name)

    # Initialize flags to determine the status of MPLS and VRF
    mpls_flag = False
    vrf_flag = False

    # Parse the MPLS output to see if any line starts with a number
    for line in result_mpls.split('\n'):
        if line and line[0].isdigit():
            mpls_flag = True
            break

    # Check VRF configuration
    command_vrf = "show ip vrf detail | i RT:|^VRF"
    result_vrf = exec_command(command_vrf, device_name)

    # Parse the VRF output to see if it has "VRF" and "RD" in the same line
    for line in result_vrf.split('\n'):
        if "VRF" in line and "RD" in line:
            if "<not set>" not in line:
                vrf_flag = True
            break

    # Update the finding and comments based on the flags
    if mpls_flag:
        check.finding += f"\nMPLS Output:\n{result_mpls}"
        check.comments += "MPLS is configured on this device and needs to be reviewed."
        check.status = "Open"
    else:
        check.finding += f"\nMPLS Output:\n{result_mpls}"
        check.comments += "MPLS is not configured on this device."

    if vrf_flag:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs configured on this device, please review."
        check.status = "Open"
    else:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs are not configured on this device."

    return check

def V221036(device_type, device_name):
    """
    Checks MPLS and VRF configurations on the Cisco switch.
    """
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Not_Applicable"  # Initialize as Not_Applicable, to be updated based on findings

    # Check MPLS configuration
    command_mpls = "show mpls forwarding-table"
    result_mpls = exec_command(command_mpls, device_name)

    # Initialize flags to determine the status of MPLS and VRF
    mpls_flag = False
    vrf_flag = False

    # Parse the MPLS output to see if any line starts with a number
    for line in result_mpls.split('\n'):
        if line and line[0].isdigit():
            mpls_flag = True
            break

    # Check VRF configuration
    command_vrf = "show ip vrf detail | i RT:|^VRF"
    result_vrf = exec_command(command_vrf, device_name)

    # Parse the VRF output to see if it has "VRF" and "RD" in the same line
    for line in result_vrf.split('\n'):
        if "VRF" in line and "RD" in line:
            if "<not set>" not in line:
                vrf_flag = True
            break

    # Update the finding and comments based on the flags
    if mpls_flag:
        check.finding += f"\nMPLS Output:\n{result_mpls}"
        check.comments += "MPLS is configured on this device and needs to be reviewed."
        check.status = "Open"
    else:
        check.finding += f"\nMPLS Output:\n{result_mpls}"
        check.comments += "MPLS is not configured on this device."

    if vrf_flag:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs configured on this device, please review."
        check.status = "Open"
    else:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs are not configured on this device."

    return check

def V221037(device_type, device_name):
    """
    Checks MPLS and VRF configurations on the Cisco switch.
    """
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Not_Applicable"  # Initialize as Not_Applicable, to be updated based on findings

    # Check MPLS configuration
    command_mpls = "show mpls forwarding-table"
    result_mpls = exec_command(command_mpls, device_name)

    # Initialize flags to determine the status of MPLS and VRF
    mpls_flag = False
    vrf_flag = False

    # Parse the MPLS output to see if any line starts with a number
    for line in result_mpls.split('\n'):
        if line and line[0].isdigit():
            mpls_flag = True
            break

    # Check VRF configuration
    command_vrf = "show ip vrf detail | i RT:|^VRF"
    result_vrf = exec_command(command_vrf, device_name)

    # Parse the VRF output to see if it has "VRF" and "RD" in the same line
    for line in result_vrf.split('\n'):
        if "VRF" in line and "RD" in line:
            if "<not set>" not in line:
                vrf_flag = True
            break

    # Update the finding and comments based on the flags
    if mpls_flag:
        check.finding += f"\nMPLS Output:\n{result_mpls}"
        check.comments += "MPLS is configured on this device and needs to be reviewed."
        check.status = "Open"
    else:
        check.finding += f"\nMPLS Output:\n{result_mpls}"
        check.comments += "MPLS is not configured on this device."

    if vrf_flag:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs configured on this device, please review."
        check.status = "Open"
    else:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs are not configured on this device."

    return check

def V221038(device_type, device_name):
    """
    Checks MPLS and VRF configurations on the Cisco switch.
    """
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Not_Applicable"  # Initialize as Not_Applicable, to be updated based on findings

    # Check MPLS configuration
    command_mpls = "show mpls forwarding-table"
    result_mpls = exec_command(command_mpls, device_name)

    # Initialize flags to determine the status of MPLS and VRF
    mpls_flag = False
    vrf_flag = False

    # Parse the MPLS output to see if any line starts with a number
    for line in result_mpls.split('\n'):
        if line and line[0].isdigit():
            mpls_flag = True
            break

    # Check VRF configuration
    command_vrf = "show ip vrf detail | i RT:|^VRF"
    result_vrf = exec_command(command_vrf, device_name)

    # Parse the VRF output to see if it has "VRF" and "RD" in the same line
    for line in result_vrf.split('\n'):
        if "VRF" in line and "RD" in line:
            if "<not set>" not in line:
                vrf_flag = True
            break

    # Update the finding and comments based on the flags
    if mpls_flag:
        check.finding += f"\nMPLS Output:\n{result_mpls}"
        check.comments += "MPLS is configured on this device and needs to be reviewed."
        check.status = "Open"
    else:
        check.finding += f"\nMPLS Output:\n{result_mpls}"
        check.comments += "MPLS is not configured on this device."

    if vrf_flag:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs configured on this device, please review."
        check.status = "Open"
    else:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs are not configured on this device."

    return check

def V221039(device_type, device_name):
    """
    Checks MPLS and VRF configurations on the Cisco switch.
    """
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Not_Applicable"  # Initialize as Not_Applicable, to be updated based on findings

    # Check MPLS configuration
    command_mpls = "show mpls forwarding-table"
    result_mpls = exec_command(command_mpls, device_name)

    # Initialize flags to determine the status of MPLS and VRF
    mpls_flag = False
    vrf_flag = False

    # Parse the MPLS output to see if any line starts with a number
    for line in result_mpls.split('\n'):
        if line and line[0].isdigit():
            mpls_flag = True
            break

    # Check VRF configuration
    command_vrf = "show ip vrf detail | i RT:|^VRF"
    result_vrf = exec_command(command_vrf, device_name)

    # Parse the VRF output to see if it has "VRF" and "RD" in the same line
    for line in result_vrf.split('\n'):
        if "VRF" in line and "RD" in line:
            if "<not set>" not in line:
                vrf_flag = True
            break

    # Update the finding and comments based on the flags
    if mpls_flag:
        check.finding += f"\nMPLS Output:\n{result_mpls}"
        check.comments += "MPLS is configured on this device and needs to be reviewed."
        check.status = "Open"
    else:
        check.finding += f"\nMPLS Output:\n{result_mpls}"
        check.comments += "MPLS is not configured on this device."

    if vrf_flag:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs configured on this device, please review."
        check.status = "Open"
    else:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs are not configured on this device."

    return check

def V221040(device_type, device_name):
    """
    Checks MPLS and VRF configurations on the Cisco switch.
    """
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Not_Applicable"  # Initialize as Not_Applicable, to be updated based on findings

    # Check MPLS configuration
    command_mpls = "show mpls forwarding-table"
    result_mpls = exec_command(command_mpls, device_name)

    # Initialize flags to determine the status of MPLS and VRF
    mpls_flag = False
    vrf_flag = False

    # Parse the MPLS output to see if any line starts with a number
    for line in result_mpls.split('\n'):
        if line and line[0].isdigit():
            mpls_flag = True
            break

    # Check VRF configuration
    command_vrf = "show ip vrf detail | i RT:|^VRF"
    result_vrf = exec_command(command_vrf, device_name)

    # Parse the VRF output to see if it has "VRF" and "RD" in the same line
    for line in result_vrf.split('\n'):
        if "VRF" in line and "RD" in line:
            if "<not set>" not in line:
                vrf_flag = True
            break

    # Update the finding and comments based on the flags
    if mpls_flag:
        check.finding += f"\nMPLS Output:\n{result_mpls}"
        check.comments += "MPLS is configured on this device and needs to be reviewed."
        check.status = "Open"
    else:
        check.finding += f"\nMPLS Output:\n{result_mpls}"
        check.comments += "MPLS is not configured on this device."

    if vrf_flag:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs configured on this device, please review."
        check.status = "Open"
    else:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs are not configured on this device."

    return check

def V221041(device_type, device_name):
    """
    Checks MPLS and VRF configurations on the Cisco switch.
    """
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Not_Applicable"  # Initialize as Not_Applicable, to be updated based on findings

    # Check MPLS configuration
    command_mpls = "show mpls forwarding-table"
    result_mpls = exec_command(command_mpls, device_name)

    # Initialize flags to determine the status of MPLS and VRF
    mpls_flag = False
    vrf_flag = False

    # Parse the MPLS output to see if any line starts with a number
    for line in result_mpls.split('\n'):
        if line and line[0].isdigit():
            mpls_flag = True
            break

    # Check VRF configuration
    command_vrf = "show ip vrf detail | i RT:|^VRF"
    result_vrf = exec_command(command_vrf, device_name)

    # Parse the VRF output to see if it has "VRF" and "RD" in the same line
    for line in result_vrf.split('\n'):
        if "VRF" in line and "RD" in line:
            if "<not set>" not in line:
                vrf_flag = True
            break

    # Update the finding and comments based on the flags
    if mpls_flag:
        check.finding += f"\nMPLS Output:\n{result_mpls}"
        check.comments += "MPLS is configured on this device and needs to be reviewed."
        check.status = "Open"
    else:
        check.finding += f"\nMPLS Output:\n{result_mpls}"
        check.comments += "MPLS is not configured on this device."

    if vrf_flag:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs configured on this device, please review."
        check.status = "Open"
    else:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs are not configured on this device."

    return check

def V221042(device_type, device_name):
    """
    Checks MPLS and VRF configurations on the Cisco switch.
    """
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Not_Applicable"  # Initialize as Not_Applicable, to be updated based on findings

    # Check MPLS configuration
    command_mpls = "show mpls forwarding-table"
    result_mpls = exec_command(command_mpls, device_name)

    # Initialize flags to determine the status of MPLS and VRF
    mpls_flag = False
    vrf_flag = False

    # Parse the MPLS output to see if any line starts with a number
    for line in result_mpls.split('\n'):
        if line and line[0].isdigit():
            mpls_flag = True
            break

    # Check VRF configuration
    command_vrf = "show ip vrf detail | i RT:|^VRF"
    result_vrf = exec_command(command_vrf, device_name)

    # Parse the VRF output to see if it has "VRF" and "RD" in the same line
    for line in result_vrf.split('\n'):
        if "VRF" in line and "RD" in line:
            if "<not set>" not in line:
                vrf_flag = True
            break

    # Update the finding and comments based on the flags
    if mpls_flag:
        check.finding += f"\nMPLS Output:\n{result_mpls}"
        check.comments += "MPLS is configured on this device and needs to be reviewed."
        check.status = "Open"
    else:
        check.finding += f"\nMPLS Output:\n{result_mpls}"
        check.comments += "MPLS is not configured on this device."

    if vrf_flag:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs configured on this device, please review."
        check.status = "Open"
    else:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs are not configured on this device."

    return check

def V221043(device_type, device_name):
    """
    Checks MPLS and VRF configurations on the Cisco switch.
    """
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Not_Applicable"  # Initialize as Not_Applicable, to be updated based on findings

    # Check MPLS configuration
    command_mpls = "show mpls forwarding-table"
    result_mpls = exec_command(command_mpls, device_name)

    # Initialize flags to determine the status of MPLS and VRF
    mpls_flag = False
    vrf_flag = False

    # Parse the MPLS output to see if any line starts with a number
    for line in result_mpls.split('\n'):
        if line and line[0].isdigit():
            mpls_flag = True
            break

    # Check VRF configuration
    command_vrf = "show ip vrf detail | i RT:|^VRF"
    result_vrf = exec_command(command_vrf, device_name)

    # Parse the VRF output to see if it has "VRF" and "RD" in the same line
    for line in result_vrf.split('\n'):
        if "VRF" in line and "RD" in line:
            if "<not set>" not in line:
                vrf_flag = True
            break

    # Update the finding and comments based on the flags
    if mpls_flag:
        check.finding += f"\nMPLS Output:\n{result_mpls}"
        check.comments += "MPLS is configured on this device and needs to be reviewed."
        check.status = "Open"
    else:
        check.finding += f"\nMPLS Output:\n{result_mpls}"
        check.comments += "MPLS is not configured on this device."

    if vrf_flag:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs configured on this device, please review."
        check.status = "Open"
    else:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs are not configured on this device."

    return check

def V221044(device_type, device_name):
    """
    Checks MPLS and VRF configurations on the Cisco switch.
    """
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Not_Applicable"  # Initialize as Not_Applicable, to be updated based on findings

    # Check MPLS configuration
    command_mpls = "show mpls forwarding-table"
    result_mpls = exec_command(command_mpls, device_name)

    # Initialize flags to determine the status of MPLS and VRF
    mpls_flag = False
    vrf_flag = False

    # Parse the MPLS output to see if any line starts with a number
    for line in result_mpls.split('\n'):
        if line and line[0].isdigit():
            mpls_flag = True
            break

    # Check VRF configuration
    command_vrf = "show ip vrf detail | i RT:|^VRF"
    result_vrf = exec_command(command_vrf, device_name)

    # Parse the VRF output to see if it has "VRF" and "RD" in the same line
    for line in result_vrf.split('\n'):
        if "VRF" in line and "RD" in line:
            if "<not set>" not in line:
                vrf_flag = True
            break

    # Update the finding and comments based on the flags
    if mpls_flag:
        check.finding += f"\nMPLS Output:\n{result_mpls}"
        check.comments += "MPLS is configured on this device and needs to be reviewed."
        check.status = "Open"
    else:
        check.finding += f"\nMPLS Output:\n{result_mpls}"
        check.comments += "MPLS is not configured on this device."

    if vrf_flag:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs configured on this device, please review."
        check.status = "Open"
    else:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs are not configured on this device."

    return check


def V221045(device_type, device_name):
    """
    Checks MPLS and VRF configurations on the Cisco switch.
    """
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Not_Applicable"  # Initialize as Not_Applicable, to be updated based on findings

    # Check MPLS configuration
    command_mpls = "show mpls forwarding-table"
    result_mpls = exec_command(command_mpls, device_name)

    # Initialize flags to determine the status of MPLS and VRF
    mpls_flag = False
    vrf_flag = False

    # Parse the MPLS output to see if any line starts with a number
    for line in result_mpls.split('\n'):
        if line and line[0].isdigit():
            mpls_flag = True
            break

    # Check VRF configuration
    command_vrf = "show ip vrf detail | i RT:|^VRF"
    result_vrf = exec_command(command_vrf, device_name)

    # Parse the VRF output to see if it has "VRF" and "RD" in the same line
    for line in result_vrf.split('\n'):
        if "VRF" in line and "RD" in line:
            if "<not set>" not in line:
                vrf_flag = True
            break

    # Update the finding and comments based on the flags
    if mpls_flag:
        check.finding += f"\nMPLS Output:\n{result_mpls}"
        check.comments += "MPLS is configured on this device and needs to be reviewed."
        check.status = "Open"
    else:
        check.finding += f"\nMPLS Output:\n{result_mpls}"
        check.comments += "MPLS is not configured on this device."

    if vrf_flag:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs configured on this device, please review."
        check.status = "Open"
    else:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs are not configured on this device."

    return check

def V221046(device_type, device_name):
    """
    Checks MPLS and VRF configurations on the Cisco switch.
    """
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Not_Applicable"  # Initialize as Not_Applicable, to be updated based on findings

    # Check MPLS configuration
    command_mpls = "show mpls forwarding-table"
    result_mpls = exec_command(command_mpls, device_name)

    # Initialize flags to determine the status of MPLS and VRF
    mpls_flag = False
    vrf_flag = False

    # Parse the MPLS output to see if any line starts with a number
    for line in result_mpls.split('\n'):
        if line and line[0].isdigit():
            mpls_flag = True
            break

    # Check VRF configuration
    command_vrf = "show ip vrf detail | i RT:|^VRF"
    result_vrf = exec_command(command_vrf, device_name)

    # Parse the VRF output to see if it has "VRF" and "RD" in the same line
    for line in result_vrf.split('\n'):
        if "VRF" in line and "RD" in line:
            if "<not set>" not in line:
                vrf_flag = True
            break

    # Update the finding and comments based on the flags
    if mpls_flag:
        check.finding += f"\nMPLS Output:\n{result_mpls}"
        check.comments += "MPLS is configured on this device and needs to be reviewed."
        check.status = "Open"
    else:
        check.finding += f"\nMPLS Output:\n{result_mpls}"
        check.comments += "MPLS is not configured on this device."

    if vrf_flag:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs configured on this device, please review."
        check.status = "Open"
    else:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs are not configured on this device."

    return check

def V221047(device_type, device_name):
    """
   Add a command or command to show its location based off configuration.
    """
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Not_Applicable"
    check.comments = "This is not a PE Switch."
    
    return check

def V221048(device_type, device_name):
    """
   Add a command or command to show its location based off configuration.
    """
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Not_Applicable"
    check.comments = "This is not a PE Switch."
    
    return check

def V221049(device_type, device_name):
    """
   Add a command or command to show its location based off configuration.
    """
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Not_Applicable"
    check.comments = "This is not a PE Switch."
    
    return check

def V221050(device_type, device_name):
    """
   Add a command or command to show its location based off configuration.
    """
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Not_Applicable"
    check.comments = "This is not a PE Switch."
    
    return check

def V221051(device_type, device_name):
    """
   Add a command or command to show its location based off configuration.
    """
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Not_Applicable"
    check.comments = "This is not a PE Switch."
    
    return check



def V221052(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"  # Default status
    command = "show platform hardware fed switch active qos queue stats internal cpu policer"
    result = exec_command(command, device_name)
    
    # Extract lines between the start and end markers
    lines = result.split('\n')
    start_idx = lines.index("QId PlcIdx  Queue Name                Enabled   Rate     Rate      Drop(Bytes)  Drop(Frames)")
    end_idx = lines.index("* NOTE: CPU queue policer rates are configured to the closest hardware supported value")
    relevant_lines = lines[start_idx + 1:end_idx]
    
    # Check if each line that starts with a number has "Yes" in it
    is_cpp_in_place = all('Yes' in line for line in relevant_lines if line.startswith(tuple('0123456789')))
    
    if is_cpp_in_place:
        check.status = "NotAFinding"
        check.comments = "CPP is in place and configured correctly."
    else:
        check.comments = "CPP does not appear to be configured correctly."
    check.finding = result
    return check    


def V221053(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Not_Applicable"

    command = "show ip multicast"
    result = exec_command(command, device_name)

    if not re.search(r"Multicast Routing: disabled.*Multicast Multipath: disabled", result, re.DOTALL):
        check.status = "Open"
        check.comments = "Multicast routing is configured and needs to be reviewed."
    else:
        check.comments = "There is no Multicast routing on this device."

    check.finding = result
    return check

def V221054(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Not_Applicable"

    command = "show ip multicast"
    result = exec_command(command, device_name)

    if not re.search(r"Multicast Routing: disabled.*Multicast Multipath: disabled", result, re.DOTALL):
        check.status = "Open"
        check.comments = "Multicast routing is configured and needs to be reviewed."
    else:
        check.comments = "There is no Multicast routing on this device."

    check.finding = result
    return check

def V221055(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Not_Applicable"

    command = "show ip multicast"
    result = exec_command(command, device_name)

    if not re.search(r"Multicast Routing: disabled.*Multicast Multipath: disabled", result, re.DOTALL):
        check.status = "Open"
        check.comments = "Multicast routing is configured and needs to be reviewed."
    else:
        check.comments = "There is no Multicast routing on this device."

    check.finding = result
    return check

def V221056(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Not_Applicable"

    command = "show ip multicast"
    result = exec_command(command, device_name)

    if not re.search(r"Multicast Routing: disabled.*Multicast Multipath: disabled", result, re.DOTALL):
        check.status = "Open"
        check.comments = "Multicast routing is configured and needs to be reviewed."
    else:
        check.comments = "There is no Multicast routing on this device."

    check.finding = result
    return check

def V221057(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Not_Applicable"

    command = "show ip multicast"
    result = exec_command(command, device_name)

    if not re.search(r"Multicast Routing: disabled.*Multicast Multipath: disabled", result, re.DOTALL):
        check.status = "Open"
        check.comments = "Multicast routing is configured and needs to be reviewed."
    else:
        check.comments = "There is no Multicast routing on this device."

    check.finding = result
    return check

def V221058(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Not_Applicable"

    command = "show ip multicast"
    result = exec_command(command, device_name)

    if not re.search(r"Multicast Routing: disabled.*Multicast Multipath: disabled", result, re.DOTALL):
        check.status = "Open"
        check.comments = "Multicast routing is configured and needs to be reviewed."
    else:
        check.comments = "There is no Multicast routing on this device."

    check.finding = result
    return check

def V221059(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Not_Applicable"

    command = "show ip multicast"
    result = exec_command(command, device_name)

    if not re.search(r"Multicast Routing: disabled.*Multicast Multipath: disabled", result, re.DOTALL):
        check.status = "Open"
        check.comments = "Multicast routing is configured and needs to be reviewed."
    else:
        check.comments = "There is no Multicast routing on this device."

    check.finding = result
    return check

def V221060(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Not_Applicable"

    command = "show ip multicast"
    result = exec_command(command, device_name)

    if not re.search(r"Multicast Routing: disabled.*Multicast Multipath: disabled", result, re.DOTALL):
        check.status = "Open"
        check.comments = "Multicast routing is configured and needs to be reviewed."
    else:
        check.comments = "There is no Multicast routing on this device."

    check.finding = result
    return check

def V221061(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Not_Applicable"

    command = "show ip multicast"
    result = exec_command(command, device_name)

    if not re.search(r"Multicast Routing: disabled.*Multicast Multipath: disabled", result, re.DOTALL):
        check.status = "Open"
        check.comments = "Multicast routing is configured and needs to be reviewed."
    else:
        check.comments = "There is no Multicast routing on this device."

    check.finding = result
    return check

def V221062(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Not_Applicable"

    command = "show ip multicast"
    result = exec_command(command, device_name)

    if not re.search(r"Multicast Routing: disabled.*Multicast Multipath: disabled", result, re.DOTALL):
        check.status = "Open"
        check.comments = "Multicast routing is configured and needs to be reviewed."
    else:
        check.comments = "There is no Multicast routing on this device."

    check.finding = result
    return check

def V221063(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Not_Applicable"

    command = "show ip multicast"
    result = exec_command(command, device_name)

    if not re.search(r"Multicast Routing: disabled.*Multicast Multipath: disabled", result, re.DOTALL):
        check.status = "Open"
        check.comments = "Multicast routing is configured and needs to be reviewed."
    else:
        check.comments = "There is no Multicast routing on this device."

    check.finding = result
    return check

def V221064(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Not_Applicable"

    command = "show ip multicast"
    result = exec_command(command, device_name)

    if not re.search(r"Multicast Routing: disabled.*Multicast Multipath: disabled", result, re.DOTALL):
        check.status = "Open"
        check.comments = "Multicast routing is configured and needs to be reviewed."
    else:
        check.comments = "There is no Multicast routing on this device."

    check.finding = result
    return check

def V221065(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Not_Applicable"

    command = "show ip multicast"
    result = exec_command(command, device_name)

    if not re.search(r"Multicast Routing: disabled.*Multicast Multipath: disabled", result, re.DOTALL):
        check.status = "Open"
        check.comments = "Multicast routing is configured and needs to be reviewed."
    else:
        check.comments = "There is no Multicast routing on this device."

    check.finding = result
    return check

def V221066(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Not_Applicable"

    command = "show ip multicast"
    result = exec_command(command, device_name)

    if not re.search(r"Multicast Routing: disabled.*Multicast Multipath: disabled", result, re.DOTALL):
        check.status = "Open"
        check.comments = "Multicast routing is configured and needs to be reviewed."
    else:
        check.comments = "There is no Multicast routing on this device."

    check.finding = result
    return check

def V221067(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Not_Applicable"

    command = "show ip multicast"
    result = exec_command(command, device_name)

    if not re.search(r"Multicast Routing: disabled.*Multicast Multipath: disabled", result, re.DOTALL):
        check.status = "Open"
        check.comments = "Multicast routing is configured and needs to be reviewed."
    else:
        check.comments = "There is no Multicast routing on this device."

    check.finding = result
    return check

def V221068(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Not_Applicable"

    command = "show ip multicast"
    result = exec_command(command, device_name)

    if not re.search(r"Multicast Routing: disabled.*Multicast Multipath: disabled", result, re.DOTALL):
        check.status = "Open"
        check.comments = "Multicast routing is configured and needs to be reviewed."
    else:
        check.comments = "There is no Multicast routing on this device."

    check.finding = result
    return check

def V221069(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Not_Applicable"

    command = "show ip multicast"
    result = exec_command(command, device_name)

    if not re.search(r"Multicast Routing: disabled.*Multicast Multipath: disabled", result, re.DOTALL):
        check.status = "Open"
        check.comments = "Multicast routing is configured and needs to be reviewed."
    else:
        check.comments = "There is no Multicast routing on this device."

    check.finding = result
    return check



def V237750(device_type, device_name):
    """
    V-237750 - The Cisco switch must have IP CEF enabled for optimized packet switching.
    """
    # Create an object of the Stig class and set default values
    check = Stig()
    check.vulid = format_vulid()
    check.status = "NotAFinding"  # Default to "Not A Finding" until proven otherwise

    # The command to execute
    command = "show ip cef summary"

    # Execute the command and store the result
    result = exec_command(command, device_name)

    # Store the command output in check.finding
    check.finding = result

    # Check if 'CEF is enabled' is NOT in the result
    if "CEF is enabled" not in result:
        check.status = "Open"
        check.comments = f"IP CEF is not running on {device_name}"
    else:
        check.comments = f"IP CEF is running on {device_name}"

    return check



def V237752(device_type, device_name):
    # Create an object of the Stig class and set default values
    check = Stig()
    check.vulid = format_vulid()
    check.status = "NotAFinding"  # Default status

    # The command to execute
    command = "show run | i ^ipv6"
    
    # Execute the command and store the result
    result = exec_command(command, device_name)
    
    # Store the command output in check.finding
    check.finding = result

    # Extract the hop limit value from the result
    match = re.search(r'ipv6 hop-limit (\d+)', result)
    if match:
        hop_limit = int(match.group(1))
        
        # Check if the hop limit is less than 32
        if hop_limit < 32:
            check.status = "Open"
            check.comments = f"IPv6 hop limit less than 32 on {device_name}"
        else:
            check.comments = f"IPv6 hop limit is set to {hop_limit} on {device_name}"
    else:
        check.status = "Open"
        check.comments = f"No 'ipv6 hop-limit' configuration found on {device_name}"
        
    return check


def V237756(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()
    result = exec_command("show ipv6 interface", device_name)
    line_count = len(result.strip().split('\n'))

    check.status = "Not_Applicable" if line_count == 2 else "Open"
    check.comments = "IPv6 is not configured on this device." if line_count == 2 else "Open - There is IPv6 configured on this device, please review configuration."
    check.finding = result

    return check
    
def V237759(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()
    result = exec_command("show ipv6 interface", device_name)
    line_count = len(result.strip().split('\n'))

    check.status = "Not_Applicable" if line_count == 2 else "Open"
    check.comments = "IPv6 is not configured on this device." if line_count == 2 else "Open - There is IPv6 configured on this device, please review configuration."
    check.finding = result

    return check

def V237762(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()
    result = exec_command("show ipv6 interface", device_name)
    line_count = len(result.strip().split('\n'))

    check.status = "Not_Applicable" if line_count == 2 else "Open"
    check.comments = "IPv6 is not configured on this device." if line_count == 2 else "Open - There is IPv6 configured on this device, please review configuration."
    check.finding = result

    return check

def V237764(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()
    result = exec_command("show ipv6 interface", device_name)
    line_count = len(result.strip().split('\n'))

    check.status = "Not_Applicable" if line_count == 2 else "Open"
    check.comments = "IPv6 is not configured on this device." if line_count == 2 else "Open - There is IPv6 configured on this device, please review configuration."
    check.finding = result

    return check


def V237766(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()
    result = exec_command("show ipv6 interface", device_name)
    line_count = len(result.strip().split('\n'))

    check.status = "Not_Applicable" if line_count == 2 else "Open"
    check.comments = "IPv6 is not configured on this device." if line_count == 2 else "Open - There is IPv6 configured on this device, please review configuration."
    check.finding = result

    return check


def V237772(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()
    result = exec_command("show ipv6 interface", device_name)
    line_count = len(result.strip().split('\n'))

    check.status = "Not_Applicable" if line_count == 2 else "Open"
    check.comments = "IPv6 is not configured on this device." if line_count == 2 else "Open - There is IPv6 configured on this device, please review configuration."
    check.finding = result

    return check


def V237774(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()
    result = exec_command("show ipv6 interface", device_name)
    line_count = len(result.strip().split('\n'))

    check.status = "Not_Applicable" if line_count == 2 else "Open"
    check.comments = "IPv6 is not configured on this device." if line_count == 2 else "Open - There is IPv6 configured on this device, please review configuration."
    check.finding = result

    return check


def V237776(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()
    result = exec_command("show ipv6 interface", device_name)
    line_count = len(result.strip().split('\n'))

    check.status = "Not_Applicable" if line_count == 2 else "Open"
    check.comments = "IPv6 is not configured on this device." if line_count == 2 else "Open - There is IPv6 configured on this device, please review configuration."
    check.finding = result

    return check


def V237778(device_type, device_name):
    check = Stig()
    check.vulid = format_vulid()
    result = exec_command("show ipv6 interface", device_name)
    line_count = len(result.strip().split('\n'))

    check.status = "Not_Applicable" if line_count == 2 else "Open"
    check.comments = "IPv6 is not configured on this device." if line_count == 2 else "Open - There is IPv6 configured on this device, please review configuration."
    check.finding = result

    return check    

'''
END IOS XE SWITCH CHECK
'''

"""
***************NXOS CHECK START************
""" 
'''
Cisco NX OS Switch L2S Security Technical Implementation Guide :: Version 2, Release: 2 Benchmark Date: 26 Jul 2023
Function name update only, need to reivew each one.
'''

def V220674(devicetype, devicename):
    # V-101219 - The Cisco switch must be configured to disable non-essential capabilities.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    check.comments = "V-220674 - Open as a non-essential features is enabled"
    command = "show feature | i telnet|dhcp|wccp|nxapi|imp"
    result = exec_command(command, devicename)
    if result.find("enabled", len(devicename) + len(command)) == -1:
        check.status = "NotAFinding"
        check.comments = "V-220674 - NAF as no non-essential features are enabled"
    check.finding = result + "\r"
    return check


def V220675(devicetype, devicename):
    # V-101221 - The Cisco switch must uniquely identify all network-connected endpoint devices before establishing any connection..
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Not_Applicable"
    check.comments = (
        "V-220675 - Not applicable - There are no end-user devices in the datacenter."
    )
    #
    return check


def V220676(devicetype, devicename):
    # V-101223 - The Cisco switch must authenticate all VLAN Trunk Protocol (VTP) messages with a hash function using the most secured cryptographic algorithm available.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "NotAFinding"
    check.comments = "V-220676 - Not running VTP."
    command = "show feature | i vtp"
    temp = ""
    result = exec_command(command, devicename)
    temp = result
    if result.find("enabled", len(devicename) + len(command)) > -1:
        command = "show vtp status"
        result = exec_command(command, devicename)
        temp = temp + "\r" + result
        if result.find("Transparent", len(devicename) + len(command)) > -1:
            check.status = "NotAFinding"
            check.comments = "V-220676 - Running VTP, but in transparent mode."
        else:
            command = "show run | i vtp.pass"
            result = exec_command(command, devicename)
            temp = temp + "\r" + result
            if result.find("password", len(devicename) + len(command)) == -1:
                check.status = "Open"
                check.comments = "V-220676 - Participating in VTP, but without a password configured."
            else:
                check.status = "NotAFinding"
                check.comments = (
                    "V-220676 - Participating in VTP with a password configured."
                )
    check.finding = temp
    return check


def V220677(devicetype, devicename):
    # V-220677 - The Cisco switch must be configured for authorized users to select a user session to capture..
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "NotAFinding"
    command = "show run | sec monitor.session"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-220677 - NAF - Datacenter switches only connect to servers.  In addition, all NXOS switches are capable of this function."
    return check



def V220678(devicetype, devicename):
    # V-220678 - The Cisco switch must be configured for authorized users to remotely view, in real time, all content related to an established user session from a component separate from The Cisco switch.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "NotAFinding"
    command = "show run | sec monitor.session"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-220678 - NAF - Datacenter switches only connect to servers.  In addition, all NXOS switches are capable of this function."
    return check



def V220679(devicetype, devicename):
    # V-220679 - The Cisco switch must authenticate all endpoint devices before establishing any connection.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "NotAFinding"
    command = "show run | i interface.Ether|dot1x|aaa.authentication.dot1x|aaa.group.server.radius|aaa.authentication.dot1x"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-220679 - NAF - Datacenter switches only connect to servers.  In addition, all NXOS switches are capable of this function."
    return check


def V220680(devicetype, devicename):
    # V-220680 - The Cisco switch must have Root Guard enabled on all switch ports connecting to access layer switches and hosts..
    check = Stig()
    MsgBox = crt.Dialog.MessageBox
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "NotAFinding"
    # Find all the root ports.
    command = "show spanning-tree brief | i Root.FWD"
    rootPorts = []
    trunkPorts = []
    result = exec_command(command, devicename)
    temp = result
    for line in result.splitlines():
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
    command = "show int trunk | i trunking | exc not-trunking"
    result = exec_command(command, devicename)
    # Now lets find all trunking ports that aren't root ports
    for line in result.splitlines():
        port = line[0 : line.find(" ")]
        isfound = False
        for portname in rootPorts:
            if portname == port:
                isfound = True
        if isfound == False:
            if line.find("#") == -1 and line.find("show") == -1:
                trunkPorts.append(port)
    temp = temp + "\r" + result
    if len(trunkPorts) == 0:
        check.comments = check.comments + "\r" + "All trunking ports are root ports."
        check.status = "NotAFinding"
    else:
        result = ""
        # Check all non-root trunk ports for root guard
        for port in trunkPorts:
            command = "show run int " + port
            portconfig = exec_command(command, devicename)
            if portconfig.find("VPC_PEER") == -1 and portconfig.find("UPLINK") == -1:
                if portconfig.find("guard root") == -1:
                    check.status = "Open"
                    check.comments = (
                        check.comments
                        + "\r Interface "
                        + port
                        + " is not configured with root guard."
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
            temp = temp + portconfig
    check.finding = temp
    # check.comments = "V-220680 - NAF - Datacenter switches only connect to servers."
    return check


def V220681(devicetype, devicename):
    # V-220681 - The Cisco switch must have BPDU Guard enabled on all user-facing or untrusted access switch ports.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Not_Applicable"
    command = "show run | i interface.Eth|bpduguard"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-220681 - Not Applicable - Datacenter switches only connect to trusted infrastructure devices."
    return check


def V220682(devicetype, devicename):
    # V-220682 -  The Cisco switch must have STP Loop Guard enabled.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    check.comments = (
        "V-220682 - OPEN - The Cisco switch must have STP Loop Guard enabled."
    )
    command = "show run | i loopguard"
    result = exec_command(command, devicename)
    if result.find("loopguard default", len(devicename) + len(command)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-220682 - NAF  The Cisco switch has STP Loop Guard enabled."
    check.finding = result + "\r"
    return check


def V220683(devicetype, devicename):
    # V-220683 - The Cisco switch must have Unknown Unicast Flood Blocking (UUFB) enabled.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Not_Applicable"
    command = "show run | i block"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-220683 - Not Applicable - Datacenter switches only connect to trusted infrastructure devices."
    return check


def V220684(devicetype, devicename):
    # V-220684 - The Cisco switch must have DHCP snooping for all user VLANs to validate DHCP messages from untrusted sources.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Not_Applicable"
    command = "show run | i dhcp.snoop"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-220684 - Not Applicable - Datacenter switches only connect to trusted infrastructure devices."
    return check


def V220685(devicetype, devicename):
    # V-220685 - The Cisco switch must have IP Source Guard enabled on all user-facing or untrusted access switch ports.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Not_Applicable"
    command = "show run | i verify.*.dhcp.snoop"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-220685 - Not Applicable - Datacenter switches only connect to trusted infrastructure devices."
    return check


def V220686(devicetype, devicename):
    # V-220686 - The Cisco switch must have Dynamic Address Resolution Protocol (ARP) Inspection (DAI) enabled on all user VLANs.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Not_Applicable"
    command = "show run | i arp.inspection.vlan"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-220686 - Not Applicable - Datacenter switches only connect to trusted infrastructure devices."
    return check


def V220687(devicetype, devicename):
    # V-220687 - The Cisco switch must have Storm Control configured on all host-facing switchports.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    check.comments = "V-220687 - Open - Need to configure storm-control."
    command = "show run | i storm.control"
    result = exec_command(command, devicename)
    if (
        result.find("storm-control unicast", len(devicename) + len(command)) > -1
        or result.find("storm-control broadcast", len(devicename) + len(command))
        > -1
    ):
        check.status = "NotAFinding"
        check.comments = "V-220687 - NAF  The Cisco switch has Storm Control enabled."
    check.finding = result
    return check


def V220688(devicetype, devicename):
    # V-220688 - The Cisco switch must have IGMP or MLD Snooping configured on all VLANs.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    check.comments = "V-220688 - Open - The Cisco switch must have IGMP or MLD Snooping configured on all VLANs."
    command = "show run all | i igmp.snooping$"
    result = exec_command(command, devicename)
    if (
        result.find("ip igmp snooping", len(devicename) + len(command)) > -1
        and result.find("ip igmp snooping", len(devicename) + len(command)) > -1
    ):
        check.status = "NotAFinding"
        check.comments = "V-220688 - NAF  The Cisco switch has IGMP or MLD snooping is enabled globally."
    check.finding = result
    return check


def V220689(devicetype, devicename):
    # V-220689 -The Cisco switch must enable Unidirectional Link Detection (UDLD) to protect against one-way connections.
    MsgBox = crt.Dialog.MessageBox
    check = Stig()
    Interfaces = []
    temp = ""
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "NotAFinding"
    check.comments = "V-220689 - NAF - The Cisco switch has UDLD feature enabled and running on all fiber attached ports.\r"
    # check.comments = "V-220689 - Open - The Cisco switch must enable Unidirectional Link Detection (UDLD) to protect against one-way connections.\r"
    # Lets make sure the feature UDLD is configured.
    command = "show run | i feature.udld"
    result = exec_command(command, devicename)
    if result.find("udld", len(devicename) + len(command)) == -1:
        check.status = "Open"
        check.comments = "V-220689 - Open - The Cisco switch must have the feature UDLD configured.\r"
    temp = result
    # Lets get all the transceivers installed on the switch
    command = "show int trans | i Ether|type"
    result = exec_command(command, devicename)
    temp = temp + result
    for intnum in range(len(result.splitlines())):
        InterfaceInfo = IntTrans()
        currentline = result.splitlines()[intnum]
        if currentline.find("Ethern") > -1:
            InterfaceInfo.interface = currentline.strip()
            nextline = "Ethernet"
            if intnum + 1 < len(result.splitlines()):
                nextline = result.splitlines()[intnum + 1]
            if nextline.find("Ethernet") == -1:
                InterfaceInfo.transtype = nextline[nextline.rfind(" ") :].strip()
            if str(InterfaceInfo.interface).find("Ethern") > -1:
                Interfaces.append(InterfaceInfo)
                # MsgBox (currentline + " " + nextline[nextline.rfind(" "):])
    # Now we'll check all the interface configs
    for Interface in Interfaces:
        if (
            Interface.transtype.find("none") == -1
            and Interface.transtype.find("#") == -1
        ):
            if (
                Interface.transtype.find("LH") > -1
                or Interface.transtype.find("SR") > -1
            ):
                # check.comments = check.comments + Interface.interface + " " + Interface.transtype + "\r"
                command = "show run int " + Interface.interface + " | i udl"
                result = exec_command(command, devicename)
                temp = temp + result
                if result.find("disabled", len(devicename) + len(command)) > -1:
                    check.status = "Open"
                    check.comments = (
                        check.comments
                        + "V-220689 - OPEN because Interface "
                        + Interface.interface
                        + " has UDPD disabled.\r"
                    )
    check.finding = temp
    return check


def V220690(devicetype, devicename):
    # V-220690 -The Cisco switch must have all disabled switch ports assigned to an unused VLAN.
    MsgBox = crt.Dialog.MessageBox
    check = Stig()
    Interfaces = []
    temp = ""
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "NotAFinding"
    check.comments = "V-220690 - NAF - The Cisco switch has all disabled switch ports assigned to an unused VLAN.\r"

    # Lets get a list of all disabled ports
    # command = "show interface status | i disabled | exc Po"
    command = "show interface status | inc sfpAbsent|disabled|xcvrAbsen"
    result = exec_command(command, devicename)
    # Lets get a port info
    for currentline in result.splitlines():
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
                temp = (
                    temp
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
        check.comments = "V-220690 - OPEN because " + temp + "\r"
    check.finding = result
    return check


def V220691(devicetype, devicename):
    # V-220691 - The Cisco switch must not have the default VLAN assigned to any host-facing switch ports.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    check.comments = "V-220691 - Open - The Cisco switch must not have the default VLAN assigned to any host-facing switch ports."
    command = "show spanning-tree vlan 1"
    result = exec_command(command, devicename)
    if result.find("does not exist", len(devicename) + len(command)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-220691 - NAF  No host-facing ports are assigned to VLAN1"
    check.finding = result
    return check


def V220692(devicetype, devicename):
    # V-220692 - The Cisco switch must have the default VLAN pruned from all trunk ports that do not require it.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    check.comments = "V-220692 - Open - The Cisco switch must have the default VLAN pruned from all trunk ports that do not require it."
    command = "show spanning-tree vlan 1"
    result = exec_command(command, devicename)
    if result.find("does not exist", len(devicename) + len(command)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-220691 - NAF VLAN1 is not in use or trunked"
    check.finding = result
    return check


def V220693(devicetype, devicename):
    # V-220693 - The Cisco switch must not use the default VLAN for management traffic.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    check.comments = "V-220693 - Open - The Cisco switch must not use the default VLAN for management traffic."
    command = "show spanning-tree vlan 1"
    result = exec_command(command, devicename)
    command = "show run int vlan 1"
    result = result + "\r" + exec_command(command, devicename)
    if (
        result.find("does not exist", len(devicename) + len(command)) > -1
        and result.find("ip address", len(devicename) + len(command)) == -1
    ):
        check.status = "NotAFinding"
        check.comments = "V-220693 - NAF VLAN1 is not being used for management."
    check.finding = result
    return check


def V220694(devicetype, devicename):
    # V-220694 - The Cisco switch must have all user-facing or untrusted ports configured as access switch ports.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Not_Applicable"
    command = "sh int status | ex trunk|xcvrAbsen|disabled"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-220694 - Not Applicable - Datacenter switches only connect to trusted infrastructure devices."
    return check


def V220695(devicetype, devicename):
    # V220695 - The native VLAN must be assigned to a VLAN ID other than the default VLAN for all 802.1q trunk links.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "NotAFinding"
    check.comments = "V220695 - NAF - The native VLAN on trunk links is other than the default VLAN for all 802.1q trunk links."

    Interfaces = []
    temp = ""
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    intCount = 0
    bolContinue = True
    # Lets get a list of all trunk ports
    command = "show int trunk"
    result = exec_command(command, devicename)
    # Lets get a port info
    for currentline in result.splitlines():
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
                temp = (
                    temp
                    + " "
                    + Interface.interface
                    + "'s native VLAN appears to be assigned to default vlan "
                    + Interface.vlan
                    + "; "
                )
    if check.status == "Open":
        check.comments = "V-220695 - OPEN because " + temp + "\r"
    check.finding = result
    return check


def V220696(devicetype, devicename):
    # V-220696 - The Cisco switch must not have any switchports assigned to the native VLAN.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    check.comments = "V-220696 - Open - The Cisco switch must not have any switchports assigned to the native VLAN."
    command = "sh int status | in connected.200"
    result = exec_command(command, devicename)
    if result.find("", len(devicename) + len(command)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-220696 - NAF Native VLAN 200 is not in use by access ports."
    check.finding = result
    return check

# Cisco NX-OS Switch NDM Security Technical Implementation Guide :: 
# Version 2, Release: 2 Benchmark Date: 23 Apr 2021

def V220474(devicetype, devicename):
    # V-220474 - The Cisco switch must be configured to limit the number of concurrent management sessions to an organization-defined number.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    check.comments = "V-220474 - OPEN - The switch is not configured to limit the number of concurrent management sessions."
    command = "show run | i session-limit"
    result = exec_command(command, devicename)
    if result.find("session-limit", len(devicename) + len(command)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-220474 - NAF - The switch is configured to limit the number of concurrent management sessions."
    check.finding = result + "\r"
    return check


def V220475(devicetype, devicename):
    # V-220475 - The Cisco switch must be configured to automatically audit account creation.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run | i aaa.accounting"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-220475 - OPEN - Account creation is not automatically audited"
    if result.find("aaa accounting", len(devicename) + len(command)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-220475 - NAF - Account creation is being audited."
    return check


def V220476(devicetype, devicename):
    # V-220476 - The Cisco switch must be configured to automatically audit account modification.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run | i aaa.accounting"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = (
        "V-220476 - OPEN - Account modification is not automatically audited"
    )
    if result.find("aaa accounting", len(devicename) + len(command)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-220476 - NAF - Account modification is being audited."
    return check


def V220477(devicetype, devicename):
    # V-220477 - The Cisco switch must be configured to automatically audit account disabling actions.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run | i aaa.accounting"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = (
        "V-220477 - OPEN - Account disabling actions is not automatically audited"
    )
    if result.find("aaa accounting", len(devicename) + len(command)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-220477 - NAF - Account disabling actions is being audited."
    return check


def V220478(devicetype, devicename):
    # V-220478 - The Cisco switch must be configured to automatically audit account removal actions.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run | i aaa.accounting"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = (
        "V-220478 - OPEN - Account removal actions is not automatically audited"
    )
    if result.find("aaa accounting", len(devicename) + len(command)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-220478 - NAF - Account removal actions is being audited."
    return check


def V220479(devicetype, devicename):
    # V-220479 - The Cisco switch must be configured to enforce approved authorizations for controlling the flow of management information within the device based on control policies.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run | egrep line.vty|access-class"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-220479 - OPEN -  The Cisco switch does not restrict management access to specific IP addresses"
    if result.find("access-class", len(devicename) + len(command)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-220479 - NAF - The Cisco switch restricts management access to specific IP addresses."
    return check


def V220480(devicetype, devicename):
    # V-220480 - The Cisco router must be configured to enforce the limit of three consecutive invalid logon attempts, after which time it must lock out the user account from accessing the device for 15 minutes.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"
    strModel = "unknown"
    strModelVersion = "unknown"

    command = "show inventory | i PID"
    result = exec_command(command, devicename)

    intStart = result.splitlines()[1].find(" ")
    intEnd = result.splitlines()[1].find(" ", intStart + 1)
    strModel = str(result.splitlines()[1][intStart:intEnd]).strip()

    if strModel.find("N9K") > -1:
        check.status = "Not_Applicable"
        check.comments = "NA: Nexus 9K series switches do not have this capability"

    if strModel.find("N5K") > -1:
        command = "sh run | i login.block"
        result = exec_command(command, devicename)
        check.finding = result
        check.comments = "V-220480 - OPEN -  Cisco switch not configured to enforce the limit of three consecutive invalid logon attempts"
        if result.find("block-for", len(devicename) + len(command)) > -1:
            check.status = "NotAFinding"
            check.comments = "V-220480 - NAF - Cisco switch configured to enforce the limit of three consecutive invalid logon attempts"

    if strModel.find("N3K") > -1:
        check.status = "Not_Applicable"
        check.comments = "NA: Nexus 3K series switches do not have this capability"

    check.finding = result
    return check


def V220481(devicetype, devicename):
    # V-220481 - The Cisco router must be configured to display the Standard Mandatory DoD Notice and Consent Banner before granting access to the device.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    command = "show run | egrep banner|User.Agreement"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-10150 - OPEN -  Cisco switch not configured to display the Standard Mandatory DoD Notice and Consent Banner"
    if result.find("User Agreement", len(devicename) + len(command)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-220480 - NAF - Cisco switch configured to display the Standard Mandatory DoD Notice and Consent Banner"
    return check


def V220482(devicetype, devicename):
    # V-220482 - The Cisco switch must be configured to protect against an individual falsely denying having performed organization-defined actions to be covered by non-repudiation.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run | i aaa.accounting"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-220482 - OPEN - Switch is not configured to protect against an individual falsely denying having performed organization-defined actions."
    if result.find("aaa accounting", len(devicename) + len(command)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-220482 - NAF - Switch is configured to protect against an individual falsely denying having performed organization-defined actions."
    return check


def V220484(devicetype, devicename):
    # V-220484 - The Cisco router must produce audit records containing information to establish where the events occurred.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run | i logging.server"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-220484 - OPEN - Cisco switch does not log events."
    if result.find("logging server", len(devicename) + len(command)) > -1:
        check.status = "NotAFinding"
        check.comments = (
            "V-220484 - NAF - Cisco switch logs all events with logging server."
        )
    return check


def V220485(devicetype, devicename):
    # V-220485 - The Cisco switch must be configured to generate audit records containing the full-text recording of privileged commands.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run | i aaa.accounting"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = (
        "V-220485 - OPEN - Cisco switch does not log all configuration changes."
    )
    if result.find("aaa accounting", len(devicename) + len(command)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-220485 - NAF - Cisco switch logs all configuration changes."
    return check


def V220486(devicetype, devicename):
    # V-220486 - The Cisco switch must be configured to disable non-essential capabilities.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    command = "show feature | i telnet|dhcp|wccp|nxapi|imp"
    result = exec_command(command, devicename)
    check.comments = "V-220486 - OPEN - Unnecessary or non-secure ports, protocols, or services are enabled."
    if result.find("enabled", len(devicename) + len(command)) == -1:
        check.status = "NotAFinding"
        check.comments = "V-220486 - NAF - Unnecessary or non-secure ports, protocols, or services are disabled."
    check.finding = result + "\r"
    return check


def V220487(devicetype, devicename):
    # V-220487 - The Cisco router must be configured with only one local account to be used as the account of last resort in the event the authentication server is unavailable.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.comments = ""
    command = "show run | i ^username"
    temp = exec_command(command, devicename)
    #
    # Replace password with ***REMOVED***
    strClean = ""
    result = ""
    for line in temp.splitlines():
        if line.find("password") > 1:
            strClean = (
                line[0 : line.find("password")] + "password <-----***REMOVED***----->"
            )
            bolPassword = 1
        else:
            strClean = line
        result = result + "\n" + strClean
    #
    check.finding = result
    check.status = "NotAFinding"
    strUserAuthLocalAccounts = ["admin", "GLBL-MCLOVIN-NEXUS", "netops_2q22"]
    strConfiguredAccounts = []
    finding = []
    # Create a list of configured accounts
    for line in result.splitlines():
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
        check.comments = "V-220487: More than one local user account found.  Please review finding details."
    else:
        check.comments = (
            check.comments + "Account creation authorized by CS, created by WANSEC"
        )
    return check


def V220488(devicetype, devicename):
    # V-220488 - The Cisco router must be configured to implement replay-resistant authentication mechanisms for network access to privileged accounts.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh ssh server"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-220488 - OPEN - FIPS mode is not enabled"
    if result.find("ssh version 2", len(devicename) + len(command)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-220488 - NAF - FIPS mode is enabled"
    return check


def V220489(devicetype, devicename):
    # V-220489 - The Cisco switch must be configured to enforce password complexity by requiring that at least one upper-case character be used.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run | in no.password"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-220489 - OPEN - Cisco switch is not configured to enforce password complexity."
    if result.find("no password", len(devicename) + len(command)) == -1:
        check.status = "NotAFinding"
        check.comments = (
            "V-220489 - NAF - Cisco switch is configured to enforce password complexity"
        )
    return check


def V220490(devicetype, devicename):
    # V-220490 - The Cisco switch must be configured to enforce password complexity by requiring that at least one lower-case character be used.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run | in no.password"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-220490 - OPEN - Cisco switch is not configured to enforce password complexity."
    if result.find("no password", len(devicename) + len(command)) == -1:
        check.status = "NotAFinding"
        check.comments = (
            "V-220490 - NAF - Cisco switch is configured to enforce password complexity"
        )
    return check


def V220491(devicetype, devicename):
    # V-220491 - The Cisco switch must be configured to enforce password complexity by requiring that at least one numeric character be used.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run | in no.password"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-220491 - OPEN - Cisco switch is not configured to enforce password complexity."
    if result.find("no password", len(devicename) + len(command)) == -1:
        check.status = "NotAFinding"
        check.comments = (
            "V-220491 - NAF - Cisco switch is configured to enforce password complexity"
        )
    return check


def V220492(devicetype, devicename):
    # V-220492 - The Cisco switch must be configured to enforce password complexity by requiring that at least one special character be used.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run | in no.password"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-220492 - OPEN - Cisco switch is not configured to enforce password complexity."
    if result.find("no password", len(devicename) + len(command)) == -1:
        check.status = "NotAFinding"
        check.comments = (
            "V-220492 - NAF - Cisco switch is configured to enforce password complexity"
        )
    return check


def V220493(devicetype, devicename):
    # V-96271 - CAT I -  The Cisco router must be configured to terminate all network connections associated with device management after 10 minutes of inactivity.
    # The network element must timeout management connections for administrative access after 10 minutes or less of inactivity.
    check = Stig()
    check.vulid = format_vulid()
    command = "show run | i timeout prev 1"
    # We're going to start with reverse logic, assume all config lines are good.  We'll look at every on and if it's > 10 min we'll fail this vuln
    check.status = "NotAFinding"
    result = exec_command(command, devicename)
    for line in result.splitlines():
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
        check.comments = "V-220492 - NAF - Timeout less than or equal to 10"
    else:
        check.comments = "V-220493 - OPEN - Timeout greater than 10."
    check.finding = result
    return check


def V220494(devicetype, devicename):
    # V-220494 - The Cisco switch must be configured to automatically audit account enabling actions.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run | i aaa.accounting"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = (
        "V-220494 - OPEN - Cisco switch not configured to log account enabling."
    )
    if result.find("aaa accounting", len(devicename) + len(command)) > -1:
        check.status = "NotAFinding"
        check.comments = (
            "V-220494 - NAF - Cisco switch configured to log account enabling."
        )
    return check


def V220495(devicetype, devicename):
    # V-220495 - The Cisco switch must be configured to audit the execution of privileged functions.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run | i aaa.accounting"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-220495 - OPEN - Cisco switch not configured to audit the execution of privileged functions."
    if result.find("aaa accounting", len(devicename) + len(command)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-220495 - NAF - Cisco switch configured to audit the execution of privileged functions."
    return check


def V220496(devicetype, devicename):
    # V-220496 - The Cisco switch must be configured to generate audit records when successful/unsuccessful attempts to log on with access privileges occur.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run | i logging.server"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-220496 - OPEN - Cisco switch does not log all logon attempts."
    if result.find("logging server", len(devicename) + len(command)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-220496 - NAF - Cisco switch does log all logon attempts with logging server."
    return check


def V220497(devicetype, devicename):
    # V-220497 - The Cisco switch must be configured to generate an alert for all audit failure events.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run | i logging.server"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-220497 - OPEN - Cisco switch does not log all logon attempts."
    if result.find("logging server", len(devicename) + len(command)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-220497 - NAF - Cisco switch does log all logon attempts with logging server."
    return check


def V220498(devicetype, devicename):
    # V-220498 -  The Cisco switch must be configured to synchronize its clock with the primary and secondary time sources using redundant authoritative time sources.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run | i ntp.server"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-220498 - OPEN - Cisco switch is not configured to synchronize its clock with redundant authoritative time sources."
    serverCount = 0
    for line in result.splitlines():
        if line.find(devicename) == -1 and line.find("server") > -1:
            serverCount += 1
    check.comments = "Found " + str(serverCount) + " NTP servers."
    if serverCount >= 2:
        check.status = "NotAFinding"
        check.comments = "V-220498 - NAF - Cisco switch is configured to synchronize its clock with redundant authoritative time sources."
    return check


def V220499(devicetype, devicename):
    # V-220499 - The Cisco router must be configured to record time stamps for log records that can be mapped to Coordinated Universal Time (UTC) or Greenwich Mean Time (GMT).
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run | i timezone"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-220499 - OPEN - Cisco switch not configured to record time stamps for log records."
    if (
        result.find("clock timezone ZULU 0 0", len(devicename) + len(command))
        > -1
    ):
        check.status = "NotAFinding"
        check.comments = "V-220499 - NAF - Cisco switch configured to record time stamps for log records."
    return check


def V220500(devicetype, devicename):
    # V-220500 - The Cisco router must be configured to authenticate SNMP messages using a FIPS-validated Keyed-Hash Message Authentication Code (HMAC).
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = format_vulid()
    check.status = "NotAFinding"
    command = "sh run | i snmp-server.*.network"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-220500 - NAF - Cisco switch is configured to authenticate SNMP messages using a FIPS-validated HMAC"
    for line in result.splitlines():
        if line.find("md5") > -1:
            check.status = "Open"
            check.comments = "V-220500 - OPEN - Cisco switch is not configured to authenticate SNMP messages using a FIPS-validated HMAC"
    return check


def V220501(devicetype, devicename):
    # V-220501 - The Cisco router must be configured to authenticate SNMP messages using a FIPS-validated Keyed-Hash Message Authentication Code (HMAC).
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = format_vulid()
    check.status = "NotAFinding"
    command = "sh run | i snmp-server.*.network"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-220501 - NAF - Cisco switch is configured to authenticate SNMP messages using a FIPS-validated HMAC"
    for line in result.splitlines():
        if line.find("md5") > -1:
            check.status = "Open"
            check.comments = "V-220501 - OPEN - Cisco switch is not configured to authenticate SNMP messages using a FIPS-validated HMAC"
    return check


def V220502(devicetype, devicename):
    # V-220502 -  The Cisco switch must be configured to authenticate Network Time Protocol (NTP) sources using authentication that is cryptographically based.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run | in ntp.authentication"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-220502 - OPEN - Cisco switch is not configured to authenticate NTP sources using authentication that is cryptographically based."
    for line in result.splitlines():
        if line.find("md5") > -1:
            check.status = "NotAFinding"
            check.comments = "V-220502 - NAF - Cisco switch is configured to authenticate NTP sources using authentication that is cryptographically based."
    return check


def V220503(devicetype, devicename):
    # V-220503 - The Cisco switch must be configured to use FIPS-validated Keyed-Hash Message Authentication Code (HMAC) to protect the integrity of remote maintenance sessions.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh ssh server"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-220503 - OPEN - Cisco switch is not configured to use FIPS-validated HMAC to protect the integrity of remote maintenance sessions."
    if result.find("ssh version 2", len(devicename) + len(command)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-220503 - NAF - Cisco switch is configured to use FIPS-validated HMAC to protect the integrity of remote maintenance sessions."
    return check


def V220504(devicetype, devicename):
    # V-220504 - The Cisco switch must be configured to implement cryptographic mechanisms to protect the confidentiality of remote maintenance sessions.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh ssh server"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-220504 - OPEN - Cisco switch is not configured to implement cryptographic mechanisms to protect the confidentiality of remote maintenance sessions."
    if result.find("ssh version 2", len(devicename) + len(command)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-220504 - NAF - Cisco switch is configured to implement cryptographic mechanisms to protect the confidentiality of remote maintenance sessions."
    return check





def V220506(devicetype, devicename):
    # V-220506 - The Cisco switch must be configured to generate log records when administrator privileges are modified.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run | i aaa.accounting"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-220506 - OPEN - Cisco switch not configured to generate log records when administrator privileges are modified."
    if result.find("aaa accounting", len(devicename) + len(command)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-220506 - NAF - Cisco switch configured to generate log records when administrator privileges are modified."
    return check


def V220507(devicetype, devicename):
    # V-220507 - The Cisco switch must be configured to generate log records when administrator privileges are deleted.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run | i aaa.accounting"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-220507 - OPEN - Cisco switch not configured to generate log records when administrator privileges are deleted."
    if result.find("aaa accounting", len(devicename) + len(command)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-220507 - NAF - Cisco switch configured to generate log records when administrator privileges are deleted."
    return check


def V220508(devicetype, devicename):
    # V-220508 - The Cisco switch must be configured to generate audit records when successful/unsuccessful logon attempts occur.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run | i logging.server"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-220508 - OPEN - Cisco switch is not configured to generate audit records when successful/unsuccessful logon attempts occur."
    if result.find("logging server", len(devicename) + len(command)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-220508 - NAF - Cisco switch is configured to generate audit records when successful/unsuccessful logon attempts occur."
    return check


def V220509(devicetype, devicename):
    # V-220509 - The Cisco switch must be configured to generate log records when administrator privileges are deleted.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run | i aaa.accounting"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-220509 - OPEN - Cisco switch not configured to generate log records when administrator privileges are deleted."
    if result.find("aaa accounting", len(devicename) + len(command)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-220509 - NAF - Cisco switch configured to generate log records when administrator privileges are deleted."
    return check


def V220510(devicetype, devicename):
    # V-220510 - The Cisco switch must generate audit records showing starting and ending time for administrator access to the system.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run | i logging.server"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-220510 - OPEN - Cisco switch is not configured to generate log records showing starting and ending time for administrator access."
    if result.find("logging server", len(devicename) + len(command)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-220510 - NAF - Cisco switch is configured to generate log records showing starting and ending time for administrator access."
    return check


def V220512(devicetype, devicename):
    # V-220512 - The Cisco switch must be configured to off-load log records onto a different system than the system being audited.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run | i logging.server"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-220512 - OPEN - Cisco switch is not configured to off-load log records onto a different system than the system being audited."
    if result.find("logging server", len(devicename) + len(command)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-220512 - NAF - Cisco switch is configured to off-load log records onto a different system than the system being audited."
    return check


def V220513(devicetype, devicename):
    # V-220513 - The Cisco switch must be configured to use an authentication server for the purpose of authenticating users prior to granting administrative access.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run | in aaa.authentication"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-220513 - OPEN - Cisco switch not configured to generate log records when administrator privileges are deleted."
    BolPassDefault = ""
    BolPassConsole = ""
    for line in result.splitlines():
        if line.find("default group") > -1:
            BolPassDefault = "pass"
    for line in result.splitlines():
        if line.find("console group") > -1:
            BolPassConsole = "pass"
    if BolPassDefault == "pass" and BolPassConsole == "pass":
        check.status = "NotAFinding"
        check.comments = "V-220513 - NAF - Cisco switch configured to generate log records when administrator privileges are deleted."
    return check


def V220514(devicetype, devicename):
    # V-220514 - The Cisco switch must be configured to support organizational requirements to conduct backups of the configuration when changes occur.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run | in event.manager"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-220514 - OPEN - Cisco switch is not configured to conduct backups of the configuration when changes occur."
    if result.find("applet", len(devicename) + len(command)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-220514 - NAF - Cisco switch is not configured to conduct backups of the configuration when changes occur."
    return check


def V220515(devicetype, devicename):
    # V-220515 - The Cisco switch must be configured to obtain its public key certificates from an appropriate certificate policy through an approved service provider.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = format_vulid()
    check.status = "NotAFinding"
    command = "sh crypto ca trustpoints"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-220515 - RCC-SWA does not use PKI Authentication. PSKs are used instead to secure communication over a service provider."
    return check


def V220516(devicetype, devicename):
    # V-220516 - The Cisco switch must be configured to send log data to a central log server for the purpose of forwarding alerts to the administrators and the ISSO.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run | i logging.server"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-220516 - OPEN - Cisco switch is not configured to send log data to the syslog server."
    if result.find("logging server", len(devicename) + len(command)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-220516 - NAF - Cisco switch is configured to send log data to the syslog server."
    return check


def V220517(devicetype, devicename):
    # V-220517 - The Cisco router must be running an IOS release that is currently supported by Cisco Systems.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"
    strModel = "unknown"
    strModelVersion = "unknown"

    command = "show inventory | i PID"
    result = exec_command(command, devicename)

    intStart = result.splitlines()[1].find(" ")
    intEnd = result.splitlines()[1].find(" ", intStart + 1)
    strModel = str(result.splitlines()[1][intStart:intEnd]).strip()

    command = "show ver | i System:|system:|NXOS:|Chassis|chassis"
    result = exec_command(command, devicename)
    if len(result.splitlines()) > 2:
        if len(result.splitlines()[1]) > 8:
            strModelVersion = result.splitlines()[1][
                result.splitlines()[1].find("version")
                + 8 : len(result.splitlines()[1])
            ]
    if strModel.find("N9K") > -1:
        if remove_char(strModelVersion) >= remove_char("70378"):
            check.status = "NotAFinding"
            check.comments = (
                "NAF: As of 1/16/2020 Nexus 9K series switches should have code level 7.0(3)I7(8).  This device has "
                + strModelVersion
            )
        else:
            check.status = "Open"
            check.comments = (
                "OPEN: As of 1/16/2020 Nexus 9K series switches should have code level 7.0(3)I7(8).  This device has "
                + strModelVersion
            )

    if strModel.find("N5K") > -1:
        if remove_char(strModelVersion) >= remove_char("73711"):
            check.status = "NotAFinding"
            check.comments = (
                "NAF: As of 1/16/2020 Nexus 5K series switches should have code level 7.3(7)N1(1b).  This device has "
                + strModelVersion
            )
        else:
            check.status = "Open"
            check.comments = (
                "OPEN: As of 1/16/2020 Nexus 5K series switches should have code level 7.3(7)N1(1b).  This device has "
                + strModelVersion
            )

    if strModel.find("N3K") > -1:
        if remove_char(strModelVersion) >= remove_char("70378"):
            check.status = "NotAFinding"
            check.comments = (
                "NAF: As of 1/16/2020 Nexus 3K series switches should have code level 7.0(3)I7(8).  This device has "
                + strModelVersion
            )
        else:
            check.status = "Open"
            check.comments = (
                "OPEN: As of 1/16/2020 Nexus 3K series switches should have code level 7.0(3)I7(8).  This device has "
                + strModelVersion
            )

    check.finding = result
    return check
    
"""
***************NXOS CHECK END************
"""     
    

"""
***************IOS XE ROUTER CHECK START************
"""   

# Cisco IOS Router NDM Security Technical Implementation Guide ::
# Version 2, Release: 3 Benchmark Date: 27 Oct 2021

def V215807(devicetype, devicename):
    # Legacy IDs: V-96189; SV-105327
    # V-215807 - CAT II - The Cisco router must be configured to limit the number of concurrent management sessions to an organization-defined number.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run | i http.secure-server"
    temp = exec_command(command, devicename)
    command = "sh run | i \line.vty.*.*|session-limit"
    result = exec_command(command, devicename)
    if result.find("session-limit", len(devicename) + len(command)) > -1:
        check.status = "NotAFinding"
    check.finding = temp + "\r" + result
    check.comments = (
        "V-215807 - CAT II - NAF as long as the VTY lines have session-limit >=2"
    )
    return check


def V215808(devicetype, devicename):
    # Legacy IDs: V-96197; SV-105335
    # V-215808 - CAT II - The Cisco router must be configured to automatically audit account creation.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run | sec log.config"
    result = exec_command(command, devicename)
    check.comments = "V-215808 - CAT II - OPEN - no logging"
    check.finding = result
    if result.find("log config", len(devicename) + len(command)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-215808 - CAT II - NAF - Logging enabled"
    return check


def V215809(devicetype, devicename):
    # Legacy IDs: V-96199; SV-105337
    # V-215809 - CAT II - The Cisco router must be configured to automatically audit account modification.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run | sec log.config"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-215809 - CAT II - OPEN - no logging"
    check.finding = result
    if result.find("log config", len(devicename) + len(command)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-215809 - CAT II - NAF - Logging enabled"
    return check


def V215810(devicetype, devicename):
    # Legacy IDs: V-96201; SV-105339
    # V-215810 - CAT II - The Cisco router must be configured to automatically audit account disabling actions.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run | sec log.config"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-215810 - CAT II - OPEN - no logging"
    check.finding = result
    if result.find("log config", len(devicename) + len(command)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-215810 - CAT II - NAF - Logging enabled"
    return check


def V215811(devicetype, devicename):
    # Legacy IDs: V-96203; SV-105341
    # V-215811 - CAT II - The Cisco router must be configured to automatically audit account removal actions.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run | sec log.config"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-215811 - CAT II - OPEN - no logging"
    check.finding = result
    if result.find("log config", len(devicename) + len(command)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-215811 - CAT II - NAF - Logging enabled"
    return check


def V215812(devicetype, devicename):
    # Legacy IDs: V-96205; SV-105343
    # V-215812 - CAT II - The Cisco router must be configured to enforce approved authorizations for controlling the flow of management information within the device based on control policies.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    check.comments = "V-215812 - OPEN - ACLs were not found."
    ACLName = "Not found"
    intCount = 0
    command = "sh run | i vty..|access-class"
    result = str(exec_command(command, devicename))
    for line in result.splitlines():
        if (
            line.find("access-class") > -1
            and intCount > 0
            and line.find("ip http") == -1
        ):
            intStart = line.find(" ", line.find("access-class") + 1)
            intEnd = line.find(" ", intStart + 1)
            ACLName = line[intStart:intEnd]
            break
        intCount = intCount + 1
    temp = result
    if len(ACLName) > 3:
        command = "sh ip access-lists " + ACLName
        result = exec_command(command, devicename)
        if len(result) > 3:
            check.status = "NotAFinding"
            check.comments = "V-215812 - NAF - ACL in place"
    check.finding = temp + "\r" + result
    return check


def V215813(devicetype, devicename):
    # Legacy IDs: V-96207; SV-105345
    # V-215813 - CAT II - The Cisco router must be configured to enforce the limit of three consecutive invalid logon attempts, after which time it must lock out the user account from accessing the device for 15 minutes.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run | i login.block"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "!V-215813 - CAT II - ****NOTE AS OF 11/1/2019 THIS IS OPEN / FINDING - BE SURE TO FIX THIS!! *** \r !V-215813 - CAT II - FIX ACTION: conf t - login block-for 900 attempts 3 within 120"
    if result.find("block-for", len(devicename) + len(command)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-215813 - CAT II - NAF - Configured to limit the number of failed logon attempts"
    return check


def V215814(devicetype, devicename):
    # Legacy IDs: V-96209; SV-105347
    # V-215814 - CAT II - The Cisco router must be configured to display the Standard Mandatory DoD Notice and Consent Banner before granting access to the device.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    command = "show run | beg banner"
    if devicetype == "NXOS":
        command = "show run | beg banner next 10"
    result = exec_command(command, devicename)
    for line in result.splitlines():
        # Look for key words that are supposed to be in the banner string
        if str(line).find("USG-authorized", 0) > 5:
            check.status = "NotAFinding"
    if check.status == "NotAFinding":
        check.comments = "Not a finding.  Correct banner in place"
    else:
        check.comments = "Open issue - could not find matching configuration."
    check.finding = result
    return check


def V215815(devicetype, devicename):
    # Legacy IDs: V-96217; SV-105355
    # V-215815 - CAT II - The Cisco router must be configured to protect against an individual falsely denying having performed organization-defined actions to be covered by non-repudiation.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run | i userinfo|logging.enable"
    # if devicetype == "NXOS":
    #    command = "sh run | i \"aaa authentic\""
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-215815 - CAT II - OPEN - Logging not configured."
    if result.find("logging enable", len(devicename) + len(command)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-215815 - CAT II - NAF - ACS logs all attempts (successful/unsuccessful) to escalate privilege to any device using TACACS"
    return check


def V215817(devicetype, devicename):
    # Legacy IDs: V-96223; SV-105361
    # V-215817 - CAT II -  The Cisco router must produce audit records containing information to establish when (date and time) the events occurred.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run | i service.timestamp"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-215817 - CAT II - Open - no timestamps configured"
    if result.find("service timestamps log", len(devicename) + len(command)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-215817 - CAT II - NAF - Timestamps configured correctly."
    return check


def V215818(devicetype, devicename):
    # Legacy IDs: V-96225; SV-105363
    # V-215818 - CAT II -  The Cisco router must produce audit records containing information to establish where the events occurred.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh ip access-lists | i .log*"
    # if devicetype == "NXOS":
    #    command = "sh run | i \"aaa authentic\""
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-215818 - CAT II - OPEN - No ACLs with logging"
    if result.find("log", len(devicename) + len(command)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-215818 - CAT II - NAF - ACL lambdaogging configured."
    return check


def V215819(devicetype, devicename):
    # Legacy IDs: V-96227; SV-105365
    # V-215819 - CAT II - The Cisco router must be configured to generate audit records containing the full-text recording of privileged commands.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run | i logging.enable|log.config"
    # if devicetype == "NXOS":
    #    command = "sh run | i \"aaa authentic\""
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-215819 - CAT II - OPEN - No Log config"
    if (
        result.find("log config", len(devicename) + len(command)) > -1
        and result.find("logging enable", len(devicename) + len(command)) > -1
    ):
        check.status = "NotAFinding"
        check.comments = "V-215819 - CAT II - NAF - Logging configured."
    return check


def V215820(devicetype, devicename):
    # Legacy IDs: V-96231; SV-105369
    # V-215820 - CAT II - The Cisco router must be configured to protect audit information from unauthorized modification.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run all | i file.privilege"
    # if devicetype == "NXOS":
    #    command = "sh run | i \"aaa authentic\""
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-215820 - CAT II - Open - non-standard config.  Please note that IOS 15.x does not support the file privilege feature."
    if result.find("file privilege 15", len(devicename) + len(command)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-215820 - CAT II - NAF - file privilege 15 configured."
    return check


def V215821(devicetype, devicename):
    # Legacy IDs: V-96233; SV-105371
    # V-215821 - CAT II - The Cisco router must be configured to protect audit information from unauthorized deletion.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run all | i file.privilege"
    # if devicetype == "NXOS":
    #    command = "sh run | i \"aaa authentic\""
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-215821 - CAT II - Open - non standard config.  Please note that IOS 15.x does not support the file privilege feature."
    if result.find("file privilege 15", len(devicename) + len(command)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-215821 - CAT II - NAF - file privilege 15 configured."
    return check


def V215822(devicetype, devicename):
    # Legacy IDs: V-96237; SV-105375
    # V-215822 - CAT II - The Cisco router must be configured to limit privileges to change the software resident within software libraries.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run all | i file.privilege"
    # if devicetype == "NXOS":
    #    command = "sh run | i \"aaa authentic\""
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-215822 - CAT II - Open.  Please note that IOS 15.x does not support the file privilege feature."
    if result.find("file privilege 15", len(devicename) + len(command)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-215822 - CAT II - NAF - file privilege 15 configured."
    return check


def V215823(devicetype, devicename):
    # Legacy IDs: V-96239; SV-105377
    # V-215823 - CAT I - The Cisco router must be configured to prohibit the use of all unnecessary and nonsecure functions and services.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "NotAFinding"
    command = "sh run | i boot.server|identd|finger|http|dns|tcp-small"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-215823 - CAT I - NAF - no unnecessary services configured"
    if (
        result.find("boot network", len(devicename) + len(command)) > -1
        or result.find("ip boot server", len(devicename) + len(command)) > -1
        or result.find("ip dns server", len(devicename) + len(command)) > -1
        or result.find("rcp-enable", len(devicename) + len(command)) > -1
        or result.find("rsh-enable", len(devicename) + len(command)) > -1
    ):
        check.status = "Open"
        check.comments = "V-215823 - CAT I - Open - unecessary services enabled."
    return check


def V215824(devicetype, devicename):
    # Legacy IDs: V-96243; SV-105381
    # V-215824 - CAT II -  The Cisco router must be configured with only one local account to be used as the account of last resort in the event the authentication server is unavailable.    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = format_vulid()
    check.comments = ""
    command = "sh run | i ^username"
    temp = exec_command(command, devicename)
    #
    # Replace password with ***REMOVED***
    strClean = ""
    result = ""
    for line in temp.splitlines():
        if line.find("secret") > 1:
            strClean = line[0 : line.find("secret")] + " <-----***REMOVED***----->"
            bolPassword = 1
        else:
            strClean = line
        result = result + "\n" + strClean
    #
    check.finding = result
    check.status = "NotAFinding"
    strUserAuthLocalAccounts = [
        "netops",
        "netops_3q20",
        "netops_4q20",
        "netops_1q21",
        "netops_2q21",
        "netops_3q21",
        "netops_4q21",
        "netops_1q22",
    ]
    strConfiguredAccounts = []
    finding = []
    # Create a list of configured accounts
    for line in result.splitlines():
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
        check.comments = "V215824: More than one local user account found.  Please review finding details. "
    else:
        check.comments = (
            check.comments + "Account creation authorized by CS, created by WANSEC"
        )
    return check


def V215826(devicetype, devicename):
    # Legacy IDs: V-96253; SV-105391
    # V-215826 - CAT II -  The Cisco router must be configured to enforce a minimum 15-character password length.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh aaa common-criteria policy all"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-215826 - NOTE:  *** As of 11/1/19 THIS IS A FINDING!!! ***"
    if len(result.splitlines()) > 2:
        check.status = "NotAFinding"
        check.comments = "V-215826 - CAT II - NAF - common criteria policy configured."
    return check


def V215827(devicetype, devicename):
    # Legacy IDs: V-96255; SV-105393
    # V-215827 - CAT II -  The Cisco router must be configured to enforce password complexity by requiring that at least one upper-case character be used.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh aaa common-criteria policy all"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-215827 - NOTE:  *** As of 11/1/19 THIS IS A FINDING!!! ***"
    if len(result.splitlines()) > 2:
        check.status = "NotAFinding"
        check.comments = "V-215827 - NAF - common criteria policy configured."
    return check


def V215828(devicetype, devicename):
    # Legacy IDs: V-96257; SV-105395
    # V-215828 - CAT II -  The Cisco router must be configured to enforce password complexity by requiring that at least one lower-case character be used.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh aaa common-criteria policy all"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-215828 - NOTE:  *** As of 11/1/19 THIS IS A FINDING!!! ***"
    if len(result.splitlines()) > 2:
        check.status = "NotAFinding"
        check.comments = "V-215828 - NAF - common criteria policy configured."
    return check


def V215829(devicetype, devicename):
    # Legacy IDs: V-96259; SV-105397
    # V-215829 - CAT II - The Cisco router must be configured to enforce password complexity by requiring that at least one numeric character be used.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh aaa common-criteria policy all"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-215829 - NOTE:  *** As of 11/1/19 THIS IS A FINDING!!! ***"
    if len(result.splitlines()) > 2:
        check.status = "NotAFinding"
        check.comments = "V-215829 - NAF - common criteria policy configured."
    return check


def V215830(devicetype, devicename):
    # Legacy IDs: V-96261; SV-105399
    # V-215830 - CAT II -  The Cisco router must be configured to enforce password complexity by requiring that at least one special character be used.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh aaa common-criteria policy all"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-215830 - NOTE:  *** As of 11/1/19 THIS IS A FINDING!!! ***"
    if len(result.splitlines()) > 2:
        check.status = "NotAFinding"
        check.comments = "V-215830 - NAF - common criteria policy configured."
    return check


def V215831(devicetype, devicename):
    # Legacy IDs: V-96263; SV-105401
    # V-215831 - CAT II -  The Cisco router must be configured to require that when a password is changed, the characters are changed in at least eight of the positions within the password.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh aaa common-criteria policy all"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-215831 - NOTE:  *** As of 11/1/19 THIS IS A FINDING!!! ***"
    if len(result.splitlines()) > 2:
        check.status = "NotAFinding"
        check.comments = "V-215831 - NAF - common criteria policy configured."
    return check


def V215832(devicetype, devicename):
    # Legacy IDs: V-96265; SV-105403
    # V-215832 - CAT I -  The Cisco router must only store cryptographic representations of passwords.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run | i service.password"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-215832 - CAT 1 - password encryption must be configured"
    if result.find("service password-", len(devicename) + len(command)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-215832 - NAF - Password encryption configured."
    return check


def V215833(devicetype, devicename):
    # Legacy IDs: V-96271; SV-105409
    # V-215833 - CAT I -  The Cisco router must be configured to terminate all network connections associated with device management after 10 minutes of inactivity.
    # The network element must timeout management connections for administrative access after 10 minutes or less of inactivity.
    check = Stig()
    check.vulid = format_vulid()
    command = "sh run all | i vty.0.4|exec-t"
    if devicetype == "NXOS":
        command = "show run | i timeout prev 1"
    # We're going to start with reverse logic, assume all config lines are good.  We'll look at every on and if it's > 10 min we'll fail this vuln
    check.status = "NotAFinding"
    result = exec_command(command, devicename)
    for line in result.splitlines():
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
    check.finding = result
    return check


def V215834(devicetype, devicename):
    # Legacy IDs: V-96285; SV-105423
    # V-215834 - CAT II -  The Cisco router must be configured to automatically audit account enabling actions.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run | i archive|log.config|logging.enable"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-215834 - Archive logging is required"
    if (
        result.find("archive", len(devicename) + len(command)) > -1
        and result.find("log config", len(devicename) + len(command)) > -1
        and result.find("logging enable", len(devicename) + len(command)) > -1
    ):
        check.status = "NotAFinding"
        check.comments = "V-215834 - CAT II - NAF - Archive logging configured"
    return check


def V215836(devicetype, devicename):
    # Legacy IDs: V-96297; SV-105435
    # V-215836 - CAT II - The Cisco router must be configured to allocate audit record storage capacity in accordance with organization-defined audit record storage requirements.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run | i logging.buffered"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = (
        "V-215836 - OPEN - suggest adding logging buffered 1000000 informational"
    )
    if result.find("logging buffered", len(devicename) + len(command)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-215836 - CAT II - NAF - ACS manages Authentication."
    return check


def V215837(devicetype, devicename):
    # Legacy IDs: V-96301; SV-105439
    # V-215837 - CAT II - The Cisco router must be configured to generate an alert for all audit failure events.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"
    command = "show logging | i Trap|Logging.to"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = (
        "V215837 - NOTE **** AS OF 11/1/19 THIS IS A FINDING!! PLEASE REMEDIATE"
    )
    if result.find("Logging to ", len(devicename) + len(command)) > -1 and (
        result.find("debugging", len(devicename) + len(command)) > -1
        or result.find("critical", len(devicename) + len(command)) > -1
        or result.find("warnings", len(devicename) + len(command)) > -1
        or result.find("notifications", len(devicename) + len(command)) > -1
        or result.find("informational", len(devicename) + len(command)) > -1
    ):
        check.status = "NotAFinding"
        check.comments = "V-215837 - CAT II - NAF - ACS manages Authentication."
    return check


def V215838(devicetype, devicename):
    # Legacy IDs: V-96303; SV-105441
    # V-215838 - CAT II -  The Cisco router must be configured to synchronize its clock with the primary and secondary time sources using redundant authoritative time sources.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run | i ntp.server"
    if devicetype == "NXOS":
        command = "sh run | i ntp.server"
    result = exec_command(command, devicename)
    check.finding = result
    serverCount = 0
    for line in result.splitlines():
        if line.find(devicename) == -1 and line.find("server") > -1:
            serverCount += 1
    check.comments = "Found " + str(serverCount) + " NTP servers."
    if serverCount >= 2:
        check.status = "NotAFinding"
    return check


def V215841(devicetype, devicename):
    # Legacy IDs: V-96317; SV-105455
    # V-215841 - CAT II - The Cisco router must be configured to authenticate SNMP messages using a FIPS-validated Keyed-Hash Message Authentication Code (HMAC).
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Not_Reviewed"
    command = "sh run | i snmp-server|snmp.user "
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-215841 authenticate SNMP messages using a FIPS-validated Keyed-Hash Message Authentication Code (HMAC)."
    command = "sh run | i snmp-server.group"
    result = exec_command(command, devicename)
    check.finding = result
    for line in result.splitlines():
        if line.find("v3") == -1 or line.find(devicename) == -1:
            check.status = "NotAFinding"
            check.comments = "NAF SNMP version 3 is in use"
    return check


def V215842(devicetype, devicename):
    # Legacy IDs: V-96319; SV-105457
    # V-215842 - CAT II - The Cisco router must be configured to encrypt SNMP messages using a FIPS 140-2 approved algorithm.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run | i v3|version.3"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-215842 - NAF - paste output"
    if result.find("v3", len(devicename) + len(command)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-215842 - SNMP v3 is in use."
    return check


def V215843(devicetype, devicename):
    # Legacy IDs: V-96321; SV-105459
    # V-215843 - CAT II -  The Cisco router must be configured to authenticate Network Time Protocol (NTP) sources using authentication that is cryptographically based.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run | in ntp authentication"
    if devicetype == "NXOS":
        command = 'sh run | in "ntp authentication"'
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = (
        "V-215843 - COMMENTS: MD5 no higher encryption - Downgrades it to a CATIII"
    )

    if result.find("md5", len(devicename + "#" + command)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-215843 - MD5 NTP authentication enabled."
    return check


def V215844(devicetype, devicename):
    # Legacy IDs: V-96327; SV-105465
    # V-V-215844 - CAT I - The Cisco router must be configured to use FIPS-validated Keyed-Hash Message Authentication Code (HMAC) to protect the integrity of remote maintenance sessions.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run all | i ssh.version|server.a"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-215844 - The Cisco router must be configured to use FIPS-validated Keyed-Hash Message Authentication Code (HMAC) to protect the integrity of remote maintenance sessions.\r Add the command ip ssh server algorithm mac hmac-sha1-96"
    if (
        result.find("ip ssh version 2", len(devicename) + len(command)) > -1
        and (
            result.find("hmac-sha1-96", len(devicename) + len(command)) > -1
            or result.find("hmac-sha2-256", len(devicename) + len(command))
        )
        > -1
    ):
        check.status = "NotAFinding"
        check.comments = (
            "V-215844 - CAT II - NAF - FIPS-validated Keyed-Hash is being used."
        )
    return check


def V215845(devicetype, devicename):
    # Legacy IDs: V-96329; SV-105467
    # V-215845 -  CAT I - The Cisco router must be configured to implement cryptographic mechanisms to protect the confidentiality of remote maintenance sessions.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run all | i ssh.version|server.a"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-215845 -  The Cisco router must be configured to implement cryptographic mechanisms to protect the confidentiality of remote maintenance sessions."
    if (
        result.find("ip ssh version 2", len(devicename) + len(command)) > -1
        and result.find("encryption aes", len(devicename) + len(command)) > -1
    ):
        check.status = "NotAFinding"
        check.comments = "V-215845 - CAT II - NAF - Specified cryptographic mechanisms are being used."
    return check


def V215848(devicetype, devicename):
    # Legacy IDs: V-96335; SV-105473
    # V-215848 - The Cisco router must be configured to generate log records when administrator privileges are deleted.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run | i logging.user|archive|log.config|logging.enable"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-215848 - The Cisco router must be configured to generate log records when administrator privileges are deleted."
    if (
        result.find("archive", len(devicename) + len(command)) > -1
        and result.find("logging enable", len(devicename) + len(command)) > -1
    ):
        check.status = "NotAFinding"
        check.comments = "V-215848 - CAT II - NAF - archive logging is enabled"
    return check


def V215849(devicetype, devicename):
    # Legacy IDs: V-96337; SV-105475
    # V-215849 - CAT II -  The Cisco router must be configured to generate audit records when successful/unsuccessful logon attempts occur.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run | i login.on"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = (
        "V-215849 - NOTE:  AS OF 11/1/19 THIS IS A FINDING - PLEASE REMEDIATE"
    )
    if (
        result.find("on-failure", len(devicename) + len(command)) > -1
        and result.find("on-success", len(devicename) + len(command)) > -1
    ):
        check.status = "NotAFinding"
        check.comments = "V-215849 - CAT II - NAF -  Audit records generated when successful/unsuccessful logon attempts occur"
    return check


def V215850(devicetype, devicename):
    # Legacy IDs: V-96339; SV-105477
    # V-215850 - CAT II -  The Cisco router must be configured to generate audit records when successful/unsuccessful logon attempts occur.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run | i logging.user|archive|log.config|logging.enable"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-215850 - The Cisco router must be configured to generate log records for privileged activities"
    if (
        result.find("archive", len(devicename) + len(command)) > -1
        and result.find("logging enable", len(devicename) + len(command)) > -1
    ):
        check.status = "NotAFinding"
        check.comments = "V-215850 - CAT II - NAF - archive logging is enabled"
    return check


def V215854(devicetype, devicename):
    # Legacy IDs: V-96351; SV-105489
    # V-215854 - CAT I - The Cisco router must be configured to use an authentication server for the purpose of authenticating users prior to granting administrative access.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run | i aaa.group|server-private"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-215854 - NAF - paste output"
    if (
        result.find("aaa group", len(devicename) + len(command)) > -1
        and result.find("server-private", len(devicename) + len(command)) > -1
    ):
        check.status = "NotAFinding"
        check.comments = (
            "V-215854 - CAT II - NAF - Authentication server(s) is configured."
        )
    return check


def V215855(devicetype, devicename):
    # Legacy IDs: V-96359; SV-105497
    # V-215855 - CAT II -  The Cisco router must employ automated mechanisms to detect the addition of unauthorized components or devices.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh event manager policy registered"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = (
        "V-215855 - NOTE:  AS OF 11/1/19 THIS IS A FINDING!!!! PLEASE REMEDIATE"
    )
    if result.find("applet", len(devicename) + len(command)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-215855 - CAT II - NAF - Applet configured and registered."
    return check


def V215856(devicetype, devicename):
    # Legacy IDs: V-96363; SV-105501
    # V-215856 - CAT II -  The Cisco router must be configured to obtain its public key certificates from an appropriate certificate policy through an approved service provider.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = format_vulid()
    check.status = "NotAFinding"
    command = "show run | i crypto.pki|enroll"
    result = exec_command(command, devicename)
    command = "show crypto pki certificates"
    result = result + exec_command(command, devicename)
    check.finding = result
    check.comments = "V-215856 - COMMENT:  RCC-SWA does not use PKI Authentication"
    return check


def V220139(devicetype, devicename):
    # Legacy IDs: V-96365; SV-105503
    # V-220139 - CAT I - The Cisco router must be configured to send log data to a syslog server for the purpose of forwarding alerts to the administrators and the ISSO.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run | i logging.host|logging.trap.no"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = (
        "V-220139 - NOTE: AS OF 11/1/19 THIS IS A FINDING!!! PLEASE REMEDIATE"
    )
    if result.find("logging host", len(devicename) + len(command)) > -1:
        check.status = "NotAFinding"
        check.comments = (
            "V-220139 - CAT I - NAF - Remote system logging server(s) in place.."
        )
    return check


def V220140(devicetype, devicename):
    # Legacy IDs: V-96369; SV-105507
    # V-220140 - CAT I - The Cisco router must be running an IOS release that is currently supported by Cisco Systems.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"
    Model = "unknown"
    ModelVersion = "unknown"

    command = "show inventory | i PID"
    result = exec_command(command, devicename)

    intStart = result.splitlines()[1].find(" ")
    intEnd = result.splitlines()[1].find(" ", intStart + 1)
    Model = str(result.splitlines()[1][intStart:intEnd]).strip()

    temp = result
    if Model.find("ASR") > -1 or Model.find("ISR4") > -1:
        command = "show ver | i IOS"
        result = exec_command(command, devicename)
        intStart = result.splitlines()[1].find(
            " ", result.splitlines()[1].find("Version") + 1
        )
        intEnd = result.splitlines()[1].find("\r", intStart)
        ModelVersion = result.splitlines()[1][intStart:]
        #crt.Dialog.MessageBox("ModelVersion is: " + str(remove_char(ModelVersion)))
        if remove_char(ModelVersion) >= remove_char("16.12.04"):
            check.status = "NotAFinding"
            check.comments = (
                "NAF: As of 9/25/2020 ASR/ISR devices should have code level 16.12.04.  This device has "
                + ModelVersion
            )
        else:
            check.status = "Open"
            check.comments = (
                "OPEN: As of 9/25/2020 ASR/ISR devices should have code level 16.12.04.  This device has "
                + ModelVersion
            )

    if Model.find("CISCO39") > -1:
        command = "show ver | i IOS"
        result = exec_command(command, devicename)
        intStart = result.splitlines()[1].find(
            " ", result.splitlines()[1].find("Version") + 1
        )
        intEnd = result.splitlines()[1].find(",", intStart)
        ModelVersion = result.splitlines()[1][intStart:intEnd]
        if remove_char(ModelVersion) >= remove_char("15.7(3)M5"):
            check.status = "NotAFinding"
            check.comments = (
                "NAF: As of 1/16/2020 ISRG2 devices should have code level 15.7(3)M5.  This device has "
                + ModelVersion
            )
        else:
            check.status = "Open"
            check.comments = (
                "OPEN: As of 1/16/2020 ISRG2 devices should have code level 15.7(3)M5.  This device has "
                + ModelVersion
            )

    if Model.find("C650") > -1:
        command = "show ver | i IOS"
        result = exec_command(command, devicename)
        intStart = result.splitlines()[1].find(
            " ", result.splitlines()[1].find("Version") + 1
        )
        intEnd = result.splitlines()[1].find(",", intStart)
        ModelVersion = result.splitlines()[1][intStart:intEnd]
        if remove_char(ModelVersion) >= remove_char("15.1(2)SY14"):
            check.status = "NotAFinding"
            check.comments = (
                "NAF: As of 10/17/2019 Cisco recomends 6500 series devices should have code level 15.1(2)SY14.  This device has "
                + ModelVersion
            )
        else:
            check.status = "Open"
            check.comments = (
                "OPEN: As of 10/17/2019 Cisco recomends 6500 series devices should have code level 15.1(2)SY14.  This device has "
                + ModelVersion
            )
    temp = temp + result
    if devicetype == "NXOS":
        command = "show ver | i System:|system:|NXOS:|Chassis|chassis"
        result = exec_command(command, devicename)
        if len(result.splitlines()) > 2:
            if len(result.splitlines()[1]) > 8:
                ModelVersion = result.splitlines()[1][
                    result.splitlines()[1].find("version")
                    + 8 : len(result.splitlines()[1])
                ]
        if Model.find("N9K") > -1:
            if remove_char(ModelVersion) >= remove_char("70376"):
                check.status = "NotAFinding"
                check.comments = (
                    "NAF: As of 1/16/2020 Nexus 9K series switches should have code level 7.0(3)I7(6).  This device has "
                    + ModelVersion
                )
            else:
                check.status = "Open"
                check.comments = (
                    "OPEN: As of 1/16/2020 Nexus 9K series switches should have code level 7.0(3)I7(6).  This device has "
                    + ModelVersion
                )

        if Model.find("N5K") > -1:
            if remove_char(ModelVersion) >= remove_char("73511"):
                check.status = "NotAFinding"
                check.comments = (
                    "NAF: As of 1/16/2020 Nexus 5K series switches should have code level 7.3(5)N1(1).  This device has "
                    + ModelVersion
                )
            else:
                check.status = "Open"
                check.comments = (
                    "OPEN: As of 1/16/2020 Nexus 5K series switches should have code level 7.0(3)I7(6).  This device has "
                    + ModelVersion
                )

        if Model.find("N3K") > -1:
            if remove_char(ModelVersion) >= remove_char("70376"):
                check.status = "NotAFinding"
                check.comments = (
                    "NAF: As of 1/16/2020 Nexus 3K series switches should have code level 7.0(3)I7(6).  This device has "
                    + ModelVersion
                )
            else:
                check.status = "Open"
                check.comments = (
                    "OPEN: As of 1/16/2020 Nexus 3K series switches should have code level 7.0(3)I7(6).  This device has "
                    + ModelVersion
                )
    else:
        if ModelVersion == "unknown":
            command = "show ver | beg Ports.Model"
            result = exec_command(command, devicename)
            if len(result.splitlines()) > 2:
                ModelVersion = result.splitlines()[3][32:46]
            if Model.find("3850") > -1 or Model.find("3650") > -1:
                if remove_char(ModelVersion) >= remove_char("16.12.04"):
                    check.status = "NotAFinding"
                    check.comments = (
                        "NAF: As of 1/16/2020 Cat 3850 and 3650 series switches should have code level 16.12.04.  This device has "
                        + ModelVersion
                    )
                else:
                    check.status = "Open"
                    check.comments = (
                        "OPEN: As of 1/16/2020 Cat 3850 and 3650 series switches should have code level 16.12.04.  This device has "
                        + ModelVersion
                    )
            if (
                Model.find("3750") > -1
                or Model.find("3560") > -1
                or Model.find("2960") > -1
            ):
                if remove_char(ModelVersion) >= remove_char("15.02(4)E09"):
                    check.status = "NotAFinding"
                    check.comments = (
                        "NAF: As of 1/16/2020 Cat 3750, 3560, and 2960 series switches should have code level 15.02(4)E9.  This device has "
                        + ModelVersion
                    )
                else:
                    check.status = "Open"
                    check.comments = (
                        "OPEN: As of 1/16/2020 Cat 3750, 3560, and 2960 series switches should have code level 15.02(4)E9.  This device has "
                        + ModelVersion
                    )
    
        # if Model.find("ASR"):
        #    ModelVersion = result.splitlines()[1][result.splitlines()[1].find("version")+8:len(result.splitlines()[1])]
    result = temp + "\r" + result
    check.finding = result
    return check

#
# Cisco IOS XE Router RTR Security Technical Implementation Guide :: 
# Version 2, Release: 4 Benchmark Date: 27 Apr 2022
#

def V216641(devicetype, devicename):
    # V-216641 - CAT II - The Cisco router must be configured to enforce approved authorizations for controlling the flow of information within the network based on organization-defined information flow control policies..
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    command = "show run | i snmp.*.location"
    result = exec_command(command, devicename)
    # Check if we're a perimeter router.  If not no ACLs are required
    if result.find("RT1") == -1:
        check.status = "NotAFinding"
        check.comments = "V-216641 - CAT II - NAF as traffic flows within theatre's area of control and seperate appliances control user traffic."
    else:
        command = "sh run | i interface|description|access-group"
        temp = exec_command(command, devicename)
        strACL = temp.splitlines(0)
        temp = ""
        for count in range(3, len(strACL)):
            if (
                strACL[count].find("access-group EGRESS") > -1
                or strACL[count].find("access-group INGRESS") > -1
            ):
                temp = (
                    temp
                    + strACL[count - 2]
                    + "\n"
                    + strACL[count - 1]
                    + "\n"
                    + strACL[count]
                    + "\n"
                )
        command = (
            "sh run | sec ip.access-list.exten.*.INGRESS|ip.access-list.exten.*.EGRESS"
        )
        result = exec_command(command, devicename)
        if temp.find("EGRESS") > -1 and result.find("INGRESS") > -1:
            check.status = "NotAFinding"
        check.finding = temp + "\r" + result
        check.comments = "V-216641 - CAT II - NAF as organization-defined information flow control policies are met for intra-theatre traffic."
    return check


def V216644(devicetype, devicename):
    # V-216644 - CAT II - The Cisco router must be configured to use encryption for routing protocol authentication..
    check = Stig()
    MsgBox = crt.Dialog.MessageBox
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "NotAFinding"
    strEIGRP_AS = "0"
    strOSPF_PID = "0"
    strISIS_PID = "0"
    strBGP_AS = "0"
    check.comments = ""
    # Lets find out which routing protocols are in use
    command = "show ip proto | i Routing.Protoc"
    result = exec_command(command, devicename)
    # Identify which routing protocols are in use and save applicable AS or PID
    for line in result.splitlines():
        line = line.replace('"', "")
        if line.find("eigrp") > -1:
            strEIGRP_AS = line.split()[-1]
        if line.find("ospf") > -1:
            strOSPF_PID = line.split()[-1]
        if line.find("bgp") > -1:
            strBGP_AS = line.split()[-1]
    # Time to verify all EIGRP neighbors are using authentication
    strEIGRP_Interfaces = []
    strEIGRP_Findings = ""
    strEIGRP_status = "NotAFinding"
    strEIGRP_VRF = ""
    # crt.Dialog.MessageBox("EIGRP AS is: " + strEIGRP_AS)
    if strEIGRP_AS == "eigrp":
        # Identify the VRF for the EIGRP Named Mode address-family
        command = "sh run | in autonomous-system"
        result = exec_command(command, devicename)
        for line in result.splitlines():
            # crt.Dialog.MessageBox("VRF is: " + line.split()[0])
            if line.find("vrf") > -1 and line.find("#") == -1:
                # crt.Dialog.MessageBox("VRF is: " + line.split()[4])
                strEIGRP_VRF = line.split()[4]
                command = (
                    "show ip eigrp vrf " + strEIGRP_VRF + " interfaces | begin Peers"
                )
                result = exec_command(command, devicename)
                strEIGRP_Findings = result
                # crt.Dialog.MessageBox("Line Count is: " + str(result.splitlines()))
                # crt.Dialog.MessageBox("Line 3 is: " + str(result.splitlines()[2]))
                if len(result.splitlines()) >= 4 and result.splitlines()[2] != "":
                    for line in result.splitlines():
                        # Output of the command shows all active EIGRP Peer interfaces if any exist.  We're going to extract the interfaces for verification.
                        if (
                            line.find("Peers") == -1
                            and line.find("#") == -1
                            and line.find("Xmit") == -1
                            and line.find("EIGRP") == -1
                        ):
                            strEIGRP_Interfaces.append(line.split()[0])
                    for interface in strEIGRP_Interfaces:
                        command = (
                            "show ip eigrp vrf "
                            + strEIGRP_VRF
                            + " interfaces detail "
                            + interface
                            + " | i Authentication"
                        )
                        result = exec_command(command, devicename)
                        strEIGRP_Findings = strEIGRP_Findings + result + "\n"
                        # Output of the command shows all active EIGRP interfaces and authentication used.
                        if result.find("md5") == -1 and result.find("sha") == -1:
                            strEIGRP_status = "Open"
                            check.comments = (
                                check.comments
                                + "EIGRP Missing authentication on "
                                + interface
                                + " in VRF "
                                + strEIGRP_VRF
                                + ".\n"
                            )
                        else:
                            check.comments = (
                                check.comments
                                + "EIGRP Authentication found for "
                                + interface
                                + " in VRF "
                                + strEIGRP_VRF
                                + ".\n"
                            )
                else:
                    check.comments = (
                        check.comments
                        + "There are no EIGRP Peers in VRF "
                        + strEIGRP_VRF
                        + ".\n"
                    )
    else:
        if int(strEIGRP_AS) > 0:
            command = "show ip eigrp interfaces | begin Peers"
            result = exec_command(command, devicename)
            strEIGRP_Findings = result
            for line in result.splitlines():
                # Output of the command shows all active EIGRP interfaces.  We're going to extract the interfaces for verification.
                if (
                    line.find("Peers") == -1
                    and line.find("#") == -1
                    and line.find("Xmit") == -1
                    and line.find("EIGRP") == -1
                ):
                    strEIGRP_Interfaces.append(line.split()[0])
            for interface in strEIGRP_Interfaces:
                command = "show run int " + interface + " | i authen.*.eigrp"
                result = exec_command(command, devicename)
                strEIGRP_Findings = strEIGRP_Findings + result + "\n"
                if result.find("md5") == -1 and result.find("sha") == -1:
                    # If MD5 or SHA is not configured on the interface we might be running named mode.  Have to check that now.
                    command = "show run | sec af-interface.*." + interface[2:]
                    result = exec_command(command, devicename)
                    strEIGRP_Findings = strEIGRP_Findings + result + "\n"
                    if result.find("sha") == -1:
                        strEIGRP_status = "Open"
                        check.comments = (
                            check.comments
                            + "EIGRP Missing authentication on "
                            + interface
                            + ".\n"
                        )
                    else:
                        check.comments = (
                            check.comments
                            + "EIGRP authentication found for "
                            + interface
                            + ".\n"
                        )

    # Time to verify all OSPF neighbors are using authentication authentication
    strOSPF_Interfaces = []
    strOSPF_Findings = ""
    strOSPF_status = "NotAFinding"
    if int(strOSPF_PID) > 0:
        command = "show ip ospf interface | i line.protocol.is.up"
        result = exec_command(command, devicename)
        for line in result.splitlines():
            # Output of the command shows all active EIGRP interfaces.  We're going to extract the interfaces for verification.
            if line.find("Loopback") == -1 and line.find("#") == -1:
                strOSPF_Interfaces.append(line.split()[0])
        for interface in strOSPF_Interfaces:
            command = "show ip ospf interface " + interface + " | i authen"
            result = exec_command(command, devicename)
            strOSPF_Findings = strOSPF_Findings + result + "\n"
            if result.find("authentication enabled") == -1:
                # If MD5 or SHA is not configured on the interface this is a finding.
                strOSPF_status = "Open"
                check.comments = (
                    check.comments
                    + "OSPF Missing authentication on "
                    + interface
                    + ".\n"
                )
            else:
                check.comments = (
                    check.comments
                    + "OSPF authentication configured on interface "
                    + interface
                    + ".\n"
                )

    # Time to verify all ISIS neighbors are using authentication authentication
    strISIS_Interfaces = []
    strISIS_Findings = ""
    strISIS_status = "NotAFinding"
    if int(strISIS_PID) > 0:
        command = "show clns neighbors"
        result = exec_command(command, devicename)
        for line in result.splitlines():
            # Output of the command shows all active ISIS Neighbors.  We're going to extract the interfaces for verification.
            if (
                line.find("System") == -1
                and line.find("#") == -1
                and line.find("Tag") == -1
                and line.find("") == -1
            ):
                strISIS_Interfaces.append(line.split()[2])
        for interface in strISIS_Interfaces:
            command = "show run int " + interface + " | i authen"
            result = exec_command(command, devicename)
            strISIS_Findings = strISIS_Findings + result + "\n"
            if result.find("md5") == -1:
                # If MD5 or SHA is not configured on the interface this is a finding.
                strOSPF_status = "Open"
                check.comments = (
                    check.comments
                    + "ISIS Missing authentication on "
                    + interface
                    + ".\n"
                )
            else:
                check.comments = (
                    check.comments
                    + "ISIS authentication configured on interface "
                    + interface
                    + ".\n"
                )

    # Time to verify all BGP neighbors are using authentication authentication
    strBGP_Neighbors = []
    strBGP_sessions = []
    strBGP_Findings = ""
    strBGP_status = "NotAFinding"
    if int(strBGP_AS) > 0:
        # Look at all the peer session templates and save the ones that contain a password
        command = "show run | i template peer-ses"
        result = exec_command(command, devicename)
        strBGP_Findings = strBGP_Findings + result + "\n"
        for session in result.splitlines():
            if session.find("peer-session") > -1:
                command = "show run | sec " + session
                #
                # Replace password with ***REMOVED***
                strClean = ""
                result = ""
                temp = exec_command(command, devicename)
                for line in temp.splitlines():
                    if line.find("password") > 1:
                        strClean = (
                            line[0 : line.find("password")]
                            + "password <-----***REMOVED***----->"
                        )
                        bolPassword = 1
                    else:
                        strClean = line
                    result = result + "\n" + strClean
                #
                strBGP_Findings = strBGP_Findings + result + "\n"
                if result.find("password") > -1:
                    strBGP_sessions.append(session.split()[-1])
        # Get all the bgp Neighbors
        command = "show run | i neigh.*.remote|neigh.*.peer-sess"
        result = exec_command(command, devicename)
        strBGP_Findings = strBGP_Findings + result + "\n"
        strBGP_neighbor_status = "Open"
        for neighbor in result.splitlines():
            strBGP_neighbor_status = "Open"
            if neighbor.find("#") == -1:
                if neighbor.find("remote-as") > -1:
                    # If a host is not covered by a peer session, make sure there is a password configured for neighbor.
                    command = (
                        "show run | i neighbor.*." + neighbor.split()[1] + ".*.password"
                    )
                    # Replace password with ***REMOVED***
                    strClean = ""
                    result = ""
                    temp = exec_command(command, devicename)
                    for line in temp.splitlines():
                        if line.find("password 7") > 1:
                            strClean = (
                                line[0 : line.find("password")]
                                + "password <-----***REMOVED***----->"
                            )
                            bolPassword = 1
                        else:
                            strClean = line
                        result = result + "\n" + strClean
                    strBGP_Findings = strBGP_Findings + result + "\n"
                    # If there's a password defined then we can cler this neighbor
                    if result.find("password") > -1:
                        strBGP_neighbor_status = "NotAFinding"
                        check.comments = (
                            check.comments
                            + "BGP neighbor "
                            + neighbor.split()[1]
                            + " is configured to use a password.\n"
                        )

                if neighbor.find("inherit peer-session") > -1:
                    # If a neighbor has a peer session, check if the session has a password configured.
                    # Loop through the peer sessions that have passwords
                    for peersession in strBGP_sessions:
                        if neighbor.split()[-1].find(peersession) > -1:
                            strBGP_neighbor_status = "NotAFinding"
                            check.comments = (
                                check.comments
                                + "BGP neighbor "
                                + neighbor.split()[1]
                                + " uses a password via peer-session "
                                + peersession
                                + "\n"
                            )
                if strBGP_neighbor_status == "Open":
                    strBGP_status = "Open"
                    check.comments = (
                        check.comments
                        + "Could not match a password for neighbor "
                        + neighbor.split()[-1]
                        + ".\n"
                    )

        if (
            strBGP_status != "NotAFinding"
            or strOSPF_status != "NotAFinding"
            or strISIS_status != "NotAFinding"
            or strEIGRP_status != "NotAFinding"
        ):
            check.status = "Open"
        check.finding = (
            strEIGRP_Findings + strOSPF_Findings + strISIS_Findings + strBGP_Findings
        )
        # check.comments = "V-216644 - CAT II - The Cisco router must be configured to use encryption for routing protocol authentication."
    return check


def V216645(devicetype, devicename):
    # V-216645 - The Cisco router must be configured to authenticate all routing protocol messages using NIST-validated FIPS 198-1 message authentication code algorithm.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "NotAFinding"
    strEIGRP_AS = "0"
    strOSPF_PID = "0"
    strBGP_AS = "0"
    check.comments = ""
    # Lets find out which routing protocols are in use
    command = "show ip proto | i Routing.Protoc"
    result = exec_command(command, devicename)
    check.finding = result
    # Identify which routing protocols are in use and save applicable AS or PID
    for line in result.splitlines():
        line = line.replace('"', "")
        if line.find("eigrp") > -1:
            strEIGRP_AS = line.split()[-1]
        if line.find("ospf") > -1:
            strOSPF_PID = line.split()[-1]
        if line.find("bgp") > -1:
            strBGP_AS = line.split()[-1]

    strOSPF_Interfaces = []
    strOSPF_Keychains = []
    strOSPF_Findings = ""
    strOSPF_status = "NotAFinding"
    if int(strOSPF_PID) > 0:
        command = "show ip ospf interface | i line.protocol.is.up"
        result = exec_command(command, devicename)
        strOSPF_Findings = result
        for line in result.splitlines():
            # Output of the command shows all active OSPF interfaces.  We're going to extract the interfaces for verification.
            if line.find("Loopback") == -1 and line.find("#") == -1:
                strOSPF_Interfaces.append(line.split()[0])
        for interface in strOSPF_Interfaces:
            command = "show run interface " + interface + " | i ospf"
            result = exec_command(command, devicename)
            strOSPF_Findings = strOSPF_Findings + result + "\n"
            if result.find("key-chain") == -1:
                strOSPF_status = "Open"
                if result.find("md5") > -1:
                    check.comments = (
                        check.comments
                        + "OSPF is using the weak MD5 auth hash on "
                        + interface
                        + ".\n"
                    )
                else:
                    check.comments = (
                        check.comments
                        + "Could not find any authentication on "
                        + interface
                        + ".\n"
                    )
            else:
                check.comments = (
                    check.comments + "OSPF key chain configured on " + interface + ".\n"
                )
                # need to add code here in the future to add the specified key chain that is in use.
                # Right now we assume that if we have a key chain then OSPF is configured correctly.

    strEIGRP_Interfaces = []
    strEIGRP_Findings = ""
    strEIGRP_status = "NotAFinding"
    strEIGRP_VRF = ""
    # crt.Dialog.MessageBox("EIGRP AS is: " + strEIGRP_AS)
    if strEIGRP_AS == "eigrp":
        # Identify the VRF for the EIGRP Named Mode address-family
        command = "sh run | in autonomous-system"
        result = exec_command(command, devicename)
        for line in result.splitlines():
            # crt.Dialog.MessageBox("VRF is: " + line.split()[0])
            if line.find("vrf") > -1 and line.find("#") == -1:
                # crt.Dialog.MessageBox("VRF is: " + line.split()[4])
                strEIGRP_VRF = line.split()[4]
                command = (
                    "show ip eigrp vrf " + strEIGRP_VRF + " interfaces | begin Peers"
                )
                result = exec_command(command, devicename)
                strEIGRP_Findings = result
                if len(result.splitlines()) >= 4 and result.splitlines()[2] != "":
                    for line in result.splitlines():
                        # Output of the command shows all active EIGRP interfaces.  We're going to extract the interfaces for verification.
                        if (
                            line.find("Peers") == -1
                            and line.find("#") == -1
                            and line.find("Xmit") == -1
                            and line.find("EIGRP") == -1
                        ):
                            strEIGRP_Interfaces.append(line.split()[0])
                    for interface in strEIGRP_Interfaces:
                        command = (
                            "show ip eigrp vrf "
                            + strEIGRP_VRF
                            + " interfaces detail "
                            + interface
                            + " | i Authentication"
                        )
                        result = exec_command(command, devicename)
                        strEIGRP_Findings = strEIGRP_Findings + result + "\n"
                        # Output of the command shows all active EIGRP interfaces and authentication used.
                        if result.find("sha") == -1:
                            strEIGRP_status = "Open"
                            check.comments = (
                                check.comments
                                + "EIGRP does not appear to be using FIPS 198-1 compliant authentication within VRF "
                                + strEIGRP_VRF
                                + ".\n"
                            )
                        else:
                            check.comments = (
                                check.comments
                                + "EIGRP appears to be using hmac-sha-256 for authentication within VRF "
                                + strEIGRP_VRF
                                + ".\n"
                            )
                else:
                    check.comments = (
                        check.comments
                        + "There are no EIGRP Peers in VRF "
                        + strEIGRP_VRF
                        + ".\n"
                    )
    else:
        if int(strEIGRP_AS) > 0:
            command = "show run | i authentication mode hmac"
            result = exec_command(command, devicename)
            strEIGRP_Findings = result
            if result.find("sha", len(devicename) + len(command)) == -1:
                check.comments = (
                    check.comments
                    + "EIGRP does not appear to be using FIPS 198-1 compliant authentication.\n"
                )
                strEIGRP_status = "Open"
            else:
                check.comments = (
                    check.comments
                    + "EIGRP appears to be using hmac-sha-256 for authentication."
                )
    if strOSPF_status != "NotAFinding" or strEIGRP_status != "NotAFinding":
        check.status = "Open"
    check.finding = check.finding + strOSPF_Findings + strEIGRP_Findings
    return check


def V216646(devicetype, devicename):
    # V-216646 - Cisco router must be configured to have all inactive interfaces disabled
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "NotAFinding"
    command = "sh int desc | exc admin.down|up|deleted"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-216646 - NAF - All inactive interfaces are disabled"
    if result.find("down", len(devicename) + len(command)) > -1:
        check.status = "Open"
        check.comments = "V-216646 - OPEN - An interface is not being used but is configured or enabled"
    return check


#def V216647(devicetype, devicename):
    # V-216647 - Cisco router must be configured to have all non-essential capabilities disabled
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    MsgBox = crt.Dialog.MessageBox
    check.vulid = format_vulid()
    check.status = "NotAFinding"
    check.comments = (
        "The router does not have unnecessary or non-secure services enabled."
    )
    command = "sh run all | in boot.network|boot.server|bootp.server|ip.identd|ip.finger|http.server|rcmd.rsh-enable|service.config|service.finger|service.tcp-small-servers|service.udp-small-servers|service.pad"
    result = exec_command(command, devicename)
    # Find services that are not disabled
    for line in result.splitlines():
        if line.find("#") == -1:
            if line.find("no") == -1:
                check.status = "Open"
                check.comments = (
                    "The router has unnecessary or non-secure services enabled."
                )
    check.finding = result
    return check


def V216649(devicetype, devicename):
    # V-216649 - The Cisco router must not be configured to have any zero-touch deployment feature enabled when connected to an operational network.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    MsgBox = crt.Dialog.MessageBox
    check.vulid = format_vulid()
    check.status = "Open"
    check.comments = "The router does not have zero-touch deployment feature disabled."
    command = "sh run | i cns|CNS"
    result = exec_command(command, devicename)
    # Find services that are not disabled
    if result.find("cns", len(devicename) + len(command)) == -1:
        check.status = "NotAFinding"
        check.comments = "The router has the zero-touch deployment feature disabled."
    check.finding = result
    return check


def V216650(devicetype, devicename):
    # V-216650 - The router must have control plane protection enabled.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    check.comments = "V-216650 - The router must have control plane protection enabled."
    command = "sh policy-map control-plane | i Class-map"
    result = exec_command(command, devicename)
    check.finding = result
    if result.find("CoPP") > -1:
        check.comments = "Control plane policing configured."
        check.status = "NotAFinding"
    return check


def V216651(devicetype, devicename):
    # V-216651 - The Cisco router must be configured to restrict traffic destined to itself..
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    check.comments = "V-216651 - The Cisco router must be configured to restrict traffic destined to itself.."
    command = "sh policy-map control-plane | i Class-map"
    result = exec_command(command, devicename)
    check.finding = result
    if result.find("CoPP") > -1:
        check.comments = "Control plane policing is configured and restricts traffic destined to itself."
        check.status = "NotAFinding"
    return check


def V216652(devicetype, devicename):
    # V-216652 -  The Cisco router must be configured to drop all fragmented Internet Control Message Protocol (ICMP) packets destined to itself.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    check.comments = "V-216652 -  The Cisco router must be configured to drop all fragmented Internet Control Message Protocol (ICMP) packets destined to itself."
    command = "show ip access-lists | i icmp.any.*.fragments|Exten"
    result = exec_command(command, devicename)
    check.finding = result
    if result.find("fragments", len(devicename) + len(command)) > -1:
        check.comments = "ACLs in place to drop fragmented icmp traffic."
        check.status = "NotAFinding"
    return check


def V216653(devicetype, devicename):
    # V-216653 -  The Cisco router must be configured to have Gratuitous ARP disabled on all external interfaces.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    check.comments = "V-216653 -  The Cisco router must be configured to have Gratuitous ARP disabled on all external interfaces."
    command = "sh run all | i gratuitous"
    result = exec_command(command, devicename)
    check.finding = result
    if result.find("no ip gratuitous-arps") > -1:
        check.comments = "The router is configured to have Gratuitous ARP disabled on all external interfaces.."
        check.status = "NotAFinding"
    return check


def V216654(devicetype, devicename):
    # V-216654 -  The Cisco router must be configured to have IP directed broadcast disabled on all interfaces.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    check.comments = "V-216654 -  The Cisco router must be configured to have IP directed broadcast disabled on all interfaces."
    command = "sh run all | i directed-broadcast"
    result = exec_command(command, devicename)
    check.finding = result
    if len(result.splitlines()) <= 2:
        check.comments = "The router appears to have directed broadcast disabled."
        check.status = "NotAFinding"
    return check


def V216655(devicetype, devicename):
    # V-216655 -  The Cisco router must be configured to have Internet Control Message Protocol (ICMP) unreachable messages disabled on all external interfaces.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    check.comments = "V-216655 -  The Cisco router must be configured to have Internet Control Message Protocol (ICMP) unreachable messages disabled on all external interfaces."
    command = "sh run | i snmp.*.location"
    result = exec_command(command, devicename)
    check.finding = result
    if result.find("RT1") > -1:
        check.comments = "This router is a external facing router.\n"
        command = "show run | i ip.unreachables"
        result = exec_command(command, devicename)
        check.finding = check.finding + result
        if (
            result.find("no ip unreach", len(devicename) + len(command)) == -1
            or result.find(
                "icmp rate-limit unreachable", len(devicename) + len(command)
            )
            == -1
        ):
            check.status = "NotAFinding"
            check.comments = check.comments + "IP unreachables is configured."
        else:
            check.comments = (
                check.comments
                + "Because this is a external facing router unreachables must be configured."
            )
    else:
        check.status = "NotAFinding"
        check.comments = (
            check.comments + "  Because this is an internal router "
            "ip unreachables"
            " configuration not required."
        )
    return check


def V216656(devicetype, devicename):
    # V-216656 -  The Cisco router must be configured to have Internet Control Message Protocol (ICMP) unreachable messages disabled on all external interfaces.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    check.comments = "V-216656 -  The Cisco router must be configured to have Internet Control Message Protocol (ICMP) unreachable messages disabled on all external interfaces."
    command = "sh run | i snmp.*.location"
    result = exec_command(command, devicename)
    check.finding = result
    if result.find("RT1") > -1 or result.find("RT1") > -1:
        check.comments = "This router is a external facing router.\n"
        command = "sh run all | i mask-reply"
        result = exec_command(command, devicename)
        check.finding = check.finding + result
        if result.find("ip mask-reply", len(devicename) + len(command)) == -1:
            check.status = "NotAFinding"
            check.comments = (
                check.comments + "V-216656: NAF - mask-reply command is NOT configured."
            )
        else:
            check.comments = (
                check.comments
                + "V-216656: OPEN - Because this is a external facing router mask-reply must not be configured."
            )
    else:
        check.status = "NotAFinding"
        check.comments = (
            check.comments + "  Because this is an internal router "
            "mask-reply"
            " configuration is not applicable."
        )
    return check


def V216657(devicetype, devicename):
    # V-216657 -  The Cisco router must be configured to have Internet Control Message Protocol (ICMP) redirect messages disabled on all external interfaces.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    check.comments = "V-216657 -  The Cisco router must be configured to have Internet Control Message Protocol (ICMP) redirect messages disabled on all external interfaces."
    command = "sh run | i snmp.*.location"
    result = exec_command(command, devicename)
    check.finding = result
    if result.find("RT1") > -1 or result.find("RT1") > -1:
        check.comments = "This router is a external facing router.\n"
        command = "sh run | i redirects|interface"
        result = exec_command(command, devicename)
        check.finding = check.finding + result
        if result.find("no ip redirects", len(devicename) + len(command)) > -1:
            check.status = "NotAFinding"
            check.comments = (
                check.comments
                + "V-216656: NAF - no ip redirects command is configured."
            )
        else:
            check.comments = (
                check.comments
                + "V-216656: OPEN - Because this is a external facing router no ip redirects must be configured."
            )
    else:
        check.status = "NotAFinding"
        check.comments = (
            check.comments + "  Because this is an internal router "
            "no ip redirects"
            " configuration is not required."
        )
    return check


def V216658(devicetype, devicename):
    # V-216658 - The network device must log all access control lists (ACL) deny statements.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = format_vulid()
    check.comments = "V-2166580 - The network device must log all access control lists (ACL) deny statements."
    check.status = "Open"
    command = "sh access-lists | i log"
    result = exec_command(command, devicename)
    check.finding = result
    if result.find(" log", len(devicename) + len(command)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-216658 - NAF - Propper logging has been configured."
    return check


def V216659(devicetype, devicename):
    # V-216659 - The Cisco router must be configured to produce audit records containing information to establish where the events occurred.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = format_vulid()
    check.comments = "V-216659 - The Cisco router must be configured to produce audit records containing information to establish where the events occurred."
    check.status = "Open"
    command = "show run | i access-list|deny.*.log-input"
    result = exec_command(command, devicename)
    check.finding = result
    if result.find("log-input", len(devicename) + len(command)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-216659 - NAF - logging-input has been configured."
    return check


def V216660(devicetype, devicename):
    # V-216660 - The Cisco router must be configured to produce audit records containing information to establish the source of the events.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = format_vulid()
    check.comments = "V-216660 - The Cisco router must be configured to produce audit records containing information to establish the source of the events."
    check.status = "Open"
    command = "show run | i access-list|deny.*.log-input"
    result = exec_command(command, devicename)
    check.finding = result
    if result.find("log-input", len(devicename) + len(command)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-216660 - NAF - logging-input has been configured."
    return check


def V216661(devicetype, devicename):
    # V-216661 - The Cisco router must be configured to disable the auxiliary port unless it is connected to a secured modem providing encryption and authentication.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = format_vulid()
    check.comments = "V-216661 - The Cisco router must be configured to disable the auxiliary port unless it is connected to a secured modem providing encryption and authentication."
    check.status = "Open"
    command = "sh run | i no exec|aux"
    result = exec_command(command, devicename)
    check.finding = result
    if result.find("no exec", len(devicename) + len(command)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-216661 - NAF - Aux exec mode has been disabled."
    return check


def V216662(devicetype, devicename):
    # V-216662 -  The Cisco perimeter router must be configured to deny network traffic by default and allow network traffic by exception.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    check.comments = "V-216662 -  The Cisco perimeter router must be configured to deny network traffic by default and allow network traffic by exception."
    command = "sh run | i snmp.*.location"
    result = exec_command(command, devicename)
    check.finding = result
    if result.find("RT1") > -1:
        check.comments = "This router is a external facing router.\n"
        command = "sh run | i ip.access-group|interface.T|interface.G|interface.B"
        result = exec_command(command, devicename)
        check.finding = check.finding + result
        if (
            result.find("INGRESS", len(devicename) + len(command)) > -1
            and result.find("EGRESS", len(devicename) + len(command)) > -1
        ):
            check.status = "NotAFinding"
            check.comments = (
                check.comments
                + "V-216662: NAF - Both INGRESS and EGRESS ACLs are in place."
            )
        else:
            check.comments = (
                check.comments
                + "V-216662: OPEN - Because this is a external facing router ingress and egress acls are required.."
            )
    else:
        check.status = "NotAFinding"
        check.comments = (
            check.comments
            + "  This is not a perimeter router, so transit traffic is allowed."
        )
    return check


def V216663(devicetype, devicename):
    # V-216663 -  The Cisco perimeter router must be configured to deny network traffic by default and allow network traffic by exception.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    check.comments = "V-216663 -  The Cisco perimeter router must be configured to deny network traffic by default and allow network traffic by exception."
    command = "sh run | i snmp.*.location"
    result = exec_command(command, devicename)
    check.finding = result
    if result.find("RT1") > -1:
        check.comments = "This router is a external facing router.\n"
        command = "sh run | i ip.access-group|interface.T|interface.G|interface.B"
        result = exec_command(command, devicename)
        check.finding = check.finding + result
        if (
            result.find("INGRESS", len(devicename) + len(command)) > -1
            and result.find("EGRESS", len(devicename) + len(command)) > -1
        ):
            check.status = "NotAFinding"
            check.comments = (
                check.comments
                + "V-216663: NAF - Both INGRESS and EGRESS ACLs are in place and control the flow of information."
            )
        else:
            check.comments = (
                check.comments
                + "V-216663: OPEN - Because this is a external facing router ingress and egress acls are required.."
            )
    else:
        check.status = "NotAFinding"
        check.comments = (
            check.comments
            + "  This is not a perimeter router, so transit traffic is allowed."
        )
    return check


def V216664(devicetype, devicename):
    # V-216664 -  The Cisco perimeter router must be configured to only allow incoming communications from authorized sources to be routed to authorized destinations.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    check.comments = "V-216664 -  The Cisco perimeter router must be configured to deny network traffic by default and allow network traffic by exception."
    command = "sh run | i snmp.*.location"
    result = exec_command(command, devicename)
    check.finding = result
    if result.find("RT1") > -1:
        check.comments = "This router is a external facing router.\n"
        command = "sh run | i ip.access-group|interface.T|interface.G|interface.B"
        result = exec_command(command, devicename)
        check.finding = check.finding + result
        if (
            result.find("INGRESS", len(devicename) + len(command)) > -1
            and result.find("EGRESS", len(devicename) + len(command)) > -1
        ):
            check.status = "NotAFinding"
            check.comments = (
                check.comments
                + "V-216664: NAF - Both INGRESS and EGRESS ACLs are in place and control the flow of information."
            )
        else:
            check.comments = (
                check.comments
                + "V-216664: OPEN - Because this is a external facing router ingress and egress acls are required.."
            )
    else:
        check.status = "NotAFinding"
        check.comments = (
            check.comments
            + "  This is not a perimeter router, so transit traffic is allowed."
        )
    return check


def V216665(devicetype, devicename):
    # V-216665 -  The Cisco perimeter router must be configured to only allow incoming communications from authorized sources to be routed to authorized destinations.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    check.comments = "V-216665 -  The Cisco perimeter router must be configured to deny network traffic by default and allow network traffic by exception."
    command = "sh run | i snmp.*.location"
    result = exec_command(command, devicename)
    check.finding = result
    if result.find("RT1") > -1:
        check.comments = "This router is a external facing router.\n"
        command = "show ip access-lists INGRESS | i 192.168.|10.0.0|100.64|127.0.0|169.254|172.16.0|192.0|198.18|198.51|203.0|224.0"
        result = exec_command(command, devicename)
        check.finding = check.finding + result
        if result.find("10.0.0", len(devicename) + len(command)) > -1:
            check.status = "NotAFinding"
            check.comments = (
                check.comments
                + "V-216664: NAF - Both INGRESS ACL is blocking Bogon IPs."
            )
        else:
            check.comments = (
                check.comments
                + "V-216664: OPEN - Ingress ACL is missing or lacking filter ranges."
            )
    else:
        check.status = "NotAFinding"
        check.comments = (
            check.comments
            + "  This is not a perimeter router, so transit traffic is allowed."
        )
    return check


def V216666(devicetype, devicename):
    # V-216666 -  The Cisco perimeter router must be configured to protect an enclave connected to an alternate gateway by using an inbound filter that only permits packets with destination addresses within the sites address space.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    check.comments = "V-216666 -  The Cisco perimeter router must be configured to deny network traffic by default and allow network traffic by exception."
    command = "sh run | i snmp.*.location"
    result = exec_command(command, devicename)
    check.finding = result
    if result.find("RT1") > -1:
        check.comments = "This router is a external facing router.\n"
        command = "sh run | i ip.access-group|interface.T|interface.G|interface.B"
        result = exec_command(command, devicename)
        check.finding = check.finding + result
        if result.find("INGRESS", len(devicename) + len(command)) > -1:
            check.status = "NotAFinding"
            check.comments = (
                check.comments
                + "V-216666: NAF - INGRESS ACL only allowed traffic to internal hosts."
            )
        else:
            check.comments = (
                check.comments
                + "V-216666: OPEN - Ingress ACL is missing or lacking configurations."
            )
    else:
        check.status = "NotAFinding"
        check.comments = (
            check.comments
            + "  This is not a perimeter router, so transit traffic is allowed."
        )
    return check


def V216667(devicetype, devicename):
    # V-216667 -  The Cisco perimeter router must be configured to not be a Border Gateway Protocol (BGP) peer to an alternate gateway service provider.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    check.comments = "V-216667 -  The Cisco perimeter router must be configured to not be a Border Gateway Protocol (BGP) peer to an alternate gateway service provider.."
    command = "sh run | i snmp.*.location"
    result = exec_command(command, devicename)
    check.finding = result
    if result.find("RT1") > -1:
        check.comments = "This router is a external facing router.\n"
        command = "sh run | sec bgp"
        result = exec_command(command, devicename)
        check.status = "NotAFinding"
        check.comments = (
            check.comments
            + "V-216666: NAF - RCC-SWA perimeter routers only peer with DISA."
        )
    else:
        check.status = "Not_Applicable"
        check.comments = (
            check.comments
            + "  This is not a perimeter router, and this check is not applicable.."
        )
    return check


def V216668(devicetype, devicename):
    # V-216668 -  The Cisco perimeter router must be configured to not redistribute static routes to an alternate gateway service provider into BGP or an Interior Gateway Protocol (IGP) peering with the NIPRNet or to other autonomous systems.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    check.comments = "V-216668 -  The Cisco perimeter router must be configured to not redistribute static routes to an alternate gateway service provider into BGP or an Interior Gateway Protocol (IGP) peering with the NIPRNet or to other autonomous systems."
    command = "sh run | i snmp.*.location"
    result = exec_command(command, devicename)
    check.finding = result
    if result.find("RT1") > -1:
        check.comments = "This router is a external facing router.\n"
        command = "sh run | sec bgp"
        result = exec_command(command, devicename)
        check.status = "NotAFinding"
        check.comments = (
            check.comments
            + "V-216668: NAF - RCC-SWA perimeter routers only peer with DISA."
        )
    else:
        check.status = "Not_Applicable"
        check.comments = (
            check.comments
            + "  This is not a perimeter router, and this check is not applicable.."
        )
    return check


def V216670(devicetype, devicename):
    # V-216670 -  The Cisco perimeter router must be configured to filter traffic destined to the enclave in accordance with the guidelines contained in DoD Instruction 8551.1
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    check.comments = "V-216670 -  The Cisco perimeter router must be configured to not redistribute static routes to an alternate gateway service provider into BGP or an Interior Gateway Protocol (IGP) peering with the NIPRNet or to other autonomous systems."
    command = "sh run | i snmp.*.location"
    result = exec_command(command, devicename)
    check.finding = result
    if result.find("RT1") > -1 or result.find("RT1") > -1:
        check.comments = "This router is a external facing router.\n"
        command = "sh run | i ip.access-group|interface.T|interface.G|interface.B"
        result = exec_command(command, devicename)
        check.finding = check.finding + result
        if result.find("INGRESS", len(devicename) + len(command)) > -1:
            check.status = "NotAFinding"
            check.comments = (
                check.comments
                + "V-216670: NAF - RCC-SWA perimeter router has an ingress ACL."
            )
    else:
        check.status = "Not_Applicable"
        check.comments = (
            check.comments
            + "  This is not a perimeter router, and this check is not applicable.."
        )
    return check


def V216671(devicetype, devicename):
    # V-216671 -  The Cisco perimeter router must be configured to filter ingress traffic at the external interface on an inbound direction.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    check.comments = "V-216671 -  The Cisco perimeter router must be configured to filter ingress traffic at the external interface on an inbound direction."
    command = "sh run | i snmp.*.location"
    result = exec_command(command, devicename)
    check.finding = result
    if result.find("RT1") > -1 or result.find("RT1") > -1:
        check.comments = "This router is a external facing router.\n"
        command = "sh run | i ip.access-group|interface.T|interface.G|interface.B"
        result = exec_command(command, devicename)
        check.finding = check.finding + result
        if result.find("INGRESS", len(devicename) + len(command)) > -1:
            check.status = "NotAFinding"
            check.comments = (
                check.comments
                + "V-216671: NAF - RCC-SWA perimeter router has an ingress ACL."
            )
    else:
        check.status = "Not_Applicable"
        check.comments = (
            check.comments
            + "  This is not a perimeter router, and this check is not applicable.."
        )
    return check


def V216672(devicetype, devicename):
    # V-216672 -  The Cisco perimeter router must be configured to filter ingress traffic at the external interface on an inbound direction.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    check.comments = "V-216672 -  The Cisco perimeter router must be configured to filter egress traffic at the internal interface on an inbound direction."
    command = "sh run | i snmp.*.location"
    result = exec_command(command, devicename)
    check.finding = result
    if result.find("RT1") > -1 or result.find("RT1") > -1:
        check.comments = "This router is a external facing router.\n"
        command = "sh run | i ip.access-group|interface.T|interface.G|interface.B"
        result = exec_command(command, devicename)
        check.finding = check.finding + result
        if result.find("EGRESS", len(devicename) + len(command)) > -1:
            check.status = "NotAFinding"
            check.comments = (
                check.comments
                + "V-216672: NAF - RCC-SWA perimeter router has an Egress ACL."
            )
    else:
        check.status = "Not_Applicable"
        check.comments = (
            check.comments
            + "  This is not a perimeter router, and this check is not applicable.."
        )
    return check


def V216674(devicetype, devicename):
    # V-216674 -  The Cisco perimeter router must be configured to have Link Layer Discovery Protocol (LLDP) disabled on all external interfaces.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    check.comments = "V-216674 -  The Cisco perimeter router must be configured to have Link Layer Discovery Protocol (LLDP) disabled on all external interfaces."
    command = "sh run | i snmp.*.location"
    result = exec_command(command, devicename)
    check.finding = result
    if result.find("RT1") > -1 or result.find("RT1") > -1:
        check.comments = "This router is a external facing router.\n"
        command = "sh lldp"
        result = exec_command(command, devicename)
        check.finding = check.finding + "\n" + result
        if result.find("not enabled", len(devicename) + len(command)) > -1:
            check.status = "NotAFinding"
            check.comments = (
                check.comments
                + "V-216674: NAF - LLDP is disabled on the RCC-SWA perimeter router."
            )
    else:
        check.status = "Not_Applicable"
        check.comments = (
            check.comments
            + "  This is not a perimeter router, and this check is not applicable.."
        )
    return check


def V216675(devicetype, devicename):
    # V-216675 -  The Cisco perimeter router must be configured to have Link Layer Discovery Protocol (LLDP) disabled on all external interfaces.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    check.comments = "V-216675 -  The Cisco perimeter router must be configured to have Cisco Discovery Protocol (CDP) disabled on all external interfaces."
    command = "sh run | i snmp.*.location"
    result = exec_command(command, devicename)
    check.finding = result
    if result.find("RT1") > -1 or result.find("RT1") > -1:
        check.comments = "This router is an external facing , perimeter outer.\n"
        command = "sh cdp"
        result = exec_command(command, devicename)
        check.finding = check.finding + "\n" + result
        if result.find("not enabled", len(devicename) + len(command)) > -1:
            check.status = "NotAFinding"
            check.comments = (
                check.comments
                + "V-216675: NAF - CDP is disabled on the RCC-SWA perimeter router."
            )
    else:
        check.status = "Not_Applicable"
        check.comments = (
            check.comments
            + "  This is not a perimeter router, and this check is not applicable.."
        )
    return check


def V216676(devicetype, devicename):
    # V-216676 -  The Cisco perimeter router must be configured to have Proxy ARP disabled on all external interfaces.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    check.comments = "V-216676 -  The Cisco perimeter router must be configured to have Proxy ARP disabled on all external interfaces.."
    command = "sh run | i snmp.*.location"
    result = exec_command(command, devicename)
    check.finding = result
    strExtInterface = "NA"
    if result.find("RT1") > -1 or result.find("RT1") > -1:
        check.comments = "This router is an external facing, perimeter router.\n"
        # Find the interface we egress out to Google with.
        command = "show ip cef 172.217.23.100"
        result = exec_command(command, devicename)
        check.finding = check.finding + "\n" + result
        for line in result.splitlines():
            if line.find("nexthop") > -1:
                strExtInterface = line.split()[2]
                check.comments = (
                    check.comments
                    + "Egress interface for the perimeter router is "
                    + strExtInterface
                )
        if strExtInterface.find("NA") == -1:
            command = "show run int " + strExtInterface
            result = exec_command(command, devicename)
            check.finding = check.finding + "\n" + result
            if result.find("no ip proxy") > -1:
                check.status = "NotAFinding"
                check.comments = (
                    check.comments
                    + "V-216676: NAF - Proxy-arp is disabled on the external interface.."
                )
            else:
                check.comments = "V-216676 -  The Cisco perimeter router must be configured to have Proxy ARP disabled on all external interfaces.."
    else:
        check.status = "Not_Applicable"
        check.comments = (
            check.comments
            + "  This is not a perimeter router, and this check is not applicable."
        )
    return check


def V216677(devicetype, devicename):
    # V-216677 -  The Cisco perimeter router must be configured to block all outbound management traffic.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    check.comments = "V-216677 -  The Cisco perimeter router must be configured to block all outbound management traffic."
    command = "sh run | i snmp.*.location"
    result = exec_command(command, devicename)
    check.finding = result
    strExtInterface = "NA"
    if result.find("RT1") > -1 or result.find("RT1") > -1:
        check.comments = "This router is an external facing , perimeter router.\n"
        # Find the interface we egress out to Google with.
        command = "show ip access-lists EGRESS | i eq.22.log|eq.tacacs|eq.snmp|eq.syslog|eq.www|deny.ip.any.any"
        result = exec_command(command, devicename)
        check.finding = check.finding + "\n" + result
        if result.find("eq 22 log", len(devicename) + len(command)) > -1:
            check.status = "NotAFinding"
            check.comments = (
                check.comments
                + "V-216676: NAF - Egress ACLs are blockng management traffic.."
            )
    else:
        check.status = "Not_Applicable"
        check.comments = (
            check.comments
            + "  This is not a perimeter router, and this check is not applicable."
        )
    return check


def V216678(devicetype, devicename):
    # V-216678 - The Cisco out-of-band management (OOBM) gateway router must be configured to transport management traffic to the Network Operations Center (NOC) via dedicated circuit, MPLS/VPN service, or IPsec tunnel.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = format_vulid()
    check.comments = "V-216678 - This is not a dedicated OOB gateway router."
    check.status = "Not_Applicable"
    # command = "show ip access-li"
    # result = exec_command(command, devicename)
    check.finding = "N/A"
    return check


def V216679(devicetype, devicename):
    # V-216679 - The Cisco out-of-band management (OOBM) gateway router must be configured to transport management traffic to the Network Operations Center (NOC) via dedicated circuit, MPLS/VPN service, or IPsec tunnel.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = format_vulid()
    check.comments = "V-216679 - This is not a dedicated OOB gateway router."
    check.status = "Not_Applicable"
    check.finding = "N/A"
    return check


def V216680(devicetype, devicename):
    # V-216680 - The Cisco out-of-band management (OOBM) gateway router must be configured to have separate Interior Gateway Protocol (IGP) instances for the managed network and management network.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = format_vulid()
    check.comments = "V-216680 - This is not a dedicated OOB gateway router."
    check.status = "Not_Applicable"
    check.finding = "N/A"
    return check


def V216681(devicetype, devicename):
    # V-216681 - The Cisco out-of-band management (OOBM) gateway router must be configured to not redistribute routes between the management network routing domain and the managed network routing domain.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = format_vulid()
    check.comments = "V-216681 - This is not a dedicated OOB gateway router."
    check.status = "Not_Applicable"
    check.finding = "N/A"
    return check


def V216682(devicetype, devicename):
    # V-216682 - The Cisco out-of-band management (OOBM) gateway router must be configured to block any traffic destined to itself that is not sourced from the OOBM network or the Network Operations Center (NOC)
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = format_vulid()
    check.comments = "V-216682 - This is not a dedicated OOB gateway router."
    check.status = "Not_Applicable"
    check.finding = "N/A"
    return check


def V216683(devicetype, devicename):
    # V-216683 - The Cisco router must be configured to only permit management traffic that ingresses and egresses the out-of-band management (OOBM) interface.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = format_vulid()
    check.comments = "V-216683 - This is not a dedicated OOB gateway router."
    check.status = "Not_Applicable"
    check.finding = "N/A"
    return check


def V216684(devicetype, devicename):
    # V-216684 - The Cisco router providing connectivity to the Network Operations Center (NOC) must be configured to forward all in-band management traffic via an IPsec tunnel.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = format_vulid()
    check.comments = "V-216684 - This is not a dedicated OOB gateway router."
    check.status = "Not_Applicable"
    check.finding = "N/A"
    return check


def V216687(devicetype, devicename):
    # V-216687 -  The Cisco BGP router must be configured to reject inbound route advertisements for any Bogon prefixes.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    check.comments = (
        check.vulid
        + " - The Cisco BGP router must be configured to reject inbound route advertisements for any Bogon prefixes."
    )
    strBGP_AS = "0"
    command = "show ip proto | i Routing.Protoc"
    result = exec_command(command, devicename)
    check.finding = result
    strPeerfinding = "NotAFinding"
    # Identify which routing protocols are in use and save applicable AS or PID
    for line in result.splitlines():
        line = line.replace('"', "")
        if line.find("bgp") > -1:
            strBGP_AS = line.split()[-1]
    strBGP_Peers = []
    if int(strBGP_AS) > 0:
        check.comments = "This router seems to be running BGP.\n"
        # Find the external bgp peers.
        command = (
            "show ip bgp vpnv4 all summary | exc memory|BGP| 65... |path|Neighbor|"
            + strBGP_AS
        )
        result = exec_command(command, devicename)
        # If we're running MP-BGP then the results will be empty.  If so we need to run the ipv4 command
        if len(result.splitlines()) <= 3:
            command = (
                "show ip bgp sum | exc memory|BGP| 65...| path|Neighbor|" + strBGP_AS
            )
            result = exec_command(command, devicename)
        check.finding = check.finding + "\n" + result
        if len(result.splitlines()) <= 4:
            check.comments = (
                check.comments + "NAF: This router does not have any eBGP peers.\n"
            )
            check.status = "NotAFinding"
        else:
            # Create a list of external BGP peers
            for line in result.splitlines():
                if len(line) > 1:
                    if line.split()[0].find(".") > -1:
                        strBGP_Peers.append(line.split()[0])
            # Lets loop through the peers, associated route maps, and the prefix lists used.
            if len(strBGP_Peers) > 0:
                # initial assumption is we're going to pass.  if we can't find an appropriate prefix list blocking networks we'll raise up a finding.
                check.status = "NotAFinding"
                # check.comments = check.comments + check.vulid +':NAF - Ingress route maps only allow expected and defined prefixes.\n'
                for peer in strBGP_Peers:
                    command = "show run | i nei.*." + peer + ".*.oute-map.*.in"
                    result = exec_command(command, devicename)
                    check.finding = check.finding + "\n" + result
                    for line in result.splitlines():
                        if line.find("route-map") > -1:
                            command = "show run | sec route-map " + line.split()[3]
                            result = exec_command(command, devicename)
                            check.finding = check.finding + "\n" + result
                            strAllowsAny = "No"
                            for configline in result.splitlines():
                                if configline.find("prefix-list") > -1:
                                    command = (
                                        "show ip prefix-list " + configline.split()[-1]
                                    )
                                    result = exec_command(command, devicename)
                                    check.finding = check.finding + "\n" + result
                                    if (
                                        result.find("deny 0.0.0.0") > -1
                                        or result.find("permit 0.0.0.0") == -1
                                    ):
                                        check.comments = (
                                            check.comments
                                            + "Prefix list "
                                            + configline.split()[-1]
                                            + " filtering peer "
                                            + peer
                                            + " appears to only allow specific prefixes.\n"
                                        )
                                    else:
                                        strPeerfinding = "Open"
                                        check.comments = (
                                            check.comments
                                            + "Prefix list "
                                            + configline.split()[-1]
                                            + " filtering peer "
                                            + peer
                                            + " appears to allow all routes.\n"
                                        )
            # Now we'll check if there was a finding during any peer check.
            if strPeerfinding != "NotAFinding":
                check.status = "Open"
                check.comments = (
                    check.comments
                    + check.vulid
                    + ":OPEN - Peering rule allows unexpected prefixes."
                )
            else:
                check.comments = (
                    check.comments
                    + check.vulid
                    + ":NAF - Ingress route maps only allow expected and defined prefixes.  Or "
                )
                check.status = "NotAFinding"
    else:
        check.comments = check.comments + "NAF: This router is not running BGP.\n"
        check.status = "Not_Applicable"
    return check


def V216688(devicetype, devicename):
    # V-216688 -  The Cisco BGP router must be configured to reject inbound route advertisements for any prefixes belonging to the local autonomous system (AS).
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    check.comments = "V-216688 - The Cisco BGP router must be configured to reject inbound route advertisements for any prefixes belonging to the local autonomous system (AS)."
    command = "sh run | i snmp.*.location"
    strBGP_Peers = []
    result = exec_command(command, devicename)
    check.finding = result
    if result.find("RT1") > -1 or result.find("RT2") > -1:
        check.comments = "This router appears to be a perimeter router.  It likely has external BGP peerings.\n"
        # Find the external bgp peers.
        command = (
            "show ip bgp vpnv4 all summary | exc memory|BGP| 65... |path|Neighbor"
        )
        result = exec_command(command, devicename)
        # If we're running MP-BGP then the results will be empty.  If so we need to run the ipv4 command
        if len(result.splitlines()) <= 3:
            command = "show ip bgp sum | exc 65...|memory|BGP|path|Neighbor"
            result = exec_command(command, devicename)
        check.finding = check.finding + "\n" + result
        # Add the list of peers to the list
        if len(result.splitlines()) > 1:
            for line in result.splitlines():
                if len(line) > 1:
                    if line.split()[0].find(".") > -1:
                        strBGP_Peers.append(line.split()[0])
        # Lets loop through the peers, associated route maps, and the prefix lists used.
        if len(strBGP_Peers) > 0:
            for peer in strBGP_Peers:
                command = "show run | i nei.*." + peer + ".*.oute-map.*.in"
                result = exec_command(command, devicename)
                check.finding = check.finding + "\n" + result
                for line in result.splitlines():
                    if line.find("route-map") > -1:
                        command = "show run | sec route-map " + line.split()[3]
                        result = exec_command(command, devicename)
                        check.finding = check.finding + "\n" + result
                        for configline in result.splitlines():
                            if configline.find("prefix-list") > -1:
                                command = (
                                    "show ip prefix-list " + configline.split()[-1]
                                )
                                result = exec_command(command, devicename)
                                check.finding = check.finding + "\n" + result
            check.status = "NotAFinding"
            check.comments = (
                check.comments
                + "V-216688: NAF - Ingress route maps only allow expected and defined prefixes."
            )
        else:
            check.status = "NotAFinding"
            check.comments = check.comments + "V-216688: NAF - There are no EBGP peers."
    else:
        check.status = "Not_Applicable"
        check.comments = (
            check.comments
            + "  This is not a router that peers with external BGP neighbors."
        )
    return check


def V216689(devicetype, devicename):
    # V-216689 -  The Cisco BGP router must be configured to reject outbound route advertisements for any prefixes belonging to the IP core.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    check.comments = (
        check.vulid
        + " - The Cisco BGP router must be configured to reject outbound route advertisements for any prefixes belonging to the IP core."
    )
    strBGP_AS = "0"
    command = "show ip proto | i Routing.Protoc"
    result = exec_command(command, devicename)
    check.finding = result
    strPeerfinding = "NotAFinding"
    # Identify which routing protocols are in use and save applicable AS or PID
    for line in result.splitlines():
        line = line.replace('"', "")
        if line.find("bgp") > -1:
            strBGP_AS = line.split()[-1]
    strBGP_Peers = []
    if int(strBGP_AS) > 0:
        check.comments = "This router seems to be running BGP.\n"
        # Find the external bgp peers.
        command = (
            "show ip bgp vpnv4 all summary | exc memory|BGP| 65... |path|Neighbor|"
            + strBGP_AS
        )
        result = exec_command(command, devicename)
        # If we're running MP-BGP then the results will be empty.  If so we need to run the ipv4 command
        if len(result.splitlines()) <= 3:
            command = (
                "show ip bgp sum | exc memory|BGP| 65...| path|Neighbor|" + strBGP_AS
            )
            result = exec_command(command, devicename)
        check.finding = check.finding + "\n" + result
        if len(result.splitlines()) <= 4:
            check.comments = (
                check.comments + "NAF: This router does not have any eBGP peers.\n"
            )
            check.status = "NotAFinding"
        else:
            # Create a list of external BGP peers
            for line in result.splitlines():
                if len(line) > 1:
                    if line.split()[0].find(".") > -1:
                        strBGP_Peers.append(line.split()[0])
            # Lets loop through the peers, associated route maps, and the prefix lists used.
            if len(strBGP_Peers) > 0:
                # initial assumption is we're going to pass.  if we can't find an appropriate prefix list blocking networks we'll raise up a finding.
                check.status = "NotAFinding"
                # check.comments = check.comments + check.vulid +':NAF - Ingress route maps only allow expected and defined prefixes.\n'
                for peer in strBGP_Peers:
                    command = "show run | i nei.*." + peer + ".*.oute-map.*.in"
                    result = exec_command(command, devicename)
                    check.finding = check.finding + "\n" + result
                    for line in result.splitlines():
                        if line.find("route-map") > -1:
                            command = "show run | sec route-map " + line.split()[3]
                            result = exec_command(command, devicename)
                            check.finding = check.finding + "\n" + result
                            for configline in result.splitlines():
                                if configline.find("prefix-list") > -1:
                                    command = (
                                        "show ip prefix-list " + configline.split()[-1]
                                    )
                                    result = exec_command(command, devicename)
                                    check.finding = check.finding + "\n" + result
                                    if (
                                        result.find("deny 0.0.0.0") > -1
                                        or result.find("permit 0.0.0.0") == -1
                                    ):
                                        check.comments = (
                                            check.comments
                                            + "Prefix list "
                                            + configline.split()[-1]
                                            + " filtering peer "
                                            + peer
                                            + " appears to only allow specific prefixes.\n"
                                        )
                                    else:
                                        strPeerfinding = "Open"
                                        check.comments = (
                                            check.comments
                                            + "Prefix list "
                                            + configline.split()[-1]
                                            + " filtering peer "
                                            + peer
                                            + " appears to allow all routes.\n"
                                        )
            # Now we'll check if there was a finding during any peer check.
            if strPeerfinding != "NotAFinding":
                check.status = "Open"
                check.comments = (
                    check.comments
                    + check.vulid
                    + ":OPEN - Peering rule allows unexpected prefixes."
                )
            else:
                check.comments = (
                    check.comments
                    + check.vulid
                    + ":NAF - Ingress route maps only allow expected and defined prefixes. Or only has iBGP peers."
                )
                check.status = "NotAFinding"
    else:
        check.comments = check.comments + "NAF: This router is not running BGP.\n"
        check.status = "Not_Applicable"
    return check


def V216690(devicetype, devicename):
    # V-216690 -  The Cisco BGP router must be configured to reject outbound route advertisements for any prefixes belonging to the IP core.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    check.comments = (
        check.vulid
        + " - The Cisco BGP router must be configured to reject outbound route advertisements for any prefixes belonging to the IP core."
    )
    strBGP_AS = "0"
    command = "show ip proto | i Routing.Protoc"
    result = exec_command(command, devicename)
    check.finding = result
    strPeerfinding = "NotAFinding"
    # Identify which routing protocols are in use and save applicable AS or PID
    for line in result.splitlines():
        line = line.replace('"', "")
        if line.find("bgp") > -1:
            strBGP_AS = line.split()[-1]
    strBGP_Peers = []
    if int(strBGP_AS) > 0:
        check.comments = "This router seems to be running BGP.\n"
        # Find the external bgp peers.
        command = (
            "show ip bgp vpnv4 all summary | exc memory|BGP| 65... |path|Neighbor|"
            + strBGP_AS
        )
        result = exec_command(command, devicename)
        # If we're running MP-BGP then the results will be empty.  If so we need to run the ipv4 command
        if len(result.splitlines()) <= 3:
            command = (
                "show ip bgp sum | exc memory|BGP| 65...| path|Neighbor|" + strBGP_AS
            )
            result = exec_command(command, devicename)
        check.finding = check.finding + "\n" + result
        if len(result.splitlines()) <= 5:
            check.comments = (
                check.comments + "NAF: This router does not have any eBGP peers.\n"
            )
            check.status = "NotAFinding"
        else:
            # Create a list of external BGP peers
            for line in result.splitlines():
                if len(line) > 1:
                    if line.split()[0].find(".") > -1:
                        strBGP_Peers.append(line.split()[0])
            # Lets loop through the peers, associated route maps, and the prefix lists used.
            if len(strBGP_Peers) > 0:
                # initial assumption is we're going to pass.  if we can't find an appropriate prefix list blocking networks we'll raise up a finding.
                check.status = "NotAFinding"
                # check.comments = check.comments + check.vulid +':NAF - Ingress route maps only allow expected and defined prefixes.\n'
                for peer in strBGP_Peers:
                    command = "show run | i nei.*." + peer + ".*.oute-map.*.in"
                    result = exec_command(command, devicename)
                    check.finding = check.finding + "\n" + result
                    for line in result.splitlines():
                        if line.find("route-map") > -1:
                            command = "show run | sec route-map " + line.split()[3]
                            result = exec_command(command, devicename)
                            check.finding = check.finding + "\n" + result
                            for configline in result.splitlines():
                                if configline.find("prefix-list") > -1:
                                    command = (
                                        "show ip prefix-list " + configline.split()[-1]
                                    )
                                    result = exec_command(command, devicename)
                                    check.finding = check.finding + "\n" + result
                                    if (
                                        result.find("deny 0.0.0.0") > -1
                                        or result.find("permit 0.0.0.0") == -1
                                    ):
                                        check.comments = (
                                            check.comments
                                            + "Prefix list "
                                            + configline.split()[-1]
                                            + " filtering peer "
                                            + peer
                                            + " appears to only allow specific prefixes.\n"
                                        )
                                    else:
                                        strPeerfinding = "Open"
                                        check.comments = (
                                            check.comments
                                            + "Prefix list "
                                            + configline.split()[-1]
                                            + " filtering peer "
                                            + peer
                                            + " appears to allow all routes.\n"
                                        )
            # Now we'll check if there was a finding during any peer check.
            if strPeerfinding != "NotAFinding":
                check.status = "Open"
                check.comments = (
                    check.comments
                    + check.vulid
                    + ":OPEN - Peering rule allows unexpected prefixes."
                )
            else:
                check.comments = (
                    check.comments
                    + check.vulid
                    + ":NAF - Ingress route maps only allow expected and defined prefixes."
                )
    else:
        check.comments = check.comments + "NAF: This router is not running BGP.\n"
        check.status = "Not_Applicable"
    return check


def V216691(devicetype, devicename):
    # V-216691 -  The Cisco BGP router must be configured to reject outbound route advertisements for any prefixes belonging to the IP core.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    check.comments = "V-216691 - The Cisco BGP router must be configured to reject outbound route advertisements for any prefixes belonging to the IP core."
    strBGP_AS = "0"
    command = "show ip proto | i Routing.Protoc"
    result = exec_command(command, devicename)
    check.finding = result
    strPeerfinding = "NotAFinding"
    # Identify which routing protocols are in use and save applicable AS or PID
    for line in result.splitlines():
        line = line.replace('"', "")
        if line.find("bgp") > -1:
            strBGP_AS = line.split()[-1]
    strBGP_Peers = []
    if int(strBGP_AS) > 0:
        check.comments = "This router seems to be running BGP.\n"
        # Find the external bgp peers.
        command = (
            "show ip bgp vpnv4 all summary | exc memory|BGP| 65... |path|Neighbor|"
            + strBGP_AS
        )
        result = exec_command(command, devicename)
        # If we're running MP-BGP then the results will be empty.  If so we need to run the ipv4 command
        if len(result.splitlines()) <= 3:
            command = (
                "show ip bgp sum | exc memory|BGP| 65...| path|Neighbor|" + strBGP_AS
            )
            result = exec_command(command, devicename)
        check.finding = check.finding + "\n" + result
        if len(result.splitlines()) <= 5:
            check.comments = (
                check.comments + "NAF: This router does not have any eBGP peers.\n"
            )
            check.status = "NotAFinding"
        else:
            # Create a list of external BGP peers
            for line in result.splitlines():
                if len(line) > 1:
                    if line.split()[0].find(".") > -1:
                        strBGP_Peers.append(line.split()[0])
            # Lets loop through the peers, associated route maps, and the prefix lists used.
            if len(strBGP_Peers) > 0:
                # initial assumption is we're going to pass.  if we can't find an appropriate prefix list blocking networks we'll raise up a finding.
                check.status = "NotAFinding"
                # check.comments = check.comments + check.vulid +':NAF - Ingress route maps only allow expected and defined prefixes.\n'
                for peer in strBGP_Peers:
                    command = "show run | i nei.*." + peer + ".*.oute-map.*.in"
                    result = exec_command(command, devicename)
                    check.finding = check.finding + "\n" + result
                    for line in result.splitlines():
                        if line.find("route-map") > -1:
                            command = "show run | sec route-map " + line.split()[3]
                            result = exec_command(command, devicename)
                            check.finding = check.finding + "\n" + result
                            for configline in result.splitlines():
                                if configline.find("prefix-list") > -1:
                                    command = (
                                        "show ip prefix-list " + configline.split()[-1]
                                    )
                                    result = exec_command(command, devicename)
                                    check.finding = check.finding + "\n" + result
                                    if (
                                        result.find("deny 0.0.0.0") > -1
                                        or result.find("permit 0.0.0.0") == -1
                                    ):
                                        check.comments = (
                                            check.comments
                                            + "Prefix list "
                                            + configline.split()[-1]
                                            + " filtering peer "
                                            + peer
                                            + " appears to only allow specific prefixes.\n"
                                        )
                                    else:
                                        strPeerfinding = "Open"
                                        check.comments = (
                                            check.comments
                                            + "Prefix list "
                                            + configline.split()[-1]
                                            + " filtering peer "
                                            + peer
                                            + " appears to allow all routes.\n"
                                        )
            # Now we'll check if there was a finding during any peer check.
            if strPeerfinding != "NotAFinding":
                check.status = "Open"
                check.comments = (
                    check.comments
                    + check.vulid
                    + ":OPEN - Peering rule allows unexpected prefixes."
                )
            else:
                check.comments = (
                    check.comments
                    + check.vulid
                    + ":NAF - Ingress route maps only allow expected and defined prefixes."
                )
    else:
        check.comments = check.comments + "NAF: This router is not running BGP.\n"
        check.status = "Not_Applicable"
    return check


def V216692(devicetype, devicename):
    # V-216692 -  verify the router is configured to deny updates received from eBGP peers that do not list their AS number as the first AS in the AS_PATH attribute..
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "NotAFinding"
    check.comments = (
        check.vulid
        + " - Verify the router is configured to deny updates received from eBGP peers that do not list their AS number as the first AS in the AS_PATH attribute.\n"
    )
    strBGP_AS = "0"
    command = "show ip proto | i Routing.Protoc"
    result = exec_command(command, devicename)
    check.finding = result
    strPeerfinding = "NotAFinding"
    # Identify which routing protocols are in use and save applicable AS or PID
    for line in result.splitlines():
        line = line.replace('"', "")
        if line.find("bgp") > -1:
            strBGP_AS = line.split()[-1]
    strBGP_Peers = []
    # If we're running BGP lets get busy...
    if int(strBGP_AS) > 0:
        check.comments = check.comments + "\nThis router seems to be running BGP.\n"
        # Find the external bgp peers.
        command = "show run all | i bgp.enforce-first-as"
        result = exec_command(command, devicename)
        check.finding = check.finding + "\n" + result
        # If we have a no then we're in violation...
        if result.find("no") > -1:
            check.status = "Open"
            check.comments = (
                check.comments
                + "\n"
                + check.vulid
                + ":OPEN - the router allows a peer to put another AS before its own."
            )
        else:
            check.comments = (
                check.comments
                + "\n"
                + check.vulid
                + ":NAF - The router denies updates from begp peers that do not list their AS number first."
            )
    else:
        check.status = "Not_Applicable"
        check.comments = (
            check.comments + "\n" + check.vulid + ":NA - Router is not running BGP."
        )
    return check


def V216693(devicetype, devicename):
    # V-216693 - The Cisco BGP router must be configured to reject route advertisements from CE routers with an originating AS in the AS_PATH attribute that does not belong to that customer.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.finding = "N/A"
    check.vulid = format_vulid()
    check.status = "Not_Applicable"
    check.comments = (
        check.vulid
        + " - The Cisco BGP router must be configured to reject route advertisements from CE routers with an originating AS in the AS_PATH attribute that does not belong to that customer.\n NAF - There is no peering with CE devices."
    )
    return check


def V216694(devicetype, devicename):
    # V-216694 -  The Cisco BGP router must be configured to use the maximum prefixes feature to protect against route table flooding and prefix de-aggregation attacks..
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "NotAFinding"
    check.comments = (
        check.vulid
        + " - The Cisco BGP router must be configured to use the maximum prefixes feature to protect against route table flooding and prefix de-aggregation attacks..\n"
    )
    strBGP_AS = "0"
    command = "show ip proto | i Routing.Protoc"
    result = exec_command(command, devicename)
    check.finding = result
    strPeerfinding = "NotAFinding"
    # Identify which routing protocols are in use and save applicable AS or PID
    for line in result.splitlines():
        line = line.replace('"', "")
        if line.find("bgp") > -1:
            strBGP_AS = line.split()[-1]
    strBGP_Peers = []
    # If we're running BGP lets get busy...
    strHasEBGP = "NO"
    if int(strBGP_AS) > 0:
        check.comments = "This router seems to be running BGP.\n"

        # Look for all the BGP neighbors on BlackCore routers
        command = "sh bgp vpnv4 unicast all summ | b Neighbor"
        result = exec_command(command, devicename)
        if result.find("Invalid") > -1 or len(result.splitlines()) < 3:
            # Look for all the BGP neighbors on Colored routers
            command = "sh bgp ipv4 unicast summ | b Neighbor"
            result = exec_command(command, devicename)

        strBGP_Findings = result + "\n"
        # strBGP_neighbor_status = 'Open'

        for neighbor in result.splitlines():
            # strBGP_neighbor_status = 'Open'
            if (
                neighbor.find("#") == -1
                and neighbor.find("Neighbor") == -1
                and len(neighbor.split()) > 3
            ):
                if neighbor.find(strBGP_AS) == -1:
                    strHasEBGP = "YES"
                    check.comments = (
                        check.comments
                        + "Found eBGP Neighbor "
                        + neighbor.split()[0]
                        + " with AS "
                        + neighbor.split()[2]
                        + "\n"
                    )
                if neighbor.find(strBGP_AS) > -1:
                    # If a host is an internal BGP neighbor, ttl-security hop is not required.
                    check.comments = (
                        check.comments
                        + "Found iBGP Neighbor "
                        + neighbor.split()[0]
                        + ", max prefix not applicable.\n"
                    )

        check.finding = check.finding + strBGP_Findings

        if strHasEBGP == "YES":
            command = "show run | i max.*.-prefix"
            result = exec_command(command, devicename)
            check.finding = check.finding + "\n" + result
            # If we have a no then we're in violation...
            if result.find("maximum-prefix") > -1:
                check.comments = (
                    check.comments
                    + "\n"
                    + check.vulid
                    + ":NAF - The number of received prefixes from each eBGP neighbor is controlled."
                )
            else:
                check.status = "Open"
                check.comments = (
                    check.comments
                    + "\n"
                    + check.vulid
                    + ":OPEN - The number of received prefixes from each eBGP neighbor is NOT controlled.."
                )
    else:
        check.status = "Not_Applicable"
        check.comments = (
            check.comments + "\n" + check.vulid + ":NA - Router is not running eBGP."
        )
    return check


def V216695(devicetype, devicename):
    # V-216695 - The Cisco BGP router must be configured to limit the prefix size on any inbound route advertisement to /24, or the least significant prefixes issued to the customer.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = format_vulid()
    check.finding = "N/A"
    check.status = "Not_Applicable"
    check.comments = (
        check.vulid
        + " - The Cisco BGP router must be configured to limit the prefix size on any inbound route advertisement to /24, or the least significant prefixes issued to the customer.\nNAF - There is no peering with CE devices."
    )
    return check


def V216696(devicetype, devicename):
    # V-216696 -  The Cisco BGP router must be configured to use its loopback address as the source address for iBGP peering sessions.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    strBGP_status = "NotAFinding"
    # check.comments = check.vulid + " -The Cisco BGP router must be configured to use its loopback address as the source address for iBGP peering sessions."
    strBGP_AS = "0"
    command = "show ip proto | i Routing.Protoc"
    result = exec_command(command, devicename)
    check.finding = result
    strPeerfinding = "NotAFinding"
    strBGP_sessions = []
    # Identify which routing protocols are in use and save applicable AS or PID
    for line in result.splitlines():
        line = line.replace('"', "")
        if line.find("bgp") > -1:
            strBGP_AS = line.split()[-1]
    strBGP_Peers = []
    strBGP_Findings = result
    if int(strBGP_AS) > 0:
        # Look at all the peer session templates and save the ones that contain a password
        command = "show run | i template peer-ses"
        result = exec_command(command, devicename)
        strBGP_Findings = strBGP_Findings + result + "\n"
        for session in result.splitlines():
            if session.find("peer-session") > -1:
                command = "show run | sec " + session
                #
                # Replace password with ***REMOVED***
                strClean = ""
                result = ""
                temp = exec_command(command, devicename)
                for line in temp.splitlines():
                    if line.find("password 7") > 1:
                        strClean = (
                            line[0 : line.find("password")]
                            + "password <-----***REMOVED***----->"
                        )
                        bolPassword = 1
                    else:
                        strClean = line
                    #
                    result = result + "\n" + strClean
                strBGP_Findings = strBGP_Findings + result + "\n"
                if result.find("update-source") > -1:
                    strBGP_sessions.append(session.split()[-1])
        # Get VPNv4 MP-BGP Neighbors on BlackCore PE routers
        # command = "show ip bgp vpnv4 all summary | inc " + strBGP_AS
        command = "show ip bgp vpnv4 all neighbors | inc AS." + strBGP_AS
        result = exec_command(command, devicename)
        # If we're not running MP-BGP then the results will be empty.  If so we need to run the ipv4 command
        if len(result.splitlines()) <= 3:
            command = "sh ip bgp neighbors | inc " + strBGP_AS
            result = exec_command(command, devicename)
        strBGP_Findings = strBGP_Findings + "\n" + result
        if len(result.splitlines()) > 2:
            strBGP_neighbor_status = "Open"
            for neighbor in result.splitlines():
                strBGP_neighbor_status = "Open"
                if neighbor.find("#") == -1:
                    neighborIP = neighbor.split()[3]
                    neighborIP = neighborIP.replace(",", "")
                    command = "show run | i neighbor.*." + neighborIP
                    # Replace password with ***REMOVED***
                    strClean = ""
                    result = ""
                    temp = exec_command(command, devicename)
                    for line in temp.splitlines():
                        if line.find("password 7") > 1:
                            strClean = (
                                line[0 : line.find("password")]
                                + "password <-----***REMOVED***----->"
                            )
                            bolPassword = 1
                        else:
                            strClean = line
                        result = result + "\n" + strClean
                    strBGP_Findings = strBGP_Findings + result + "\n"
                    check.comments = (
                        check.comments
                        + "Found iBGP Neighbor "
                        + neighborIP
                        + "\n"
                    )
                    if result.find("update-source Loopback") > -1:
                        strBGP_neighbor_status = "NotAFinding"
                        check.comments = (
                            check.comments
                            + "BGP neighbor "
                            + neighborIP
                            + " is configured to use update-source Loopback.\n"
                        )
                    if result.find("inherit peer-session") > -1:
                        # If a neighbor has a peer session, check if the session has a password configured.
                        # Loop through the peer sessions that have passwords
                        for peersession in strBGP_sessions:
                            if result.find(peersession) > -1:
                                strBGP_neighbor_status = "NotAFinding"
                                check.comments = (
                                    check.comments
                                    + " - BGP neighbor "
                                    + neighborIP
                                    + " has a loopback for an update-source through peer-session "
                                    + peersession
                                    + ".\n"
                                )
                    if strBGP_neighbor_status == "Open":
                        strBGP_status = "Open"
                        check.comments = (
                            check.comments
                            + "Could not match a configuration for neighbor "
                            + neighborIP
                            + ".\n"
                        )

            if strBGP_status != "NotAFinding":
                check.status = "Open"
            else:
                check.status = "NotAFinding"
            check.finding = strBGP_Findings
            # check.comments = "V-216644 - CAT II - The Cisco router must be configured to use encryption for routing protocol authentication."
        else:
            check.status = "NotAFinding"
            check.comments = check.comments + "There are no iBGP neighbors."
    else:
        check.status = "Not_Applicable"
        check.comments = (
            check.comments + "\n" + check.vulid + ":NA - Router is not running BGP."
        )
    return check


def V216697(devicetype, devicename):
    # V-216697 -  The Cisco MPLS router must be configured to use its loopback address as the source address for LDP peering sessions.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "NotAFinding"
    check.comments = (
        check.vulid
        + " -The Cisco MPLS router must be configured to use its loopback address as the source address for LDP peering sessions.\n"
    )
    strPeerfinding = "NotAFinding"
    strLDP = "NA"
    command = "show mpls ldp igp sync"
    result = exec_command(command, devicename)
    check.finding = result
    # Find out if we're running MPLS
    if result.find("LDP configured") > -1:
        strLDP = "enabled"
    # If we're running BGP lets get busy...
    if strLDP == "enabled":
        check.comments = "This router seems to be running MPLS.\n"
        # Find the external bgp peers.
        command = "show run | i mpls.*.uter-id"
        result = exec_command(command, devicename)
        check.finding = check.finding + "\n" + result
        # If we have a no then we're in violation...
        if result.find("ldp router-id Loopback") > -1:
            check.comments = (
                check.comments
                + "\n"
                + check.vulid
                + ":NAF - The router is configured to use its loopback address for LDP peering."
            )
        else:
            check.status = "Open"
            check.comments = (
                check.comments
                + "\n"
                + check.vulid
                + ":OPEN - The router is not configured to use its loopback address for LDP peering."
            )
    else:
        check.status = "Not_Applicable"
        check.comments = (
            check.comments
            + "\n"
            + check.vulid
            + ":NA - Router is not running LDP/MPLS so this check is not applicable."
        )
    return check


def V216698(devicetype, devicename):
    # V-216698 -  The Cisco MPLS router must be configured to synchronize Interior Gateway Protocol (IGP) and LDP to minimize packet loss.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "NotAFinding"
    check.comments = (
        check.vulid
        + " -The Cisco MPLS router must be configured to synchronize Interior Gateway Protocol (IGP) and LDP to minimize packet loss.\n"
    )
    strPeerfinding = "NotAFinding"
    strLDP = "NA"
    command = "show mpls ldp igp sync"
    result = exec_command(command, devicename)
    check.finding = result
    # Find out if we're running MPLS
    if result.find("LDP configured") > -1:
        strLDP = "enabled"
    # If we're running BGP lets get busy...
    if strLDP == "enabled":
        check.comments = "This router seems to be running MPLS.\n"
        # Find the external bgp peers.
        command = "show run all | i mpls.*.sync"
        result = exec_command(command, devicename)
        check.finding = check.finding + "\n" + result
        # If we have a no then we're in violation...
        if result.find("mpls ldp igp sync") > -1:
            check.comments = (
                check.comments
                + "\n"
                + check.vulid
                + ":NAF -  The router is configured to synchronize IGP and LDP."
            )
        else:
            check.status = "Open"
            check.comments = (
                check.comments
                + "\n"
                + check.vulid
                + ":OPEN -  The router is not configured to synchronize IGP and LDP."
            )
    else:
        check.status = "Not_Applicable"
        check.comments = (
            check.comments
            + "\n"
            + check.vulid
            + ":NA - Router is not running LDP/MPLS so this check is not applicable."
        )
    return check


def V216699(devicetype, devicename):
    # V-216699 -  The MPLS router with RSVP-TE enabled must be configured with message pacing to adjust maximum burst and maximum number of RSVP messages to an output queue based on the link speed and input queue size of adjacent core routers.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "NotAFinding"
    check.comments = (
        check.vulid
        + " -The MPLS router with RSVP-TE enabled must be configured with message pacing to adjust maximum burst and maximum number of RSVP messages to an output queue based on the link speed and input queue size of adjacent core routers.\n"
    )
    strPeerfinding = "NotAFinding"
    strLDP = "NA"
    command = "show run | i mpls.traff.*.tunnels"
    result = exec_command(command, devicename)
    check.finding = result
    # Find out if we're running MPLS
    if result.find("mpls traffic-eng tunnels") > -1:
        strLDP = "enabled"
    # If we're running BGP lets get busy...
    if strLDP == "enabled":
        check.comments = "This router seems to be running MPLS-TE.\n"
        # Find the external bgp peers.
        command = "show run all | i ip.rsvp.*.rate-limit"
        result = exec_command(command, devicename)
        check.finding = check.finding + "\n" + result
        # If we have a no then we're in violation...
        if result.find("ip rsvp signalling rate-limit") > -1:
            check.comments = (
                check.comments
                + "\n"
                + check.vulid
                + ":NAF -  The router is configured  rate limit RSVP messages."
            )
        else:
            check.status = "Open"
            check.comments = (
                check.comments
                + "\n"
                + check.vulid
                + ":OPEN -  The router is not configured to rate limit RSVP messages."
            )
    else:
        check.status = "Not_Applicable"
        check.comments = (
            check.comments + "\n" + check.vulid + ":NA - Router is not running MPLS-TE."
        )
    return check


def V216700(devicetype, devicename):
    # V-216700 -  The Cisco MPLS router must be configured to have TTL Propagation disabled.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "NotAFinding"
    check.comments = (
        check.vulid
        + " -The Cisco MPLS router must be configured to have TTL Propagation disabled.\n"
    )
    strPeerfinding = "NotAFinding"
    strLDP = "NA"
    command = "show mpls ldp discovery"
    result = exec_command(command, devicename)
    check.finding = result
    # Find out if we're running MPLS
    if result.find("Local LDP Identifier") > -1:
        strLDP = "enabled"
    # If we're running LDP lets get busy...
    if strLDP == "enabled":
        check.comments = "This router seems to be running MPLS.\n"
        # Find mpls configs.
        command = "show run all | i mpls.*.propagate-ttl"
        result = exec_command(command, devicename)
        check.finding = check.finding + "\n" + result
        # If we have a no then we're in violation...
        if result.find("no") > -1:
            check.comments = (
                check.comments
                + "\n"
                + check.vulid
                + ":NAF -  The router is configured to disable TTL propagation."
            )
        else:
            check.status = "Open"
            check.comments = (
                check.comments
                + "\n"
                + check.vulid
                + ":OPEN -  The router is not configured to disable TTL propagation."
            )
    else:
        check.status = "Not_Applicable"
        check.comments = (
            check.comments + "\n" + check.vulid + ":NA - Router is not running MPLS."
        )
    return check


def V216701(devicetype, devicename):
    # V-216701 -  The Cisco PE router must be configured to have each Virtual Routing and Forwarding (VRF) instance bound to the appropriate physical or logical interfaces .
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "NotAFinding"
    check.comments = (
        check.vulid
        + " -The Cisco PE router must be configured to have each Virtual Routing and Forwarding (VRF) instance bound to the appropriate physical or logical interfaces.\n"
    )
    strLDP = "NA"
    command = "show mpls ldp discovery"
    result = exec_command(command, devicename)
    check.finding = result
    # Find out if we're running MPLS
    if result.find("Local LDP Identifier") > -1:
        strLDP = "enabled"
    # If we're running LDP lets get busy...
    if strLDP == "enabled":
        check.comments = "This router seems to be running MPLS.\n"
        # Find the cef configs.
        command = "show vrf"
        result = exec_command(command, devicename)
        check.finding = check.finding + "\n" + result
        # If we have a no then we're in violation...
        if result.find("Interfaces") > -1:
            check.comments = (
                check.comments
                + "\n"
                + check.vulid
                + ":NAF -  Each CE-facing interface is only associated to one VRF."
            )
        else:
            check.status = "Open"
            check.comments = (
                check.comments
                + "\n"
                + check.vulid
                + ":OPEN -  Each CE-facing interface is NOT associated to one VRF"
            )
    else:
        check.status = "Not_Applicable"
        check.comments = (
            check.comments + "\n" + check.vulid + ":NA - Router is not running MPLS."
        )
    return check


def V216702(devicetype, devicename):
    # V-216702 -  The Cisco PE router must be configured to have each Virtual Routing and Forwarding (VRF) instance with the appropriate Route Target .
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "NotAFinding"
    check.comments = (
        check.vulid
        + " -The Cisco PE router must be configured to have each Virtual Routing and Forwarding (VRF) instance with the appropriate Route Target .\n"
    )
    strLDP = "NA"
    command = "show mpls ldp discovery"
    result = exec_command(command, devicename)
    check.finding = result
    # Find out if we're running MPLS
    if result.find("Local LDP Identifier") > -1:
        strLDP = "enabled"
    # If we're running LDP lets get busy...
    if strLDP == "enabled":
        check.comments = "This router seems to be running MPLS.\n"
        # Find the cef configs.
        command = "show run | sec vrf.definition"
        result = exec_command(command, devicename)
        check.finding = check.finding + "\n" + result
        # If we have a no then we're in violation...
        if result.find("route-target export") > -1:
            check.comments = (
                check.comments + "\n" + check.vulid + ":NAF -  The router"
                "s RT is configured for each VRF."
            )
        else:
            check.status = "Open"
            check.comments = (
                check.comments + "\n" + check.vulid + ":OPEN -  The router"
                "s RT is NOT configured for each VRF"
            )
    else:
        check.status = "Not_Applicable"
        check.comments = (
            check.comments + "\n" + check.vulid + ":NA - Router is not running MPLS."
        )
    return check


def V216703(devicetype, devicename):
    # V-216703 -  The Cisco PE router must be configured to have each VRF with the appropriate Route Distinguisher (RD).
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "NotAFinding"
    check.comments = (
        check.vulid
        + " -The Cisco PE router must be configured to have each VRF with the appropriate Route Distinguisher (RD).\n"
    )
    strLDP = "NA"
    command = "show mpls ldp discovery"
    result = exec_command(command, devicename)
    check.finding = result
    # Find out if we're running MPLS
    if result.find("Local LDP Identifier") > -1:
        strLDP = "enabled"
    # If we're running LDP lets get busy...
    if strLDP == "enabled":
        check.comments = "This router seems to be running MPLS.\n"
        # Find the cef configs.
        command = "show run | sec vrf.definition"
        result = exec_command(command, devicename)
        check.finding = check.finding + "\n" + result
        # If we have a no then we're in violation...
        if result.find("rd") > -1 and result.find(":") > -1:
            check.comments = (
                check.comments
                + "\n"
                + check.vulid
                + ":NAF -  The Cisco PE router is configured to have each VRF with the appropriate Route Distinguisher (RD)"
            )
        else:
            check.status = "Open"
            check.comments = (
                check.comments
                + "\n"
                + check.vulid
                + ":OPEN -  The Cisco PE router is NOT configured to have each VRF with the appropriate Route Distinguisher (RD)"
            )
    else:
        check.status = "Not_Applicable"
        check.comments = (
            check.comments + "\n" + check.vulid + ":NA - Router is not running MPLS."
        )
    return check


def V216704(devicetype, devicename):
    # V-216704 -  The Cisco PE router providing MPLS Layer 2 Virtual Private Network (L2VPN) services must be configured to authenticate targeted Label Distribution Protocol (LDP) sessions.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "NotAFinding"
    check.comments = (
        check.vulid
        + " -The Cisco PE router providing MPLS Layer 2 Virtual Private Network (L2VPN) services must be configured to authenticate targeted Label Distribution Protocol (LDP) sessions.\n"
    )
    strLDP = "NA"
    command = "show mpls ldp discovery"
    result = exec_command(command, devicename)
    check.finding = result
    # Find out if we're running MPLS
    if result.find("Local LDP Identifier") > -1:
        strLDP = "enabled"
    # If we're running LDP lets get busy...
    if strLDP == "enabled":
        check.comments = "This router seems to be running MPLS.\n"
        # Find the cef configs.
        command = "show run | i mpls.*.nei"
        #
        # Replace password with ***REMOVED***
        strClean = ""
        result = ""
        temp = exec_command(command, devicename)
        for line in temp.splitlines():
            if line.find("password") > 1:
                strClean = (
                    line[0 : line.find("password")]
                    + "password <-----***REMOVED***----->"
                )
                bolPassword = 1
            else:
                strClean = line
            #
            result = result + "\n" + strClean
        check.finding = check.finding + "\n" + result
        # If we have a no then we're in violation...
        if result.find("password") > -1:
            check.comments = (
                check.comments
                + "\n"
                + check.vulid
                + ":NAF - The Cisco PE router is configured to authenticate LDP neighbors."
            )
        else:
            check.status = "Open"
            check.comments = (
                check.comments
                + "\n"
                + check.vulid
                + ":OPEN - The Cisco PE router is NOT configured to authenticate LDP neighbors."
            )
    else:
        check.status = "Not_Applicable"
        check.comments = (
            check.comments + "\n" + check.vulid + ":NA - Router is not running MPLS."
        )
    return check


def V216705(devicetype, devicename):
    # V-216705 -  the correct VC ID is configured for each attachment circuit.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "NotAFinding"
    check.comments = (
        check.vulid
        + " - Verify the correct VC ID is configured for each attachment circuit.\n"
    )
    strLDP = "NA"
    command = "show xconnect pwmib | i up|VC"
    result = exec_command(command, devicename)
    check.finding = result
    # Find out if we're running MPLS
    if len(result.splitlines()) > 5:
        strLDP = "enabled"
    # If we're running LDP lets get busy...
    if strLDP == "enabled":
        check.comments = "This router seems to be running MPLS.\n"
        # Find the cef configs.
        command = "show xconnect pwmib | exc pw"
        result = exec_command(command, devicename)
        check.finding = check.finding + "\n" + result
        # If we have a no then we're in violation...
        if result.find("Encap") > -1:
            check.comments = (
                check.comments
                + "\n"
                + check.vulid
                + ":NAF - The CE-facing interface that is configured for VPWS is unique."
            )
        else:
            check.status = "Open"
            check.comments = (
                check.comments
                + "\n"
                + check.vulid
                + ":OPEN - The CE-facing interface that is configured for VPWS is NOT unique."
            )
    else:
        check.status = "Not_Applicable"
        check.comments = (
            check.comments
            + "\n"
            + check.vulid
            + ":NA - Router is not terminating any Virtual Private Wire Service (VPWS)."
        )
    return check


def V216706(devicetype, devicename):
    # V-216706 -  The Cisco PE router providing Virtual Private LAN Services (VPLS) must be configured to have all attachment circuits defined to the virtual forwarding instance (VFI) with the globally unique VPN ID assigned for each customer VLAN.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "NotAFinding"
    check.comments = (
        check.vulid
        + " - The Cisco PE router providing Virtual Private LAN Services (VPLS) must be configured to have all attachment circuits defined to the virtual forwarding instance (VFI) with the globally unique VPN ID assigned for each customer VLAN.\n"
    )
    strLDP = "NA"
    command = "show run | sec l2.vfi"
    result = exec_command(command, devicename)
    check.finding = result
    # Find out if we're running MPLS
    if len(result.splitlines()) > 2:
        strLDP = "enabled"
    # If we're running LDP lets get busy...
    if strLDP == "enabled":
        check.comments = "This router seems to be running VPLS VFI.\n"
        # Find the cef configs.
        command = "show xconnect pwmib | exc pw"
        result = exec_command(command, devicename)
        check.finding = check.finding + "\n" + result
        # If we have a no then we're in violation...
        if result.find("VC ID") > -1:
            check.comments = (
                check.comments
                + "\n"
                + check.vulid
                + ":NAF - Attachment circuits are associated to the appropriate VFI."
            )
        else:
            check.status = "Open"
            check.comments = (
                check.comments
                + "\n"
                + check.vulid
                + ":OPEN - Attachment circuits are NOT associated to the appropriate VFI."
            )
    else:
        check.status = "Not_Applicable"
        check.comments = (
            check.comments
            + "\n"
            + check.vulid
            + ":NA - Router is not providing L2 VFI services."
        )
    return check


def V216707(devicetype, devicename):
    # V-216707 -  The Cisco PE router providing Virtual Private LAN Services (VPLS) must be configured to have all attachment circuits defined to the virtual forwarding instance (VFI) with the globally unique VPN ID assigned for each customer VLAN.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "NotAFinding"
    check.comments = (
        check.vulid
        + " - The Cisco PE router providing Virtual Private LAN Services (VPLS) must be configured to have all attachment circuits defined to the virtual forwarding instance (VFI) with the globally unique VPN ID assigned for each customer VLAN.\n"
    )
    strLDP = "NA"
    command = "show run | sec l2.vfi"
    result = exec_command(command, devicename)
    check.finding = result
    # Find out if we're running MPLS
    if len(result.splitlines()) > 2:
        strLDP = "enabled"
    # If we're running LDP lets get busy...
    if strLDP == "enabled":
        check.comments = "This router seems to be running VPLS VFI.\n"
        # If we have a no split horizon then we're in violation...
        if result.find("no-split-horizon") == -1:
            check.comments = (
                check.comments
                + "\n"
                + check.vulid
                + ":NAF - Split horizon is not enabled."
            )
        else:
            check.status = "Open"
            check.comments = (
                check.comments
                + "\n"
                + check.vulid
                + ":OPEN - If split horizon is not enabled, this is a finding.."
            )
    else:
        check.status = "Not_Applicable"
        check.comments = (
            check.comments
            + "\n"
            + check.vulid
            + ":NA - Router is not providing L2 VFI services."
        )
    return check


def V216708(devicetype, devicename):
    # V-216708 -  The Cisco PE router providing Virtual Private LAN Services (VPLS) must be configured to have traffic storm control thresholds on CE-facing interfaces.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "NotAFinding"
    check.comments = (
        check.vulid
        + " - The Cisco PE router providing Virtual Private LAN Services (VPLS) must be configured to have traffic storm control thresholds on CE-facing interfaces.\n"
    )
    strLDP = "NA"
    strVPLS = "NotAFinding"
    command = "show xconnect pwmib | exc pw"
    result = exec_command(command, devicename)
    check.finding = result
    # Find out if we have local ports terminating VPWS
    if len(result.splitlines()) > 5:
        strLDP = "enabled"
        command = "show run | sec service.instance|bridge"
        result = exec_command(command, devicename)
        check.finding = check.finding + result
        if len(result.splitlines()) > 3:
            for line in result.splitlines():
                if line.find("MPLS") > -1:
                    command = "show run int " + line.split()[-1]
                    result = exec_command(command, devicename)
                    check.finding = check.finding + result
                    if result.find("storm-control") == -1:
                        strVPLS = "Open"
                        check.comments = (
                            check.comments
                            + "OPEN: Missing storm control on VPLS interface "
                            + line.split()[-1]
                            + "\n"
                        )
            if strVPLS != "NotAFinding":
                check.status = "Open"
                check.comments = (
                    check.comments
                    + "OPEN: Private LAN Services (VPLS) must be configured to have traffic storm control thresholds on CE-facing interfaces.\n"
                )
            else:
                check.status = "NotAFinding"
                check.comments = check.comments + "NAF: Storm control is in place.\n"
        else:
            check.status = "NotAFinding"
            check.comments = (
                check.comments
                + "NAF: There is no service instance or bridge group configured.\n"
            )
    else:
        check.status = "Not_Applicable"
        check.comments = (
            check.comments
            + "\n"
            + check.vulid
            + ":NA - Router is not providing L2 VFI services."
        )
    return check


def V216709(devicetype, devicename):
    # V-216709 -  The Cisco PE router must be configured to implement Internet Group Management Protocol (IGMP) or Multicast Listener Discovery (MLD) snooping for each Virtual Private LAN Services (VPLS) bridge domain.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "NotAFinding"
    check.comments = (
        check.vulid
        + " - The Cisco PE router must be configured to implement Internet Group Management Protocol (IGMP) or Multicast Listener Discovery (MLD) snooping for each Virtual Private LAN Services (VPLS) bridge domain.\n"
    )
    strLDP = "NA"
    strVPLS = "NotAFinding"
    command = "show xconnect pwmib | exc pw"
    result = exec_command(command, devicename)
    check.finding = result
    # Find out if we have local ports terminating VPWS
    if len(result.splitlines()) > 5:
        strLDP = "enabled"
        # If we're running LDP lets get busy...
        # Find out if igmp snooping configured
        command = "show run | sec bridge-domain"
        result = exec_command(command, devicename)
        check.finding = check.finding + result
        if len(result.splitlines()) > 3:
            command = "show run | i igmp.snoop"
            result = exec_command(command, devicename)
            check.finding = check.finding + result
            if result.find("ip igmp snooping") == -1:
                check.status = "Open"
                check.comments = (
                    check.comments
                    + "OPEN: Missing IGMP or MLD snooping for IPv4 and IPv6 multicast traffic respectively for each VPLS bridge domain.\n"
                )
            else:
                check.status = "NotAFinding"
                check.comments = (
                    check.comments
                    + "NAF: Found IGMP or MLD snooping for IPv4 and IPv6 multicast traffic respectively for each VPLS bridge domain.\n"
                )
        else:
            check.status = "NotAFinding"
            check.comments = check.comments + "NAF: No bridge domain configured.\n"

    else:
        check.status = "Not_Applicable"
        check.comments = (
            check.comments
            + "\n"
            + check.vulid
            + ":NA - Router is not providing L2 VFI services."
        )
    return check


def V216710(devicetype, devicename):
    # V-216710 - The Cisco PE router must be configured to limit the number of MAC addresses it can learn for each Virtual Private LAN Services (VPLS) bridge domain.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "NotAFinding"
    check.comments = (
        check.vulid
        + " - The Cisco PE router must be configured to limit the number of MAC addresses it can learn for each Virtual Private LAN Services (VPLS) bridge domain.\n"
    )
    strLDP = "NA"
    strVPLS = "NotAFinding"
    command = "show xconnect pwmib | exc pw"
    result = exec_command(command, devicename)
    check.finding = result
    # Find out if we have local ports terminating VPWS
    if len(result.splitlines()) > 5:
        # If we're running LDP lets get busy...
        # Find out if igmp snooping configured
        command = "show run | sec bridge-domain"
        result = exec_command(command, devicename)
        check.finding = check.finding + result
        if len(result.splitlines()) > 3:
            if result.find("mac limit maximum") == -1:
                check.status = "Open"
                check.comments = (
                    check.comments
                    + "OPEN: Missing IGMP or MLD snooping for IPv4 and IPv6 multicast traffic respectively for each VPLS bridge domain.\n"
                )
            else:
                check.status = "NotAFinding"
                check.comments = (
                    check.comments
                    + "NAF: Found IGMP or MLD snooping for IPv4 and IPv6 multicast traffic respectively for each VPLS bridge domain.\n"
                )
        else:
            check.status = "NotAFinding"
            check.comments = check.comments + "NAF: No bridge domain configured.\n"

    else:
        check.status = "Not_Applicable"
        check.comments = (
            check.comments
            + "\n"
            + check.vulid
            + ":NA - Router is not providing L2 VFI services."
        )
    return check

def V216711(devicetype, devicename):
    # V-216711 -  The Cisco PE router must be configured to block any traffic that is destined to IP core infrastructure.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Not_Applicable"
    # Find all physical interfaces that could be CE facig
    command = "show int desc | i up"
    result = exec_command(command, devicename)
    check.finding = result
    strIntStatus = "Not_Applicable"
    strPolicies = []
    strInterfaces = result.splitlines()
    bolHasSWAB = 0
    for line in strInterfaces:
        if len(line.split()) > 1:
            if (
                line.split()[0].find("Lo") == -1
                and line.split()[0].find("Tu") == -1
                and line.split()[0].find("RESERVED") == -1
                and line.split()[0].find("#") == -1
                and line.split()[0].find("pw") == -1
            ):
                command = (
                    "sh run int "
                    + line.split()[0]
                    + " | i vrf.forwarding|ip.verify.unicast.source.*.any|description|inter"
                )
                result = exec_command(command, devicename)
                check.finding = check.finding + result
                if result.find("SWAB") > -1:
                    bolHasSWAB = 1
                    strVRF = ""
                    strIntStatus = "NotAFinding"
                    # Right now this will always pass.  We can add a check for ACLs later if needed.
                    if result.find("SWAB") == -1:
                        strIntStatus = "Open"

                    for command in result.splitlines():
                        if command.find("vrf forwarding") > -1:
                            strVRF = command.split()[2]

                    check.comments = (
                        check.comments
                        + "Interface "
                        + line.split()[0]
                        + " is configured for VRF "
                        + strVRF
                    )
                    if strIntStatus == "Open":
                        check.comments = (
                            check.comments + " and does NOT have a VRF configured.\n"
                        )
                    else:
                        check.comments = (
                            check.comments
                            + ", which prevents core network elements from being accessible from any external hosts.\n"
                        )
    if bolHasSWAB == 0:
        check.status = "Not_Applicable"
        check.comments = (
            check.comments
            + check.vulid
            + " -Not Applicable - This is not a PE router so this check is not applicable.."
        )
    else:
        check.status = strIntStatus
        check.comments = (
            check.comments
            + check.vulid
            + " The Cisco PE router must be configured to block any traffic that is destined to IP core infrastructure."
        )
    return check


def V216712(devicetype, devicename):
    # V-216712 -  The Cisco PE router must be configured with Unicast Reverse Path Forwarding (uRPF) loose mode enabled on all CE-facing interfaces.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Not_Applicable"
    # Find all physical interfaces that could be CE facig
    command = "show int desc | i up"
    result = exec_command(command, devicename)
    check.finding = result
    strIntStatus = "Not_Applicable"
    strPolicies = []
    strInterfaces = result.splitlines()
    bolHasSWAB = 0
    for line in strInterfaces:
        if len(line.split()) > 1:
            if (
                line.split()[0].find("Lo") == -1
                and line.split()[0].find("Tu") == -1
                and line.split()[0].find("RESERVED") == -1
                and line.split()[0].find("#") == -1
                and line.split()[0].find("pw") == -1
            ):
                command = (
                    "sh run int "
                    + line.split()[0]
                    + " | i vrf.forwarding|ip.verify.unicast.source.*.any|inter"
                )
                result = exec_command(command, devicename)
                check.finding = check.finding + result
                if result.find("SWAB") > -1:
                    bolHasSWAB = 1
                    strVRF = ""
                    strIntStatus = "NotAFinding"

                    if result.find("ip verify unicast source") == -1:
                        strIntStatus = "Open"
                    # This is a CE facing interface based on a VRF defination.

                    for command in result.splitlines():
                        if command.find("vrf forwarding") > -1:
                            strVRF = command.split()[2]

                    check.comments = (
                        check.comments
                        + "Interface "
                        + line.split()[0]
                        + " is configured for VRF "
                        + strVRF
                    )
                    if strIntStatus == "Open":
                        check.comments = (
                            check.comments + " and does NOT have uRPF configured.\n"
                        )
                    else:
                        check.comments = check.comments + " and has uRPF configured.\n"
    if bolHasSWAB == 0:
        check.status = "Not_Applicable"
        check.comments = (
            check.comments
            + check.vulid
            + " -Not Applicable - This is not a PE router so this check is not applicable.."
        )
    else:
        check.status = strIntStatus
        check.comments = (
            check.comments
            + check.vulid
            + " -OPEN - The Cisco PE router must be configured with Unicast Reverse Path Forwarding (uRPF) loose mode enabled on all CE-facing interfaces."
        )
    # else:
    #    check.comments = check.comments + check.vulid + " -NAF - The Cisco PE router is configured with Unicast Reverse Path Forwarding (uRPF) loose mode enabled on all CE-facing interfaces."
    return check


def V216714(devicetype, devicename):
    # V-216714 - The Cisco P router must be configured to implement a Quality-of-Service (QoS) policy in accordance with the QoS DODIN Technical Profile.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    # Find all physical interfaces that could be configured for QoS
    command = "show int desc | i up"
    result = exec_command(command, devicename)
    check.finding = result
    strIntStatus = "Open"
    strPolicies = []
    strInterfaces = result.splitlines()
    for line in strInterfaces:
        if len(line.split()) > 1:
            if (
                line.split()[0].find("Lo") == -1
                and line.split()[0].find("Tu") == -1
                and line.split()[0].find("RESERVED") == -1
                and line.split()[0].find("#") == -1
                and line.split()[0].find("pw") == -1
            ):
                command = (
                    "sh run int "
                    + line.split()[0]
                    + " | i service-policy.input|service-policy.output|description|inter"
                )
                result = exec_command(command, devicename)
                check.finding = check.finding + result
                # Look for the config line that specifies policies.
                for command in result.splitlines():
                    if (
                        command.find("service-policy input") > -1
                        or command.find("service-policy output") > -1
                    ):
                        # If we have a QoS policy defined, add it to our list of QoS policies.
                        if command.split()[2] not in strPolicies:
                            strPolicies.append(command.split()[2])
                        check.status = "NotAFinding"
                        check.comments = (
                            check.comments
                            + "Found QoS policy on interface "
                            + line.split()[0]
                            + ".\n"
                        )

    if check.status == "Open":
        check.comments = (
            check.vulid
            + " -OPEN - The Cisco PE router must be configured to implement a Quality-of-Service (QoS) policy in accordance with the QoS DODIN Technical Profile."
        )
    else:
        for policy in strPolicies:
            command = "show run | sec policy-map." + policy.strip()
            result = exec_command(command, devicename)
            check.finding = check.finding + result
        check.comments = (
            check.comments
            + check.vulid
            + " -NAF - The Cisco PE router is configured to enforce a Quality-of-Service (QoS) policy."
        )
    return check


def V216715(devicetype, devicename):
    # V-216715 - The Cisco P router must be configured to implement a Quality-of-Service (QoS) policy in accordance with the QoS DODIN Technical Profile.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    # Find all physical interfaces that could be configured for QoS
    command = "show int desc | i up"
    result = exec_command(command, devicename)
    check.finding = result
    strIntStatus = "Open"
    strPolicies = []
    strInterfaces = result.splitlines()
    for line in strInterfaces:
        if len(line.split()) > 1:
            if (
                line.split()[0].find("Lo") == -1
                and line.split()[0].find("Tu") == -1
                and line.split()[0].find("RESERVED") == -1
                and line.split()[0].find("#") == -1
                and line.split()[0].find("pw") == -1
            ):
                command = (
                    "sh run int "
                    + line.split()[0]
                    + " | i service-policy.input|service-policy.output|description|inter"
                )
                result = exec_command(command, devicename)
                check.finding = check.finding + result
                # Look for the config line that specifies policies.
                for command in result.splitlines():
                    if (
                        command.find("service-policy input") > -1
                        or command.find("service-policy output") > -1
                    ):
                        # If we have a QoS policy defined, add it to our list of QoS policies.
                        if command.split()[2] not in strPolicies:
                            strPolicies.append(command.split()[2])
                        check.status = "NotAFinding"
                        check.comments = (
                            check.comments
                            + "Found QoS policy on interface "
                            + line.split()[0]
                            + ".\n"
                        )

    if check.status == "Open":
        check.comments = (
            check.vulid
            + " -OPEN - The Cisco P router must be configured to implement a Quality-of-Service (QoS) policy in accordance with the QoS DODIN Technical Profile."
        )
    else:
        for policy in strPolicies:
            command = "show run | sec policy-map." + policy.strip()
            result = exec_command(command, devicename)
            check.finding = check.finding + result
        check.comments = (
            check.comments
            + check.vulid
            + " -NAF - The Cisco P router is configured to implement a Quality-of-Service (QoS) policy."
        )
    return check


def V216716(devicetype, devicename):
    # V-216716 - The Cisco PE router must be configured to enforce a Quality-of-Service (QoS) policy to limit the effects of packet flooding denial of service (DoS) attacks.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run class-map | in class-map|dscp.cs1"
    result = exec_command(command, devicename)
    check.finding = result
    if result.find("cs1") > -1:
        check.status = "NotAFinding"
        check.comments = (
            check.vulid + " -NAF - QoS is configured to enforce a QoS policy to limit the effects of packet flooding DoS attacks."
        )
    else:
        check.comments = check.vulid + " -OPEN - QoS is NOT configured to enforce a QoS policy to limit the effects of packet flooding DoS attacks."
    return check


def V216717(devicetype, devicename):
    # V-216717 -  The Cisco multicast router must be configured to disable Protocol Independent Multicast (PIM) on all interfaces that are not required to support multicast routing.
    check = Stig()
    result = ""
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    strPIMInterfaces = []
    # Find all physical interfaces running PIM
    command = "show ip pim interface | exc Tunn|Loop"
    result = exec_command(command, devicename)
    check.finding = result
    strIntStatus = "NotAFinding"
    # If we have pim running on an interface, we need to check.  Else Not applicable.
    if result.find("v2/SD") > -1:
        strPIMInterfaces = result.splitlines()
        for interface in strPIMInterfaces:
            if len(interface.split()) > 1:
                if (
                    interface.split()[1].find("Ether") > -1
                    or interface.split()[1].find("Port") > -1
                ):
                    command = "sh run int " + interface.split()[1]
                    result = exec_command(command, devicename)
                    check.finding = check.finding + result
                    if (
                        result.find("shutdown") == -1
                        and result.find("TIER0") == -1
                    ):
                        strIntStatus = "Open"
                        check.comments = (
                            check.comments
                            + "PIM appears to be on an EGRESS interface "
                            + interface.split()[1]
                            + ".\n"
                        )
        if strIntStatus == "NotAFinding":
            check.comments = (
                check.vulid
                + "- NAF - The Cisco multicast router either has (PIM) neighbor filter configured or a disabled interface."
            )
            check.status = "NotAFinding"
        else:
            check.comments = (
                check.comments
                + check.vulid
                + "- OPEN - The Cisco multicast router must be configured to disable Protocol Independent Multicast (PIM) on all interfaces that are not required to support multicast routing.."
            )
            check.status = "Open"
    else:
        check.status = "Not_Applicable"
        check.comments = (
            check.comments
            + check.vulid
            + "- NA - Router does not have multicast configured"
        )
    return check


def V216718(devicetype, devicename):
    # V-216718 -  The Cisco multicast router must be configured to bind a Protocol Independent Multicast (PIM) neighbor filter to interfaces that have PIM enabled..
    check = Stig()
    result = ""
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    strPIMInterfaces = []
    # Find all physical interfaces running PIM
    command = "show ip pim interface | exc Tunn|Loop"
    result = exec_command(command, devicename)
    check.finding = result
    strIntStatus = "NotAFinding"
    # If we have pim running on an interface, we need to check.  Else Not applicable.
    if result.find("v2/SD") > -1:
        strPIMInterfaces = result.splitlines()
        for interface in strPIMInterfaces:
            if len(interface.split()) > 1:
                if (
                    interface.split()[1].find("Ether") > -1
                    or interface.split()[1].find("Port") > -1
                ):
                    command = "sh run int " + interface.split()[1]
                    result = exec_command(command, devicename)
                    check.finding = check.finding + result
                    if (
                        result.find("shutdown") == -1
                        and result.find("ip pim neighbor-filter") == -1
                    ):
                        strIntStatus = "Open"
                        check.comments = (
                            check.comments
                            + "Could not find a pim filter on interface "
                            + interface.split()[1]
                            + ".\n"
                        )
        if strIntStatus == "NotAFinding":
            check.comments = (
                check.vulid
                + "- NAF - The Cisco multicast router either has (PIM) neighbor filter configured or a disabled interface."
            )
            check.status = "NotAFinding"
        else:
            check.comments = (
                check.comments
                + check.vulid
                + "- OPEN - The Cisco multicast router must have a (PIM) neighbor filter applied to interfaces that have PIM enabled."
            )
            check.status = "Open"
    else:
        check.status = "Not_Applicable"
        check.comments = (
            check.comments
            + check.vulid
            + "- NA - Router does not have multicast configured"
        )
    return check


def V216719(devicetype, devicename):
    # V-216719 -  The Cisco multicast edge router must be configured to establish boundaries for administratively scoped multicast traffic.
    check = Stig()
    result = ""
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    command = "sh run | i snmp.*.location"
    result = exec_command(command, devicename)
    check.finding = result
    if result.find("RT1") > -1 or result.find("RT1") > -1:
        check.comments = "This router is a external facing router.\n"
        command = "show run | i ip.pim"
        result = exec_command(command, devicename)
        check.finding = check.finding + result
        # Find the interface egressing the network.
        # Then check if it has PIM configured.
        # Still TBD!!!!!!!!!!!!!!
        if result.find("pim rp-address") > -1:
            command = "sh run  | inc ip.pim.accept-register.list"
            if result.find("pim accept-register list") > -1:
                check.status = "NotAFinding"
                check.comments = (
                    check.vulid
                    + "- OPEN - The Cisco multicast edge router must be configured to establish boundaries for administratively scoped multicast traffic.."
                )
            else:
                check.status = "Open"
                check.comments = (
                    check.vulid
                    + "- NAF - The Cisco multicast edge router is configured to establish boundaries for administratively scoped multicast traffic."
                )
        else:
            check.status = "Not_Applicable"
            check.comments = (
                check.comments
                + check.vulid
                + "- NA - Router  does not have multicast configured.."
            )
    else:
        check.status = "Not_Applicable"
        check.comments = (
            check.vulid
            + "- NA - Router is not a multicast edge or it does not have multicast configured.."
        )
    check.finding = result
    return check


def V216720(devicetype, devicename):
    # V-216720 -  router must be configured to limit the multicast forwarding cache so that its resources are not saturated.
    check = Stig()
    result = ""
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    command = "sh run | in pim.rp"
    result = exec_command(command, devicename)
    # Find the DR interfaces
    if result.find("pim rp-address") > -1:
        command = "sh run  | inc ip.pim.accept-register.list"
        if result.find("pim accept-register list") > -1:
            check.status = "NotAFinding"
            check.comments = (
                check.vulid
                + "- OPEN - The router must be configured to limit the multicast forwarding cache so that its resources are not saturated."
            )
        else:
            check.status = "Open"
            check.comments = (
                check.vulid
                + "- NAF - router is configured to limit the multicast forwarding cache so that its resources are not saturated."
            )
    else:
        check.status = "Not_Applicable"
        check.comments = (
            check.vulid + "- NA - Router does not have multicast configured"
        )
    check.finding = result
    return check


def V216721(devicetype, devicename):
    # V-216721 -  The Cisco multicast Rendezvous Point (RP) router must be configured to filter Protocol Independent Multicast (PIM) Register messages received from the Designated Router (DR) for any undesirable multicast groups and sources.
    check = Stig()
    result = ""
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    command = "sh run | in pim.rp"
    result = exec_command(command, devicename)
    # Find the DR interfaces
    if result.find("pim rp-address") > -1:
        command = "sh run  | inc ip.pim.accept-register.list"
        if result.find("pim accept-register list") > -1:
            check.status = "NotAFinding"
            check.comments = (
                check.vulid
                + "- OPEN - router must be configured to filter Protocol Independent Multicast (PIM) Register messages "
            )
        else:
            check.status = "Open"
            check.comments = (
                check.vulid
                + "- NAF - router is configured to filter Protocol Independent Multicast (PIM) Register messages "
            )
    else:
        check.status = "Not_Applicable"
        check.comments = (
            check.vulid + "- NA - Router does not have multicast configured"
        )
    check.finding = result
    return check


def V216722(devicetype, devicename):
    # V-216722 - The Cisco multicast Designated Router (DR) must be configured to limit the number of mroute states resulting from Internet Group Management Protocol (IGMP) and Multicast Listener Discovery (MLD) Host Membership Reports.
    check = Stig()
    result = ""
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    command = "sh run | in pim.rp"
    result = exec_command(command, devicename)
    # Find the DR interfaces
    if result.find("pim rp-address") > -1:
        command = "sh run  | inc pim.accept-rp"
        if result.find("pim accept-rp") > -1:
            check.status = "NotAFinding"
            check.comments = (
                check.vulid
                + "- OPEN - RP is configured to filter join messages received from the DR for any undesirable multicast groups"
            )
        else:
            check.status = "Open"
            check.comments = (
                check.vulid
                + "- NAF - RP is not configured to filter join messages received from the DR for any undesirable multicast groups"
            )
    else:
        check.status = "Not_Applicable"
        check.comments = (
            check.vulid + "- NA - Router does not have multicast configured"
        )
    check.finding = result
    return check


def V216723(devicetype, devicename):
    # V-216723 - The Cisco multicast Rendezvous Point (RP) must be configured to rate limit the number of Protocol Independent Multicast (PIM) Register messages.
    check = Stig()
    temp = ""
    result = ""
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run | in igmp.join"
    temp = exec_command(command, devicename)
    # Find the DR interfaces
    if len(temp.splitlines()) > 4:
        for pimneigh in temp.splitlines():
            if pimneigh.find("Address") == -1 and pimneigh.find("DR") > -1:
                # If a PIM neighbor is a DR, check the interface for IGMP limit.
                command = (
                    "sh run interface " + pimneigh.split()[1] + " | inc igmp.limit"
                )
                result = result + "\r" + exec_command(command, devicename)
                if result.find("igmp limit") > -1:
                    check.status = "NotAFinding"
                    check.comments = (
                        check.comments
                        + check.vulid
                        + "- NAF - DR interface "
                        + pimneigh.split()[1]
                        + " RP is limiting PIM register messages.\n"
                    )
                else:
                    check.status = "Open"
                    check.comments = (
                        check.comments
                        + check.vulid
                        + "- OPEN - DR interface "
                        + pimneigh.split()[1]
                        + " RP is not limiting PIM register messages.\n"
                    )
    else:
        check.status = "Not_Applicable"
        check.comments = check.vulid + "- NA - Router is not configured for multicast."
    check.finding = temp + result
    return check


def V216724(devicetype, devicename):
    # V-216724 - The Cisco multicast Designated Router (DR) must be configured to filter the Internet Group Management Protocol (IGMP) and Multicast Listener Discovery (MLD) Report messages to allow hosts to join only multicast groups that have been approved by the organization.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Not_Applicable"
    command = "sh run | in igmp.join"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-216724 - NA - COMMENTS: This requirement is only applicable to Source Specific Multicast (SSM) implementation."
    return check


def V216725(devicetype, devicename):
    # V-216725 - The Cisco multicast Designated Router (DR) must be configured to filter the Internet Group Management Protocol (IGMP) and Multicast Listener Discovery (MLD) Report messages to allow hosts to join a multicast group only from sources that have been approved by the organization.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Not_Applicable"
    command = "sh run | in igmp.join"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-216725 - NA - COMMENTS: This requirement is only applicable to Source Specific Multicast (SSM) implementation."
    return check


def V216726(devicetype, devicename):
    # V-216726 - The Cisco multicast Designated Router (DR) must be configured to limit the number of mroute states resulting from Internet Group Management Protocol (IGMP) and Multicast Listener Discovery (MLD) Host Membership Reports.
    check = Stig()
    temp = ""
    result = ""
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    command = "sh run | in igmp.join"
    temp = exec_command(command, devicename)
    # Find the DR interfaces
    if len(temp.splitlines()) > 4:
        for pimneigh in temp.splitlines():
            if pimneigh.find("Address") == -1 and pimneigh.find("DR") > -1:
                # If a PIM neighbor is a DR, check the interface for IGMP limit.
                command = (
                    "sh run interface " + pimneigh.split()[1] + " | inc igmp.limit"
                )
                result = result + "\r" + exec_command(command, devicename)
                if result.find("igmp limit") > -1:
                    check.status = "NotAFinding"
                    check.comments = (
                        check.comments
                        + check.vulid
                        + "- NAF - DR interface "
                        + pimneigh.split()[1]
                        + " is configured to limit the number of mroute states.\n"
                    )
                else:
                    check.status = "Open"
                    check.comments = (
                        check.comments
                        + check.vulid
                        + "- OPEN - DR interface "
                        + pimneigh.split()[1]
                        + " is not configured to limit the number of mroute states.\n"
                    )
    else:
        check.status = "Not_Applicable"
        check.comments = check.vulid + "- NA - Router is not configured for multicast."
    check.finding = temp + result
    return check


def V216727(devicetype, devicename):
    # V-216727 - The Cisco multicast Designated Router (DR) must be configured to limit the number of mroute states resulting from Internet Group Management Protocol (IGMP) and Multicast Listener Discovery (MLD) Host Membership Reports.
    check = Stig()
    temp = ""
    result = ""
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    command = "sh run | in pim.rp"
    temp = exec_command(command, devicename)
    # Find the DR interfaces
    if len(temp.splitlines()) > 2:
        command = "sh run  | inc pim.spt-threshold"
        result = result + "\r" + exec_command(command, devicename)
        if result.find("pim spt-threshold infinity") > -1:
            check.status = "NotAFinding"
            check.comments = (
                check.vulid
                + "- NAF - DR is configured to increase the SPT threshold or set to infinity to minimalize (S, G) state"
            )
        if result.find("pim spt-threshold infinity") == -1:
            check.status = "Open"
            check.comments = (
                check.vulid
                + "- OPEN - DR is not configured to increase the SPT threshold or set to infinity to minimalize (S, G) state"
            )
        else:
            check.status = "Not_Applicable"
            check.comments = check.vulid + "- NA - Router is not a DR."
    else:
        check.status = "Not_Applicable"
        check.comments = check.vulid + "- NA - Router does not have a PIM RP configured"
    check.finding = temp + result
    return check


def V216728(devicetype, devicename):
    # V-216728 -  The Cisco Multicast Source Discovery Protocol (MSDP) router must be configured to only accept MSDP packets from known MSDP peers.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = ""
    check.comments = ""
    command = "sh run | in ip.msdp"
    result = exec_command(command, devicename)
    check.finding = result
    if result.find("password") == -1:
        check.status = "Open"
        check.comments = "V-216728 - OPEN - The router is not configured to only accept MSDP packets from known MSDP peers"
    if result.find("password") > -1:
        check.status = "NotAFinding"
        check.comments = "V-216728 - NAF - The router is configured to only accept MSDP packets from known MSDP peers"
    else:
        check.status = "Not_Applicable"
        check.comments = "V-216728 - NA - The router is not configured as a MSDP router"
    return check


def V216729(devicetype, devicename):
    # V-216729 -  The Cisco Multicast Source Discovery Protocol (MSDP) router must be configured to authenticate all received MSDP packets.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = ""
    check.comments = ""
    command = "sh run | in ip.msdp"
    result = exec_command(command, devicename)
    check.finding = result
    if result.find("password") == -1:
        check.status = "Open"
        check.comments = (
            "V-216729 - OPEN - The router does not require MSDP authentication"
        )
    if result.find("password") > -1:
        check.status = "NotAFinding"
        check.comments = "V-216729 - NAF - The router does require MSDP authentication"
    else:
        check.status = "Not_Applicable"
        check.comments = "V-216729 - NA - The router is not configured as a MSDP router"
    return check


def V216730(devicetype, devicename):
    # V-216730 -  The Cisco Multicast Source Discovery Protocol (MSDP) router must be configured to filter received source-active multicast advertisements for any undesirable multicast groups and sources.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = ""
    check.comments = ""
    command = "sh run | in ip.msdp"
    result = exec_command(command, devicename)
    check.finding = result
    if result.find("msdp sa-filter") == -1:
        check.status = "Open"
        check.comments = "V-216730 - OPEN - The router is not configured with an import policy to filter undesirable SA multicast advertisements"
    if result.find("msdp sa-filter") > -1:
        check.status = "NotAFinding"
        check.comments = "V-216730 - NAF - The router is configured with an import policy to filter undesirable SA multicast advertisements"
    else:
        check.status = "Not_Applicable"
        check.comments = "V-216730 - NA - The router is not configured as a MSDP router"
    return check


def V216731(devicetype, devicename):
    # V-216731 -  The Cisco Multicast Source Discovery Protocol (MSDP) router must be configured to filter source-active multicast advertisements to external MSDP peers to avoid global visibility of local-only multicast sources and groups.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = ""
    check.comments = ""
    command = "sh run | in ip.msdp"
    result = exec_command(command, devicename)
    check.finding = result
    if result.find("msdp sa-filter") == -1:
        check.status = "Open"
        check.comments = "V-216731 - OPEN - The router is not configured with an export policy to filter local source-active multicast advertisements"
    if result.find("msdp sa-filter") > -1:
        check.status = "NotAFinding"
        check.comments = "V-216731 - NAF - The router is configured with an export policy to filter local source-active multicast advertisements"
    else:
        check.status = "Not_Applicable"
        check.comments = "V-216731 - NA - The router is not configured as a MSDP router"
    return check


def V216732(devicetype, devicename):
    # V-216732 -  The Cisco Multicast Source Discovery Protocol (MSDP) router must be configured to limit the amount of source-active messages it accepts on a per-peer basis.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = ""
    check.comments = ""
    command = "sh run | in ip.msdp"
    result = exec_command(command, devicename)
    check.finding = result
    if result.find("msdp sa-limit") == -1:
        check.status = "Open"
        check.comments = "V-216732 - OPEN - The router is not configured to limit the source-active messages it accepts"
    if result.find("msdp sa-limit") > -1:
        check.status = "NotAFinding"
        check.comments = "V-216732 - NAF - The router is configured to limit the source-active messages it accepts"
    else:
        check.status = "Not_Applicable"
        check.comments = "V-216732 - NA - The router is not configured as a MSDP router"
    return check


def V216733(devicetype, devicename):
    # V-216733 -  The Cisco Multicast Source Discovery Protocol (MSDP) router must be configured to use a loopback address as the source address when originating MSDP traffic.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = ""
    check.comments = ""
    command = "sh run | in ip.msdp"
    result = exec_command(command, devicename)
    check.finding = result
    if result.find("loopback") == -1:
        check.status = "Open"
        check.comments = "V-216733 - OPEN - The router does not use its loopback address as the source address when originating MSDP traffic"
    if result.find("loopback") > -1:
        check.status = "NotAFinding"
        check.comments = "V-216733 - NAF - The router does use its loopback address as the source address when originating MSDP traffic"
    else:
        check.status = "Not_Applicable"
        check.comments = "V-216733 - NA - The router is not configured as a MSDP router"
    return check


def V216994(devicetype, devicename):
    # V-216994 - The Cisco router must be configured to implement message authentication for all control plane protocols.
    check = Stig()
    check.vulid = format_vulid()
    check.comments = ""
    check.status = "Open"
    bolEIGRP = False
    bolOSPF = False
    isEIGRP = False
    isOSPF = False
    isBGP = False
    temp1 = temp2 = temp3 = temp4 = ""
    command = "sh ip eigrp neighbors"
    result = exec_command(command, devicename)
    if len(result.splitlines()) > 3:
        isEIGRP = True
    temp1 = result
    command = "sh ip ospf neighbor"
    result = exec_command(command, devicename)
    if len(result.splitlines()) > 3:
        isOSPF = True
    command = "sh bgp all summ"
    result = exec_command(command, devicename)
    if len(result.splitlines()) > 3:
        isBGP = True
    if (isEIGRP == False) and (isOSPF == False) and (isBGP == False):
        check.status = "Not_Applicable"
        check.comments = " Neither EIGRP, OSPF, or BGP is is use.  No control plane protocol configured."
    else:
        if isEIGRP == True:
            temp2 = result
            command = "sh run | sec router.eigrp"
            result = exec_command(command, devicename)
            check.finding = result
            if (
                result.find("authentication mode", len(devicename) + len(command))
                > -1
            ):
                check.comments = "V-216994 - NAF - EIGRP authentication is enabled"
                bolEIGRP = False
            else:
                check.comments = "V-216994 - OPEN - EIGRP authentication is not enabled"
                bolEIGRP = True
        if isOSPF == True:
            temp3 = result
            command = "sh run | sec router.ospf "
            result = exec_command(command, devicename)
            if result.find("message-digest", len(devicename) + len(command)) > -1:
                check.comments = "V-216994 - NAF - OSPF authentication is enabled"
                bolOSPF = False
            else:
                check.comments = "V-216994 - OPEN - OSPF authentication is not enabled"
                bolOSPF = True
        if isBGP == True:
            temp4 = result
            command = "sh run | sec router.bgp"
            # Replace password with ***REMOVED***
            strClean = ""
            result = ""
            temp = exec_command(command, devicename)
            for line in temp.splitlines():
                if line.find("password") > 1:
                    strClean = (
                        line[0 : line.find("password")]
                        + "password <-----***REMOVED***----->"
                    )
                    bolPassword = 1
                else:
                    strClean = line
                result = result + "\n" + strClean
            check.finding = result
            if result.find("password", len(devicename) + len(command)) == -1:
                check.status = "Open"
                check.comments = (
                    check.comments + " and BGP authentication is not enabled"
                )
            else:
                if isEIGRP == True:
                    if bolEIGRP == False:
                        check.comments = (
                            check.comments + " and BGP authentication is enabled"
                        )
                        check.status = "NotAFinding"
                    if bolEIGRP == True:
                        check.comments = (
                            check.comments + " and BGP authentication is enabled"
                        )
                        check.status = "Open"
                if isOSPF == True:
                    if bolOSPF == False:
                        check.comments = (
                            check.comments + " and BGP authentication is enabled"
                        )
                        check.status = "NotAFinding"
                    if bolOSPF == True:
                        check.comments = (
                            check.comments + " and BGP authentication is enabled"
                        )
                        check.status = "Open"
    result = temp1 + temp2 + temp3 + temp4 + result
    check.finding = result
    return check


def V216995(devicetype, devicename):
    # V-216995 - The Cisco router must be configured to use keys with a duration not exceeding 180 days for authenticating routing protocol messages.
    # create a list of active keychains
    # Loop through each keychain, and show keys
    # 2 keys = a return length of 9.  If greater, we have more than 2 keys
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"
    check.comments = (
        "V-216995 - OPEN - Router has keys with lifetime of more than 180 days"
    )
    KeyChain = []
    numChains = 0
    numTooManyKeys = 0
    command = "sh key chain | i Key-"
    result = exec_command(command, devicename)
    temp = result
    for line in result.splitlines():
        if line.find("Key-chain") > -1:
            KeyChain.append(line[line.find(" ") : line.find(":")].strip())
    for chain in KeyChain:
        numChains = numChains + 1
        command = "show key chain " + chain
        result = exec_command(command, devicename)
        temp = temp + "\r" + result
        if len(result.splitlines()) > 11:
            numTooManyKeys = numTooManyKeys + 1
    check.finding = temp
    check.comments = (
        "Found "
        + str(numChains)
        + " keychains, of which "
        + str(numTooManyKeys)
        + " contained more than two keys."
    )
    numTooManyKeys = 0
    if numTooManyKeys == 0:
        check.status = "NotAFinding"
        check.comments = (
            "V-216995 - NAF - Router keys are within the lifetime of 180 days"
        )
    return check


# def V216996(devicetype, devicename):
    # V-216996 - A service or feature that calls home to the vendor must be disabled.
    # check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    # check.vulid = format_vulid()
    # check.comments = "V-216996 - OPEN - Call-Home is not disbaled"
    # check.status = "Open"
    # command = "sh run all | i call-home"
    # result = exec_command(command, devicename)
    # check.finding = result
    # if result.find("no service call-home", len(devicename) + len(command)) > -1:
        # check.status = "NotAFinding"
        # check.comments = "V-216996 - NAF - Call-Home is disabled"
    # return check


def V216997(devicetype, devicename):
    # V-216997 -  The Cisco perimeter router must be configured to restrict it from accepting outbound IP packets that contain an illegitimate address in the source address field via egress filter or by enabling Unicast Reverse Path Forwarding (uRPF).
    check = Stig()
    check.vulid = format_vulid()
    check.comments = "V-216997 - OPEN - uRPF or an egress ACL has not been configured on all internal interfaces to restrict the router from accepting outbound IP packets"
    check.status = "Open"
    command = "show run | i snmp.*.location"
    result = exec_command(command, devicename)
    check.finding = result
    # Check if we're a perimeter router.
    if result.find("RT1") == -1:
        check.status = "NotAFinding"
        check.comments = (
            check.vulid + " - NAF as this device is not a perimeter router."
        )
    else:
        command = "sh run | in unicast.source"
        result = exec_command(command, devicename)
        check.finding = check.finding + result
        if result.find("unicast", len(devicename) + len(command)) > -1:
            check.status = "NotAFinding"
            check.comments = "V-216997 - NAF - uRPF or an egress ACL has not been configured on all internal interfaces to restrict the router from accepting outbound IP packets"
    return check


def V216998(devicetype, devicename):
    # V-216998 -  The Cisco perimeter router must be configured to block all packets with any IP options.
    check = Stig()
    check.vulid = format_vulid()
    check.comments = "V-216998 - OPEN - The router is not configured to drop all packets with IP options"
    check.status = "Open"
    command = "show run | i snmp.*.location"
    result = exec_command(command, devicename)
    # Check if we're a perimeter router.  If not no ACLs are required
    if result.find("RT1", len(devicename) + len(command)) == -1:
        check.status = "NotAFinding"
        check.comments = (
            check.vulid + " - NAF as this device is not a perimeter router."
        )
    else:
        command = "sh access-lists | i option"
        result = exec_command(command, devicename)
        check.finding = result
        if result.find("option", len(devicename) + len(command)) > -1:
            check.status = "NotAFinding"
            check.comments = "V-216998 - NAF - The router is configured to drop all packets with IP options"
    return check


def V216999(devicetype, devicename):
    # V-216999-  The Cisco BGP router must be configured to enable the Generalized TTL Security Mechanism (GTSM).
    check = Stig()
    MsgBox = crt.Dialog.MessageBox
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "NotAFinding"
    strBGP_AS = "0"
    check.comments = ""
    # Lets find out if the BGP routing protocols is in use
    command = "show ip proto | i Routing.Protoc"
    result = exec_command(command, devicename)
    # Identify BGP routing protocols is in use and save applicable AS
    for line in result.splitlines():
        line = line.replace('"', "")
        if line.find("bgp") > -1:
            strBGP_AS = line.replace('"', "").split()[-1]
    # Time to verify all eBGP neighbors are using ttl-security hops
    # strBGP_neighbor = []
    # strBGP_sessions = []2266
    strBGP_Findings = ""
    strBGP_status = "NotAFinding"
    if int(strBGP_AS) > 0:
        # Look for all the mBGP neighbors on BlackCore routers
        command = "sh bgp vpnv4 unicast all summ | b Neighbor"
        result = exec_command(command, devicename)
        if result.find("Invalid") > -1:
            # Look for all the eBGP neighbors on Colored routers
            command = "sh bgp ipv4 unicast summ | b Neighbor"
            result = exec_command(command, devicename)
        strBGP_Findings = strBGP_Findings + result + "\n"
        strBGP_neighbor_status = "Open"
        for neighbor in result.splitlines():
            strBGP_neighbor_status = "Open"
            if (
                neighbor.find("#") == -1
                and neighbor.find("Neighbor") == -1
                and len(neighbor.split()) > 3
            ):
                if neighbor.find(strBGP_AS) == -1:
                    # If a host is an external BGP neighbor, make sure there is a ttl-security hop configured for neighbor.
                    command = (
                        "sh run | in neighbor.*." + neighbor.split()[0] + ".*.ttl"
                    )
                    result = exec_command(command, devicename)
                    strBGP_Findings = strBGP_Findings + result + "\n"
                    # If there's a ttl-security hop defined then we can clear this neighbor
                    if result.find("ttl-security hops") > -1:
                        strBGP_neighbor_status = "NotAFinding"
                        check.comments = (
                            check.comments
                            + "BGP neighbor "
                            + neighbor.split()[0]
                            + " is configured to use ttl-security hop.\n"
                        )
                if neighbor.find(strBGP_AS) > -1:
                    # If a host is an internal BGP neighbor, ttl-security hop is not required.
                    strBGP_neighbor_status = "NotAFinding"
                    check.comments = (
                        check.comments
                        + "BGP neighbor "
                        + neighbor.split()[0]
                        + " is an internal BGP neighbor.\n"
                    )
                if strBGP_neighbor_status == "Open":
                    strBGP_status = "Open"
                    check.comments = (
                        check.comments
                        + "Could not find ttl-security hop for neighbor "
                        + neighbor.split()[0]
                        + ".\n"
                    )
        if strBGP_status != "NotAFinding":
            check.status = "Open"
        check.finding = strBGP_Findings
        # check.comments = "V-216999 - CAT II - The Cisco router must be configured to use encryption for routing protocol authentication."
    return check


def V217000(devicetype, devicename):
    # V-217000 - The Cisco BGP router must be configured to use a unique key for each autonomous system (AS) that it peers with.
    check = Stig()
    temp = ""
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Open"
    check.comments = "V-217000 - The router is not using unique keys within the same or between autonomous systems (AS)."
    command = "sh run | sec bgp"
    #
    # Replace password with ***REMOVED***
    bolPassword = 0
    strClean = ""
    result = ""
    temp = exec_command(command, devicename)
    for line in temp.splitlines():
        if line.find("password") > 1:
            strClean = (
                line[0 : line.find("password")] + "password <-----***REMOVED***----->"
            )
            bolPassword = 1
        else:
            strClean = line
        #
        result = result + "\n" + strClean
    check.finding = result
    if (
        len(result.splitlines()) < 3
        or result.find("password ", len(devicename + "#" + command)) > -1
    ):
        if bolPassword == 1:
            check.comments = "V-217000 - NAF - The router is using unique keys within the same or between autonomous systems (AS)."
        else:
            check.comments = "V-217000 - NAF - BGP not running."
        check.status = "NotAFinding"
    return check


def V217001(devicetype, devicename):
    # V-217001 - The Cisco PE router must be configured to ignore or drop all packets with any IP options.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    MsgBox = crt.Dialog.MessageBox
    check.vulid = format_vulid()
    check.status = "Open"
    check.comments = "V-217001 - OPEN - The router is not configured to drop or block all packets with IP options"
    command = "sh run | in ip options"
    result = exec_command(command, devicename)
    # Find services that are not disabled
    if (
        result.find("ip options ignore", len(devicename) + len(command))
        or result.find("ip options drop", len(devicename) + len(command)) > -1
    ):
        check.status = "NotAFinding"
        check.comments = "V-217001 - NAF -The router is configured to drop or block all packets with IP options"
    check.finding = result
    return check


def V229031(devicetype, devicename):
    # V-229031 - The Cisco router must be configured to have Cisco Express Forwarding enabled.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    MsgBox = crt.Dialog.MessageBox
    check.vulid = format_vulid()
    check.status = "Open"
    check.comments = "V-229031 - OPEN - The router does not have CEF enabled."
    command = "sh ip cef summ"
    result = exec_command(command, devicename)
    # Find services that are not disabled
    if result.find("IPv4 CEF is enabled", len(devicename) + len(command)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-229031 - NAF -The router has CEF enabled."
    check.finding = result
    return check


def V230039(devicetype, devicename):
    # V-230039 - The Cisco router must be configured to advertise a hop limit of at least 32 in Router Advertisement messages for IPv6 stateless auto-configuration deployments.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    MsgBox = crt.Dialog.MessageBox
    check.vulid = format_vulid()
    check.status = "Open"
    check.comments = "V-230039 - OPEN - The router has not been configured and has not been set to at least 32."
    command = "sh run | in ipv6.hop-limit"
    result = exec_command(command, devicename)
    # Find services that are not disabled
    if result.find("ipv6 hop-limit", len(devicename) + len(command)) > -1:
        check.status = "NotAFinding"
        check.comments = "V-230039 - NAF - The router has been configured and has been set to at least 32."
    check.finding = result
    return check


def V230042(devicetype, devicename):
    # V-230042 - The Cisco router must not be configured to use IPv6 Site Local Unicast addresses.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    MsgBox = crt.Dialog.MessageBox
    check.vulid = format_vulid()
    check.status = "Open"
    check.comments = "V-230042 - OPEN -  IPv6 Site Local Unicast addresses are defined"
    command = "sh run | in FEC0::"
    result = exec_command(command, devicename)
    # Find services that are not disabled
    if result.find("FEC0::", len(devicename) + len(command)) == -1:
        check.status = "NotAFinding"
        check.comments = (
            "V-230042 - NAF -  IPv6 Site Local Unicast addresses are not defined"
        )
    check.finding = result
    return check


def V230045(devicetype, devicename):
    # V-230045 - The Cisco perimeter router must be configured to suppress Router Advertisements on all external IPv6-enabled interfaces.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Not_Applicable"
    command = "sh ipv6 access-list"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-230045 - NA - COMMENTS: No external interface is configured with ipv6 on this router."
    return check


def V230048(devicetype, devicename):
    # V-230048 - The Cisco perimeter router must be configured to drop IPv6 undetermined transport packets.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Not_Applicable"
    command = "sh ipv6 access-list"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-230048 - NA - COMMENTS: No inbound interface is configured with ipv6 on this router."
    return check


def V230051(devicetype, devicename):
    # V-230051 - The Cisco perimeter router must be configured drop IPv6 packets with a Routing Header type 0, 1, or 3–255.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Not_Applicable"
    command = "sh ipv6 access-list"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-230051 - NA - COMMENTS: No inbound interface is configured with ipv6 on this router."
    return check


def V230146(devicetype, devicename):
    # V-230146 - The Cisco perimeter router must be configured to drop IPv6 packets containing a Hop-by-Hop header with invalid option type values.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Not_Applicable"
    command = "sh ipv6 access-list"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-230146 - NA - COMMENTS: No inbound interface is configured with ipv6 on this router."
    return check


def V230150(devicetype, devicename):
    # V-230150 - The Cisco perimeter router must be configured to drop IPv6 packets containing a Destination Option header with invalid option type values.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Not_Applicable"
    command = "sh ipv6 access-list"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-230150 - NA - COMMENTS: No inbound interface is configured with ipv6 on this router."
    return check


def V230153(devicetype, devicename):
    # V-230153 - The Cisco perimeter router must be configured to drop IPv6 packets containing an extension header with the Endpoint Identification option.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Not_Applicable"
    command = "sh ipv6 access-list"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-230153 - NA - COMMENTS: No inbound interface is configured with ipv6 on this router."
    return check


def V230156(devicetype, devicename):
    # V-230156 - The Cisco perimeter router must be configured to drop IPv6 packets containing the NSAP address option within Destination Option header.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Not_Applicable"
    command = "sh ipv6 access-list"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-230156 - NA - COMMENTS: No inbound interface is configured with ipv6 on this router."
    return check


def V230159(devicetype, devicename):
    # V-230159 - The Cisco perimeter router must be configured to drop IPv6 packets containing a Hop-by-Hop or Destination Option extension header with an undefined option type.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
    check.status = "Not_Applicable"
    command = "sh ipv6 access-list"
    result = exec_command(command, devicename)
    check.finding = result
    check.comments = "V-230159 - NA - COMMENTS: No inbound interface is configured with ipv6 on this router."
    return check


def Vtemplate(devicetype, devicename):
    # Info about Vulnerability.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Not_Reviewed"
    command = "sh run| i aaa authentic"
    # if devicetype == "NXOS":
    #    command = "sh run | i \"aaa authentic\""
    result = exec_command(command, devicename)
    check.finding = result
    # Time to check the results of the command...   save check status to check.status and commants to check.comments
    # if len(result1.splitlines()) < 3 and len(result2.splitlines()) < 3:
    # 	check.status = "NotAFinding"
    # 	check.comments = "NAF - There are no community or user accounts."
    # if result.find("logging level", len(devicename + "#" + command)) > -1:
    #        check.status = "NotAFinding"
    #        check.comments = "NXOS logging enabled."
    #
    return check



"""
***************IOS XE ROUTER CHECK END************
"""      



# ----------------------------------------------------------------------------------------
def Is_It_Int(s):
    try:
        int(s)
        return True
    except ValueError:
        return False


def remove_dup(duplicate):
    final_list = []
    for num in duplicate:
        if num not in final_list:
            final_list.append(num)
    return final_list


def remove_char(x):
    Output = re.sub("\D", "", x)
    return Output

  
def format_vulid():
    return f"{inspect.stack()[1].function[:1]}-{inspect.stack()[1].function[1:]}"    

def get_script_path():
    # Get the current script's directory using SecureCRT's scripting API
    script_dir = crt.ScriptFullName
    return os.path.dirname(script_dir)

strFilePath = get_script_path()

# Append the script's directory to sys.path
sys.path.append(strFilePath)

def read_function_names_from_ckl(ckl_filename):
    """Reads the Vuln_Num values from the CKL file and returns them in the V###### format."""
    function_names = []
    
    # Create the full path to the CKL file
    full_ckl_path = os.path.join(strFilePath, ckl_filename)
    # Read the CKL file
    tree = ET.parse(full_ckl_path)
    root = tree.getroot()
    for vuln in root.iter('VULN'):
        for stig_data in vuln.findall('STIG_DATA'):
            vuln_attribute = stig_data.find('VULN_ATTRIBUTE')
            if vuln_attribute is not None and vuln_attribute.text == 'Vuln_Num':
                attribute_data = stig_data.find('ATTRIBUTE_DATA')
                if attribute_data is not None:
                    function_name = attribute_data.text.replace("-", "")
                    function_names.append(function_name)
    return function_names


def read_function_names_from_csv(filename):
    """Reads the function names from the STIG CSV file."""
    full_path = os.path.join(strFilePath, filename)
    with open(full_path, "r") as file:
        reader = csv.reader(file)
        # Skip the header
        next(reader, None)
        # Get the first element from each row
        return [row[0] for row in reader if row]

def read_function_names(ckl_filename):
    # Full path to the CSV file
    stig_csv_file = os.path.join(strFilePath, "stig_vul.csv")

    # First, try reading from the CSV file
    function_names = read_function_names_from_csv(stig_csv_file)

    # If no function names are found in the CSV, read from the CKL file
    if not function_names:
        function_names = read_function_names_from_ckl(ckl_filename)  # Note: No path joining here

    return function_names



def send_command(command, device_name):
    if device_name.find(".") > -1:
        prompt = "#"
    else:
        prompt = device_name + "#"
    crt.Screen.WaitForStrings([prompt], 1)
    crt.Screen.Send(command + "\r")
    return crt.Screen.ReadString(prompt, 30)


def exec_command(command, device_name):
    output = command_cache.get(device_name, command)

    if output is None:
        result = send_command(command, device_name)
        result = handle_errors(result, command, device_name)

        if "." in device_name:
            output = result.strip().replace(device_name, "")
        else:
            result = result.replace('\r', '')
            output = f"{device_name}#{result}{device_name}#"

        if "Invalid" not in output:
            command_cache.add(device_name, command, output)

    return output


def load_template(template_name):
    full_path = os.path.join(strFilePath, template_name)
    try:
        with open(full_path, "r", encoding="utf-8") as objStigTemplateFile:
            content = objStigTemplateFile.read()
            return content
    except FileNotFoundError:
        crt.Dialog.MessageBox(f"Template file not found at: {full_path}")
        return ''


def read_hosts_from_csv(filename):
    host_data = []
    with open(filename, 'r') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            host_data.append(row)
    return host_data


def create_log_file():
    log_file_name = "cisco_stig_scanner_v_4" + str(today) + ".csv"
    log_file_path = os.path.join(strFilePath, log_file_name)
    return open(log_file_path, "a")


def log_error(message):
    """Utility function to log errors to a file."""
    log_filename = "error_log.txt"
    log_path = os.path.join(strFilePath, log_filename)
    with open(log_path, "a") as error_log:
        error_log.write(f"{message}\n")


def connect_to_host(strHost, connection_type='default'):
    global stored_username, stored_password  # Declare them as global so that we can modify them
    
    # Define different types of connection strings
    connect_string_default = f"/SSH2 /ACCEPTHOSTKEYS /Z 4 {strHost}"
    connect_string_pki = f"/SSH2 /AUTH publickey /ACCEPTHOSTKEYS /Z 4 {strHost}"
    
    if connection_type == 'user_pass':
        # Use stored username and password if available
        if not stored_username:
            stored_username = crt.Dialog.Prompt("Enter your username:", "Login", "", False).strip()
        if not stored_password:
            stored_password = crt.Dialog.Prompt("Enter your password:", "Login", "", True).strip()
        
        connect_string_user_pass = f"/SSH2 /L {stored_username} /PASSWORD {stored_password} /AUTH keyboard-interactive /ACCEPTHOSTKEYS /Z 4 {strHost}"
    
    # Choose the appropriate connection string based on the connection_type argument
    if connection_type == 'pki':
        connect_string = connect_string_pki
    elif connection_type == 'user_pass':
        connect_string = connect_string_user_pass
    else:  # default
        connect_string = connect_string_default
    
    # Terminal settings
    term_len = "term len 0"
    term_width = "term width 400"
    
    # Initialize log file
    log_file = create_log_file()
    
    try:
        # Attempt to connect to the host
        crt.Session.Connect(connect_string, False)
    except ScriptError:
        # Log any errors that occur during connection
        error = crt.GetLastErrorMessage()
        log_error(f"Failed to connect to host {strHost}. Error: {error}")
        log_file.write(f"Error accessing host {strHost} {error}\r")
        return None, None

    if crt.Session.Connected:
        crt.Screen.Synchronous = True
        
        # Check for the presence of the "#" or ">" prompts or any error messages
        found_index = crt.Screen.WaitForStrings(["#", ">", "failed", "error", "refused", "timed out"], 15)
        
        if found_index in [3, 4, 5]:  # Any error message was found
            error_line = crt.Screen.Get(crt.Screen.CurrentRow, 0, crt.Screen.CurrentRow, crt.Screen.CurrentColumn - 1)
            log_error(f"Connection error with host {strHost}. Error on line: {error_line}")
            log_file.write(f"Connection error with host {strHost}. Error on line: {error_line}\r")
            return None, None
        
        # Set terminal length and width
        exec_command(f"{term_len}\r", strHost)
        crt.Screen.WaitForStrings(["#", ">"], 15)
        exec_command(f"{term_width}\r", strHost)

        # Get the device name from the current screen
        device_name = crt.Screen.Get(crt.Screen.CurrentRow, 0, crt.Screen.CurrentRow, crt.Screen.CurrentColumn - 2).replace("#", "")
        return device_name, device_name
    else:
        return None, None


def handle_errors(result, command, device_name):
    """Handle errors during command execution."""
    # Determine the prompt based on the device name
    prompt = "#" if "." in device_name else f"{device_name}#"

    # If the result is shorter than the device name, an error likely occurred
    if len(result) < len(device_name):
        crt.Screen.WaitForStrings([prompt], 1)
        crt.Screen.Send("\x03\r")
        result = crt.Screen.ReadString(prompt, 10)
        crt.Screen.WaitForStrings([prompt], 5)
        crt.Screen.Send(f"{command}\r")
        result = crt.Screen.ReadString(prompt, 110)

    # Additional error handling for connection failures
    if "Failed to connect" in result:
        log_error(result)
        print(f"Error: {result}")
        # Continue with the next host or operation
        return result

    return result



def process_host(host, ckl_filename, log_file, auth_method):
    host = host.replace("\n", "")
    device_type = "IOS"
    stig_list = []
    
    # Map auth_method to connection_type
    connection_type_map = {
        '2FA': 'pki',
        'un': 'user_pass'
    }
    connection_type = connection_type_map.get(auth_method, 'default')
    
    # Pass connection_type to connect_to_host
    device_name, _ = connect_to_host(host, connection_type)
    
    if device_name is None:
        return
    
    # Read the function names based on the provided CKL filename
    stig_vul_list = read_function_names(ckl_filename)
    
    # Load the CKL template for the current host
    ckl_content = load_template(ckl_filename)
    
    if host and "#" not in host:
        for func_name in stig_vul_list:
            func = globals()[func_name]
            stig_list.append(func(device_type, device_name.strip()))

        for obj in stig_list:
            log_to_csv(obj, host, device_name, device_name, log_file)
            ckl_content = update_ckl_template(obj, ckl_content)

        # Parse the CKL XML and replace the placeholders for hostname and IP
        root = ET.fromstring(ckl_content)
        root.find('.//ASSET/HOST_NAME').text = str(device_name)
        root.find('.//ASSET/HOST_IP').text = str(host)
        ckl_content = ET.tostring(root, encoding='utf-8').decode('utf-8')
        
        # Extract relevant part from template name to use in the CKL filename
        template_part = ckl_filename.split(".")[0]  # Remove the ".ckl" extension
        name_parts = template_part.split("-")
        name_prefix = "-".join(name_parts[:-1])  # Keep the prefix
        
        # Create the new CKL filename
        ckl_file = os.path.join(strFilePath, f"{device_name}_{name_prefix}_{strDateTime}.ckl")
        
        # Write the CKL content to the file
        with open(ckl_file, "w", encoding="utf-8") as objCKLFile:
            objCKLFile.write(ckl_content)

    crt.Session.Disconnect()


def log_to_csv(obj, host, device_name, common_name, log_file):
    finding_details = xml.sax.saxutils.escape(obj.finding)
    comments = xml.sax.saxutils.escape(obj.comments)
    log_file.write(f"{strDateTime},{host},{common_name.strip()},{device_name.strip()},{obj.vulid},{obj.status},\"{finding_details}\",\"{comments}\",,\n")


def update_ckl_template(obj, ckl):
    root = ET.fromstring(ckl)
    for vuln in root.iter('VULN'):
        for stig_data in vuln.findall('STIG_DATA'):
            vuln_attribute = stig_data.find('VULN_ATTRIBUTE')
            if vuln_attribute is not None and vuln_attribute.text == 'Vuln_Num':
                attribute_data = stig_data.find('ATTRIBUTE_DATA')
                if attribute_data is not None and attribute_data.text == obj.vulid:
                    vuln.find('STATUS').text = obj.status
                    vuln.find('FINDING_DETAILS').text = xml.sax.saxutils.escape(obj.finding)
                    vuln.find('COMMENTS').text = xml.sax.saxutils.escape(obj.comments)

    return ET.tostring(root, encoding='utf-8').decode('utf-8')


def Main():
    # Read the hosts, auth, and ckl information from the CSV file
    csv_filename = os.path.join(strFilePath, "host.csv")
    hosts_data = read_hosts_from_csv(csv_filename)
    global stored_username, stored_password  # Declare them as global
    
    # Initialize a log file
    log_file = create_log_file()
    
    # Write the header to the log file
    log_file.write("Date,Hostname,CommonName,DeviceName,VulnID,Status,Finding,Comments,,\n")
    
    # Initialize a counter for total hosts (currently unused)
    int_total_hosts = 0
    
    # Prompt once for 'un' authentication and store the username and password
    if any(host_info['auth'] == 'un' and "#" not in host_info['skip'] for host_info in hosts_data):
        stored_username = crt.Dialog.Prompt("Enter your username for 'un' authentication:", "Login", "", False).strip()
        stored_password = crt.Dialog.Prompt("Enter your password for 'un' authentication:", "Login", "", True).strip()

    for host_info in hosts_data:
        # Skip the row if 'skip' column has "#"
        if "#" in host_info['skip']:
            continue
        
        # Get host, ckl filename, and auth method from the current row
        host = host_info['host']
        ckl_filename = host_info['ckl']
        auth_method = host_info['auth']
    
        # Process the host
        process_host(host, ckl_filename, log_file, auth_method)
    
    # Write the total number of hosts checked to the log file
    log_file.write(f"{strDateTime},Total Hosts Checked: {int_total_hosts},,\n")
    
    # Close the log file
    log_file.close()



Main()
t2 = time.perf_counter()
ShowTimer = crt.Dialog.MessageBox(f'The script finished executing in {round(t2-t1,2)} seconds.')