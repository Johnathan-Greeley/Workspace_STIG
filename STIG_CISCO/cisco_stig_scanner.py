# $language = "python3"
# $interface = "1.0"
# Version:4.1.2.L.14

'''
This is a fork of the autostig scripts, starting with Version 4. This version consolidates all vulnerability checks into a single script.
Creator: Johnathan A. Greeley
As of 2023-OCT-02, checks for IOS XE SWITCH, IOS XE Router & NXOS have been imported, tested, and are functioning as expected.
The next step involves refactoring all imported vulnerabilities.

Version: cisco_stig_scanner_v4.1
Update as of 2023-NOV-16:
- First review of Cisco NX OS Switch L2S Security is complete; follow-up is needed.
- Addressed file path issues in SecureCRT; paths no longer need to be hardcoded, setting the stage for modularization.
- Created short status codes for vulnerability status.
- Updated the Stig class with a mapping of short status codes for CKL & CKLB file compatibility.
- Moved the logic for formatting vulnerability IDs to the Stig class, allowing direct passing of vulnerability function names for checklist formatting.
- Added error handling logic to the Stig class for graceful handling of errors related to vulnerability functions.
- Added a clear method to the Stig class to reset Stig data before moving to the next host. This is a precaution as SecureCRT sometimes deviates from Python's default behavior.
- Added a clear method to the Commandcache class to reset command data before moving to the next host.
- Added a cleaning method to the Commandcache class to remove sensitive data before writing to logs and/or checklists.
- Added a dispatch functions for checklists to support dual use of CKL & CKLB files.
- Removed old logging logic and introduced new logging functions.
- Added a txt error log for failed connections, detailing the host and the reason for failure.
- Introduced a CSV logger for hosts scanned each day, tracked by host and appended until the end of the day.
- Implemented a logger for failed vulnerability functions.
- Removed CKL processing logic from the 'process_host' and 'connect_to_host' functions in preparation for CKLB functions.
- Added a function to read vulnerability names from CKLB files and remove the '-' for calling the list of vulnerability functions.
- Added functions to update and write STIG data to CKLB files.
- Removed unused functions and classes and reorganized the script, placing support and command functions at the top, followed by vulnerability functions, with processing and main functions at the end.
- Updated the script's execution time display to show minutes and seconds, along with the number of hosts scanned and the number of failures.
- Added a function to display a count of hosts in the current connection tab (e.g., 192.168.1.1 (3 of 5)).
- Consolidated most time-related logic into the 'display_summary' function.

Version: cisco_stig_scanner_v4.1.1 (last update: 2023-NOV-20)
- Transitioned checklist classe for modularization.
- Introduced ChecklistManager class for checklist-related operations.
- Moved following functions/logic to ChecklistManager:
    - read_function_names_from_cklb
    - read_function_names_from_ckl
    - read_function_names_from_csv
    - load_ckl_template
    - load_cklb_template
    - update_and_write_cklb
    - update_and_write_ckl
    - update_cklb_template
    - update_ckl_template
- Transferred Stig status mapping from Stig class to ChecklistManager.
- Updated functions interacting with checklists to utilize ChecklistManager.
- Updated delegator functions:
    - read_function_names_from_checklist
    - read_function_names
    - load_template
    - update_and_write_checklist

Version: cisco_stig_scanner_v4.1.2 (last update: 2023-NOV-23)
- Bug fix: Addressed issue with 'term len 0' command in 2FA hosts.
- Corrected 'set_terminal_settings' to address premature '#' command issue.
- Bug fix: Resolved authentication failure handling, preventing unnecessary user input.
- Utilized crt API to suppress pop-up on failed connections.
- Note: Logging logic in place but requires fine-tuning.

Version: cisco_stig_scanner_v4.1.2.d (last update: 2023-NOV-30)
- Updated 'connect_to_host' to use 'handle_connection_failure'.
- Renamed 'prompt_for_un_authentication' to 'get_credentials'.
- Shifted 't1', 'command_cache' from global to 'Main'.
- Moved 'stored_username', 'stored_password' from global to 'get_credentials'.
- Enabled writing to both CKL & CKLB for a single host by removing the file extension from the template name in the host CSV. To write to both file types for the same host, simply omit the file extension.
- Updated functions to support dual checklist writing:
    - 'read_function_names'
    - 'read_function_names_from_checklist'
    - 'update_and_write_checklist'
- Removed 'load_template' (no longer used).
- Note: Pending relocation of connection logic into a dedicated class.
Version: cisco_stig_scanner_v4.1.2.k (last update: 2024-MAY-24)
-updated,V216645,V217000,V220140,215823,215833,215854,220139,215842
-Removed, 216644,V216651,V216652,V216994,V216995
-Updated Vuls for IOS XE Switch, IOS XE RTR, NXOS.
-Updated CKLB/CKL(Emass export) files
-Note: Pending update of Switch RTR Vuls.
-Note: Still working on "clean_output" its not cleaning 100% of the keys at this time.
Version: cisco_stig_scanner_v4.1.2.k.3 (last update: 2024-AUG-06)
Updated CKLB/CKL(Emass export) files to V3R1
-Note: added flag to show script running in CRT
-Updated header info above each section of VUL checks to reflect current versions.
'''

'''
TODO LIST

1. Review and Refactor Vulnerability Functions:
   - Conduct a thorough review of existing vulnerability functions.
   - Refactor as needed to enhance efficiency, readability, and maintainability.

2. Automated Configuration Corrections:
   - Implement functions in vulnerability checks that suggest or apply configuration corrections when possible.

3. Enhanced Logging:
   - Improve logging mechanisms to provide more informative and user-friendly outputs.

4. Connection Error Handling Improvements:
   - Enhance the handling of connection errors, especially in cases of incorrect authentication settings.
   - Address issues where the script hangs and requires manual interruption.

5. Commandcache Cleanup Enhancements:
   - Improve the cleanup logic in Commandcache to ensure comprehensive removal of all sensitive data.

6. Hardware and Software Information Retrieval:
   - Develop a function to retrieve hardware and software information at the start of processing each host.
   - Utilize this information for the 'device_type' attribute in relevant functions.

7. Metadata and Versioning for Vulnerability Functions:
   - Begin adding metadata and version information to each vulnerability function.
   - Track changes and provide context for future updates and reviews.

8. Modularization Roadmap and Testing:
   - Outline a plan for the modularization of the script.
   - Begin testing modular components, especially in the context of SecureCRT integration.

9. External Testing Tool for Vulnerability Functions:
   - Develop a tool for testing vulnerability functions outside of the script/SecureCRT environment.
   - Aim to expedite the process of updating and validating vulnerability functions.
'''


# Standard library imports
import os
import datetime
from datetime import date
import sys
import re
import string
import csv
import html #for wirtinig escapes when saving some output to files.
import json #To support CKLB files
import inspect
import time
import array
import traceback
import uuid #Needed for updating the CKLB templet.
import xml.etree.ElementTree as ET #For working with CKL files
import xml.sax.saxutils # For working with CKL files
from collections import OrderedDict, namedtuple

# Third-party imports
from packaging import version

# Check if 'crt' is a defined variable in the globals() dictionary
if 'crt' in globals():
    RUNNING_IN_SECURECRT = True
    # Use SecureCRT's scripting API to get the full path of the current script
    script_dir, script_name = os.path.split(crt.ScriptFullName)
    # If the script directory is not already in sys.path, add it at the beginning
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)
    # Set the current working directory to the script's directory
    os.chdir(script_dir)  # Use script_dir which contains the directory of the current script
else:
    RUNNING_IN_SECURECRT = False

# Local application/library specific imports
#import SecureCRT  


class Stig:
    # Class-level mappings for status codes and severity
    STATUS_MAP_CKL = {
        "NR": "Not_Reviewed",
        "NF": "NotAFinding",
        "NA": "Not_Applicable",
        "OP": "Open"
    }

    STATUS_MAP_CKLB = {
        "NR": "not_reviewed",
        "NA": "not_applicable",
        "OP": "open",
        "NF": "not_a_finding"
    }

    SEVERITY_MAP = {
        "low": "CAT III",
        "medium": "CAT II",
        "high": "CAT I"
    }

    def __init__(self):
        self.vulid = ""
        self.device_type = ""
        self.finding = ""
        self.status = "OP"  # Default status when a Stig instance is created
        self.severity = "default"  # Severity level, can be updated later
        self.comments = ""

    def set_vulid(self, func_name=None):
        """
        Sets the formatted vulnerability ID based on the provided or calling function's name.

        Args:
        - func_name (str, optional): The name of the function. If not provided, it will use the calling function's name.
        """
        if not func_name:
            # Inspect the stack to get the name of the calling function
            caller_frame = inspect.currentframe().f_back
            func_name = caller_frame.f_code.co_name

        # Format the function name and set it as the vulnerability ID
        if func_name.startswith('V') and func_name[1:].isdigit():
            self.vulid = f"{func_name[:1]}-{func_name[1:]}"  # Correctly format as 'V-######'
        else:
            self.vulid = func_name

    def handle_error(self, func_name, exception):
        """
        Handles errors that occur during vulnerability checks. Logs the error to a CSV file
        and sets the appropriate attributes in the Stig object to reflect the error status.

        Args:
        - func_name (str): The name of the function where the error occurred.
        - exception (Exception): The exception object representing the error.
        """
        # Log the error to the CSV file
        log_vuln_check_error(self.device_name, self.device_type, func_name, exception)

        # Set the Stig object attributes to reflect the error
        self.set_vulid(func_name)
        self.status = "NR"
        existing_finding = self.finding if self.finding else ""
        self.finding = f"{existing_finding}\nError occurred during execution: {str(exception)}"
        self.comments = f"Error in {func_name}: {str(exception)}"

    def clear(self):
        """Resets all attributes to their default values."""
        self.vulid = ""
        self.device_type = ""
        self.finding = ""
        self.status = "OP"
        self.severity = "default"
        self.comments = ""

    @classmethod
    def get_status(cls, checklist_type, short_code):
        """Returns the full status description based on the checklist type and short code."""
        if checklist_type == 'ckl':
            return cls.STATUS_MAP_CKL.get(short_code, "OP")
        elif checklist_type == 'cklb':
            return cls.STATUS_MAP_CKLB.get(short_code, "open")
        else:
            raise ValueError("Unsupported checklist type.")

    @classmethod
    def get_severity(cls, severity_code):
        """Returns the mapped severity level."""
        return cls.SEVERITY_MAP.get(severity_code.lower(), "default")


class ChecklistManager:
    def __init__(self):
        self.template_cache = {}  # Cache for loaded checklist templates
        self.vuln_info_cache = {}  # Cache for parsed vulnerability data

    def read_vuln_info(self, checklist_file):
        base_name, file_extension = os.path.splitext(checklist_file)
        file_extension = file_extension.lower()

        # Determine the key for caching based on extension
        cache_key = base_name + file_extension
        
        # Check if vulnerability data has already been loaded
        if cache_key in self.vuln_info_cache:
            return self.vuln_info_cache[cache_key]

        # Load the template files into cache and read vulnerability info
        if file_extension == '.ckl':
            if cache_key not in self.template_cache:
                self.template_cache[cache_key] = self.load_ckl_template(checklist_file)
            vuln_info = self.read_vuln_info_from_ckl(checklist_file)

        elif file_extension == '.cklb':
            if cache_key not in self.template_cache:
                self.template_cache[cache_key] = self.load_cklb_template(checklist_file)
            vuln_info = self.read_vuln_info_from_cklb(checklist_file)

        elif file_extension == '':  # No extension provided
            # Load both templates and read vulnerability info
            ckl_key = base_name + '.ckl'
            cklb_key = base_name + '.cklb'

            if ckl_key not in self.template_cache:
                self.template_cache[ckl_key] = self.load_ckl_template(ckl_key)
            if cklb_key not in self.template_cache:
                self.template_cache[cklb_key] = self.load_cklb_template(cklb_key)

            # Load vulnerability info from either file type, giving preference to CKL
            vuln_info_ckl = self.read_vuln_info_from_ckl(ckl_key)
            self.vuln_info_cache[ckl_key] = vuln_info_ckl

            vuln_info_cklb = self.read_vuln_info_from_cklb(cklb_key)
            self.vuln_info_cache[cklb_key] = vuln_info_cklb

            # Return based on the extension of the file passed in
            if os.path.exists(base_name + '.ckl'):
                return vuln_info_ckl
            else:
                return vuln_info_cklb
        else:
            raise ValueError("Unsupported checklist file format. Provide a .ckl, .cklb, or no extension for both.")

        # Cache the vulnerability info for future use
        self.vuln_info_cache[cache_key] = vuln_info
        return vuln_info

    def read_vuln_info_from_ckl(self, checklist_file):
        ckl_content = self.template_cache[checklist_file]  # Assumes the template is already loaded
        vuln_info = {}
        root = ET.fromstring(ckl_content)
        
        for vuln in root.iter('VULN'):
            original_vuln_num = None
            function_name = None
            severity = None
            
            for stig_data in vuln.findall('STIG_DATA'):
                vuln_attribute = stig_data.find('VULN_ATTRIBUTE')
                if vuln_attribute is not None and vuln_attribute.text == 'Vuln_Num':
                    attribute_data = stig_data.find('ATTRIBUTE_DATA')
                    if attribute_data is not None:
                        original_vuln_num = attribute_data.text
                        function_name = original_vuln_num.replace("-", "")
                
                if vuln_attribute is not None and vuln_attribute.text == 'Severity':
                    severity_data = stig_data.find('ATTRIBUTE_DATA')
                    if severity_data is not None:
                        severity = severity_data.text  # Store the original severity code
            
            if original_vuln_num and function_name and severity:
                vuln_info[original_vuln_num] = (function_name, severity)

        return vuln_info

    def read_vuln_info_from_cklb(self, checklist_file):
        cklb_content = self.template_cache[checklist_file]  # Assumes the template is already loaded
        vuln_info = {}
        for stig in cklb_content.get('stigs', []):
            for rule in stig['rules']:
                group_id = rule.get('group_id')
                severity = rule.get('severity')
                
                if group_id:
                    function_name = group_id.replace("-", "")
                    vuln_info[group_id] = (function_name, severity)

        return vuln_info

    def load_ckl_template(self, template_name):
        try:
            with open(template_name, "r", encoding="utf-8") as ckl_file:
                return ckl_file.read()
        except Exception as e:
            raise Exception(f"Error loading CKL template file {template_name}: {e}")

    def load_cklb_template(self, template_name):
        try:
            with open(template_name, "r", encoding="utf-8") as cklb_file:
                return json.load(cklb_file)
        except json.JSONDecodeError as e:
            raise JSONDecodeError(f"Error parsing JSON from CKLB template file {template_name}: {e}")

    def update_and_write_ckl(self, stig_list, device_name, host, checklist_file):
        date_str = datetime.datetime.now().strftime("%d-%b-%Y").upper()
        ckl_content = self.template_cache.get(checklist_file) or self.load_ckl_template(checklist_file)
        for obj in stig_list:
            ckl_content = self.update_ckl_template(obj, ckl_content)
        root = ET.fromstring(ckl_content)
        root.find('.//ASSET/HOST_NAME').text = str(device_name)
        root.find('.//ASSET/HOST_IP').text = str(host)
        ckl_content = ET.tostring(root, encoding='utf-8').decode('utf-8')
        template_part = checklist_file.split(".")[0]
        name_parts = template_part.split("-")
        name_prefix = "-".join(name_parts[:-1])
        new_ckl_filename = f"{device_name}_{name_prefix}_{date_str}.ckl"
        with open(new_ckl_filename, "w", encoding="utf-8") as objCKLFile:
            objCKLFile.write(ckl_content)

    def update_and_write_cklb(self, stig_list, device_name, host, checklist_file):
        date_str = datetime.datetime.now().strftime("%d-%b-%Y").upper()
        cklb_content = self.template_cache.get(checklist_file) or self.load_cklb_template(checklist_file)

        # Generate a new UUID and assign it to the id field
        cklb_content['id'] = str(uuid.uuid4())

        for obj in stig_list:
            cklb_content = self.update_cklb_template(obj, cklb_content)
        cklb_content['target_data']['host_name'] = device_name
        cklb_content['target_data']['ip_address'] = host
        cklb_content['title'] = f"{device_name}_{date_str}"

        template_part = checklist_file.split(".")[0]
        name_parts = template_part.split("-")
        name_prefix = "-".join(name_parts[:-1])
        new_cklb_filename = f"{device_name}_{name_prefix}_{date_str}.cklb"

        with open(new_cklb_filename, 'w', encoding='utf-8') as file:
            json.dump(cklb_content, file, indent=4)

    def update_ckl_template(self, obj, ckl):
        full_status_ckl = Stig.get_status('ckl', obj.status)
        root = ET.fromstring(ckl)
        for vuln in root.iter('VULN'):
            for stig_data in vuln.findall('STIG_DATA'):
                vuln_attribute = stig_data.find('VULN_ATTRIBUTE')
                if vuln_attribute is not None and vuln_attribute.text == 'Vuln_Num':
                    attribute_data = stig_data.find('ATTRIBUTE_DATA')
                    if attribute_data is not None and attribute_data.text == obj.vulid:
                        vuln.find('STATUS').text = full_status_ckl
                        vuln.find('FINDING_DETAILS').text = xml.sax.saxutils.escape(obj.finding)
                        vuln.find('COMMENTS').text = xml.sax.saxutils.escape(obj.comments)
        return ET.tostring(root, encoding='utf-8').decode('utf-8')

    def update_cklb_template(self, obj, cklb):
        full_status_cklb = Stig.get_status('cklb', obj.status)
        for stig in cklb['stigs']:
            for rule in stig['rules']:
                if rule['group_id'] == obj.vulid:
                    rule['status'] = full_status_cklb
                    rule['finding_details'] = html.escape(obj.finding)
                    rule['comments'] = html.escape(obj.comments)
                    break
        return cklb


class IntStatus:
    def __init__(self):
        self.interface = "undefined"
        self.description = "undefined"
        self.vlan = "undefined"

class IntTrans:
    def __init__(self):
        self.interface = "undefined"
        self.transtype = "none"
        self.device_name = "undefined"

class Commandcache:
    def __init__(self):
        self.cache = {}

    def add(self, device_name, command, output):
        # Clean the output before adding it to the cache
        clean_output = self.clean_output(output)
        self.cache[(device_name, command)] = clean_output

    def get(self, device_name, command):
        # Retrieve the cleaned output from the cache
        return self.cache.get((device_name, command))

    def clear(self):
        """ Clears the cache. """
        self.cache.clear()

    def clean_output(self, output):
        # Regex patterns to match sensitive data patterns with multiline and dotall flags
        hash_patterns = [
            re.compile(r'(server-private\s+\S+\s+key\s+\d+\s+)(\S+)', re.VERBOSE | re.MULTILINE | re.DOTALL),
            re.compile(r'(mpls ldp neighbor\s+\S+\s+password\s+\d+\s+)(\S+)', re.VERBOSE | re.MULTILINE | re.DOTALL),
            re.compile(r'(username\s+\S+\s+.*?secret\s+\d+\s+)(\S+)', re.VERBOSE | re.MULTILINE | re.DOTALL),
            re.compile(r'(crypto isakmp key\s+\d+\s+)(\S+)(?=\s+address)', re.VERBOSE | re.MULTILINE | re.DOTALL),
            re.compile(r'(password\s+\d+\s+)(\S+)', re.VERBOSE | re.MULTILINE | re.DOTALL),
            re.compile(r'(ip ospf message-digest-key\s+\d+\s+md5\s+\d+\s+)(\S+)', re.VERBOSE | re.MULTILINE | re.DOTALL),
            re.compile(r'(authentication mode hmac-sha-256\s+\d\s+)(\S+)', re.VERBOSE | re.MULTILINE | re.DOTALL),
            re.compile(r'(key-string\s+\d+\s+)(\S+)', re.VERBOSE | re.MULTILINE | re.DOTALL),
            re.compile(r'(authentication mode hmac-sha-256 7\s+)(\S+)', re.VERBOSE | re.MULTILINE | re.DOTALL),
            re.compile(r'(snmp-server user\s+\S+\s+auth sha\s+\S+\s+priv aes-128\s+)(\S+).*', re.VERBOSE | re.MULTILINE | re.DOTALL),
            # Updated NTP regex to sanitize until the optional space and digit
            re.compile(r'(ntp authentication-key\s+\d+\s+(hmac-sha2-256|md5)\s+).*', re.VERBOSE | re.MULTILINE | re.DOTALL),
        ]
        
        # Clean the output
        for pattern in hash_patterns:
            output = pattern.sub(r'\1***SANITISED***', output)
        
        return output



# Usage of cleaning when adding data to the cache
# This would be in the part of the script where command outputs are processed
# command_cache.add(device_name, command, raw_output)

#place holder
#class ConnectionManager:


# Grouping global variables here
# As of 2023-NOV-30 all but one (path import near the the top) have been global
# variable has been moved into a function.


#Helper Functions


def remove_char(x):
    """
    Removes all non-digit characters from a string.
    
    Args:
    - x (str): The string from which to remove characters.
    
    Returns:
    - str: The modified string containing only digits.
    """
    Output = re.sub("\D", "", x)
    return Output

  
def read_function_names_from_checklist(checklist_file):
    """
    Reads function names from the checklist file based on its format. 
    Supports .ckl and .cklb formats. If no extension is provided, defaults to .ckl format.

    Args:
    - checklist_file (str): The filename of the checklist.

    Returns:
    - list: A list of function names read from the given checklist file.

    Raises:
    - ValueError: If an unsupported file format is provided.
    """
    checklist_manager = ChecklistManager()
    file_extension = os.path.splitext(checklist_file)[1].lower()

    if file_extension == '.ckl':
        return checklist_manager.read_function_names_from_ckl(checklist_file)
    elif file_extension == '.cklb':
        return checklist_manager.read_function_names_from_cklb(checklist_file)
    elif file_extension == '':
        # Default to CKL format if no extension is provided
        return checklist_manager.read_function_names_from_ckl(checklist_file + '.ckl')
    else:
        raise ValueError("Unsupported file format. Please provide a .ckl or .cklb file.")


def read_function_names(checklist_file):
    """
    Attempts to read function names from a STIG CSV file. If the CSV file is empty or not present,
    the function then reads from a provided CKL or CKLB checklist file based on its extension.
    If no extension is provided, defaults to .ckl format.
    
    Args:
    - checklist_file (str): The name of the CKL or CKLB checklist file to read from if CSV is empty.
    
    Returns:
    - list: A list of function names.
    """
    checklist_manager = ChecklistManager()
    function_names = checklist_manager.read_function_names_from_csv("stig_vul.csv")
    
    if not function_names:
        file_extension = os.path.splitext(checklist_file)[1].lower()

        if file_extension == '.ckl' or file_extension == '':
            # Default to CKL format if no extension is provided
            checklist_file_with_ext = checklist_file if file_extension else checklist_file + '.ckl'
            return checklist_manager.read_function_names_from_ckl(checklist_file_with_ext)
        elif file_extension == '.cklb':
            return checklist_manager.read_function_names_from_cklb(checklist_file)
        else:
            raise ValueError("Unsupported checklist file format. Provide a .ckl, .cklb, or no extension for CKL.")

    return function_names


def read_hosts_and_templates_from_csv(filename):
    """
    Reads host information from a CSV file, preloads all necessary checklist templates,
    and sorts the hosts by authentication method (2FA, then un, then others).

    Args:
    - filename (str): The name of the CSV file.

    Returns:
    - list: A sorted list of dictionaries, each containing host information.
    """
    host_data = []
    checklist_manager = ChecklistManager()

    with open(filename, 'r') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            if row['skip'].strip() == "#":
                continue  # Skip rows marked with '#'
            host_data.append(row)
            checklist_file = row['checklist']
            checklist_manager.read_vuln_info(checklist_file)  # Preload the checklist template

    # Sort the host data: 2FA first, then un, then others
    host_data.sort(key=lambda x: (x['auth'] != '2FA', x['auth'] != 'un'))

    return host_data


#Look into moving logic into a logging Class
def get_daily_log_filename(script_name="cisco_stig_scanner_v4", file_extension=".csv"):
    date_str = datetime.datetime.now().strftime("%d-%b-%Y").upper()
    return f"{script_name}_{date_str}{file_extension}"


#Look into moving logic into a logging Class
def log_stig_results_to_csv(stig_list, host, device_name):
    log_filename = get_daily_log_filename()
    file_exists = os.path.isfile(log_filename)
    
    with open(log_filename, 'a', newline='', encoding='utf-8') as csvfile:
        csv_writer = csv.writer(csvfile)
        if not file_exists:
            csv_writer.writerow(["Date", "Hostname", "CommonName", "DeviceName", "VulnID", "CAT", "Status", "Finding", "Comments"])
        
        for stig in stig_list:
            # Map the severity using the Stig class method
            cat = Stig.get_severity(stig.severity)
            
            csv_writer.writerow([
                datetime.datetime.now().strftime("%b-%d-%Y"),
                host,
                "",  # CommonName (if applicable)
                device_name,
                stig.vulid,
                cat,
                stig.status,
                stig.finding,
                stig.comments
            ])


#Look into moving logic into a logging Class
def log_vuln_check_error(device_name, device_type, func_name, e):
    """
    Logs an error that occurred during a vulnerability check to a CSV file.

    Args:
    - device_name (str): The name of the device.
    - device_type (str): The type of the device.
    - func_name (str): The name of the function where the error occurred.
    - e (Exception): The exception object.
    """
    log_filename = f"vuln_check_errors_{datetime.datetime.now().strftime('%d-%b-%Y').upper()}.csv"
    exc_type, exc_value, exc_traceback = sys.exc_info()
    tb_info = traceback.extract_tb(exc_traceback)[-1]
    line_number = tb_info[1]
    error_message = str(exc_value).strip()

    with open(log_filename, 'a', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow([
            datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            device_name,
            device_type,
            func_name,
            exc_type.__name__,
            f"Line {line_number}: {error_message}"
        ])

#Look into moving logic into a logging Class
def log_connection_error(host, auth_method, error_message):
    """
    Logs an error message for a failed connection attempt to a file, removing extra whitespace.

    Args:
    - host (str): The hostname or IP address.
    - auth_method (str): The authentication method used.
    - error_message (str): The error message to log.

    Returns:
    None
    """
    log_filename = f"connection_errors_{datetime.datetime.now().strftime('%d-%b-%Y').upper()}.txt"
    with open(log_filename, "a") as error_log:
        # Strip leading/trailing whitespace from the error message
        clean_error_message = error_message.strip()
        log_entry = f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {host} - {auth_method} - {clean_error_message}\n"
        error_log.write(log_entry)


#Commection Management


#Look into moving crt logic out of this function in prep for creating connection Class
def connect_to_host(strHost, connection_type, current_host_number, total_hosts_count):
    global stored_username, stored_password

    # Generate the connection string
    connect_string = get_connection_string(strHost, connection_type, stored_username, stored_password)

    try:
        # Attempt to connect to the host in a new tab
        newTab = crt.Session.ConnectInTab(connect_string, False, True)
        if newTab.Session.Connected:
            # Set the tab title to include the host being scanned and its progress number
            tab_title = f"{strHost} ({current_host_number} of {total_hosts_count})"
            newTab.Caption = tab_title
            newTab.Screen.Synchronous = True

            # Set terminal settings and get the device name
            set_terminal_settings(strHost)
            device_name = get_device_name()
            return device_name, device_name
        else:
            # Connection failed but no exception was raised
            handle_connection_failure(strHost, connection_type)  # Using handle_connection_failure
            return None, None
    except ScriptError as e:
        # Handle the failed connection attempt using handle_connection_failure
        handle_connection_failure(strHost, connection_type, f"ScriptError: {e}")
        return None, None
        

#this may be turn into connection type and then move the crt logic into its own function
#this would be needed in prep for the connection class
def get_connection_string(strHost, connection_type, stored_username, stored_password):
    """
    Generates the connection string based on the connection type and credentials.
   
    Args:
    - strHost (str): The hostname.
    - connection_type (str): The type of connection ('user_pass', 'pki', or 'default').
    - stored_username (str): The stored username for authentication.
    - stored_password (str): The stored password for authentication.
   
    Returns:
    - str: The generated connection string.
    """
    connect_string_default = f"/SSH2 /ACCEPTHOSTKEYS /Z 0 {strHost}"
    connect_string_pki = f"/SSH2 /AUTH publickey /ACCEPTHOSTKEYS /Z 0 {strHost}"
   
    if connection_type == 'user_pass':
        if not stored_username:
            stored_username = crt.Dialog.Prompt("Enter your username:", "Login", "", False).strip()
        if not stored_password:
            stored_password = crt.Dialog.Prompt("Enter your password:", "Login", "", True).strip()
        return f"/SSH2 /L {stored_username} /PASSWORD {stored_password} /AUTH keyboard-interactive /ACCEPTHOSTKEYS /Z 0 {strHost}"
   
    if connection_type == 'pki':
        return connect_string_pki
    else:
        return connect_string_default

#need to move crt logic out of here in prep for connection Class
#also some ssh clients may not need to set 'term len' or may do it already, will need to account for this
def set_terminal_settings(strHost):
    """
    Sets terminal settings for the session.
   
    Args:
    - strHost (str): The hostname.
   
    Returns:
    None
    """
    crt.Screen.WaitForStrings(["#", ">"], 15)
    term_len = "term len 0"
    term_width = "term width 400"
    exec_command(f"{term_len}", strHost)
    exec_command(f"{term_width}", strHost)


#write a function that gets device info like make/model/SN/OS
#def get_device_info():

#This may get turn into get prompt and the crt logic will be moved into its own function
#This would be done to prep for the connection Class
def get_device_name():
    """
    Retrieves the device name from the current screen in the terminal.
   
    Args:
    None
   
    Returns:
    - str: The device name.
    """
    return crt.Screen.Get(crt.Screen.CurrentRow, 0, crt.Screen.CurrentRow, crt.Screen.CurrentColumn - 2).replace("#", "")


#Command and Error Handling

#Need to bust out the crt logic from this and turn this into a passthrough for
#for ssh clients in prep of connection Class.
def send_command(command, device_name):
    """
    Sends a command to the terminal and returns the output.
   
    Args:
    - command (str): The command to send.
    - device_name (str): The name of the device to send the command to.
   
    Returns:
    - str: The output from the command execution.
    """
    if device_name.find(".") > -1:
        prompt = "#"
    else:
        prompt = device_name + "#"
    crt.Screen.WaitForStrings([prompt], 1)
    crt.Screen.Send(command + "\r")
    return crt.Screen.ReadString(prompt, 30)


def exec_command(command, device_name):
    """
    Executes a command on a device, cleans, and caches the output.
   
    Args:
    - command (str): The command to execute.
    - device_name (str): The name of the device.
   
    Returns:
    - str: The cleaned output from the command execution, with device name included.
    """
    # Try to retrieve the cleaned output from the cache first
    output = command_cache.get(device_name, command)

    # If the output is not in the cache, execute the command and clean the result
    if output is None:
        result = send_command(command, device_name)
        result = handle_errors(result, command, device_name)

        # Cleaning the output
        cleaned_output = command_cache.clean_output(result)

        # Reconstructing the output with the device name
        if "." in device_name:
            output = cleaned_output.strip()
        else:
            output = f"{device_name}#{cleaned_output}{device_name}#"

        # Adding the cleaned (and reconstructed) output to the cache
        command_cache.add(device_name, command, output)

    return output


#Need to bust out the crt logic for prep of the connection Class
def handle_errors(result, command, device_name):
    """
    Handles errors during command execution and logs them.
   
    Args:
    - result (str): The result from the command execution.
    - command (str): The command that was executed.
    - device_name (str): The name of the device.
   
    Returns:
    - str: The processed result, taking into account any errors.
    """
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
    # if "Failed to connect" in result:
        # log_error(result)
        # print(f"Error: {result}")
        # Continue with the next host or operation
        # return result

    return result
    
    
def handle_connection_failure(strHost, connection_type, additional_info=""):
    # SecureCRT specific error handling for authentication failure
    error_message = crt.GetLastErrorMessage()
    if "Authentication failed" in error_message or "Login incorrect" in error_message:
        error_message = f"Authentication failed for {strHost} using {connection_type}: {error_message}"

    if additional_info:
        error_message += f" Additional info: {additional_info}"

    log_connection_error(strHost, connection_type, error_message)

#Vulnerability Check Functions 


"""
--------------------------------------------------------------------------
Cisco IOS XE Switch NDM Security Technical Implementation Guide
Version 3, Release: 1 Benchmark Date: 24 July 2024
--------------------------------------------------------------------------
"""


def V220518(device_type, device_name):
    """
    V-220518 - CAT II - The Cisco switch must be configured to limit the number of concurrent management sessions to an organization-defined number.
    logic updated 2023-SEP-05 by Johnathan Greeley, removed module lookup and changes command.
    """
    check = Stig()
    check.set_vulid()
    check.status = "OP"

    # Run the command to check for session limit and vty line configuration
    command = "show run | s ^line.(vty|con)"
    result = exec_command(command, device_name)

    # Check if session limit is set
    if "session-limit" in result:
        session_limit = re.search(r"session-limit (\d+)", result)
        if session_limit and int(session_limit.group(1)) < 2:
            check.status = "NF"
            check.finding = result
            check.comments = "V-220518 - CAT II - NAF as long as the VTY lines have session-limit >=2"
        else:
            check.status = "OP"
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
            check.status = "NF"
            check.finding = result
            check.comments = "V-220518 - CAT II - NAF as only vty 0 to 4 are open and all other lines are closed."
        else:
            check.status = "OP"
            check.finding = result
            check.comments = "V-220518 - CAT II - VTY lines configuration is not as expected."

    return check




def V220519(device_type, device_name):
    """
    V-220519 - CAT II - The Cisco switch must be configured to automatically audit account creation.
    updated command to "show run | s ^archive" by Johnathan Greeley 2023-SEP-05
    """
    check = Stig()
    check.set_vulid()
    check.status = "OP"

    command = "show run | s ^archive"
    result = exec_command(command, device_name)

    # Default comments and finding
    check.comments = "V-220519 - CAT II - OPEN - no logging"
    check.finding = result

    # Check if "log config" is present in the result
    if re.search(r'log config', result[len(device_name) + len(command):]):
        check.status = "NF"
        check.comments = "V-220519 - CAT II - NAF - Logging enabled"

    return check


def V220520(device_type, device_name):
    """
    V220520 - CAT II - The Cisco switch must be configured to automatically audit account modification.
    updated command to "show run | s ^archive" by Johnathan Greeley 2023-SEP-05
    """
    check = Stig()
    check.set_vulid()
    check.status = "OP"

    command = "show run | s ^archive"
    result = exec_command(command, device_name)

    # Default comments and finding
    check.comments = "V220520 - CAT II - OPEN - no logging"
    check.finding = result

    # Check if "log config" is present in the result
    if re.search(r'log config', result[len(device_name) + len(command):]):
        check.status = "NF"
        check.comments = "V220520 - CAT II - NAF - Logging enabled"

    return check


def V220521(device_type, device_name):
    """
    V-220521 - CAT II - The Cisco switch must be configured to automatically audit account disabling actions.
    updated command to "show run | s ^archive" by Johnathan Greeley 2023-SEP-05
    """
    check = Stig()
    check.set_vulid()
    check.status = "OP"

    command = "show run | s ^archive"
    result = exec_command(command, device_name)

    # Default comments and finding
    check.comments = "V-220521 - CAT II - OPEN - no logging"
    check.finding = result

    # Check if "log config" is present in the result
    if re.search(r'log config', result[len(device_name) + len(command):]):
        check.status = "NF"
        check.comments = "V-220521 - CAT II - NAF - Logging enabled"

    return check


def V220522(device_type, device_name):
    """
    V-220522 - CAT II - The Cisco switch must be configured to automatically audit account removal actions.
    updated command to "show run | s ^archive" by Johnathan Greeley 2023-SEP-05
    """
    check = Stig()
    check.set_vulid()
    check.status = "OP"

    command = "show run | s ^archive"
    result = exec_command(command, device_name)

    # Default comments and finding
    check.comments = "V-220522 - CAT II - OPEN - no logging"
    check.finding = result

    # Check if "log config" is present in the result
    if re.search(r'log config', result[len(device_name) + len(command):]):
        check.status = "NF"
        check.comments = "V-220522 - CAT II - NAF - Logging enabled"

    return check


def V220523(device_type, device_name):
    """
    V-220523 - CAT II - The Cisco switch must be configured to enforce approved authorizations for controlling the flow of management information within the device based on control policies.
    Updated by Johnathan Greeley 2023-SEP-05, used "show run | s ^line.(vty|con)" to use from command cach
    """
    check = Stig()
    check.set_vulid()
    check.status = "OP"
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
            check.status = "NF"
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
    check.set_vulid()
    check.status = "OP"

    command = "sh run | i login.block"
    result = exec_command(command, device_name)

    check.finding = result
    check.comments = "!V-220524 - CAT II - ****NOTE AS OF 11/1/2019 THIS IS OPEN / FINDING - BE SURE TO FIX THIS!! *** \r !V-220524 - CAT II - FIX ACTION: conf t - login block-for 900 attempts 3 within 120"

    # Search for "block-for" in the result
    if re.search(r'block-for', result):
        check.status = "NF"
        check.comments = "V-220524 - CAT II - NAF - Configured to limit the number of failed logon attempts"

    return check    


def V220525(device_type, device_name):
    """
    V-220525 - CAT II - The Cisco switch must be configured to display the Standard Mandatory DoD Notice and Consent Banner before granting access to the device.
    """
    check = Stig()
    check.set_vulid()
    check.status = "OP"

    command = "show banner login"
    result = exec_command(command, device_name)

    # Look for key words that are supposed to be in the banner string
    if re.search(r'USG-authorized', result):
        check.status = "NF"
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
    check.set_vulid()
    check.status = "OP"

    command = "show run | s ^archive"
    result = exec_command(command, device_name)

    # Look for key words that are supposed to be in the configuration
    if re.search(r'logging enable', result):
        check.status = "NF"
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
    check.set_vulid()
    check.status = "OP"

    command = "sh run | i service.timestamp"
    result = exec_command(command, device_name)

    # Look for key words that are supposed to be in the configuration
    if re.search(r'service timestamps log', result):
        check.status = "NF"
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
    check.set_vulid()
    check.status = "OP"

    command = "sh ip access-lists | i .log-input*"
    result = exec_command(command, device_name)

    # Look for key words that are supposed to be in the configuration
    if re.search(r'log', result):
        check.status = "NF"
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
    check.set_vulid()
    check.status = "OP"

    command = "show run | s ^archive"
    result = exec_command(command, device_name)

    # Look for key words that are supposed to be in the configuration
    if re.search(r'log config', result) and re.search(r'logging enable', result):
        check.status = "NF"
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
    check.set_vulid()
    check.status = "OP"

    command = "sh run all | i file.privilege"
    result = exec_command(command, device_name)

    # Look for key words that are supposed to be in the configuration
    if re.search(r'file privilege 15', result):
        check.status = "NF"
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
    check.set_vulid()
    check.status = "OP"

    command = "sh run all | i file.privilege"
    result = exec_command(command, device_name)

    check.finding = result
    check.comments = (
        "V-220532 - CAT II - Open - non-standard config. "
        "Please note that IOS 15.x does not support the file privilege feature."
    )

    if "file privilege 15" in result[len(device_name) + len(command):]:
        check.status = "NF"
        check.comments = "V-220532 - CAT II - NAF - file privilege 15 configured."

    return check    


def V220533(device_type, device_name):
    """
    V-220533 - CAT II - The Cisco switch must be configured to limit privileges to change the software resident within software libraries.
    """
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"

    command = "sh run all | i file.privilege"
    result = exec_command(command, device_name)

    check.finding = result
    check.comments = (
        "V-220533 - CAT II - Open. "
        "Please note that IOS 15.x does not support the file privilege feature."
    )

    if "file privilege 15" in result[len(device_name) + len(command):]:
        check.status = "NF"
        check.comments = "V-220533 - CAT II - NAF - file privilege 15 configured."

    return check

def V220534(device_type, device_name):
    """
    V-220534 - CAT I - The Cisco switch must be configured to disable unnecessary services.
    Update by Johnathan Greeley 2023-SEP-05, command updated, looking for all the service listed in vul
    """
    check = Stig()
    check.set_vulid()
    check.status = "NF"

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
            check.status = "OP"
            check.comments = f"V-220534 - CAT I - Open - {service} service enabled."
            break

    return check


def V220535(device_type, device_name):
    """
    V-220535 - CAT II - The Cisco switch must be configured to have only one local user account.
    """
    check = Stig()
    check.set_vulid()
    command = "sh run | i ^username"
    result = exec_command(command, device_name)
    check.finding = result

    # Use a regular expression to match lines that precisely start with 'username' followed by at least one whitespace
    configured_accounts = re.findall(r'^username\s+\S+', result, re.MULTILINE)

    # Check if there's more than one user account
    if len(configured_accounts) > 1:
        check.status = "OP"
        check.comments = f"V220535: More than one local user account found. Please review finding details."
    else:
        check.status = "NF"
        check.comments = "Only one local account configured."

    return check



def V220537(device_type, device_name):
    """
    V-220537 - CAT II - The Cisco switch must be configured to enforce a minimum 15-character password length.
    Updated by Johnathan Greeley 2023-SEP-05, check output for what VUL is asking for.
    """
    REQUIRED_MIN_LENGTH = 15
    check = Stig()
    check.set_vulid()
    check.status = "OP"
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
                    check.status = "NF"
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
    check.set_vulid()
    check.status = "OP"
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
            check.status = "NF"
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
    check.set_vulid()
    check.status = "OP"
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
            check.status = "NF"
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
    check.set_vulid()
    check.status = "OP"
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
            check.status = "NF"
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
    check.set_vulid()
    check.status = "OP"
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
            check.status = "NF"
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
    check.set_vulid()
    check.status = "OP"
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
            check.status = "NF"
            check.comments = f"V-220542 - NAF - common criteria policy configured. The Number of character changes is configured to {char_changes}."

    return check
    
    
def V220543(device_type, device_name):
    """
    V-220543 - CAT I - The Cisco switch must only store cryptographic representations of passwords.
    """
    # Create a Stig object and set the vulnerability ID
    check = Stig()
    check.set_vulid()
    check.status = "OP"

    # Execute the command and store the result
    command = "sh run | i service.password"
    result = exec_command(command, device_name)

    # Check if the result contains the "service password-" string
    if re.search(r'service password-', result):
        check.status = "NF"
        check.comments = "V-220543 - NAF - Password encryption configured."
    else:
        check.comments = "V-220543 - CAT 1 - password encryption must be configured"

    check.finding = result

    return check

def V220544(device_type, device_name):
    """
    V-220544 - CAT I - The Cisco switch must be configured to terminate all network connections associated with device management after 5 minutes of inactivity.
    Updated by Johnathan Greeley on 2023-SEP-05
    """
    # Create a Stig object and set the vulnerability ID
    check = Stig()
    check.set_vulid()

    # Execute the command and store the result
    command = "show run | s ^line.(vty|con)"
    result = exec_command(command, device_name)

    # Assume all config lines are good. If any line has a timeout > 5 min, set status to "OP"
    check.status = "NF"
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
                check.status = "OP"
                break
        if match_exec:
            timeout_minutes = int(match_exec.group(1))
            if timeout_minutes > 5:
                check.status = "OP"
                break

    # Set comments based on the check status
    if check.status == "NF":
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
    check.set_vulid()

    # Execute the command and store the result
    command = "show run | s ^archive"
    result = exec_command(command, device_name)

    # Set the initial status and comments
    check.status = "OP"
    check.comments = "V-220545 - Archive logging is required"

    # Check if the result contains the required configuration
    if re.search(r'(?s)archive.*log config.*logging enable', result):
        check.status = "NF"
        check.comments = "V-220545 - CAT II - NAF - Archive logging configured"

    check.finding = result

    return check


def V220546(device_type, device_name):
    """
    V-220546 - CAT II - The Cisco switch must be configured to audit the execution of privileged functions.
    """
    # Create a Stig object and set the vulnerability ID
    check = Stig()
    check.set_vulid()

    # Set the initial status and comments
    check.status = "OP"
    check.comments = "V-220546 - CAT II - Logging required"

    # Execute the command and store the result
    command = "sh run | i ^archive"
    result = exec_command(command, device_name)

    # Append the result of the second command execution to the first result
    result += "\r" + exec_command(command, device_name)

    # Check if the result contains the required configuration
    if re.search(r'log config', result):
        check.status = "NF"
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
    check.set_vulid()

    # Execute the command and store the result
    command = "sh run | i ^logging.buffered"
    result = exec_command(command, device_name)

    # Use regex to search for the required configuration
    match = re.search(r'logging buffered (\d+) informational', result)
    if match:
        buffer_size = match.group(1)
        check.status = "NF"
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
    check.set_vulid()

    # Set the initial status and comments
    check.status = "OP"
    check.comments = "V220548 - NOTE **** AS OF 11/1/19 THIS IS A FINDING!! PLEASE REMEDIATE"

    # Execute the command and store the result
    command = "show logging | i Trap|Logging.to"
    result = exec_command(command, device_name)

    # Check if the result contains the required configuration
    if "Logging to" in result and re.search(r"(debugging|critical|warnings|notifications|informational)", result):
        check.status = "NF"
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
    check.set_vulid()

    # Set the initial status
    check.status = "OP"

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
            check.status = "NF"
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
    check.set_vulid()

    # Set the initial status
    check.status = "NF"

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
            check.status = "OP"
            check.comments = "Finding: SNMP group not using version 3."
            return check
        elif "snmp-server host" in line and "version 3" not in line:
            check.status = "OP"
            check.comments = "Finding: SNMP host not using version 3."
            return check

    # Check for active users and their settings from the second command's result
    users = re.findall(r"User name: (\S+)", result2)
    for user in users:
        user_data = re.search(rf"User name: {user}.*?Authentication Protocol: (\S+).*?Privacy Protocol: (\S+)", result2, re.DOTALL)
        if user_data:
            auth_protocol, privacy_protocol = user_data.groups()
            if not (auth_protocol == "SHA" and privacy_protocol.startswith("AES")):
                check.status = "OP"
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
    check.set_vulid()

    # Set the initial status
    check.status = "NF"

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
            check.status = "OP"
            check.comments = "Finding: SNMP group not using version 3."
            return check
        elif "snmp-server host" in line and "version 3" not in line:
            check.status = "OP"
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
                    check.status = "OP"
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
    check.set_vulid()
    check.status = "OP"

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
            check.status = "NF"
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
    check.set_vulid()
    check.status = "OP"

    # Execute command and get result
    command = "show run all | i ^ip.ssh.(version|server.algorithm.)"
    result = exec_command(command, device_name)

    # Update check findings and comments
    check.finding = result
    check.comments = "V-220555 - The Cisco switch must be configured to use FIPS-validated Keyed-Hash Message Authentication Code (HMAC) to protect the integrity of remote maintenance sessions.\r Add the command ip ssh server algorithm mac hmac-sha1-96"

    # Check if the result contains required strings using regex
    if re.search(r"ip ssh version 2", result) and re.search(r"hmac-sha2", result):
        check.status = "NF"
        check.comments = "V-220555 - CAT II - NAF - FIPS-validated Keyed-Hash is being used."

    return check

def V220556(device_type, device_name):
    """
    V-220556 -  CAT I - The Cisco switch must be configured to implement cryptographic mechanisms to protect the confidentiality of remote maintenance sessions.
    """

    # Initialize Stig object
    check = Stig()
    check.set_vulid()
    check.status = "OP"

    # Execute command and get result
    command = "show run all | i ^ip.ssh.(version|server.algorithm.)"
    result = exec_command(command, device_name)

    # Update check findings and comments
    check.finding = result
    check.comments = "V-220556 -  The Cisco switch must be configured to implement cryptographic mechanisms to protect the confidentiality of remote maintenance sessions."

    # Check if the result contains required strings using regex
    if re.search(r"ip ssh version 2", result) and (re.search(r"encryption aes128", result) or re.search(r"encryption aes192", result) or re.search(r"encryption aes256", result)):
        check.status = "NF"
        check.comments = "V-220556 - CAT II - NAF - Specified cryptographic mechanisms are being used."

    return check
def V220558(device_type, device_name):
    """
    V-220558 - CAT II -The Cisco switch must be configured to generate log records when administrator privileges are modified.
    """

    # Initialize Stig object
    check = Stig()
    check.set_vulid()
    check.status = "OP"

    # Execute command and get result
    command = "sh run | i logging.user|archive|log.config|logging.enable"
    result = exec_command(command, device_name)

    # Update check findings and comments
    check.finding = result
    check.comments = "V-220558 - The Cisco switch must be configured to generate log records when administrator privileges are modified."

    # Check if the result contains required strings using regex
    if re.search(r"archive", result) and re.search(r"logging enable", result):
        check.status = "NF"
        check.comments = "V-220558 - CAT II - NAF - archive logging is enabled."

    return check


def V220559(device_type, device_name):
    """
    V-220559 - The Cisco switch must be configured to generate log records when administrator privileges are deleted.
    """

    # Initialize Stig object
    check = Stig()
    check.set_vulid()
    check.status = "OP"

    # Execute command and get result
    command = "sh run | i logging.user|archive|log.config|logging.enable"
    result = exec_command(command, device_name)

    # Update check findings and comments
    check.finding = result
    check.comments = "V-220559 - The Cisco switch must be configured to generate log records when administrator privileges are deleted."

    # Check if the result contains required strings using regex
    if re.search(r"archive", result) and re.search(r"logging enable", result):
        check.status = "NF"
        check.comments = "V-220559 - CAT II - NAF - archive logging is enabled."

    return check


def V220560(device_type, device_name):
    """
    V-220560 - CAT II -  The Cisco switch must be configured to generate audit records when successful/unsuccessful logon attempts occur.
    """

    # Initialize Stig object
    check = Stig()
    check.set_vulid()
    check.status = "OP"

    # Execute command and get result
    command = "sh run | i login.on"
    result = exec_command(command, device_name)

    # Update check findings and comments
    check.finding = result
    check.comments = "V-220560 - NOTE:  AS OF 11/1/19 THIS IS A FINDING - PLEASE REMEDIATE"

    # Check if the result contains required strings using regex
    if re.search(r"on-failure", result) and re.search(r"on-success", result):
        check.status = "NF"
        check.comments = "V-220560 - CAT II - NAF -  Audit records generated when successful/unsuccessful logon attempts occur."

    return check


def V220561(device_type, device_name):
    """
    V-220561 - CAT II -  The Cisco switch must be configured to generate log records for privileged activities.
    updated command to "show run | s ^archive" by Johnathan Greeley 2023-SEP-05
    """

    # Initialize Stig object
    check = Stig()
    check.set_vulid()
    check.status = "OP"

    # Execute command and get result
    command = "show run | s ^archive"
    result = exec_command(command, device_name)

    # Update check findings and comments
    check.finding = result
    check.comments = "V-220561 - The Cisco switch must be configured to generate log records for privileged activities"

    # Check if the result contains required strings using regex
    if re.search(r"archive", result) and re.search(r"logging enable", result):
        check.status = "NF"
        check.comments = "V-220561 - CAT II - NAF - archive logging is enabled"

    return check


def V220563(device_type, device_name):
    """
    V-220563 - CAT II - The Cisco switch must be configured to generate log records when concurrent logons from different workstations occur.
    """

    # Initialize Stig object
    check = Stig()
    check.set_vulid()
    check.status = "OP"

    # Execute command and get result
    command = "sh run | i login.on"
    result = exec_command(command, device_name)

    # Update check findings and comments
    check.finding = result
    check.comments = "V-220563 - CAT II - NAF - paste output"

    # Check if the result contains required string using regex
    if re.search(r"login on-success log", result):
        check.status = "NF"
        check.comments = "V-220563 - CAT II - NAF - Login on-success log is configured."

    return check


def V220564(device_type, device_name):
    """
    V-220564 - CAT II - The Cisco switch must be configured to off-load log records onto a different system than the system being audited.
    """

    # Initialize Stig object
    check = Stig()
    check.set_vulid()
    check.status = "OP"

    # Execute command and get result
    command = "sh run | i logging.host|logging.trap"
    result = exec_command(command, device_name)

    # Update check findings and comments
    check.finding = result
    check.comments = "V-220564 - NOTE:  AS OF 11/1/19 THIS IS A FINDING!!!! PLEASE REMEDIATE"

    # Check if the result contains required strings using regex
    if re.search(r"logging host", result) and re.search(r"logging trap", result):
        check.status = "NF"
        check.comments = "V-220564 - CAT II - NAF - Login on-success log is configured."

    return check


def V220565(device_type, device_name):
    """
    V-220565 - CAT I - The Cisco switch must be configured to use an authentication server for the purpose of authenticating users prior to granting administrative access.
    """

    # Initialize Stig object
    check = Stig()
    check.set_vulid()
    check.status = "OP"

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
            check.status = "NF"
            check.comments = f"V-220565 - CAT I - NAF - {server_name} is configured correctly."
        else:
            check.comments = f"V-220565 - CAT I - {server_name} is not configured correctly."

    # Check for login authentication value
    login_auth_matches = re.findall(r"aaa authentication login (\S+) group", result2)
    for login_auth_value in login_auth_matches:
        if f"login authentication {login_auth_value}" in result2:
            check.comments += f"\nValue {login_auth_value} is using TACACS."
        else:
            check.status = "OP"
            check.comments += f"\nValue {login_auth_value} is not using TACACS."

    # Check if the authentication source is tied to TACACS
    auth_sources = re.findall(r"aaa authentication login (\S+) local", result2)
    for source in auth_sources:
        if f"login authentication {source}" in result2:
            check.status = "OP"
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
    check.set_vulid()
    check.status = "OP"

    # Execute command and get result
    command = "sh event manager policy registered"
    result = exec_command(command, device_name)

    # Update check findings and comments
    check.finding = result
    check.comments = "V-220566 - NOTE:  AS OF 11/1/19 THIS IS A FINDING!!!! PLEASE REMEDIATE"

    # Check if the result contains required strings using regex
    if re.search(r"applet", result):
        check.status = "NF"
        check.comments = "V-220566 - CAT II - NAF - Applet configured and registered."

    return check


def V220567(device_type, device_name):
    """
    Update to confirm 2FA
    V-220567 - CAT II - The Cisco switch must be configured to obtain its public key certificates from an appropriate certificate policy through an approved service provider.
    """

    # Initialize Stig object
    check = Stig()
    check.set_vulid()
    check.status = "NF"

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
        check.status = "OP"
        comments.append("Self-signed certificates are being used for terminal access. They should be removed.")
    else:
        comments.append("No self-signed certificates are used for terminal access.")

    check.comments = "\n".join(comments)

    return check
    
    
def V220568(device_type, device_name):
    check = Stig()
    check.set_vulid()
    check.status = "OP"

    command = "show logging | i Trap|Logging.to"
    result = exec_command(command, device_name)

    check.finding = result

    if result.count("Logging to") >= 2:
        check.status = "NF"
        check.comments = "V-220568 - CAT I - NAF - Remote system logging server(s) in place.."
    else:
        check.comments = "V-220568 - NOTE: AS OF 11/1/19 THIS IS A FINDING!!! PLEASE REMEDIATE"

    return check



def V220569(device_type, device_name):
    check = Stig()
    check.set_vulid()
    check.status = "OP"

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
                check.status = "NF"
                check.comments = (
                    f"NAF: As of 1/16/2020 {check_item['device']} devices should have code level {check_item['version']}.  This device has "
                    + model_version
                )
            else:
                check.status = "OP"
                check.comments = (
                    f"OPEN: As of 1/16/2020 {check_item['device']} devices should have code level {check_item['version']}.  This device has "
                    + model_version
                )

    check.finding = result
    return check


"""
--------------------------------------------------------------------------
Cisco IOS XE Switch L2S Security Technical Implementation Guide
Version 3, Release: 1 Benchmark Date: 24 July 2024
--------------------------------------------------------------------------
"""


def V220649(device_type, device_name):
    """
    V-220649 - The Cisco switch must uniquely identify all network-connected endpoint devices before establishing any connection.
    """
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NA"
    check.comments = "V-220649 - Not applicable - There are no end-user devices in the datacenter."
    
    return check


def V220650(device_type, device_name):
    """
    V-220650 - The Cisco switch must authenticate all VLAN Trunk Protocol (VTP) messages with a hash function using the most secured cryptographic algorithm available.
    """
    check = Stig()
    check.set_vulid()
    check.status = "NF"
    check.comments = "V-220650 - Not running VTP."

    command = "show vtp status"
    result = exec_command(command, device_name)

    # Check if VTP is off
    if "VTP Operating Mode                : Off" in result:
        check.status = "NF"
        check.comments = "V-220650 - NAF - VTP configured but mode is off thus no need for a password."
    else:
        command = "show vtp password"
        vtp_pass_result = exec_command(command, device_name)
        result += "\r" + vtp_pass_result

        if "Password" not in vtp_pass_result:
            check.status = "OP"
            check.comments = "V-220650 - Open - Participating in VTP, but without a password configured."
        else:
            check.status = "NF"
            check.comments = "V-220650 - NAF - Participating in VTP with a password configured."

    check.finding = result
    return check


def V220651(device_type, device_name):
    """
    V-220651 - The Cisco switch must manage excess bandwidth to limit the effects of packet flooding types of denial of service (DoS) attacks.
    """
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NF"
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
    check.set_vulid()
    check.status = "NF"

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
        check.status = "NF"
    else:
        result = ""
        # Check all non-root trunk ports for root guard
        for port in trunk_ports:
            command = "show run int " + port
            port_config = exec_command(command, device_name)
            if "UL" not in port_config and "DL" not in port_config:
                if "guard root" not in port_config:
                    check.status = "OP"
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
    check.set_vulid()
    check.status = "NA"

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
    check.set_vulid()
    check.status = "OP"
    check.comments = "V-220657 - OPEN - The Cisco switch must have STP Loop Guard enabled."

    command = "show run | i loopguard"
    result = exec_command(command, device_name)

    if "loopguard default" in result[len(device_name) + len(command):]:
        check.status = "NF"
        check.comments = "V-220657 - NAF  The Cisco switch has STP Loop Guard enabled."

    check.finding = f"{result}\r"

    return check


def V220658(device_type, device_name):
    """
    V-220658 - The Cisco switch must have Unknown Unicast Flood Blocking (UUFB) enabled.
    """
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NA"
    
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
    check.set_vulid()
    check.status = "NA"
    
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
    check.set_vulid()
    check.status = "NA"
    
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
    check.set_vulid()
    check.status = "NA"
    
    command = "show run | i arp.inspection.vlan"
    result = exec_command(command, device_name)
    
    check.finding = result
    check.comments = "V-220661 - Not Applicable - Datacenter switches only connect to trusted infrastructure devices."
    
    return check



def V220662(device_type, device_name):
    # V-220662 - The Cisco switch must have Storm Control configured on all host-facing switchports.
    check = Stig()
    check.set_vulid()
    check.status = "NF"
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
        check.status = "NF"
    else:
        result = ""
        # Check all non-root trunk ports for root guard
        for port in trunkPorts:
            command= "show run int " + port
            portconfig = exec_command(command, device_name)
            if portconfig.find("UL") == -1 and portconfig.find("DL") == -1:
                if portconfig.find("storm-control") == -1:
                    check.status = "OP"
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
    check.set_vulid()
    check.status = "OP"
    check.comments = "V-220663 - Open - The Cisco switch must have IGMP or MLD Snooping configured on all VLANs."

    command = "show run all | i igmp.snooping$"
    result = exec_command(command, device_name)

    if "ip igmp snooping" in result[len(device_name) + len(command):]:
        check.status = "NF"
        check.comments = "V-220663 - NAF  The Cisco switch has IGMP or MLD snooping is enabled globally."

    check.finding = result
    return check


def V220664(device_type, device_name):
    # V-220664 - Rule Title: The Cisco switch must implement Rapid STP where VLANs span multiple switches with redundant links.
    check = Stig()
    check.set_vulid()
    check.status = "OP"
    check.comments = "V-220664 - Open - The Cisco switch must implement Rapid STP where VLANs span multiple switches with redundant links."

    command = "show spanning-tree summary | i mode"
    result = exec_command(command, device_name)

    if "rapid" in result or "mst" in result:
        check.status = "NF"
        check.comments = "V-220664 - NAF  The Cisco switch has RPVST enabled."

    check.finding = result
    return check


def V220665(device_type, device_name):
    # V-220665 - Rule Title: The Cisco switch must enable Unidirectional Link Detection (UDLD) to protect against one-way connections.
    check = Stig()
    check.set_vulid()
    check.status = "OP"
    check.comments = "V-220665 - Open - The Cisco switch must enable Unidirectional Link Detection (UDLD) to protect against one-way connections.\r"

    command = "show run | i ^udld"
    result = exec_command(command, device_name)

    if "enable" in result or "aggressive" in result:
        check.status = "NF"
        check.comments = "V-220665 - NAF - The Cisco switch has UDLD feature enabled and running on all fiber attached ports.\r"

    check.finding = result
    return check



def V220666(device_type, device_name):
    check = Stig()
    check.set_vulid()
    check.status = "NF"
    check.comments = "The Cisco switch ports must have nonegotiate off on all trunks."

    command = "show interfaces switchport | i ^Negotiation|^Name:"
    result = exec_command(command, device_name)

    findings = re.findall(r"Name: (.+?)\nNegotiation of Trunking: On", result)

    if findings:
        check.status = "OP"
        check.comments += "\nThe following interfaces are set to On:\n" + "\n".join(findings)
        check.comments += "\n\nPlease add the following configuration to correct the findings:\n"
        for interface in findings:
            check.comments += f"\ninterface {interface}\nswitchport nonegotiate\n!"

    check.finding = result
    return check


def V220667(device_type, device_name):
    # there is an issue writing comments when dealing with trunk and dis port configs but is mark open
    check = Stig()
    check.set_vulid()
    check.status = "NF"
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
        check.status = "OP"
        check.comments = "V-220667 - OPEN because of the below findings:\n{}\r".format(findings_str)

    check.finding = result1 + "\n" + result2
    return check




def V220668(device_type, device_name):
    # V-220668 - The Cisco switch must not have the default VLAN assigned to any host-facing switch ports.
    check = Stig()
    check.set_vulid()
    check.status = "OP"
    check.comments = "V-220668 - Open - The Cisco switch must not have the default VLAN assigned to any host-facing switch ports."

    command = "show spanning-tree vlan 1"
    result = exec_command(command, device_name)

    if "does not exist" in result[len(device_name) + len(command):]:
        check.status = "NF"
        check.comments = "V-220668 - NAF  No host-facing ports are assigned to VLAN1"

    check.finding = result
    return check


def V220669(device_type, device_name):
    # The Cisco switch must have the default VLAN pruned from all trunk ports that do not require it.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has. We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    check.comments = "V-220669 - Open - The Cisco switch must have the default VLAN pruned from all trunk ports that do not require it."

    command = "show spanning-tree vlan 1"
    result = exec_command(command, device_name)

    # Using regex to find the string "does not exist" in the result
    if re.search("does not exist", result[len(device_name) + len(command):]):
        check.status = "NF"
        check.comments = "V-220669 - NAF VLAN1 is not in use or trunked"

    check.finding = result
    return check

def V220670(device_type, device_name):
    # The Cisco switch must not use the default VLAN for management traffic.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has. We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    check.comments = "V-220670 - Open - The Cisco switch must not use the default VLAN for management traffic."

    command1 = "show spanning-tree vlan 1"
    command2 = "show run int vlan 1"
    result = exec_command(command1, device_name) + "\r" + exec_command(command2, device_name)

    # Using regex to find the strings "does not exist" and "no ip address" in the result
    if re.search("does not exist", result[len(device_name) + len(command2):]) and re.search("no ip address", result[len(device_name) + len(command2):]):
        check.status = "NF"
        check.comments = "V-220670 - NAF VLAN1 is not being used for management."

    check.finding = result
    return check


def V220671(device_type, device_name):
    # The Cisco switch must have all user-facing or untrusted ports configured as access switch ports.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has. We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NA"

    command = "sh int status | ex trunk|666|disabled"
    result = exec_command(command, device_name)

    check.finding = result
    check.comments = "V-220671 - Not Applicable - Datacenter switches only connect to trusted infrastructure devices."

    return check


def V220672(device_type, device_name):
    # The native VLAN must be assigned to a VLAN ID other than the default VLAN for all 802.1q trunk links.
    check = Stig()
    check.set_vulid()
    check.status = "NF"
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
            check.status = "OP"
            temp += f" {interface.interface}'s native VLAN appears to be assigned to default vlan {interface.vlan}; "

    if check.status == "OP":
        check.comments = f"V-220672 - OPEN because {temp}\r"
    check.finding = result

    return check


def V220673(device_type, device_name):
    # The Cisco switch must not have any switchports assigned to the native VLAN.
    check = Stig()
    check.set_vulid()
    check.status = "OP"
    check.comments = "V-220673 - Open - The Cisco switch must not have any switchports assigned to the native VLAN."

    command = "sh int status | in connected.2172"
    result = exec_command(command, device_name)

    if "" in result[len(device_name) + len(command):]:
        check.status = "NF"
        check.comments = "V-220673 - NAF Native VLAN 200 is not in use by access ports."

    check.finding = result

    return check


"""
--------------------------------------------------------------------------
Cisco IOS XE Switch RTR Security Technical Implementation Guide
Version 3, Release: 1 Benchmark Date: 24 Jul 2024
--------------------------------------------------------------------------
"""


def V220986(device_type, device_name):
    check = Stig()
    check.set_vulid()
    check.status = "OP"
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
    check.set_vulid()
    check.status = "NF"
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
                check.status = "OP"
                check.comments += "\nAuthentication mode is not set in EIGRP interfaces."
            else:
                check.status = "NF"
                check.comments += "\nEIGRP interfaces have authentication set."
        else:
            check.status = "OP"
            check.comments += "\nRouting Protocol is not EIGRP."
    else:
        check.status = "NA"
        check.comments += "\nRouting Protocol is not set."

    return check
    
def V220988(device_type, device_name):
    check = Stig()
    check.set_vulid()
    check.status = "NF"
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
                check.status = "OP"
                check.comments += "\nAuthentication mode is not set in EIGRP interfaces."
            else:
                check.status = "NA"
                check.comments += "\nEIGRP interfaces have authentication set HMAC not Keys."
        else:
            check.status = "OP"
            check.comments += "\nRouting Protocol is not EIGRP.Configs need to be reviewed"
    else:
        check.status = "NA"
        check.comments += "\nRouting Protocol is not set."

    return check    

def V220989(device_type, device_name):
    check = Stig()
    check.set_vulid()
    check.status = "NF"
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
                check.status = "OP"
                check.comments += "\nAuthentication mode is not set in EIGRP interfaces."
            else:
                check.status = "NA"
                check.comments += "\nEIGRP interfaces have authentication set HMAC not Keys."
        else:
            check.status = "OP"
            check.comments += "\nRouting Protocol is not EIGRP.Configs need to be reviewed"
    else:
        check.status = "NA"
        check.comments += "\nRouting Protocol is not set."

    return check    
    
    
def V220990(device_type, device_name):
    check = Stig()
    check.set_vulid()
    check.status = "NF"
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
                check.status = "OP"
                check.comments += "\nAuthentication mode is not set in EIGRP interfaces."
            else:
                check.status = "NA"
                check.comments += "\nEIGRP interfaces have authentication set HMAC not Keys."
        else:
            check.status = "OP"
            check.comments += "\nRouting Protocol is not EIGRP.Configs need to be reviewed"
    else:
        check.status = "NA"
        check.comments += "\nRouting Protocol is not set."

    return check

def V220991(device_type, device_name):
    check = Stig()
    check.set_vulid()
    check.status = "NF"
    check.comments = "The Cisco switch ports must not have interfaces in a down state."

    command = "show int des | ex admin|up"
    result = exec_command(command, device_name)

    # Use regular expression to find interfaces with "down" status
    findings = re.findall(r"(?m)^(\S+)\s+down\s+down", result)

    if findings:
        check.status = "OP"
        check.comments += "\nThe following interfaces are in a down state:\n" + "\n".join(findings)
        check.comments += "\n\nPlease investigate why these interfaces are down."

    check.finding = result
    return check

def V220994(device_type, device_name):
    check = Stig()
    check.set_vulid()
    check.status = "NF"
    check.comments = "V-220994 - The Cisco switch must have boot options set correctly."

    # Define the command to run
    command = "show run | i boot(-start|-end|.network)|^cns"

    # Execute the command and get the result
    result = exec_command(command, device_name)

    # Count the number of lines in the result
    line_count = len(result.strip().split("\n"))

    # Check if the result has more than 2 lines
    if line_count > 2:
        check.status = "OP"
        check.comments += f"\nThe device has extra boot options:\n{result}"

    # Storing the complete result, including the device name and prompt
    check.finding = result
    return check
    
def V220995(device_type, device_name):
    check = Stig()
    check.set_vulid()
    check.status = "OP"  # Default status
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
        check.status = "NF"
        check.comments = "CPP is in place and configured correctly."
    else:
        check.comments = "CPP does not appear to be configured correctly."
    check.finding = result
    return check

def V220996(device_type, device_name):
    check = Stig()
    check.set_vulid()
    check.status = "OP"  # Default status
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
        check.status = "NF"
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
    check.set_vulid()
    check.status = "OP"  # Default status
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
        check.status = "NF"
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
    check.set_vulid()
    check.status = "NF"  

    # The command to execute
    command = "show run | i gratuitous-arps"
    
    # Execute the command and store the result
    result = exec_command(command, device_name)
    
    # Store the command output in check.finding
    check.finding = result

    # Check if 'no ip gratuitous-arps' is NOT in the result
    if "no ip gratuitous-arps" not in result:
        check.status = "OP"
        check.comments = "Gratuitous arps are NOT disabled globally"
    else:
        check.comments = "Gratuitous arps are disabled globally"

    return check


def V220999(device_type, device_name):
    check = Stig()
    check.set_vulid()
    check.status = "NF"
    check.comments = "V-220999 - IP directed broadcast command must not be found on any interface."

    # Define the command to run
    command = "show run all | i ip directed-broadcast"

    # Execute the command and get the result
    result = exec_command(command, device_name)

    # Count the number of lines in the result
    line_count = len(result.strip().split("\n"))

    # Check if the result has more than 2 lines
    if line_count > 2:
        check.status = "OP"
        check.comments += "IP directed broadcast command found, look at findings"

    # Storing the complete result, including the device name and prompt
    check.finding = result
    return check


def V221000(device_type, device_name):
    # Create an object of the Stig class and set default values
    check = Stig()
    check.set_vulid()
    check.status = "NF"

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
            check.status = "OP"
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
    check.set_vulid()
    check.status = "NF"
    check.comments = "V-221001 - IP mask-reply command must not be found on any interface."

    # Define the command to run
    command = "show run all | i ip mask-reply"

    # Execute the command and get the result
    result = exec_command(command, device_name)

    # Count the number of lines in the result
    line_count = len(result.strip().split("\n"))

    # Check if the result has more than 2 lines
    if line_count > 2:
        check.status = "OP"
        check.comments += "IP mask-replay command found, look at findings"

    # Storing the complete result, including the device name and prompt
    check.finding = result
    return check


def V221002(device_type, device_name):
    # Create an object of the Stig class and set default values
    check = Stig()
    check.set_vulid()
    check.status = "NF"

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
            check.status = "OP"
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
    check.set_vulid()
    check.status = "OP"  # Default status
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
        check.status = "NF"
        check.comments = "CPP is in place and configured correctly."
    else:
        check.comments = "CPP does not appear to be configured correctly."
    check.finding = result
    return check
    

def V221004(device_type, device_name):
    check = Stig()
    check.set_vulid()
    check.status = "NF"

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
        check.status = "OP"
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
    check.set_vulid()
    check.status = "NF"

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
        check.status = "OP"
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
    check.set_vulid()
    check.status = "NF"

    # The command to execute
    command = "show run | s line aux 0"

    # Execute the command and store the result
    result = exec_command(command, device_name)

    # Store the command output in check.finding
    check.finding = result

    # Check for the presence of "line aux" and "no exec" in the result
    if "line aux" not in result or "no exec" not in result:
        check.status = "OP"
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
    check.set_vulid()
    check.status = "NA"
    check.comments = "This is not a perimeter device the FIREWALLS above are the perimeter."
    
    return check

def V221008(device_type, device_name):
    """
   Add a command or command to show its location based off configuration.
    """
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NA"
    check.comments = "This is not a perimeter device the FIREWALLS above are the perimeter."
    
    return check

def V221009(device_type, device_name):
    """
   Add a command or command to show its location based off configuration.
    """
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NA"
    check.comments = "This is not a perimeter device the FIREWALLS above are the perimeter."
    
    return check

def V221010(device_type, device_name):
    """
   Add a command or command to show its location based off configuration.
    """
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NA"
    check.comments = "This is not a perimeter device the FIREWALLS above are the perimeter."
    
    return check

def V221011(device_type, device_name):
    """
   Add a command or command to show its location based off configuration.
    """
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NA"
    check.comments = "This is not a perimeter device the FIREWALLS above are the perimeter."
    
    return check

def V221012(device_type, device_name):
    """
   Add a command or command to show its location based off configuration.
    """
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NA"
    check.comments = "This is not a perimeter device the FIREWALLS above are the perimeter."
    
    return check

def V221013(device_type, device_name):
    """
   Add a command or command to show its location based off configuration.
    """
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NA"
    check.comments = "This is not a perimeter device the FIREWALLS above are the perimeter."
    
    return check

def V221014(device_type, device_name):
    """
   Add a command or command to show its location based off configuration.
    """
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NA"
    check.comments = "This is not a perimeter device the FIREWALLS above are the perimeter."
    
    return check

def V221015(device_type, device_name):
    """
   Add a command or command to show its location based off configuration.
    """
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NA"
    check.comments = "This is not a perimeter device the FIREWALLS above are the perimeter."
    
    return check

def V221016(device_type, device_name):
    """
   Add a command or command to show its location based off configuration.
    """
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NA"
    check.comments = "This is not a perimeter device the FIREWALLS above are the perimeter."
    
    return check

def V221017(device_type, device_name):
    """
   Add a command or command to show its location based off configuration.
    """
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NA"
    check.comments = "This is not a perimeter device the FIREWALLS above are the perimeter."
    
    return check

    
def V221018(device_type, device_name):
    # Create an object of the Stig class and set default values
    check = Stig()
    check.set_vulid()
    check.status = "NA"

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
            check.status = "OP"
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
    check.set_vulid()
    check.status = "NA"
    check.comments = "This is not a perimeter device the FIREWALLS above are the perimeter."
    
    return check


def V221020(device_type, device_name):
    
    check = Stig()
    # The vulnerability ID MUST match what the stig file has. We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NA"
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
    check.set_vulid()  # Automatically format the vulnerability ID
    check.status = "NA"  # Default status
    
    # Send the command 'show ip bgp' to the device
    command = "show ip bgp"
    result = exec_command(command, device_name)

    # Check for "% BGP not active" in the output
    if "% BGP not active" in result:
        check.status = "NA"
        check.comments = f"No active BGP process on {device_name}"
    else:
        check.status = "OP"
        check.comments = f"BGP is active on {device_name} please review"

    check.finding = result  # Store the result as the finding

    return check


def V221022(device_type, device_name):
    check = Stig()
    check.set_vulid()  # Automatically format the vulnerability ID
    check.status = "NA"  # Default status
    
    # Send the command 'show ip bgp' to the device
    command = "show ip bgp"
    result = exec_command(command, device_name)

    # Check for "% BGP not active" in the output
    if "% BGP not active" in result:
        check.status = "NA"
        check.comments = f"No active BGP process on {device_name}"
    else:
        check.status = "OP"
        check.comments = f"BGP is active on {device_name}; please review"

    check.finding = result  # Store the result as the finding

    return check

def V221023(device_type, device_name):
    check = Stig()
    check.set_vulid()  # Automatically format the vulnerability ID
    check.status = "NA"  # Default status
    
    # Send the command 'show ip bgp' to the device
    command = "show ip bgp"
    result = exec_command(command, device_name)

    # Check for "% BGP not active" in the output
    if "% BGP not active" in result:
        check.status = "NA"
        check.comments = f"No active BGP process on {device_name}"
    else:
        check.status = "OP"
        check.comments = f"BGP is active on {device_name}; please review"

    check.finding = result  # Store the result as the finding

    return check

def V221024(device_type, device_name):
    check = Stig()
    check.set_vulid()  # Automatically format the vulnerability ID
    check.status = "NA"  # Default status
    
    # Send the command 'show ip bgp' to the device
    command = "show ip bgp"
    result = exec_command(command, device_name)

    # Check for "% BGP not active" in the output
    if "% BGP not active" in result:
        check.status = "NA"
        check.comments = f"No active BGP process on {device_name}"
    else:
        check.status = "OP"
        check.comments = f"BGP is active on {device_name}; please review"

    check.finding = result  # Store the result as the finding

    return check

def V221025(device_type, device_name):
    check = Stig()
    check.set_vulid()  # Automatically format the vulnerability ID
    check.status = "NA"  # Default status
    
    # Send the command 'show ip bgp' to the device
    command = "show ip bgp"
    result = exec_command(command, device_name)

    # Check for "% BGP not active" in the output
    if "% BGP not active" in result:
        check.status = "NA"
        check.comments = f"No active BGP process on {device_name}"
    else:
        check.status = "OP"
        check.comments = f"BGP is active on {device_name}; please review"

    check.finding = result  # Store the result as the finding

    return check

def V221026(device_type, device_name):
    check = Stig()
    check.set_vulid()  # Automatically format the vulnerability ID
    check.status = "NA"  # Default status
    
    # Send the command 'show ip bgp' to the device
    command = "show ip bgp"
    result = exec_command(command, device_name)

    # Check for "% BGP not active" in the output
    if "% BGP not active" in result:
        check.status = "NA"
        check.comments = f"No active BGP process on {device_name}"
    else:
        check.status = "OP"
        check.comments = f"BGP is active on {device_name}; please review"

    check.finding = result  # Store the result as the finding

    return check

def V221027(device_type, device_name):
    check = Stig()
    check.set_vulid()  # Automatically format the vulnerability ID
    check.status = "NA"  # Default status
    
    # Send the command 'show ip bgp' to the device
    command = "show ip bgp"
    result = exec_command(command, device_name)

    # Check for "% BGP not active" in the output
    if "% BGP not active" in result:
        check.status = "NA"
        check.comments = f"No active BGP process on {device_name}"
    else:
        check.status = "OP"
        check.comments = f"BGP is active on {device_name}; please review"

    check.finding = result  # Store the result as the finding

    return check

def V221028(device_type, device_name):
    check = Stig()
    check.set_vulid()  # Automatically format the vulnerability ID
    check.status = "NA"  # Default status
    
    # Send the command 'show ip bgp' to the device
    command = "show ip bgp"
    result = exec_command(command, device_name)

    # Check for "% BGP not active" in the output
    if "% BGP not active" in result:
        check.status = "NA"
        check.comments = f"No active BGP process on {device_name}"
    else:
        check.status = "OP"
        check.comments = f"BGP is active on {device_name}; please review"

    check.finding = result  # Store the result as the finding

    return check

def V221029(device_type, device_name):
    check = Stig()
    check.set_vulid()  # Automatically format the vulnerability ID
    check.status = "NA"  # Default status
    
    # Send the command 'show ip bgp' to the device
    command = "show ip bgp"
    result = exec_command(command, device_name)

    # Check for "% BGP not active" in the output
    if "% BGP not active" in result:
        check.status = "NA"
        check.comments = f"No active BGP process on {device_name}"
    else:
        check.status = "OP"
        check.comments = f"BGP is active on {device_name}; please review"

    check.finding = result  # Store the result as the finding

    return check

def V221030(device_type, device_name):
    check = Stig()
    check.set_vulid()  # Automatically format the vulnerability ID
    check.status = "NA"  # Default status
    
    # Send the command 'show ip bgp' to the device
    command = "show ip bgp"
    result = exec_command(command, device_name)

    # Check for "% BGP not active" in the output
    if "% BGP not active" in result:
        check.status = "NA"
        check.comments = f"No active BGP process on {device_name}"
    else:
        check.status = "OP"
        check.comments = f"BGP is active on {device_name}; please review"

    check.finding = result  # Store the result as the finding

    return check

def V221031(device_type, device_name):
    check = Stig()
    check.set_vulid()  # Automatically format the vulnerability ID
    check.status = "NA"  # Default status
    
    # Send the command 'show ip bgp' to the device
    command = "show ip bgp"
    result = exec_command(command, device_name)

    # Check for "% BGP not active" in the output
    if "% BGP not active" in result:
        check.status = "NA"
        check.comments = f"No active BGP process on {device_name}"
    else:
        check.status = "OP"
        check.comments = f"BGP is active on {device_name}; please review"

    check.finding = result  # Store the result as the finding

    return check

def V221032(device_type, device_name):
    check = Stig()
    check.set_vulid()  # Automatically format the vulnerability ID
    check.status = "NA"  # Default status
    
    # Send the command 'show ip bgp' to the device
    command = "show ip bgp"
    result = exec_command(command, device_name)

    # Check for "% BGP not active" in the output
    if "% BGP not active" in result:
        check.status = "NA"
        check.comments = f"No active BGP process on {device_name}"
    else:
        check.status = "OP"
        check.comments = f"BGP is active on {device_name}; please review"

    check.finding = result  # Store the result as the finding

    return check
    
    
def V221033(device_type, device_name):
    
    check = Stig()
    check.set_vulid()
    check.status = "NA"  # Initialize as Not_Applicable, to be updated based on findings

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
        check.status = "OP"
    else:
        check.finding += f"\nMPLS Output:\n{result_mpls}"
        check.comments += "MPLS is not configured on this device."

    if vrf_flag:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs configured on this device, please review."
        check.status = "OP"
    else:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs are not configured on this device."

    return check


def V221034(device_type, device_name):
    """
    Checks MPLS and VRF configurations on the Cisco switch.
    """
    check = Stig()
    check.set_vulid()
    check.status = "NA"  # Initialize as Not_Applicable, to be updated based on findings

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
        check.status = "OP"
    else:
        check.finding += f"\nMPLS Output:\n{result_mpls}"
        check.comments += "MPLS is not configured on this device."

    if vrf_flag:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs configured on this device, please review."
        check.status = "OP"
    else:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs are not configured on this device."

    return check

def V221035(device_type, device_name):
    """
    Checks MPLS and VRF configurations on the Cisco switch.
    """
    check = Stig()
    check.set_vulid()
    check.status = "NA"  # Initialize as Not_Applicable, to be updated based on findings

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
        check.status = "OP"
    else:
        check.finding += f"\nMPLS Output:\n{result_mpls}"
        check.comments += "MPLS is not configured on this device."

    if vrf_flag:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs configured on this device, please review."
        check.status = "OP"
    else:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs are not configured on this device."

    return check

def V221036(device_type, device_name):
    """
    Checks MPLS and VRF configurations on the Cisco switch.
    """
    check = Stig()
    check.set_vulid()
    check.status = "NA"  # Initialize as Not_Applicable, to be updated based on findings

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
        check.status = "OP"
    else:
        check.finding += f"\nMPLS Output:\n{result_mpls}"
        check.comments += "MPLS is not configured on this device."

    if vrf_flag:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs configured on this device, please review."
        check.status = "OP"
    else:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs are not configured on this device."

    return check

def V221037(device_type, device_name):
    """
    Checks MPLS and VRF configurations on the Cisco switch.
    """
    check = Stig()
    check.set_vulid()
    check.status = "NA"  # Initialize as Not_Applicable, to be updated based on findings

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
        check.status = "OP"
    else:
        check.finding += f"\nMPLS Output:\n{result_mpls}"
        check.comments += "MPLS is not configured on this device."

    if vrf_flag:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs configured on this device, please review."
        check.status = "OP"
    else:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs are not configured on this device."

    return check

def V221038(device_type, device_name):
    """
    Checks MPLS and VRF configurations on the Cisco switch.
    """
    check = Stig()
    check.set_vulid()
    check.status = "NA"  # Initialize as Not_Applicable, to be updated based on findings

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
        check.status = "OP"
    else:
        check.finding += f"\nMPLS Output:\n{result_mpls}"
        check.comments += "MPLS is not configured on this device."

    if vrf_flag:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs configured on this device, please review."
        check.status = "OP"
    else:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs are not configured on this device."

    return check

def V221039(device_type, device_name):
    """
    Checks MPLS and VRF configurations on the Cisco switch.
    """
    check = Stig()
    check.set_vulid()
    check.status = "NA"  # Initialize as Not_Applicable, to be updated based on findings

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
        check.status = "OP"
    else:
        check.finding += f"\nMPLS Output:\n{result_mpls}"
        check.comments += "MPLS is not configured on this device."

    if vrf_flag:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs configured on this device, please review."
        check.status = "OP"
    else:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs are not configured on this device."

    return check

def V221040(device_type, device_name):
    """
    Checks MPLS and VRF configurations on the Cisco switch.
    """
    check = Stig()
    check.set_vulid()
    check.status = "NA"  # Initialize as Not_Applicable, to be updated based on findings

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
        check.status = "OP"
    else:
        check.finding += f"\nMPLS Output:\n{result_mpls}"
        check.comments += "MPLS is not configured on this device."

    if vrf_flag:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs configured on this device, please review."
        check.status = "OP"
    else:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs are not configured on this device."

    return check

def V221041(device_type, device_name):
    """
    Checks MPLS and VRF configurations on the Cisco switch.
    """
    check = Stig()
    check.set_vulid()
    check.status = "NA"  # Initialize as Not_Applicable, to be updated based on findings

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
        check.status = "OP"
    else:
        check.finding += f"\nMPLS Output:\n{result_mpls}"
        check.comments += "MPLS is not configured on this device."

    if vrf_flag:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs configured on this device, please review."
        check.status = "OP"
    else:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs are not configured on this device."

    return check

def V221042(device_type, device_name):
    """
    Checks MPLS and VRF configurations on the Cisco switch.
    """
    check = Stig()
    check.set_vulid()
    check.status = "NA"  # Initialize as Not_Applicable, to be updated based on findings

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
        check.status = "OP"
    else:
        check.finding += f"\nMPLS Output:\n{result_mpls}"
        check.comments += "MPLS is not configured on this device."

    if vrf_flag:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs configured on this device, please review."
        check.status = "OP"
    else:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs are not configured on this device."

    return check

def V221043(device_type, device_name):
    """
    Checks MPLS and VRF configurations on the Cisco switch.
    """
    check = Stig()
    check.set_vulid()
    check.status = "NA"  # Initialize as Not_Applicable, to be updated based on findings

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
        check.status = "OP"
    else:
        check.finding += f"\nMPLS Output:\n{result_mpls}"
        check.comments += "MPLS is not configured on this device."

    if vrf_flag:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs configured on this device, please review."
        check.status = "OP"
    else:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs are not configured on this device."

    return check

def V221044(device_type, device_name):
    """
    Checks MPLS and VRF configurations on the Cisco switch.
    """
    check = Stig()
    check.set_vulid()
    check.status = "NA"  # Initialize as Not_Applicable, to be updated based on findings

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
        check.status = "OP"
    else:
        check.finding += f"\nMPLS Output:\n{result_mpls}"
        check.comments += "MPLS is not configured on this device."

    if vrf_flag:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs configured on this device, please review."
        check.status = "OP"
    else:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs are not configured on this device."

    return check


def V221045(device_type, device_name):
    """
    Checks MPLS and VRF configurations on the Cisco switch.
    """
    check = Stig()
    check.set_vulid()
    check.status = "NA"  # Initialize as Not_Applicable, to be updated based on findings

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
        check.status = "OP"
    else:
        check.finding += f"\nMPLS Output:\n{result_mpls}"
        check.comments += "MPLS is not configured on this device."

    if vrf_flag:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs configured on this device, please review."
        check.status = "OP"
    else:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs are not configured on this device."

    return check

def V221046(device_type, device_name):
    """
    Checks MPLS and VRF configurations on the Cisco switch.
    """
    check = Stig()
    check.set_vulid()
    check.status = "NA"  # Initialize as Not_Applicable, to be updated based on findings

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
        check.status = "OP"
    else:
        check.finding += f"\nMPLS Output:\n{result_mpls}"
        check.comments += "MPLS is not configured on this device."

    if vrf_flag:
        check.finding += f"\nVRF Output:\n{result_vrf}"
        check.comments += "\nVRFs configured on this device, please review."
        check.status = "OP"
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
    check.set_vulid()
    check.status = "NA"
    check.comments = "This is not a PE Switch."
    
    return check

def V221048(device_type, device_name):
    """
   Add a command or command to show its location based off configuration.
    """
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NA"
    check.comments = "This is not a PE Switch."
    
    return check

def V221049(device_type, device_name):
    """
   Add a command or command to show its location based off configuration.
    """
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NA"
    check.comments = "This is not a PE Switch."
    
    return check

def V221050(device_type, device_name):
    """
   Add a command or command to show its location based off configuration.
    """
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NA"
    check.comments = "This is not a PE Switch."
    
    return check

def V221051(device_type, device_name):
    """
   Add a command or command to show its location based off configuration.
    """
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NA"
    check.comments = "This is not a PE Switch."
    
    return check



def V221052(device_type, device_name):
    check = Stig()
    check.set_vulid()
    check.status = "OP"  # Default status
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
        check.status = "NF"
        check.comments = "CPP is in place and configured correctly."
    else:
        check.comments = "CPP does not appear to be configured correctly."
    check.finding = result
    return check    


def V221053(device_type, device_name):
    check = Stig()
    check.set_vulid()
    check.status = "NA"

    command = "show ip multicast"
    result = exec_command(command, device_name)

    if not re.search(r"Multicast Routing: disabled.*Multicast Multipath: disabled", result, re.DOTALL):
        check.status = "OP"
        check.comments = "Multicast routing is configured and needs to be reviewed."
    else:
        check.comments = "There is no Multicast routing on this device."

    check.finding = result
    return check

def V221054(device_type, device_name):
    check = Stig()
    check.set_vulid()
    check.status = "NA"

    command = "show ip multicast"
    result = exec_command(command, device_name)

    if not re.search(r"Multicast Routing: disabled.*Multicast Multipath: disabled", result, re.DOTALL):
        check.status = "OP"
        check.comments = "Multicast routing is configured and needs to be reviewed."
    else:
        check.comments = "There is no Multicast routing on this device."

    check.finding = result
    return check

def V221055(device_type, device_name):
    check = Stig()
    check.set_vulid()
    check.status = "NA"

    command = "show ip multicast"
    result = exec_command(command, device_name)

    if not re.search(r"Multicast Routing: disabled.*Multicast Multipath: disabled", result, re.DOTALL):
        check.status = "OP"
        check.comments = "Multicast routing is configured and needs to be reviewed."
    else:
        check.comments = "There is no Multicast routing on this device."

    check.finding = result
    return check

def V221056(device_type, device_name):
    check = Stig()
    check.set_vulid()
    check.status = "NA"

    command = "show ip multicast"
    result = exec_command(command, device_name)

    if not re.search(r"Multicast Routing: disabled.*Multicast Multipath: disabled", result, re.DOTALL):
        check.status = "OP"
        check.comments = "Multicast routing is configured and needs to be reviewed."
    else:
        check.comments = "There is no Multicast routing on this device."

    check.finding = result
    return check

def V221057(device_type, device_name):
    check = Stig()
    check.set_vulid()
    check.status = "NA"

    command = "show ip multicast"
    result = exec_command(command, device_name)

    if not re.search(r"Multicast Routing: disabled.*Multicast Multipath: disabled", result, re.DOTALL):
        check.status = "OP"
        check.comments = "Multicast routing is configured and needs to be reviewed."
    else:
        check.comments = "There is no Multicast routing on this device."

    check.finding = result
    return check

def V221058(device_type, device_name):
    check = Stig()
    check.set_vulid()
    check.status = "NA"

    command = "show ip multicast"
    result = exec_command(command, device_name)

    if not re.search(r"Multicast Routing: disabled.*Multicast Multipath: disabled", result, re.DOTALL):
        check.status = "OP"
        check.comments = "Multicast routing is configured and needs to be reviewed."
    else:
        check.comments = "There is no Multicast routing on this device."

    check.finding = result
    return check

def V221059(device_type, device_name):
    check = Stig()
    check.set_vulid()
    check.status = "NA"

    command = "show ip multicast"
    result = exec_command(command, device_name)

    if not re.search(r"Multicast Routing: disabled.*Multicast Multipath: disabled", result, re.DOTALL):
        check.status = "OP"
        check.comments = "Multicast routing is configured and needs to be reviewed."
    else:
        check.comments = "There is no Multicast routing on this device."

    check.finding = result
    return check

def V221060(device_type, device_name):
    check = Stig()
    check.set_vulid()
    check.status = "NA"

    command = "show ip multicast"
    result = exec_command(command, device_name)

    if not re.search(r"Multicast Routing: disabled.*Multicast Multipath: disabled", result, re.DOTALL):
        check.status = "OP"
        check.comments = "Multicast routing is configured and needs to be reviewed."
    else:
        check.comments = "There is no Multicast routing on this device."

    check.finding = result
    return check

def V221061(device_type, device_name):
    check = Stig()
    check.set_vulid()
    check.status = "NA"

    command = "show ip multicast"
    result = exec_command(command, device_name)

    if not re.search(r"Multicast Routing: disabled.*Multicast Multipath: disabled", result, re.DOTALL):
        check.status = "OP"
        check.comments = "Multicast routing is configured and needs to be reviewed."
    else:
        check.comments = "There is no Multicast routing on this device."

    check.finding = result
    return check

def V221062(device_type, device_name):
    check = Stig()
    check.set_vulid()
    check.status = "NA"

    command = "show ip multicast"
    result = exec_command(command, device_name)

    if not re.search(r"Multicast Routing: disabled.*Multicast Multipath: disabled", result, re.DOTALL):
        check.status = "OP"
        check.comments = "Multicast routing is configured and needs to be reviewed."
    else:
        check.comments = "There is no Multicast routing on this device."

    check.finding = result
    return check

def V221063(device_type, device_name):
    check = Stig()
    check.set_vulid()
    check.status = "NA"

    command = "show ip multicast"
    result = exec_command(command, device_name)

    if not re.search(r"Multicast Routing: disabled.*Multicast Multipath: disabled", result, re.DOTALL):
        check.status = "OP"
        check.comments = "Multicast routing is configured and needs to be reviewed."
    else:
        check.comments = "There is no Multicast routing on this device."

    check.finding = result
    return check

def V221064(device_type, device_name):
    check = Stig()
    check.set_vulid()
    check.status = "NA"

    command = "show ip multicast"
    result = exec_command(command, device_name)

    if not re.search(r"Multicast Routing: disabled.*Multicast Multipath: disabled", result, re.DOTALL):
        check.status = "OP"
        check.comments = "Multicast routing is configured and needs to be reviewed."
    else:
        check.comments = "There is no Multicast routing on this device."

    check.finding = result
    return check

def V221065(device_type, device_name):
    check = Stig()
    check.set_vulid()
    check.status = "NA"

    command = "show ip multicast"
    result = exec_command(command, device_name)

    if not re.search(r"Multicast Routing: disabled.*Multicast Multipath: disabled", result, re.DOTALL):
        check.status = "OP"
        check.comments = "Multicast routing is configured and needs to be reviewed."
    else:
        check.comments = "There is no Multicast routing on this device."

    check.finding = result
    return check

def V221066(device_type, device_name):
    check = Stig()
    check.set_vulid()
    check.status = "NA"

    command = "show ip multicast"
    result = exec_command(command, device_name)

    if not re.search(r"Multicast Routing: disabled.*Multicast Multipath: disabled", result, re.DOTALL):
        check.status = "OP"
        check.comments = "Multicast routing is configured and needs to be reviewed."
    else:
        check.comments = "There is no Multicast routing on this device."

    check.finding = result
    return check

def V221067(device_type, device_name):
    check = Stig()
    check.set_vulid()
    check.status = "NA"

    command = "show ip multicast"
    result = exec_command(command, device_name)

    if not re.search(r"Multicast Routing: disabled.*Multicast Multipath: disabled", result, re.DOTALL):
        check.status = "OP"
        check.comments = "Multicast routing is configured and needs to be reviewed."
    else:
        check.comments = "There is no Multicast routing on this device."

    check.finding = result
    return check

def V221068(device_type, device_name):
    check = Stig()
    check.set_vulid()
    check.status = "NA"

    command = "show ip multicast"
    result = exec_command(command, device_name)

    if not re.search(r"Multicast Routing: disabled.*Multicast Multipath: disabled", result, re.DOTALL):
        check.status = "OP"
        check.comments = "Multicast routing is configured and needs to be reviewed."
    else:
        check.comments = "There is no Multicast routing on this device."

    check.finding = result
    return check

def V221069(device_type, device_name):
    check = Stig()
    check.set_vulid()
    check.status = "NA"

    command = "show ip multicast"
    result = exec_command(command, device_name)

    if not re.search(r"Multicast Routing: disabled.*Multicast Multipath: disabled", result, re.DOTALL):
        check.status = "OP"
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
    check.set_vulid()
    check.status = "NF"  # Default to "Not A Finding" until proven otherwise

    # The command to execute
    command = "show ip cef summary"

    # Execute the command and store the result
    result = exec_command(command, device_name)

    # Store the command output in check.finding
    check.finding = result

    # Check if 'CEF is enabled' is NOT in the result
    if "CEF is enabled" not in result:
        check.status = "OP"
        check.comments = f"IP CEF is not running on {device_name}"
    else:
        check.comments = f"IP CEF is running on {device_name}"

    return check



def V237752(device_type, device_name):
    # Create an object of the Stig class and set default values
    check = Stig()
    check.set_vulid()
    check.status = "NF"  # Default status

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
            check.status = "OP"
            check.comments = f"IPv6 hop limit less than 32 on {device_name}"
        else:
            check.comments = f"IPv6 hop limit is set to {hop_limit} on {device_name}"
    else:
        check.status = "OP"
        check.comments = f"No 'ipv6 hop-limit' configuration found on {device_name}"
        
    return check


def V237756(device_type, device_name):
    check = Stig()
    check.set_vulid()
    result = exec_command("show ipv6 interface", device_name)
    line_count = len(result.strip().split('\n'))

    check.status = "NA" if line_count == 2 else "OP"
    check.comments = "IPv6 is not configured on this device." if line_count == 2 else "Open - There is IPv6 configured on this device, please review configuration."
    check.finding = result

    return check
    
def V237759(device_type, device_name):
    check = Stig()
    check.set_vulid()
    result = exec_command("show ipv6 interface", device_name)
    line_count = len(result.strip().split('\n'))

    check.status = "NA" if line_count == 2 else "OP"
    check.comments = "IPv6 is not configured on this device." if line_count == 2 else "Open - There is IPv6 configured on this device, please review configuration."
    check.finding = result

    return check

def V237762(device_type, device_name):
    check = Stig()
    check.set_vulid()
    result = exec_command("show ipv6 interface", device_name)
    line_count = len(result.strip().split('\n'))

    check.status = "NA" if line_count == 2 else "OP"
    check.comments = "IPv6 is not configured on this device." if line_count == 2 else "Open - There is IPv6 configured on this device, please review configuration."
    check.finding = result

    return check

def V237764(device_type, device_name):
    check = Stig()
    check.set_vulid()
    result = exec_command("show ipv6 interface", device_name)
    line_count = len(result.strip().split('\n'))

    check.status = "NA" if line_count == 2 else "OP"
    check.comments = "IPv6 is not configured on this device." if line_count == 2 else "Open - There is IPv6 configured on this device, please review configuration."
    check.finding = result

    return check


def V237766(device_type, device_name):
    check = Stig()
    check.set_vulid()
    result = exec_command("show ipv6 interface", device_name)
    line_count = len(result.strip().split('\n'))

    check.status = "NA" if line_count == 2 else "OP"
    check.comments = "IPv6 is not configured on this device." if line_count == 2 else "Open - There is IPv6 configured on this device, please review configuration."
    check.finding = result

    return check


def V237772(device_type, device_name):
    check = Stig()
    check.set_vulid()
    result = exec_command("show ipv6 interface", device_name)
    line_count = len(result.strip().split('\n'))

    check.status = "NA" if line_count == 2 else "OP"
    check.comments = "IPv6 is not configured on this device." if line_count == 2 else "Open - There is IPv6 configured on this device, please review configuration."
    check.finding = result

    return check


def V237774(device_type, device_name):
    check = Stig()
    check.set_vulid()
    result = exec_command("show ipv6 interface", device_name)
    line_count = len(result.strip().split('\n'))

    check.status = "NA" if line_count == 2 else "OP"
    check.comments = "IPv6 is not configured on this device." if line_count == 2 else "Open - There is IPv6 configured on this device, please review configuration."
    check.finding = result

    return check


def V237776(device_type, device_name):
    check = Stig()
    check.set_vulid()
    result = exec_command("show ipv6 interface", device_name)
    line_count = len(result.strip().split('\n'))

    check.status = "NA" if line_count == 2 else "OP"
    check.comments = "IPv6 is not configured on this device." if line_count == 2 else "Open - There is IPv6 configured on this device, please review configuration."
    check.finding = result

    return check


def V237778(device_type, device_name):
    check = Stig()
    check.set_vulid()
    result = exec_command("show ipv6 interface", device_name)
    line_count = len(result.strip().split('\n'))

    check.status = "NA" if line_count == 2 else "OP"
    check.comments = "IPv6 is not configured on this device." if line_count == 2 else "Open - There is IPv6 configured on this device, please review configuration."
    check.finding = result

    return check    


"""
--------------------------------------------------------------------------
Cisco NX OS Switch L2S Security Technical Implementation Guide
Version 3, Release: 1 Benchmark Date: 24 July 2024
--------------------------------------------------------------------------
"""


def V220674(device_type, device_name):
    """
    V-220674 - The Cisco switch must be configured to disable non-essential capabilities.
    """
    check = Stig()
    check.set_vulid()
    check.status = "NF"
    check.comments = "V-220674 - NAF as no non-essential features are enabled"

    # List of non-essential services (excluding VTP)
    non_essential_services = [
        "telnet", "dhcp", "wccp", "nxapi", "imp"
    ]

    # Execute the command to check the status of features
    command = "show feature | i " + "|".join(non_essential_services)
    result = exec_command(command, device_name)

    # Initialize a list to store enabled services
    enabled_services = []

    # Regex to find enabled services
    regex_enabled = re.compile(r"\b(enabled)\b")
    
    # Check if any non-essential features are enabled
    for line in result.splitlines():
        if regex_enabled.search(line):
            enabled_services.append(line.strip())

    # Update status and comments based on the findings
    if enabled_services:
        check.status = "OP"
        check.comments = "V-220674 - CAT I - OPEN - non-essential features enabled:\n" + "\n".join(enabled_services)
    else:
        check.status = "NF"
        check.comments = "V-220674 - NAF as no non-essential features are enabled"
    
    check.finding = result
    return check


def V220675(device_type, device_name):
    # V-101221 - The Cisco switch must uniquely identify all network-connected endpoint devices before establishing any connection..
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NA"
    check.comments = (
        "V-220675 - Not applicable - There are no end-user devices in the datacenter."
    )
    #
    return check


def V220676(device_type, device_name):
    # V-101223 - The Cisco switch must authenticate all VLAN Trunk Protocol (VTP) messages with a hash function using the most secured cryptographic algorithm available.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NF"
    check.comments = "V-220676 - Not running VTP."
    command = "show feature | i telnet|dhcp|wccp|nxapi|imp|vtp"
    temp = ""
    result = exec_command(command, device_name)
    temp = result
    if result.find("enabled", len(device_name) + len(command)) > -1:
        command = "show vtp status"
        result = exec_command(command, device_name)
        temp = temp + "\r" + result
        if result.find("Transparent", len(device_name) + len(command)) > -1:
            check.status = "NF"
            check.comments = "V-220676 - Running VTP, but in transparent mode."
        else:
            command = "show run | i vtp.pass"
            result = exec_command(command, device_name)
            temp = temp + "\r" + result
            if result.find("password", len(device_name) + len(command)) == -1:
                check.status = "OP"
                check.comments = "V-220676 - Participating in VTP, but without a password configured."
            else:
                check.status = "NF"
                check.comments = (
                    "V-220676 - Participating in VTP with a password configured."
                )
    check.finding = temp
    return check


def V220677(device_type, device_name):
    # V-220677 - The Cisco switch must be configured for authorized users to select a user session to capture..
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NF"
    command = "show run | sec monitor.session"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-220677 - NAF - Datacenter switches only connect to servers.  In addition, all NXOS switches are capable of this function."
    return check

#leaving for testing as needed. VUL FAIL TEST
# def V220677(device_type, device_name):
    # V-220677 - The Cisco switch must be configured for authorized users to select a user session to capture.
    # check = Stig()
    # check.set_vulid()
    # check.status = "NF"
    # command = "show run | sec monitor.session"

    # Executing the command and getting the result
    # result = exec_command(command, device_name)

    # Intentional syntax error
    # For example, using an undefined variable
    # result = some_undefined_variable + result

    # check.finding = result
    # check.comments = "V-220677 - NAF - Datacenter switches only connect to servers. In addition, all NXOS switches are capable of this function."

    # return check


def V220678(device_type, device_name):
    # V-220678 - The Cisco switch must be configured for authorized users to remotely view, in real time, all content related to an established user session from a component separate from The Cisco switch.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NF"
    command = "show run | sec monitor.session"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-220678 - NAF - Datacenter switches only connect to servers.  In addition, all NXOS switches are capable of this function."
    return check



def V220679(device_type, device_name):
    # V-220679 - The Cisco switch must authenticate all endpoint devices before establishing any connection.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NF"
    command = "show run | i interface.Ether|dot1x|aaa.authentication.dot1x|aaa.group.server.radius|aaa.authentication.dot1x"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-220679 - NAF - Datacenter switches only connect to servers.  In addition, all NXOS switches are capable of this function."
    return check


def V220680(device_type, device_name):
    check = Stig()
    check.set_vulid()
    check.status = "NF"
    temp = ""

    # Find all unique root ports
    root_ports = list(set([
        line.split(" ")[0]
        for line in exec_command("show spanning-tree brief | i Root.FWD", device_name).splitlines()
        if "#" not in line and "show" not in line
    ]))
    check.comments = f"Found the following root ports: {', '.join(root_ports)}"

    # Find all unique trunk ports that aren't root ports
    trunk_ports = list(set([
        line.split(" ")[0]
        for line in exec_command("show int trunk | i trunking | exc not-trunking", device_name).splitlines()
        if line.split(" ")[0] not in root_ports and "#" not in line and "show" not in line
    ]))

    # Evaluate trunk ports for root guard configuration
    if not trunk_ports:
        check.comments += "\nAll trunking ports are root ports."
        check.status = "NF"
    else:
        for port in trunk_ports:
            port_config = exec_command(f"show run int {port}", device_name)
            temp += port_config
            if "VPC_PEER" not in port_config and "UPLINK" not in port_config:
                if "guard root" not in port_config:
                    check.status = "OP"
                    check.comments += f"\nInterface {port} is not configured with root guard."
                else:
                    check.comments += f"\nInterface {port} is configured correctly."
            else:
                check.comments += f"\nInterface {port} does not require root guard."

    check.finding = temp
    return check


def V220681(device_type, device_name):
    # V-220681 - The Cisco switch must have BPDU Guard enabled on all user-facing or untrusted access switch ports.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NA"
    command = "show run | i interface.Eth|bpduguard"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-220681 - Not Applicable - Datacenter switches only connect to trusted infrastructure devices."
    return check


def V220682(device_type, device_name):
    check = Stig()
    check.set_vulid()
    check.status = "OP"
    check.comments = "V-220682 - OPEN - The Cisco switch must have STP Loop Guard enabled."

    result = exec_command("show run | i loopguard", device_name)
    if "loopguard default" in result[len(device_name) + len("show run | i loopguard"):]:
        check.status = "NF"
        check.comments = "V-220682 - NAF - The Cisco switch has STP Loop Guard enabled."

    check.finding = result + "\r"
    return check

"""
V220683
I don't think this is NA it states all access ports, need to review
"""

def V220683(device_type, device_name):
    # V-220683 - The Cisco switch must have Unknown Unicast Flood Blocking (UUFB) enabled.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NA"
    command = "show run | i block"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-220683 - Not Applicable - Datacenter switches only connect to trusted infrastructure devices."
    return check


def V220684(device_type, device_name):
    # V-220684 - The Cisco switch must have DHCP snooping for all user VLANs to validate DHCP messages from untrusted sources.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NA"
    command = "show run | i dhcp.snoop"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-220684 - Not Applicable - Datacenter switches only connect to trusted infrastructure devices."
    return check


def V220685(device_type, device_name):
    # V-220685 - The Cisco switch must have IP Source Guard enabled on all user-facing or untrusted access switch ports.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NA"
    command = "show run | i verify.*.dhcp.snoop"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-220685 - Not Applicable - Datacenter switches only connect to trusted infrastructure devices."
    return check


def V220686(device_type, device_name):
    # V-220686 - The Cisco switch must have Dynamic Address Resolution Protocol (ARP) Inspection (DAI) enabled on all user VLANs.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NA"
    command = "show run | i arp.inspection.vlan"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-220686 - Not Applicable - Datacenter switches only connect to trusted infrastructure devices."
    return check


def V220687(device_type, device_name):
    check = Stig()
    check.set_vulid()
    check.status = "OP"

    command = exec_command("show run | sec ^interface|^port-profile | ex .access.vlan.666|ip|mtu|trunk.(native|allowed)", device_name)
    check.finding = command

    interfaces = command.split("interface ")
    port_profiles = command.split("port-profile type ethernet ")
    
    port_profile_dict = {profile.split("\n")[0].strip(): "storm-control" in profile for profile in port_profiles[1:]}
    iface_states = {}

    for interface in interfaces[1:]:
        lines = interface.strip().split("\n")
        if_name = lines[0].strip()
        iface_states[if_name] = {'is_access': False, 'has_storm_control': False}

        for line in lines[1:]:
            if "switchport access vlan" in line:
                iface_states[if_name]['is_access'] = True
            elif "storm-control" in line:
                iface_states[if_name]['has_storm_control'] = True
            elif "inherit port-profile" in line:
                profile_name = line.split()[-1]
                iface_states[if_name]['has_storm_control'] = port_profile_dict.get(profile_name, False)

    non_compliant_ports = [k for k, v in iface_states.items() if v['is_access'] and not v['has_storm_control']]

    if non_compliant_ports:
        check.comments = "V-220687 - Open - The following access ports do not have storm control:\n" + ",\n".join(non_compliant_ports)
    else:
        check.status = "NF"
        check.comments = "V-220687 - NAF - All access ports have storm control or inherit a compliant port-profile."

    return check


def V220688(device_type, device_name):
    # Initialize STIG check
    check = Stig()
    check.set_vulid()
    check.status = "OP"
    check.comments = "V-220688 - Open - The Cisco switch must have IGMP or MLD Snooping configured on all VLANs."

    # Run the command and get its output
    command = "show run all | i igmp.snooping$"
    result = exec_command(command, device_name)

    # Check for IGMP or MLD snooping in the output
    if "ip igmp snooping" in result:
        check.status = "NF"
        check.comments = "V-220688 - NAF  The Cisco switch has IGMP or MLD snooping is enabled globally."

    # Save the output as the finding
    check.finding = result
    return check


def V220689(device_type, device_name):
    # Initialize STIG check
    check = Stig()
    check.set_vulid()
    check.status = "NF"
    check.comments = "V-220689 - NAF - The Cisco switch has UDLD feature enabled and running on all fiber attached ports.\r"
    
    # Verify if the UDLD feature is enabled globally
    command = "show run | i feature.udld"
    result = exec_command(command, device_name)
    temp = result  # Store command results for later use
    
    if "udld" not in result:
        check.status = "OP"
        check.comments = "V-220689 - Open - The Cisco switch must have the feature UDLD configured.\r"
    
    # Collect information about interfaces with transceivers
    command = "show int trans | i Ether|type"
    result = exec_command(command, device_name)
    temp += result
    
    # Initialize the Interfaces list
    Interfaces = []
    for line in result.splitlines():
        if "Ethern" in line:
            interface = IntTrans()
            interface.interface = line.strip()
            Interfaces.append(interface)
            
    # Check configurations for each interface
    for Interface in Interfaces:
        if Interface.transtype not in ["none", "#"] and ("LH" in Interface.transtype or "SR" in Interface.transtype):
            command = f"show run int {Interface.interface} | i udl"
            result = exec_command(command, device_name)
            temp += result
            if "disabled" in result:
                check.status = "OP"
                check.comments += f"V-220689 - OPEN because Interface {Interface.interface} has UDPD disabled.\r"
                
    # Store all command results as the finding
    check.finding = temp
    return check


def V220690(device_type, device_name):
    check = Stig()
    Interfaces = []
    unused_vlans = set()
    temp = []
    
    check.set_vulid()
    check.status = "NF"
    check.comments = "V-220690 - NAF - The Cisco switch has all disabled switch ports assigned to an unused VLAN."
    
    # Initialize finding details as an empty string
    check.finding = ''
    
    # Get a list of all disabled or unused ports
    command1 = "show interface status | inc sfpAbsent|disabled|xcvrAbsen"
    result1 = exec_command(command1, device_name)
    
    # Append the first command output to finding details
    check.finding += f'{result1}\n\n'
    
    for currentline in result1.splitlines():
        vlan_search = re.search(r'\b\d+\b', currentline[40:])
        if vlan_search:
            vlan = vlan_search.group()
            unused_vlans.add(int(vlan))
    
    # Get trunk port configurations
    command2 = "show run | i ^interface|trunk"
    result2 = exec_command(command2, device_name)
    
    # Append the second command output to finding details
    check.finding += f'{result2}\n'
    
    trunk_config_lines = result2.splitlines()
    
    for i, line in enumerate(trunk_config_lines):
        if "interface" in line and "Ethernet" in line:
            port = line.split()[-1]
            for j in range(i+1, len(trunk_config_lines)):
                if "switchport trunk allowed vlan" in trunk_config_lines[j]:
                    allowed_vlans = trunk_config_lines[j].split()[-1]
                    for vlan_entry in allowed_vlans.split(","):
                        if "-" in vlan_entry:
                            start_vlan, end_vlan = map(int, vlan_entry.split("-"))
                            if any(start_vlan <= unused_vlan <= end_vlan for unused_vlan in unused_vlans):
                                check.status = "OP"
                                temp.append(f"{port} allows traffic from one of the unused VLANs in range {start_vlan}-{end_vlan};")
                        elif int(vlan_entry) in unused_vlans:
                            check.status = "OP"
                            temp.append(f"{port} allows traffic from unused VLAN {vlan_entry};")
                    break
    
    if check.status == "OP":
        check.comments = "V-220690 - OPEN because:\r\n" + "\r\n".join(temp)
    
    return check


def V220691(device_type, device_name):
    # Initialize Stig object and set vulnerability ID
    check = Stig()
    check.set_vulid()
    
    # Default status and comments
    check.status = "OP"
    check.comments = ("V-220691 - Open - The Cisco switch must not have the default VLAN "
                      "assigned to any host-facing switch ports.")
    
    # Execute the command and store the result
    command = "show spanning-tree vlan 1"
    result = exec_command(command, device_name)
    
    # Check if the result indicates that VLAN 1 does not exist
    search_str = "does not exist"
    search_start = len(device_name) + len(command)
    if result.find(search_str, search_start) > -1:
        check.status = "NF"
        check.comments = "V-220691 - NAF  No host-facing ports are assigned to VLAN1"
    
    # Store the command result as the finding
    check.finding = result
    
    return check


def V220692(device_type, device_name):
    # V-220692 - The Cisco switch must have the default VLAN pruned from all trunk ports that do not require it.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    check.comments = "V-220692 - Open - The Cisco switch must have the default VLAN pruned from all trunk ports that do not require it."
    command = "show spanning-tree vlan 1"
    result = exec_command(command, device_name)
    if result.find("does not exist", len(device_name) + len(command)) > -1:
        check.status = "NF"
        check.comments = "V-220691 - NAF VLAN1 is not in use or trunked"
    check.finding = result
    return check


def V220693(device_type, device_name):
    # V-220693 - The Cisco switch must not use the default VLAN for management traffic.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    check.comments = "V-220693 - Open - The Cisco switch must not use the default VLAN for management traffic."
    command = "show spanning-tree vlan 1"
    result = exec_command(command, device_name)
    command = "show run int vlan 1"
    result = result + "\r" + exec_command(command, device_name)
    if (
        result.find("does not exist", len(device_name) + len(command)) > -1
        and result.find("ip address", len(device_name) + len(command)) == -1
    ):
        check.status = "NF"
        check.comments = "V-220693 - NAF VLAN1 is not being used for management."
    check.finding = result
    return check


def V220694(device_type, device_name):
    # V-220694 - The Cisco switch must have all user-facing or untrusted ports configured as access switch ports.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NA"
    command = "sh int status | ex trunk|xcvrAbsen|disabled"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-220694 - Not Applicable - Datacenter switches only connect to trusted infrastructure devices."
    return check


def V220695(device_type, device_name):
    check = Stig()
    check.set_vulid()
    check.status = "NF"
    check.comments = ("V220695 - NAF - The native VLAN on trunk links is other than the default VLAN for all 802.1q trunk links.")
    
    interfaces = []
    temp = ""
    int_count = 0
    
    # Get a list of all trunk ports
    command = "show int trunk"
    result = exec_command(command, device_name)
    
    # Parse output to get port info
    for line in result.splitlines():
        if "--------" in line:
            int_count += 1
        if "Eth" in line or "Po" in line and "#" not in line and int_count <= 2:
            intf_info = IntStatus()
            intf_info.interface = line[0:12].strip()
            intf_info.vlan = line[14:22].strip()
            interfaces.append(intf_info)
    
    # Check if any port is in VLAN 1
    for intf in interfaces:
        if "undefined" not in intf.interface:
            if intf.vlan == "1":
                check.status = "OP"
                temp += f" {intf.interface}'s native VLAN appears to be assigned to default vlan {intf.vlan}; "
    
    if check.status == "OP":
        check.comments = f"V-220695 - OPEN because {temp}\r"
    
    check.finding = result
    return check


def V220696(device_type, device_name):
    # V-220696 - The Cisco switch must not have any switchports assigned to the native VLAN.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    check.comments = f"V-220696 - Open - The Cisco switch must not have any switchports assigned to the native VLAN."
    
    # Prepare the regex to capture native VLANs
    regex = r"Eth[^\n]+?(\d+)\s+trunking"
    
    # Initialize an empty vlan_list
    vlan_list = []
    
    # Command to get trunking information
    trunk_command = "show interface trunk"
    trunk_result = exec_command(trunk_command, device_name)
    check.finding += f"Command: {trunk_command}\nResult: {trunk_result}\n"
    
    # Extract native VLANs
    native_vlan_match = re.search(regex, trunk_result)
    if native_vlan_match:
        native_vlans = re.findall(r"(\d+)", native_vlan_match.group(1))
        native_vlans = list(set(native_vlans))  # Remove duplicates
    else:
        check.comments = "Unable to determine native VLANs from the 'show interface trunk' command output."
        return check
    
    # Command to check switchports
    # Populate vlan_list here, as needed.
    # vlan_list = [some, values, here]
    
    vlan_str = "|".join(map(str, vlan_list))
    command = f"sh int status | in connected.({vlan_str})"
    result = exec_command(command, device_name)
    check.finding += f"Command: {command}\nResult: {result}\n"
    
    if all(vlan not in native_vlans for vlan in vlan_list):
        check.status = "NF"
        clean_vlan_str = ", ".join(map(str, vlan_list))
        check.comments = f"V-220696 - NAF Native VLANs {clean_vlan_str} are not in use by access ports."
        
    return check


"""
--------------------------------------------------------------------------
Cisco NX OS Switch NDM Security Technical Implementation Guide
Version 3, Release: 1 Benchmark Date: 24 July 2024
--------------------------------------------------------------------------
"""


def V220474(device_type, device_name):
    # V-220474 - The Cisco switch must be configured to limit the number of concurrent management sessions to an organization-defined number.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    check.comments = "V-220474 - OPEN - The switch is not configured to limit the number of concurrent management sessions."
    command = "show run | i session-limit"
    result = exec_command(command, device_name)
    if result.find("session-limit", len(device_name) + len(command)) > -1:
        check.status = "NF"
        check.comments = "V-220474 - NAF - The switch is configured to limit the number of concurrent management sessions."
    check.finding = result + "\r"
    return check


def V220475(device_type, device_name):
    # V-220475 - The Cisco switch must be configured to automatically audit account creation.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    command = "sh run | i aaa.accounting"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-220475 - OPEN - Account creation is not automatically audited"
    if result.find("aaa accounting", len(device_name) + len(command)) > -1:
        check.status = "NF"
        check.comments = "V-220475 - NAF - Account creation is being audited."
    return check


def V220476(device_type, device_name):
    # V-220476 - The Cisco switch must be configured to automatically audit account modification.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    command = "sh run | i aaa.accounting"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = (
        "V-220476 - OPEN - Account modification is not automatically audited"
    )
    if result.find("aaa accounting", len(device_name) + len(command)) > -1:
        check.status = "NF"
        check.comments = "V-220476 - NAF - Account modification is being audited."
    return check


def V220477(device_type, device_name):
    # V-220477 - The Cisco switch must be configured to automatically audit account disabling actions.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    command = "sh run | i aaa.accounting"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = (
        "V-220477 - OPEN - Account disabling actions is not automatically audited"
    )
    if result.find("aaa accounting", len(device_name) + len(command)) > -1:
        check.status = "NF"
        check.comments = "V-220477 - NAF - Account disabling actions is being audited."
    return check


def V220478(device_type, device_name):
    # V-220478 - The Cisco switch must be configured to automatically audit account removal actions.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    command = "sh run | i aaa.accounting"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = (
        "V-220478 - OPEN - Account removal actions is not automatically audited"
    )
    if result.find("aaa accounting", len(device_name) + len(command)) > -1:
        check.status = "NF"
        check.comments = "V-220478 - NAF - Account removal actions is being audited."
    return check


def V220479(device_type, device_name):
    # V-220479 - The Cisco switch must be configured to enforce approved authorizations for controlling the flow of management information within the device based on control policies.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    command = "sh run | egrep line.vty|access-class"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-220479 - OPEN -  The Cisco switch does not restrict management access to specific IP addresses"
    if result.find("access-class", len(device_name) + len(command)) > -1:
        check.status = "NF"
        check.comments = "V-220479 - NAF - The Cisco switch restricts management access to specific IP addresses."
    return check


def V220480(device_type, device_name):
    check = Stig()
    check.set_vulid()
    check.status = "OP"

    # Execute the command to get the device model
    command = "show inventory | i PID"
    result = exec_command(command, device_name)

    # Use regular expression to find the model
    match = re.search(r'PID:\s*(N\dK)-', result)
    strModel = match.group(1) if match else "unknown"

    if "N9K" in strModel:
        check.status = "NA"
        check.comments = "NA: Nexus 9K series switches do not have this capability"
        return check

    if "N5K" in strModel:
        command = "sh run | i login.block"
        result = exec_command(command, device_name)
        check.finding = result
        if "block-for" in result:
            check.status = "NF"
            check.comments = "V-220480 - NAF - Cisco switch configured to enforce the limit of three consecutive invalid logon attempts"
        else:
            check.comments = "V-220480 - OPEN - Cisco switch not configured to enforce the limit of three consecutive invalid logon attempts"

    elif "N3K" in strModel:
        check.status = "NA"
        check.comments = "NA: Nexus 3K series switches do not have this capability"

    else:
        check.finding = result
        check.comments = "V-220480 - OPEN - Unable to determine switch model"

    return check



def V220481(device_type, device_name):
    # V-220481 - The Cisco router must be configured to display the Standard Mandatory DoD Notice and Consent Banner before granting access to the device.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    command = "show run | egrep banner|User.Agreement"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-10150 - OPEN -  Cisco switch not configured to display the Standard Mandatory DoD Notice and Consent Banner"
    if result.find("User Agreement", len(device_name) + len(command)) > -1:
        check.status = "NF"
        check.comments = "V-220480 - NAF - Cisco switch configured to display the Standard Mandatory DoD Notice and Consent Banner"
    return check


def V220482(device_type, device_name):
    # V-220482 - The Cisco switch must be configured to protect against an individual falsely denying having performed organization-defined actions to be covered by non-repudiation.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    command = "sh run | i aaa.accounting"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-220482 - OPEN - Switch is not configured to protect against an individual falsely denying having performed organization-defined actions."
    if result.find("aaa accounting", len(device_name) + len(command)) > -1:
        check.status = "NF"
        check.comments = "V-220482 - NAF - Switch is configured to protect against an individual falsely denying having performed organization-defined actions."
    return check


def V220484(device_type, device_name):
    # V-220484 - The Cisco router must produce audit records containing information to establish where the events occurred.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    command = "sh run | i logging.server"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-220484 - OPEN - Cisco switch does not log events."
    if result.find("logging server", len(device_name) + len(command)) > -1:
        check.status = "NF"
        check.comments = (
            "V-220484 - NAF - Cisco switch logs all events with logging server."
        )
    return check


def V220485(device_type, device_name):
    # V-220485 - The Cisco switch must be configured to generate audit records containing the full-text recording of privileged commands.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    command = "sh run | i aaa.accounting"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = (
        "V-220485 - OPEN - Cisco switch does not log all configuration changes."
    )
    if result.find("aaa accounting", len(device_name) + len(command)) > -1:
        check.status = "NF"
        check.comments = "V-220485 - NAF - Cisco switch logs all configuration changes."
    return check


def V220486(device_type, device_name):
    # V-220486 - The Cisco switch must be configured to disable non-essential capabilities.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    command = "show feature | i telnet|dhcp|wccp|nxapi|imp"
    result = exec_command(command, device_name)
    check.comments = "V-220486 - OPEN - Unnecessary or non-secure ports, protocols, or services are enabled."
    if result.find("enabled", len(device_name) + len(command)) == -1:
        check.status = "NF"
        check.comments = "V-220486 - NAF - Unnecessary or non-secure ports, protocols, or services are disabled."
    check.finding = result + "\r"
    return check

    
def V220487(device_type, device_name):
    # V-220487 - The Cisco router must be configured with only one local account to be used as the account of last resort.
    check = Stig()
    check.set_vulid()
    command = "show run | i ^username"
    result = exec_command(command, device_name)  # Cleansing is expected to happen in exec_command now

    # Initialize variables to determine check status and comments
    check.status = "NF"
    check.comments = ""
    strUserAuthLocalAccounts = ["admin", "GLBL-MCLOVIN-NEXUS", "netops_2q22"]
    strConfiguredAccounts = []

    # Extract configured accounts from the command output
    for line in result.splitlines():
        if line.startswith("username"):
            username = line.split()[1]  # Assumes username is always second word in line
            strConfiguredAccounts.append(username)

    # Determine if each configured account is authorized
    for account in strConfiguredAccounts:
        if account.strip() not in strUserAuthLocalAccounts:
            check.status = "OP"
            check.comments += f"Unauthorized user found: {account}\r\n"

    if check.status == "OP":
        check.comments += "V-220487: More than one local user account found. Please review finding details."
    else:
        check.comments += "Account creation authorized by CS, created by WANSEC."

    check.finding = result  # Store the sanitized result as finding
    return check    


def V220488(device_type, device_name):
    # V-220488 - The Cisco router must be configured to implement replay-resistant authentication mechanisms for network access to privileged accounts.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    command = "sh ssh server"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-220488 - OPEN - FIPS mode is not enabled"
    if result.find("ssh version 2", len(device_name) + len(command)) > -1:
        check.status = "NF"
        check.comments = "V-220488 - NAF - FIPS mode is enabled"
    return check


def V220489(device_type, device_name):
    # V-220489 - The Cisco switch must be configured to enforce password complexity by requiring that at least one upper-case character be used.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    command = "sh run | in no.password"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-220489 - OPEN - Cisco switch is not configured to enforce password complexity."
    if result.find("no password", len(device_name) + len(command)) == -1:
        check.status = "NF"
        check.comments = (
            "V-220489 - NAF - Cisco switch is configured to enforce password complexity"
        )
    return check


def V220490(device_type, device_name):
    # V-220490 - The Cisco switch must be configured to enforce password complexity by requiring that at least one lower-case character be used.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    command = "sh run | in no.password"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-220490 - OPEN - Cisco switch is not configured to enforce password complexity."
    if result.find("no password", len(device_name) + len(command)) == -1:
        check.status = "NF"
        check.comments = (
            "V-220490 - NAF - Cisco switch is configured to enforce password complexity"
        )
    return check


def V220491(device_type, device_name):
    # V-220491 - The Cisco switch must be configured to enforce password complexity by requiring that at least one numeric character be used.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    command = "sh run | in no.password"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-220491 - OPEN - Cisco switch is not configured to enforce password complexity."
    if result.find("no password", len(device_name) + len(command)) == -1:
        check.status = "NF"
        check.comments = (
            "V-220491 - NAF - Cisco switch is configured to enforce password complexity"
        )
    return check


def V220492(device_type, device_name):
    # V-220492 - The Cisco switch must be configured to enforce password complexity by requiring that at least one special character be used.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    command = "sh run | in no.password"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-220492 - OPEN - Cisco switch is not configured to enforce password complexity."
    if result.find("no password", len(device_name) + len(command)) == -1:
        check.status = "NF"
        check.comments = (
            "V-220492 - NAF - Cisco switch is configured to enforce password complexity"
        )
    return check


def V220493(device_type, device_name):
    # V-96271 - CAT I -  The Cisco router must be configured to terminate all network connections associated with device management after 10 minutes of inactivity.
    # The network element must timeout management connections for administrative access after 10 minutes or less of inactivity.
    check = Stig()
    check.set_vulid()
    command = "show run | i timeout prev 1"
    # We're going to start with reverse logic, assume all config lines are good.  We'll look at every on and if it's > 10 min we'll fail this vuln
    check.status = "NF"
    result = exec_command(command, device_name)
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
                check.status = "OP"
    if check.status == "NF":
        check.comments = "V-220492 - NAF - Timeout less than or equal to 10"
    else:
        check.comments = "V-220493 - OPEN - Timeout greater than 10."
    check.finding = result
    return check


def V220494(device_type, device_name):
    # V-220494 - The Cisco switch must be configured to automatically audit account enabling actions.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    command = "sh run | i aaa.accounting"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = (
        "V-220494 - OPEN - Cisco switch not configured to log account enabling."
    )
    if result.find("aaa accounting", len(device_name) + len(command)) > -1:
        check.status = "NF"
        check.comments = (
            "V-220494 - NAF - Cisco switch configured to log account enabling."
        )
    return check


def V220495(device_type, device_name):
    # V-220495 - The Cisco switch must be configured to audit the execution of privileged functions.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    command = "sh run | i aaa.accounting"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-220495 - OPEN - Cisco switch not configured to audit the execution of privileged functions."
    if result.find("aaa accounting", len(device_name) + len(command)) > -1:
        check.status = "NF"
        check.comments = "V-220495 - NAF - Cisco switch configured to audit the execution of privileged functions."
    return check


def V220496(device_type, device_name):
    # V-220496 - The Cisco switch must be configured to generate audit records when successful/unsuccessful attempts to log on with access privileges occur.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    command = "sh run | i logging.server"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-220496 - OPEN - Cisco switch does not log all logon attempts."
    if result.find("logging server", len(device_name) + len(command)) > -1:
        check.status = "NF"
        check.comments = "V-220496 - NAF - Cisco switch does log all logon attempts with logging server."
    return check


def V220497(device_type, device_name):
    # V-220497 - The Cisco switch must be configured to generate an alert for all audit failure events.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    command = "sh run | i logging.server"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-220497 - OPEN - Cisco switch does not log all logon attempts."
    if result.find("logging server", len(device_name) + len(command)) > -1:
        check.status = "NF"
        check.comments = "V-220497 - NAF - Cisco switch does log all logon attempts with logging server."
    return check


def V220498(device_type, device_name):
    # V-220498 -  The Cisco switch must be configured to synchronize its clock with the primary and secondary time sources using redundant authoritative time sources.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    command = "sh run | i ntp.server"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-220498 - OPEN - Cisco switch is not configured to synchronize its clock with redundant authoritative time sources."
    serverCount = 0
    for line in result.splitlines():
        if line.find(device_name) == -1 and line.find("server") > -1:
            serverCount += 1
    check.comments = "Found " + str(serverCount) + " NTP servers."
    if serverCount >= 2:
        check.status = "NF"
        check.comments = "V-220498 - NAF - Cisco switch is configured to synchronize its clock with redundant authoritative time sources."
    return check


def V220499(device_type, device_name):
    # V-220499 - The Cisco router must be configured to record time stamps for log records that can be mapped to Coordinated Universal Time (UTC) or Greenwich Mean Time (GMT).
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    command = "sh run | i timezone"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-220499 - OPEN - Cisco switch not configured to record time stamps for log records."
    if (
        result.find("clock timezone ZULU 0 0", len(device_name) + len(command))
        > -1
    ):
        check.status = "NF"
        check.comments = "V-220499 - NAF - Cisco switch configured to record time stamps for log records."
    return check


def V220500(device_type, device_name):
    # V-220500 - The Cisco router must be configured to authenticate SNMP messages using a FIPS-validated Keyed-Hash Message Authentication Code (HMAC).
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.set_vulid()
    check.status = "NF"
    command = "sh run | i snmp-server.*.network"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-220500 - NAF - Cisco switch is configured to authenticate SNMP messages using a FIPS-validated HMAC"
    for line in result.splitlines():
        if line.find("md5") > -1:
            check.status = "OP"
            check.comments = "V-220500 - OPEN - Cisco switch is not configured to authenticate SNMP messages using a FIPS-validated HMAC"
    return check


def V220501(device_type, device_name):
    # V-220501 - The Cisco router must be configured to authenticate SNMP messages using a FIPS-validated Keyed-Hash Message Authentication Code (HMAC).
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.set_vulid()
    check.status = "NF"
    command = "sh run | i snmp-server.*.network"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-220501 - NAF - Cisco switch is configured to authenticate SNMP messages using a FIPS-validated HMAC"
    for line in result.splitlines():
        if line.find("md5") > -1:
            check.status = "OP"
            check.comments = "V-220501 - OPEN - Cisco switch is not configured to authenticate SNMP messages using a FIPS-validated HMAC"
    return check


def V220502(device_type, device_name):
    # V-220502 -  The Cisco switch must be configured to authenticate Network Time Protocol (NTP) sources using authentication that is cryptographically based.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    command = "sh run | in ntp.authentication"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-220502 - OPEN - Cisco switch is not configured to authenticate NTP sources using authentication that is cryptographically based."
    for line in result.splitlines():
        if line.find("md5") > -1:
            check.status = "NF"
            check.comments = "V-220502 - NAF - Cisco switch is configured to authenticate NTP sources using authentication that is cryptographically based."
    return check


def V220503(device_type, device_name):
    # V-220503 - The Cisco switch must be configured to use FIPS-validated Keyed-Hash Message Authentication Code (HMAC) to protect the integrity of remote maintenance sessions.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    command = "sh ssh server"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-220503 - OPEN - Cisco switch is not configured to use FIPS-validated HMAC to protect the integrity of remote maintenance sessions."
    if result.find("ssh version 2", len(device_name) + len(command)) > -1:
        check.status = "NF"
        check.comments = "V-220503 - NAF - Cisco switch is configured to use FIPS-validated HMAC to protect the integrity of remote maintenance sessions."
    return check


def V220504(device_type, device_name):
    # V-220504 - The Cisco switch must be configured to implement cryptographic mechanisms to protect the confidentiality of remote maintenance sessions.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    command = "sh ssh server"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-220504 - OPEN - Cisco switch is not configured to implement cryptographic mechanisms to protect the confidentiality of remote maintenance sessions."
    if result.find("ssh version 2", len(device_name) + len(command)) > -1:
        check.status = "NF"
        check.comments = "V-220504 - NAF - Cisco switch is configured to implement cryptographic mechanisms to protect the confidentiality of remote maintenance sessions."
    return check


def V220506(device_type, device_name):
    # V-220506 - The Cisco switch must be configured to generate log records when administrator privileges are modified.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    command = "sh run | i aaa.accounting"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-220506 - OPEN - Cisco switch not configured to generate log records when administrator privileges are modified."
    if result.find("aaa accounting", len(device_name) + len(command)) > -1:
        check.status = "NF"
        check.comments = "V-220506 - NAF - Cisco switch configured to generate log records when administrator privileges are modified."
    return check


def V220507(device_type, device_name):
    # V-220507 - The Cisco switch must be configured to generate log records when administrator privileges are deleted.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    command = "sh run | i aaa.accounting"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-220507 - OPEN - Cisco switch not configured to generate log records when administrator privileges are deleted."
    if result.find("aaa accounting", len(device_name) + len(command)) > -1:
        check.status = "NF"
        check.comments = "V-220507 - NAF - Cisco switch configured to generate log records when administrator privileges are deleted."
    return check


def V220508(device_type, device_name):
    # V-220508 - The Cisco switch must be configured to generate audit records when successful/unsuccessful logon attempts occur.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    command = "sh run | i logging.server"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-220508 - OPEN - Cisco switch is not configured to generate audit records when successful/unsuccessful logon attempts occur."
    if result.find("logging server", len(device_name) + len(command)) > -1:
        check.status = "NF"
        check.comments = "V-220508 - NAF - Cisco switch is configured to generate audit records when successful/unsuccessful logon attempts occur."
    return check


def V220509(device_type, device_name):
    # V-220509 - The Cisco switch must be configured to generate log records when administrator privileges are deleted.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    command = "sh run | i aaa.accounting"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-220509 - OPEN - Cisco switch not configured to generate log records when administrator privileges are deleted."
    if result.find("aaa accounting", len(device_name) + len(command)) > -1:
        check.status = "NF"
        check.comments = "V-220509 - NAF - Cisco switch configured to generate log records when administrator privileges are deleted."
    return check


def V220510(device_type, device_name):
    # V-220510 - The Cisco switch must generate audit records showing starting and ending time for administrator access to the system.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    command = "sh run | i logging.server"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-220510 - OPEN - Cisco switch is not configured to generate log records showing starting and ending time for administrator access."
    if result.find("logging server", len(device_name) + len(command)) > -1:
        check.status = "NF"
        check.comments = "V-220510 - NAF - Cisco switch is configured to generate log records showing starting and ending time for administrator access."
    return check


def V220512(device_type, device_name):
    # V-220512 - The Cisco switch must be configured to off-load log records onto a different system than the system being audited.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    command = "sh run | i logging.server"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-220512 - OPEN - Cisco switch is not configured to off-load log records onto a different system than the system being audited."
    if result.find("logging server", len(device_name) + len(command)) > -1:
        check.status = "NF"
        check.comments = "V-220512 - NAF - Cisco switch is configured to off-load log records onto a different system than the system being audited."
    return check


def V220513(device_type, device_name):
    # V-220513 - The Cisco switch must be configured to use an authentication server for the purpose of authenticating users prior to granting administrative access.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    command = "sh run | in aaa.authentication"
    result = exec_command(command, device_name)
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
        check.status = "NF"
        check.comments = "V-220513 - NAF - Cisco switch configured to generate log records when administrator privileges are deleted."
    return check


def V220514(device_type, device_name):
    # V-220514 - The Cisco switch must be configured to support organizational requirements to conduct backups of the configuration when changes occur.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.set_vulid()
    check.status = "OP"
    command = "sh run | in event.manager"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-220514 - OPEN - Cisco switch is not configured to conduct backups of the configuration when changes occur."
    if result.find("applet", len(device_name) + len(command)) > -1:
        check.status = "NF"
        check.comments = "V-220514 - NAF - Cisco switch is not configured to conduct backups of the configuration when changes occur."
    return check


def V220515(device_type, device_name):
    # V-220515 - The Cisco switch must be configured to obtain its public key certificates from an appropriate certificate policy through an approved service provider.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.set_vulid()
    check.status = "NF"
    command = "sh crypto ca trustpoints"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-220515 - RCC-SWA does not use PKI Authentication. PSKs are used instead to secure communication over a service provider."
    return check


def V220516(device_type, device_name):
    # V-220516 - The Cisco switch must be configured to send log data to a central log server for the purpose of forwarding alerts to the administrators and the ISSO.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    command = "sh run | i logging.server"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-220516 - OPEN - Cisco switch is not configured to send log data to the syslog server."
    if result.find("logging server", len(device_name) + len(command)) > -1:
        check.status = "NF"
        check.comments = "V-220516 - NAF - Cisco switch is configured to send log data to the syslog server."
    return check


def V220517(device_type, device_name):
    """
    V-220517 - The Cisco router must be running an IOS release that is currently supported by Cisco Systems.
    """
    check = Stig()
    check.set_vulid()
    check.status = "OP"  # Open by default

    # Command to get the version and model
    command = "show ver | i System:|system:|NXOS:|Chassis|chassis"
    result = exec_command(command, device_name)
    check.finding = result

    # Skip the command line and process the actual output lines
    output_lines = result.splitlines()[1:]

    # Use regex to find model and version
    version_str = None
    model_str = None

    debug_info = []

    for line in output_lines:
        debug_info.append(f"Processing line: {line}")
        if not version_str:
            version_match = re.search(r'NXOS:\s+version\s+([^\s]+)|system:\s+version\s+([^\s]+)', line, re.IGNORECASE)
            if version_match:
                version_str = version_match.group(1) or version_match.group(2)
                debug_info.append(f"Found version: {version_str}")
        if not model_str:
            model_match = re.search(r'cisco\s+Nexus\s*(\d{4})', line, re.IGNORECASE)
            if model_match:
                model_str = model_match.group(1).upper()
                debug_info.append(f"Found model: {model_str}")
        if version_str and model_str:
            break

    if not model_str or not version_str:
        check.comments = "Unable to determine the model or version from the output. Debug info:\n" + "\n".join(debug_info)
        return check

    # Map models to known series
    if model_str.startswith("9"):
        model_str = "N9K"
    elif model_str.startswith("5"):
        model_str = "N5K"
    elif model_str.startswith("3"):
        model_str = "N3K"

    # Define the checks for model and version
    checks = [
        {"model_str": "N9K", "version": "9.3(12)", "device": "Nexus 9K"},
        {"model_str": "N5K", "version": "7.3(7)N1(1b)", "device": "Nexus 5K"},
        {"model_str": "N3K", "version": "7.0(3)I7(8)", "device": "Nexus 3K"},
    ]

    # Iterate through the checks and determine the status
    for check_item in checks:
        if check_item["model_str"] == model_str:
            if version.parse(version_str) >= version.parse(check_item["version"]):
                check.status = "NF"
                check.comments = (
                    f"NAF: As of 07/30/2023 {check_item['device']} devices should have code level {check_item['version']}. This device has "
                    + version_str
                )
            else:
                check.status = "OP"
                check.comments = (
                    f"OPEN: As of 07/30/2023 {check_item['device']} devices should have code level {check_item['version']}. This device has "
                    + version_str
                )
            break
        else:
            debug_info.append(f"Model {model_str} did not match {check_item['model_str']}")

    if check.status == "OP":
        check.comments += "\nDebug info:\n" + "\n".join(debug_info)

    return check



def V260464(device_type, device_name):
    # V-260464 - The router must have control plane protection enabled.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    check.comments = "V-260464 - Cisco switch is not configured with a control plane policy."
    command = "sh run all | sec service-policy.input"
    result = exec_command(command, device_name)
    check.finding = result
    if result.find("copp") > -1:
        check.comments = "V-260464 - NAF - Cisco switch is configured with a control plane policy."
        check.status = "NF"
    return check

"""
--------------------------------------------------------------------------
Cisco IOS XE Router NDM Security Technical Implementation Guide
Version 3, Release: 1 Benchmark Date: 24 July 2024
--------------------------------------------------------------------------
"""


def V215807(device_type, device_name):
    # Legacy IDs: V-96189; SV-105327
    # V-215807 - CAT II - The Cisco router must be configured to limit the number of concurrent management sessions to an organization-defined number.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    command = "sh run | i http.secure-server"
    temp = exec_command(command, device_name)
    command = "sh run | i \line.vty.*.*|session-limit"
    result = exec_command(command, device_name)
    if result.find("session-limit", len(device_name) + len(command)) > -1:
        check.status = "NF"
    check.finding = temp + "\r" + result
    check.comments = (
        "V-215807 - CAT II - NAF as long as the VTY lines have session-limit >=2"
    )
    return check


def V215808(device_type, device_name):
    # Legacy IDs: V-96197; SV-105335
    # V-215808 - CAT II - The Cisco router must be configured to automatically audit account creation.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    command = "sh run | sec log.config"
    result = exec_command(command, device_name)
    check.comments = "V-215808 - CAT II - OPEN - no logging"
    check.finding = result
    if result.find("log config", len(device_name) + len(command)) > -1:
        check.status = "NF"
        check.comments = "V-215808 - CAT II - NAF - Logging enabled"
    return check


def V215809(device_type, device_name):
    # Legacy IDs: V-96199; SV-105337
    # V-215809 - CAT II - The Cisco router must be configured to automatically audit account modification.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    command = "sh run | sec log.config"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-215809 - CAT II - OPEN - no logging"
    check.finding = result
    if result.find("log config", len(device_name) + len(command)) > -1:
        check.status = "NF"
        check.comments = "V-215809 - CAT II - NAF - Logging enabled"
    return check


def V215810(device_type, device_name):
    # Legacy IDs: V-96201; SV-105339
    # V-215810 - CAT II - The Cisco router must be configured to automatically audit account disabling actions.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    command = "sh run | sec log.config"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-215810 - CAT II - OPEN - no logging"
    check.finding = result
    if result.find("log config", len(device_name) + len(command)) > -1:
        check.status = "NF"
        check.comments = "V-215810 - CAT II - NAF - Logging enabled"
    return check


def V215811(device_type, device_name):
    # Legacy IDs: V-96203; SV-105341
    # V-215811 - CAT II - The Cisco router must be configured to automatically audit account removal actions.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    command = "sh run | sec log.config"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-215811 - CAT II - OPEN - no logging"
    check.finding = result
    if result.find("log config", len(device_name) + len(command)) > -1:
        check.status = "NF"
        check.comments = "V-215811 - CAT II - NAF - Logging enabled"
    return check


def V215812(device_type, device_name):
    # Legacy IDs: V-96205; SV-105343
    # V-215812 - CAT II - The Cisco router must be configured to enforce approved authorizations for controlling the flow of management information within the device based on control policies.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    check.comments = "V-215812 - OPEN - ACLs were not found."
    ACLName = "Not found"
    intCount = 0
    command = "sh run | i vty..|access-class"
    result = str(exec_command(command, device_name))
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
        result = exec_command(command, device_name)
        if len(result) > 3:
            check.status = "NF"
            check.comments = "V-215812 - NAF - ACL in place"
    check.finding = temp + "\r" + result
    return check


def V215813(device_type, device_name):
    # Legacy IDs: V-96207; SV-105345
    # V-215813 - CAT II - The Cisco router must be configured to enforce the limit of three consecutive invalid logon attempts, after which time it must lock out the user account from accessing the device for 15 minutes.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    command = "sh run | i login.block"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "!V-215813 - CAT II - ****NOTE AS OF 11/1/2019 THIS IS OPEN / FINDING - BE SURE TO FIX THIS!! *** \r !V-215813 - CAT II - FIX ACTION: conf t - login block-for 900 attempts 3 within 120"
    if result.find("block-for", len(device_name) + len(command)) > -1:
        check.status = "NF"
        check.comments = "V-215813 - CAT II - NAF - Configured to limit the number of failed logon attempts"
    return check


def V215814(device_type, device_name):
    # Legacy IDs: V-96209; SV-105347
    # V-215814 - CAT II - The Cisco router must be configured to display the Standard Mandatory DoD Notice and Consent Banner before granting access to the device.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    command = "show run | beg banner"
    if device_type == "NXOS":
        command = "show run | beg banner next 10"
    result = exec_command(command, device_name)
    for line in result.splitlines():
        # Look for key words that are supposed to be in the banner string
        if str(line).find("USG-authorized", 0) > 5:
            check.status = "NF"
    if check.status == "NF":
        check.comments = "Not a finding.  Correct banner in place"
    else:
        check.comments = "Open issue - could not find matching configuration."
    check.finding = result
    return check


def V215815(device_type, device_name):
    # Legacy IDs: V-96217; SV-105355
    # V-215815 - CAT II - The Cisco router must be configured to protect against an individual falsely denying having performed organization-defined actions to be covered by non-repudiation.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    command = "sh run | i userinfo|logging.enable"
    # if device_type == "NXOS":
    #    command = "sh run | i \"aaa authentic\""
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-215815 - CAT II - OPEN - Logging not configured."
    if result.find("logging enable", len(device_name) + len(command)) > -1:
        check.status = "NF"
        check.comments = "V-215815 - CAT II - NAF - ACS logs all attempts (successful/unsuccessful) to escalate privilege to any device using TACACS"
    return check


def V215817(device_type, device_name):
    # Legacy IDs: V-96223; SV-105361
    # V-215817 - CAT II -  The Cisco router must produce audit records containing information to establish when (date and time) the events occurred.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    command = "sh run | i service.timestamp"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-215817 - CAT II - Open - no timestamps configured"
    if result.find("service timestamps log", len(device_name) + len(command)) > -1:
        check.status = "NF"
        check.comments = "V-215817 - CAT II - NAF - Timestamps configured correctly."
    return check


def V215818(device_type, device_name):
    # Legacy IDs: V-96225; SV-105363
    # V-215818 - CAT II -  The Cisco router must produce audit records containing information to establish where the events occurred.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    command = "sh ip access-lists | i .log*"
    # if device_type == "NXOS":
    #    command = "sh run | i \"aaa authentic\""
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-215818 - CAT II - OPEN - No ACLs with logging"
    if result.find("log", len(device_name) + len(command)) > -1:
        check.status = "NF"
        check.comments = "V-215818 - CAT II - NAF - ACL lambdaogging configured."
    return check


def V215819(device_type, device_name):
    # Legacy IDs: V-96227; SV-105365
    # V-215819 - CAT II - The Cisco router must be configured to generate audit records containing the full-text recording of privileged commands.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    command = "sh run | i logging.enable|log.config"
    # if device_type == "NXOS":
    #    command = "sh run | i \"aaa authentic\""
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-215819 - CAT II - OPEN - No Log config"
    if (
        result.find("log config", len(device_name) + len(command)) > -1
        and result.find("logging enable", len(device_name) + len(command)) > -1
    ):
        check.status = "NF"
        check.comments = "V-215819 - CAT II - NAF - Logging configured."
    return check


def V215820(device_type, device_name):
    # Legacy IDs: V-96231; SV-105369
    # V-215820 - CAT II - The Cisco router must be configured to protect audit information from unauthorized modification.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    command = "sh run all | i file.privilege"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-215820 - CAT II - Open - non-standard config.  Please note that IOS 15.x does not support the file privilege feature."
    if result.find("file privilege 15", len(device_name) + len(command)) > -1:
        check.status = "NF"
        check.comments = "V-215820 - CAT II - NAF - file privilege 15 configured."
    return check


def V215821(device_type, device_name):
    # Legacy IDs: V-96233; SV-105371
    # V-215821 - CAT II - The Cisco router must be configured to protect audit information from unauthorized deletion.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    command = "sh run all | i file.privilege"
    # if device_type == "NXOS":
    #    command = "sh run | i \"aaa authentic\""
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-215821 - CAT II - Open - non standard config.  Please note that IOS 15.x does not support the file privilege feature."
    if result.find("file privilege 15", len(device_name) + len(command)) > -1:
        check.status = "NF"
        check.comments = "V-215821 - CAT II - NAF - file privilege 15 configured."
    return check


def V215822(device_type, device_name):
    # Legacy IDs: V-96237; SV-105375
    # V-215822 - CAT II - The Cisco router must be configured to limit privileges to change the software resident within software libraries.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    command = "sh run all | i file.privilege"
    # if device_type == "NXOS":
    #    command = "sh run | i \"aaa authentic\""
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-215822 - CAT II - Open.  Please note that IOS 15.x does not support the file privilege feature."
    if result.find("file privilege 15", len(device_name) + len(command)) > -1:
        check.status = "NF"
        check.comments = "V-215822 - CAT II - NAF - file privilege 15 configured."
    return check


def V215823(device_type, device_name):
    # Legacy IDs: V-96239; SV-105377
    # V-215823 - CAT I - The Cisco router must be configured to prohibit the use of all unnecessary and nonsecure functions and services.
    check = Stig()
    check.set_vulid()
    check.status = "NF"  # Not a Finding
    check.comments = "V-215823 - CAT I - NAF - no unnecessary services configured"

    command = (
        "sh run | i boot.network|boot.server|bootp|dns|identd|finger|^ip.http|rcmd|service.config|"
        "small-servers|service.pad|call-home"
    )
    result = exec_command(command, device_name)
    check.finding = result

    # Ensure we only search the actual command output
    output_lines = result.splitlines()

    unnecessary_services = [
        "boot network",
        "ip boot server",
        "ip bootp server",
        "ip dns server",
        "ip identd",
        "ip finger",
        "ip http server",
        "ip http secure-server",
        "rcp-enable",
        "rsh-enable",
        "service config",
        "service finger",
        "small-servers",
        "service pad",
        "service call-home"
    ]

    findings = []

    for line in output_lines:
        for service in unnecessary_services:
            if re.fullmatch(service, line.strip()):
                findings.append(service)

    if findings:
        check.status = "OP"  # Open
        check.comments = "V-215823 - CAT I - OPEN - unnecessary services enabled.\n" + "\n".join(findings)

    return check

def V215824(device_type, device_name):
    """
    V-215824 - CAT II - The Cisco router must be configured with only one local account
    to be used as the account of last resort in the event the authentication server is unavailable.
    """
    check = Stig()
    check.set_vulid()
    command = "sh run | i ^username"
    result = exec_command(command, device_name)
    check.finding = result

    # Use a regular expression to match lines that precisely start with 'username' followed by at least one whitespace
    configured_accounts = re.findall(r'^username\s+\S+', result, re.MULTILINE)

    user_count = len(configured_accounts)

    # Mark status based on user account count
    if user_count > 1:
        check.status = "OP"
        check.comments = f"V-215824: More than one local user account found. Please review finding details."
    else:
        check.status = "NF"
        check.comments = "V-215824: One or zero local user accounts configured, compliant with STIG requirement."

    return check



def V215826(device_type, device_name):
    # Legacy IDs: V-96253; SV-105391
    # V-215826 - CAT II -  The Cisco router must be configured to enforce a minimum 15-character password length.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.set_vulid()
    check.status = "OP"
    command = "sh aaa common-criteria policy all"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-215826 - NOTE:  *** As of 11/1/19 THIS IS A FINDING!!! ***"
    if len(result.splitlines()) > 2:
        check.status = "NF"
        check.comments = "V-215826 - CAT II - NAF - common criteria policy configured."
    return check


def V215827(device_type, device_name):
    # Legacy IDs: V-96255; SV-105393
    # V-215827 - CAT II -  The Cisco router must be configured to enforce password complexity by requiring that at least one upper-case character be used.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.set_vulid()
    check.status = "OP"
    command = "sh aaa common-criteria policy all"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-215827 - NOTE:  *** As of 11/1/19 THIS IS A FINDING!!! ***"
    if len(result.splitlines()) > 2:
        check.status = "NF"
        check.comments = "V-215827 - NAF - common criteria policy configured."
    return check


def V215828(device_type, device_name):
    # Legacy IDs: V-96257; SV-105395
    # V-215828 - CAT II -  The Cisco router must be configured to enforce password complexity by requiring that at least one lower-case character be used.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.set_vulid()
    check.status = "OP"
    command = "sh aaa common-criteria policy all"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-215828 - NOTE:  *** As of 11/1/19 THIS IS A FINDING!!! ***"
    if len(result.splitlines()) > 2:
        check.status = "NF"
        check.comments = "V-215828 - NAF - common criteria policy configured."
    return check


def V215829(device_type, device_name):
    # Legacy IDs: V-96259; SV-105397
    # V-215829 - CAT II - The Cisco router must be configured to enforce password complexity by requiring that at least one numeric character be used.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.set_vulid()
    check.status = "OP"
    command = "sh aaa common-criteria policy all"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-215829 - NOTE:  *** As of 11/1/19 THIS IS A FINDING!!! ***"
    if len(result.splitlines()) > 2:
        check.status = "NF"
        check.comments = "V-215829 - NAF - common criteria policy configured."
    return check


def V215830(device_type, device_name):
    # Legacy IDs: V-96261; SV-105399
    # V-215830 - CAT II -  The Cisco router must be configured to enforce password complexity by requiring that at least one special character be used.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.set_vulid()
    check.status = "OP"
    command = "sh aaa common-criteria policy all"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-215830 - NOTE:  *** As of 11/1/19 THIS IS A FINDING!!! ***"
    if len(result.splitlines()) > 2:
        check.status = "NF"
        check.comments = "V-215830 - NAF - common criteria policy configured."
    return check


def V215831(device_type, device_name):
    # Legacy IDs: V-96263; SV-105401
    # V-215831 - CAT II -  The Cisco router must be configured to require that when a password is changed, the characters are changed in at least eight of the positions within the password.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.set_vulid()
    check.status = "OP"
    command = "sh aaa common-criteria policy all"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-215831 - NOTE:  *** As of 11/1/19 THIS IS A FINDING!!! ***"
    if len(result.splitlines()) > 2:
        check.status = "NF"
        check.comments = "V-215831 - NAF - common criteria policy configured."
    return check


def V215832(device_type, device_name):
    # Legacy IDs: V-96265; SV-105403
    # V-215832 - CAT I -  The Cisco router must only store cryptographic representations of passwords.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.set_vulid()
    check.status = "OP"
    command = "sh run | i service.password"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-215832 - CAT 1 - password encryption must be configured"
    if result.find("service password-", len(device_name) + len(command)) > -1:
        check.status = "NF"
        check.comments = "V-215832 - NAF - Password encryption configured."
    return check


def V215833(device_type, device_name):
    # Legacy IDs: V-96271; SV-105409
    # V-215833 - CAT I - The Cisco router must be configured to terminate all network connections associated with device management after 5 minutes of inactivity.
    # The network element must timeout management connections for administrative access after 5 minutes or less of inactivity.
    check = Stig()
    check.set_vulid()

    # Execute the command and store the result
    command = "show run | s ^line.(vty|con)"
    result = exec_command(command, device_name)

    # Assume all config lines are good. If any line has a timeout > 5 min, set status to "OP"
    check.status = "NF"
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
                check.status = "OP"
                break
        if match_exec:
            timeout_minutes = int(match_exec.group(1))
            if timeout_minutes > 5:
                check.status = "OP"
                break

    # Set comments based on the check status
    if check.status == "NF":
        check.comments = "Not a finding. Timeout less than or equal to 5 minutes."
    else:
        check.comments = "Open issue - found configuration with timeout greater than 5 minutes."

    check.finding = result

    return check


def V215834(device_type, device_name):
    # Legacy IDs: V-96285; SV-105423
    # V-215834 - CAT II -  The Cisco router must be configured to automatically audit account enabling actions.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.set_vulid()
    check.status = "OP"
    command = "sh run | i archive|log.config|logging.enable"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-215834 - Archive logging is required"
    if (
        result.find("archive", len(device_name) + len(command)) > -1
        and result.find("log config", len(device_name) + len(command)) > -1
        and result.find("logging enable", len(device_name) + len(command)) > -1
    ):
        check.status = "NF"
        check.comments = "V-215834 - CAT II - NAF - Archive logging configured"
    return check


def V215836(device_type, device_name):
    # Legacy IDs: V-96297; SV-105435
    # V-215836 - CAT II - The Cisco router must be configured to allocate audit record storage capacity in accordance with organization-defined audit record storage requirements.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.set_vulid()
    check.status = "OP"
    command = "sh run | i logging.buffered"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = (
        "V-215836 - OPEN - suggest adding logging buffered 1000000 informational"
    )
    if result.find("logging buffered", len(device_name) + len(command)) > -1:
        check.status = "NF"
        check.comments = "V-215836 - CAT II - NAF - ACS manages Authentication."
    return check


def V215837(device_type, device_name):
    # Legacy IDs: V-96301; SV-105439
    # V-215837 - CAT II - The Cisco router must be configured to generate an alert for all audit failure events.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.set_vulid()
    check.status = "OP"
    command = "show logging | i Trap|Logging.to"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = (
        "V215837 - NOTE **** AS OF 11/1/19 THIS IS A FINDING!! PLEASE REMEDIATE"
    )
    if result.find("Logging to ", len(device_name) + len(command)) > -1 and (
        result.find("debugging", len(device_name) + len(command)) > -1
        or result.find("critical", len(device_name) + len(command)) > -1
        or result.find("warnings", len(device_name) + len(command)) > -1
        or result.find("notifications", len(device_name) + len(command)) > -1
        or result.find("informational", len(device_name) + len(command)) > -1
    ):
        check.status = "NF"
        check.comments = "V-215837 - CAT II - NAF - ACS manages Authentication."
    return check


def V215838(device_type, device_name):
    # Legacy IDs: V-96303; SV-105441
    # V-215838 - CAT II -  The Cisco router must be configured to synchronize its clock with the primary and secondary time sources using redundant authoritative time sources.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.set_vulid()
    check.status = "OP"
    command = "sh run | i ntp.server"
    if device_type == "NXOS":
        command = "sh run | i ntp.server"
    result = exec_command(command, device_name)
    check.finding = result
    serverCount = 0
    for line in result.splitlines():
        if line.find(device_name) == -1 and line.find("server") > -1:
            serverCount += 1
    check.comments = "Found " + str(serverCount) + " NTP servers."
    if serverCount >= 2:
        check.status = "NF"
    return check


def V215841(device_type, device_name):
    # Legacy IDs: V-96317; SV-105455
    # V-215841 - CAT II - The Cisco router must be configured to authenticate SNMP messages using a FIPS-validated Keyed-Hash Message Authentication Code (HMAC).
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.set_vulid()
    check.status = "NF"
    command = "sh run | i snmp-server|snmp.user "
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-215841 authenticate SNMP messages using a FIPS-validated Keyed-Hash Message Authentication Code (HMAC)."
    command = "sh run | i snmp-server.group"
    result = exec_command(command, device_name)
    check.finding = result
    for line in result.splitlines():
        if line.find("v3") == -1 or line.find(device_name) == -1:
            check.status = "NF"
            check.comments = "NAF SNMP version 3 is in use"
    return check


def V215842(device_type, device_name):
    # Legacy IDs: V-96319; SV-105457
    # V-215842 - CAT II - The Cisco router must be configured to encrypt SNMP messages using a FIPS 140-2 approved algorithm.
    check = Stig()
    check.set_vulid()

    # Command to fetch SNMP users
    command = "sh snmp user | in ^User|^Privacy"
    result = exec_command(command, device_name)
    check.finding = result
    line_count = 0
    comments = []

    # Regex patterns for matching lines
    user_pattern = re.compile(r'User\s+(\S+)')
    privacy_pattern = re.compile(r'Privacy\s+(\S+)')

    for line in result.splitlines():
        if "#" not in line:
            match = user_pattern.search(line)
            if match:
                snmp_user = match.group(1)
                command = f"sh snmp user {snmp_user} | in Privacy"
                snmp_result = exec_command(command, device_name)
                check.finding += snmp_result

                # Check for AES128 or AES256 encryption
                encrypted = False
                for snmp_user_line in snmp_result.splitlines():
                    if "#" not in snmp_user_line:
                        privacy_match = privacy_pattern.search(snmp_user_line)
                        if privacy_match:
                            encryption_type = privacy_match.group(1)
                            if encryption_type in ["AES128", "AES256"]:
                                encrypted = True
                            comments.append(f"{snmp_user} is configured with {encryption_type}.")
                if not encrypted:
                    line_count += 1

    if line_count > 0:
        check.status = "OP"  # Open
        comments.append("V-215842 - OPEN - Cisco router is not configured to encrypt SNMP messages using a FIPS 140-2 approved algorithm (AES128 and AES256).")
    else:
        check.status = "NF"  # Not a finding
        comments.append("V-215842 - NAF - Cisco router is configured to encrypt SNMP messages using a FIPS 140-2 approved algorithm, AES128 and AES256.")

    check.comments = "\n".join(comments)
    return check


def V215843(device_type, device_name):
    # Legacy IDs: V-96321; SV-105459
    # V-215843 - CAT II -  The Cisco router must be configured to authenticate Network Time Protocol (NTP) sources using authentication that is cryptographically based.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.set_vulid()
    check.status = "OP"
    command = "sh run | in ntp authentication"
    if device_type == "NXOS":
        command = 'sh run | in "ntp authentication"'
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = (
        "V-215843 - COMMENTS: MD5 no higher encryption - Downgrades it to a CATIII"
    )

    if result.find("md5", len(device_name + "#" + command)) > -1:
        check.status = "NF"
        check.comments = "V-215843 - MD5 NTP authentication enabled."
    return check


def V215844(device_type, device_name):
    # Legacy IDs: V-96327; SV-105465
    # V-V-215844 - CAT I - The Cisco router must be configured to use FIPS-validated Keyed-Hash Message Authentication Code (HMAC) to protect the integrity of remote maintenance sessions.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.set_vulid()
    check.status = "OP"
    command = "sh run all | i ssh.version|server.a"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-215844 - The Cisco router must be configured to use FIPS-validated Keyed-Hash Message Authentication Code (HMAC) to protect the integrity of remote maintenance sessions.\r Add the command ip ssh server algorithm mac hmac-sha1-96"
    if (
        result.find("ip ssh version 2", len(device_name) + len(command)) > -1
        and (
            result.find("hmac-sha1-96", len(device_name) + len(command)) > -1
            or result.find("hmac-sha2-256", len(device_name) + len(command))
        )
        > -1
    ):
        check.status = "NF"
        check.comments = (
            "V-215844 - CAT II - NAF - FIPS-validated Keyed-Hash is being used."
        )
    return check


def V215845(device_type, device_name):
    # Legacy IDs: V-96329; SV-105467
    # V-215845 -  CAT I - The Cisco router must be configured to implement cryptographic mechanisms to protect the confidentiality of remote maintenance sessions.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.set_vulid()
    check.status = "OP"
    command = "sh run all | i ssh.version|server.a"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-215845 -  The Cisco router must be configured to implement cryptographic mechanisms to protect the confidentiality of remote maintenance sessions."
    if (
        result.find("ip ssh version 2", len(device_name) + len(command)) > -1
        and result.find("encryption aes", len(device_name) + len(command)) > -1
    ):
        check.status = "NF"
        check.comments = "V-215845 - CAT II - NAF - Specified cryptographic mechanisms are being used."
    return check


def V215848(device_type, device_name):
    # Legacy IDs: V-96335; SV-105473
    # V-215848 - The Cisco router must be configured to generate log records when administrator privileges are deleted.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.set_vulid()
    check.status = "OP"
    command = "sh run | i logging.user|archive|log.config|logging.enable"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-215848 - The Cisco router must be configured to generate log records when administrator privileges are deleted."
    if (
        result.find("archive", len(device_name) + len(command)) > -1
        and result.find("logging enable", len(device_name) + len(command)) > -1
    ):
        check.status = "NF"
        check.comments = "V-215848 - CAT II - NAF - archive logging is enabled"
    return check


def V215849(device_type, device_name):
    # Legacy IDs: V-96337; SV-105475
    # V-215849 - CAT II -  The Cisco router must be configured to generate audit records when successful/unsuccessful logon attempts occur.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.set_vulid()
    check.status = "OP"
    command = "sh run | i login.on"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = (
        "V-215849 - NOTE:  AS OF 11/1/19 THIS IS A FINDING - PLEASE REMEDIATE"
    )
    if (
        result.find("on-failure", len(device_name) + len(command)) > -1
        and result.find("on-success", len(device_name) + len(command)) > -1
    ):
        check.status = "NF"
        check.comments = "V-215849 - CAT II - NAF -  Audit records generated when successful/unsuccessful logon attempts occur"
    return check


def V215850(device_type, device_name):
    # Legacy IDs: V-96339; SV-105477
    # V-215850 - CAT II -  The Cisco router must be configured to generate audit records when successful/unsuccessful logon attempts occur.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.set_vulid()
    check.status = "OP"
    command = "sh run | i logging.user|archive|log.config|logging.enable"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-215850 - The Cisco router must be configured to generate log records for privileged activities"
    if (
        result.find("archive", len(device_name) + len(command)) > -1
        and result.find("logging enable", len(device_name) + len(command)) > -1
    ):
        check.status = "NF"
        check.comments = "V-215850 - CAT II - NAF - archive logging is enabled"
    return check


def V215854(device_type, device_name):
    # Legacy IDs: V-96351; SV-105489
    # V-215854 - CAT I - The Cisco router must be configured to use at least two authentication servers for the purpose of authenticating users prior to granting administrative access.
    check = Stig()
    check.set_vulid()
    
    # Initialize the count of authentication servers
    auth_server_count = 0
    
    # Command to fetch the relevant configuration lines
    command = "sh run | i server-private"
    result = exec_command(command, device_name)
    check.finding = result
    
    # Use regex to count the number of 'server-private' entries
    auth_server_count = len(re.findall(r'^.*server-private.*$', result, re.MULTILINE))
    
    # Determine the status and comments based on the count of authentication servers
    if auth_server_count > 1:
        check.status = "NF"  # Not a finding
        check.comments = "V-215854 - NAF - Two or more authentication servers are configured."
    else:
        check.status = "OP"  # Open
        check.comments = "V-215854 - OPEN - Two or more authentication servers are not configured."
    
    return check


def V215855(device_type, device_name):
    # Legacy IDs: V-96359; SV-105497
    # V-215855 - CAT II -  The Cisco router must employ automated mechanisms to detect the addition of unauthorized components or devices.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.set_vulid()
    check.status = "OP"
    command = "sh event manager policy registered"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = (
        "V-215855 - NOTE:  AS OF 11/1/19 THIS IS A FINDING!!!! PLEASE REMEDIATE"
    )
    if result.find("applet", len(device_name) + len(command)) > -1:
        check.status = "NF"
        check.comments = "V-215855 - CAT II - NAF - Applet configured and registered."
    return check


def V215856(device_type, device_name):
    # Legacy IDs: V-96363; SV-105501
    # V-215856 - CAT II -  The Cisco router must be configured to obtain its public key certificates from an appropriate certificate policy through an approved service provider.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.set_vulid()
    check.status = "NF"
    command = "show run | i crypto.pki|enroll"
    result = exec_command(command, device_name)
    command = "show crypto pki certificates"
    result = result + exec_command(command, device_name)
    check.finding = result
    check.comments = "V-215856 - COMMENT:  RCC-SWA does not use PKI Authentication"
    return check

def V220139(device_type, device_name):
    # Legacy IDs: V-96365; SV-105503
    # V-220139 - CAT I - The Cisco router must be configured to send log data to at least two syslog servers
    # for the purpose of forwarding alerts to the administrators and the information system security officer (ISSO).
    check = Stig()
    check.set_vulid()

    # Command to fetch the relevant configuration lines
    command = "sh run | i logging.host"
    result = exec_command(command, device_name)
    check.finding = result

    # Count the number of 'logging host' entries using regex
    log_server_count = len(re.findall(r'^logging host', result, re.MULTILINE))

    # Determine the status and comments based on the count of logging servers
    if log_server_count >= 2:
        check.status = "NF"  # Not a finding
        check.comments = "V-220139 - NAF - At least two logging servers are configured."
    else:
        check.status = "OP"  # Open
        check.comments = "V-220139 - OPEN - At least two logging servers are not configured."

    return check

def V220140(device_type, device_name):
    # Legacy IDs: V-96369; SV-105507
    # V-220140 - CAT I - The Cisco router must be running an IOS release that is currently supported by Cisco Systems.
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.set_vulid()
    check.status = "OP"
    Model = "unknown"
    ModelVersion = "unknown"

    command = "show inventory | i PID"
    result = exec_command(command, device_name)

    intStart = result.splitlines()[1].find(" ")
    intEnd = result.splitlines()[1].find(" ", intStart + 1)
    Model = str(result.splitlines()[1][intStart:intEnd]).strip()

    temp = result
    if Model.find("ASR") > -1 or Model.find("ISR4") > -1:
        command = "show ver | i IOS"
        result = exec_command(command, device_name)
        intStart = result.splitlines()[1].find(
            " ", result.splitlines()[1].find("Version") + 1
        )
        intEnd = result.splitlines()[1].find("\r", intStart)
        ModelVersion = result.splitlines()[1][intStart:]
        #crt.Dialog.MessageBox("ModelVersion is: " + str(remove_char(ModelVersion)))
        if remove_char(ModelVersion) >= remove_char("17.09.04a"):
            check.status = "NF"
            check.comments = (
                "NAF: As of 20-Oct-2023 ASR/ISR devices should have code level 17.09.04a.  This device has "
                + ModelVersion
            )
        else:
            check.status = "OP"
            check.comments = (
                "OPEN: As of 20-Oct-2023 ASR/ISR devices should have code level 17.09.04a.  This device has "
                + ModelVersion
            )

    if Model.find("CISCO39") > -1:
        command = "show ver | i IOS"
        result = exec_command(command, device_name)
        intStart = result.splitlines()[1].find(
            " ", result.splitlines()[1].find("Version") + 1
        )
        intEnd = result.splitlines()[1].find(",", intStart)
        ModelVersion = result.splitlines()[1][intStart:intEnd]
        if remove_char(ModelVersion) >= remove_char("15.7(3)M5"):
            check.status = "NF"
            check.comments = (
                "NAF: As of 1/16/2020 ISRG2 devices should have code level 15.7(3)M5.  This device has "
                + ModelVersion
            )
        else:
            check.status = "OP"
            check.comments = (
                "OPEN: As of 1/16/2020 ISRG2 devices should have code level 15.7(3)M5.  This device has "
                + ModelVersion
            )

    if Model.find("C650") > -1:
        command = "show ver | i IOS"
        result = exec_command(command, device_name)
        intStart = result.splitlines()[1].find(
            " ", result.splitlines()[1].find("Version") + 1
        )
        intEnd = result.splitlines()[1].find(",", intStart)
        ModelVersion = result.splitlines()[1][intStart:intEnd]
        if remove_char(ModelVersion) >= remove_char("15.1(2)SY14"):
            check.status = "NF"
            check.comments = (
                "NAF: As of 10/17/2019 Cisco recomends 6500 series devices should have code level 15.1(2)SY14.  This device has "
                + ModelVersion
            )
        else:
            check.status = "OP"
            check.comments = (
                "OPEN: As of 10/17/2019 Cisco recomends 6500 series devices should have code level 15.1(2)SY14.  This device has "
                + ModelVersion
            )
    temp = temp + result
    if device_type == "NXOS":
        command = "show ver | i System:|system:|NXOS:|Chassis|chassis"
        result = exec_command(command, device_name)
        if len(result.splitlines()) > 2:
            if len(result.splitlines()[1]) > 8:
                ModelVersion = result.splitlines()[1][
                    result.splitlines()[1].find("version")
                    + 8 : len(result.splitlines()[1])
                ]
        if Model.find("N9K") > -1:
            if remove_char(ModelVersion) >= remove_char("70376"):
                check.status = "NF"
                check.comments = (
                    "NAF: As of 1/16/2020 Nexus 9K series switches should have code level 7.0(3)I7(6).  This device has "
                    + ModelVersion
                )
            else:
                check.status = "OP"
                check.comments = (
                    "OPEN: As of 1/16/2020 Nexus 9K series switches should have code level 7.0(3)I7(6).  This device has "
                    + ModelVersion
                )

        if Model.find("N5K") > -1:
            if remove_char(ModelVersion) >= remove_char("73511"):
                check.status = "NF"
                check.comments = (
                    "NAF: As of 1/16/2020 Nexus 5K series switches should have code level 7.3(5)N1(1).  This device has "
                    + ModelVersion
                )
            else:
                check.status = "OP"
                check.comments = (
                    "OPEN: As of 1/16/2020 Nexus 5K series switches should have code level 7.0(3)I7(6).  This device has "
                    + ModelVersion
                )

        if Model.find("N3K") > -1:
            if remove_char(ModelVersion) >= remove_char("70376"):
                check.status = "NF"
                check.comments = (
                    "NAF: As of 1/16/2020 Nexus 3K series switches should have code level 7.0(3)I7(6).  This device has "
                    + ModelVersion
                )
            else:
                check.status = "OP"
                check.comments = (
                    "OPEN: As of 1/16/2020 Nexus 3K series switches should have code level 7.0(3)I7(6).  This device has "
                    + ModelVersion
                )
    else:
        if ModelVersion == "unknown":
            command = "show ver | beg Ports.Model"
            result = exec_command(command, device_name)
            if len(result.splitlines()) > 2:
                ModelVersion = result.splitlines()[3][32:46]
            if Model.find("3850") > -1 or Model.find("3650") > -1:
                if remove_char(ModelVersion) >= remove_char("16.12.10a"):
                    check.status = "NF"
                    check.comments = (
                        "NAF: Cat 3850 and 3650 series switches should have code level 16.12.10a.  This device has "
                        + ModelVersion
                    )
                else:
                    check.status = "OP"
                    check.comments = (
                        "OPEN: Cat 3850 and 3650 series switches should have code level 16.12.10a.  This device has "
                        + ModelVersion
                    )
            if (
                Model.find("3750") > -1
                or Model.find("3560") > -1
                or Model.find("2960") > -1
            ):
                if remove_char(ModelVersion) >= remove_char("15.02(4)E09"):
                    check.status = "NF"
                    check.comments = (
                        "NAF: As of 1/16/2020 Cat 3750, 3560, and 2960 series switches should have code level 15.02(4)E9.  This device has "
                        + ModelVersion
                    )
                else:
                    check.status = "OP"
                    check.comments = (
                        "OPEN: As of 1/16/2020 Cat 3750, 3560, and 2960 series switches should have code level 15.02(4)E9.  This device has "
                        + ModelVersion
                    )
    
        # if Model.find("ASR"):
        #    ModelVersion = result.splitlines()[1][result.splitlines()[1].find("version")+8:len(result.splitlines()[1])]
    result = temp + "\r" + result
    check.finding = result
    return check


"""
--------------------------------------------------------------------------
Cisco IOS XE Router RTR Security Technical Implementation Guide
Version 3, Release: 1 Benchmark Date: 24 July 2024
--------------------------------------------------------------------------
"""


def V216641(device_type, device_name):
    # V-216641 - CAT II - The Cisco router must be configured to enforce approved authorizations for controlling the flow of information within the network based on organization-defined information flow control policies..
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    command = "show run | i snmp.*.location"
    result = exec_command(command, device_name)
    # Check if we're a perimeter router.  If not no ACLs are required
    if result.find("RT1") == -1:
        check.status = "NF"
        check.comments = "V-216641 - CAT II - NAF as traffic flows within theatre's area of control and seperate appliances control user traffic."
    else:
        command = "sh run | i interface|description|access-group"
        temp = exec_command(command, device_name)
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
        result = exec_command(command, device_name)
        if temp.find("EGRESS") > -1 and result.find("INGRESS") > -1:
            check.status = "NF"
        check.finding = temp + "\r" + result
        check.comments = "V-216641 - CAT II - NAF as organization-defined information flow control policies are met for intra-theatre traffic."
    return check


def V216645(device_type, device_name):
    # V-216645 - The Cisco router must be configured to authenticate all routing protocol messages using NIST-validated FIPS 198-1 message authentication code algorithm.
    check = Stig()
    check.set_vulid()
    check.status = "NF"
    check.comments = ""

    # Lets find out which routing protocols are in use
    command = "show ip proto | i Routing.Protoc"
    result = exec_command(command, device_name)
    check.finding = result

    strEIGRP_AS = "0"
    strOSPF_PID = "0"
    strBGP_AS = "0"

    # Identify which routing protocols are in use and save applicable AS or PID
    for line in result.splitlines():
        line = line.replace('"', "")
        if "eigrp" in line:
            strEIGRP_AS = line.split()[-1]
        if "ospf" in line:
            strOSPF_PID = line.split()[-1]
        if "bgp" in line:
            strBGP_AS = line.split()[-1]

    strOSPF_Interfaces = []
    strOSPF_Findings = ""
    strOSPF_status = "NF"
    if int(strOSPF_PID) > 0:
        command = "show ip ospf interface | i line.protocol.is.up"
        result = exec_command(command, device_name)
        strOSPF_Findings = result
        for line in result.splitlines():
            if "Loopback" not in line and "#" not in line:
                strOSPF_Interfaces.append(line.split()[0])
        for interface in strOSPF_Interfaces:
            command = f"show run interface {interface} | i ospf"
            result = exec_command(command, device_name)
            strOSPF_Findings += result + "\n"
            if "key-chain" not in result:
                strOSPF_status = "OP"
                if "md5" in result:
                    check.comments += f"OSPF is using the weak MD5 auth hash on {interface}.\n"
                else:
                    check.comments += f"Could not find any authentication on {interface}.\n"
            else:
                keychains = re.findall(r'key-chain (\S+)', result)
                for keychain in keychains:
                    if "md5" in result:
                        check.comments += f"OSPF is using the weak MD5 auth hash on {interface}.\n"
                        strOSPF_status = "OP"
                    else:
                        command = f"sh key chain {keychain} | in sha"
                        strKeyChain = exec_command(command, device_name)
                        strOSPF_Findings += strKeyChain + "\n"
                        if len(strKeyChain.splitlines()) > 3:
                            check.comments += f"OSPF key chain {keychain} is configured to use SHA on {interface}.\n"

    strEIGRP_Interfaces = []
    strEIGRP_Findings = ""
    strEIGRP_status = "NF"
    strEIGRP_VRF = ""
    if strEIGRP_AS == "eigrp":
        command = "sh run | in autonomous-system"
        result = exec_command(command, device_name)
        for line in result.splitlines():
            if "vrf" in line and "#" not in line:
                strEIGRP_VRF = line.split()[4]
                command = f"show ip eigrp vrf {strEIGRP_VRF} interfaces | begin Peers"
                result = exec_command(command, device_name)
                strEIGRP_Findings = result
                if len(result.splitlines()) >= 4 and result.splitlines()[2] != "":
                    for line in result.splitlines():
                        if all(x not in line for x in ["Peers", "#", "Xmit", "EIGRP"]):
                            strEIGRP_Interfaces.append(line.split()[0])
                    for interface in strEIGRP_Interfaces:
                        command = f"show ip eigrp vrf {strEIGRP_VRF} interfaces detail {interface} | i Authentication"
                        result = exec_command(command, device_name)
                        strEIGRP_Findings += result + "\n"
                        if "sha" not in result:
                            strEIGRP_status = "OP"
                            check.comments += f"EIGRP does not appear to be using FIPS 198-1 compliant authentication within VRF {strEIGRP_VRF}.\n"
                        else:
                            check.comments += f"EIGRP appears to be using hmac-sha-256 for authentication within VRF {strEIGRP_VRF}.\n"
                else:
                    check.comments += f"There are no EIGRP Peers in VRF {strEIGRP_VRF}.\n"
    else:
        if int(strEIGRP_AS) > 0:
            command = "show run | i authentication mode hmac"
            result = exec_command(command, device_name)
            strEIGRP_Findings = result
            if "sha" not in result:
                check.comments += "EIGRP does not appear to be using FIPS 198-1 compliant authentication.\n"
                strEIGRP_status = "OP"
            else:
                check.comments += "EIGRP appears to be using hmac-sha-256 for authentication.\n"

    strBGP_Findings = ""
    strBGP_status = "NF"
    command = "sh bgp ipv4 unicast summ | b Neighbor"
    result = exec_command(command, device_name)
    strBGP_Findings = result + "\n"
    if len(result.splitlines()) >= 3:
        for neighbor in result.splitlines():
            if "#" not in neighbor and "Neighbor" not in neighbor and len(neighbor.split()) > 3:
                neighbor_ip = neighbor.split()[0]
                command = f"sh run | in ^_neighbor {neighbor_ip} password"
                strTemp1 = exec_command(command, device_name)
                if len(strTemp1.splitlines()) >= 3:
                    check.comments += f"Neighbor {neighbor_ip} is not using FIPS 198-1 algorithms\n"
                    strBGP_status = "OP"
                else:
                    command = f"sh run | in {neighbor_ip}.*.peer-session"
                    strTemp2 = exec_command(command, device_name)
                    if len(strTemp2.splitlines()) >= 3:
                        for peerSession in strTemp2.splitlines():
                            if "#" not in peerSession:
                                command = f"sh run | sec template.*.{peerSession.split()[4]}"
                                strTemp3 = exec_command(command, device_name)
                                if "password" in strTemp3:
                                    check.comments += f"Neighbor {neighbor_ip} in peer-session {peerSession.split()[4]} is not using FIPS 198-1 algorithms\n"
                                    strBGP_status = "OP"
                                elif "ao" in strTemp3:
                                    check.comments += f"Neighbor {neighbor_ip} in peer-session {peerSession.split()[4]} is using FIPS 198-1 algorithms\n"
                    else:
                        command = f"sh run | in {neighbor_ip}.peer-group"
                        strTemp3 = exec_command(command, device_name)
                        if len(strTemp3.splitlines()) >= 3:
                            for peerGroup in strTemp3.splitlines():
                                if "#" not in peerGroup:
                                    command = f"sh run | in {peerGroup.split()[3]}.password"
                                    strTemp4 = exec_command(command, device_name)
                                    if "password" in strTemp4:
                                        check.comments += f"Neighbor {neighbor_ip} in peer-group {peerGroup.split()[3]} is not using FIPS 198-1 algorithms\n"
                                        strBGP_status = "OP"
                        else:
                            check.comments += f"Neighbor {neighbor_ip} is not using FIPS 198-1 algorithms\n"

    command = "sh bgp vpnv4 unicast all summ | b Neighbor"
    result = exec_command(command, device_name)
    strBGP_Findings += result + "\n"
    if len(result.splitlines()) >= 3:
        for neighbor in result.splitlines():
            if "#" not in neighbor and "Neighbor" not in neighbor and len(neighbor.split()) > 3:
                neighbor_ip = neighbor.split()[0]
                command = f"sh run | in ^_neighbor {neighbor_ip} password"
                strTemp1 = exec_command(command, device_name)
                if len(strTemp1.splitlines()) >= 3:
                    check.comments += f"Neighbor {neighbor_ip} is not using FIPS 198-1 algorithms\n"
                    strBGP_status = "OP"
                else:
                    command = f"sh run | in ^_ neighbor {neighbor_ip} password"
                    strTemp1 = exec_command(command, device_name)
                    if len(strTemp1.splitlines()) >= 3:
                        check.comments += f"Neighbor {neighbor_ip} is not using FIPS 198-1 algorithms\n"
                        strBGP_status = "OP"
                    else:
                        command = f"sh run | in {neighbor_ip}.*.peer-session"
                        strTemp2 = exec_command(command, device_name)
                        if len(strTemp2.splitlines()) >= 3:
                            for peerSession in strTemp2.splitlines():
                                if "#" not in peerSession:
                                    command = f"sh run | sec template.*.{peerSession.split()[4]}"
                                    strTemp3 = exec_command(command, device_name)
                                    if "password" in strTemp3:
                                        check.comments += f"Neighbor {neighbor_ip} in peer-session {peerSession.split()[4]} is not using FIPS 198-1 algorithms\n"
                                        strBGP_status = "OP"
                                    elif "ao" in strTemp3:
                                        check.comments += f"Neighbor {neighbor_ip} in peer-session {peerSession.split()[4]} is using FIPS 198-1 algorithms\n"
                                    else:
                                        check.comments += f"Neighbor {neighbor_ip} is not using FIPS 198-1 algorithms\n"
                                        strBGP_status = "OP"

    if strOSPF_status != "NF" or strEIGRP_status != "NF" or strBGP_status != "NF":
        check.status = "OP"
        check.comments += "V-216645 - OPEN - At least one routed interface is not configured with a FIPS 198-1 message authentication code algorithm.\n"
    else:
        check.comments += "V-216645 - NAF - All routing interfaces are configured with a FIPS 198-1 message authentication code algorithm.\n"

    check.finding += strOSPF_Findings + strEIGRP_Findings + strBGP_Findings
    return check


def V216646(device_type, device_name):
    # V-216646 - Cisco router must be configured to have all inactive interfaces disabled
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NF"
    command = "sh int desc | exc admin.down|up|deleted"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-216646 - NAF - All inactive interfaces are disabled"
    if result.find("down", len(device_name) + len(command)) > -1:
        check.status = "OP"
        check.comments = "V-216646 - OPEN - An interface is not being used but is configured or enabled"
    return check


def V216649(device_type, device_name):
    # V-216649 - The Cisco router must not be configured to have any zero-touch deployment feature enabled when connected to an operational network.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    MsgBox = crt.Dialog.MessageBox
    check.set_vulid()
    check.status = "OP"
    check.comments = "The router does not have zero-touch deployment feature disabled."
    command = "sh run | i cns|CNS"
    result = exec_command(command, device_name)
    # Find services that are not disabled
    if result.find("cns", len(device_name) + len(command)) == -1:
        check.status = "NF"
        check.comments = "The router has the zero-touch deployment feature disabled."
    check.finding = result
    return check


def V216650(device_type, device_name):
    # V-216650 - The router must have control plane protection enabled.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    check.comments = "V-216650 - The router must have control plane protection enabled."
    command = "sh policy-map control-plane | i Class-map"
    result = exec_command(command, device_name)
    check.finding = result
    if result.find("CoPP") > -1:
        check.comments = "Control plane policing configured."
        check.status = "NF"
    return check


def V216653(device_type, device_name):
    # V-216653 -  The Cisco router must be configured to have Gratuitous ARP disabled on all external interfaces.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    check.comments = "V-216653 -  The Cisco router must be configured to have Gratuitous ARP disabled on all external interfaces."
    command = "sh run all | i gratuitous"
    result = exec_command(command, device_name)
    check.finding = result
    if result.find("no ip gratuitous-arps") > -1:
        check.comments = "The router is configured to have Gratuitous ARP disabled on all external interfaces.."
        check.status = "NF"
    return check


def V216654(device_type, device_name):
    # V-216654 -  The Cisco router must be configured to have IP directed broadcast disabled on all interfaces.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    check.comments = "V-216654 -  The Cisco router must be configured to have IP directed broadcast disabled on all interfaces."
    command = "sh run all | i directed-broadcast"
    result = exec_command(command, device_name)
    check.finding = result
    if len(result.splitlines()) <= 2:
        check.comments = "The router appears to have directed broadcast disabled."
        check.status = "NF"
    return check


def V216655(device_type, device_name):
    # V-216655 -  The Cisco router must be configured to have Internet Control Message Protocol (ICMP) unreachable messages disabled on all external interfaces.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    check.comments = "V-216655 -  The Cisco router must be configured to have Internet Control Message Protocol (ICMP) unreachable messages disabled on all external interfaces."
    command = "sh run | i snmp.*.location"
    result = exec_command(command, device_name)
    check.finding = result
    if result.find("RT1") > -1:
        check.comments = "This router is a external facing router.\n"
        command = "show run | i ip.unreachables"
        result = exec_command(command, device_name)
        check.finding = check.finding + result
        if (
            result.find("no ip unreach", len(device_name) + len(command)) == -1
            or result.find(
                "icmp rate-limit unreachable", len(device_name) + len(command)
            )
            == -1
        ):
            check.status = "NF"
            check.comments = check.comments + "IP unreachables is configured."
        else:
            check.comments = (
                check.comments
                + "Because this is a external facing router unreachables must be configured."
            )
    else:
        check.status = "NF"
        check.comments = (
            check.comments + "  Because this is an internal router "
            "ip unreachables"
            " configuration not required."
        )
    return check


def V216656(device_type, device_name):
    # V-216656 -  The Cisco router must be configured to have Internet Control Message Protocol (ICMP) unreachable messages disabled on all external interfaces.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    check.comments = "V-216656 -  The Cisco router must be configured to have Internet Control Message Protocol (ICMP) unreachable messages disabled on all external interfaces."
    command = "sh run | i snmp.*.location"
    result = exec_command(command, device_name)
    check.finding = result
    if result.find("RT1") > -1 or result.find("RT1") > -1:
        check.comments = "This router is a external facing router.\n"
        command = "sh run all | i mask-reply"
        result = exec_command(command, device_name)
        check.finding = check.finding + result
        if result.find("ip mask-reply", len(device_name) + len(command)) == -1:
            check.status = "NF"
            check.comments = (
                check.comments + "V-216656: NAF - mask-reply command is NOT configured."
            )
        else:
            check.comments = (
                check.comments
                + "V-216656: OPEN - Because this is a external facing router mask-reply must not be configured."
            )
    else:
        check.status = "NF"
        check.comments = (
            check.comments + "  Because this is an internal router "
            "mask-reply"
            " configuration is not applicable."
        )
    return check


def V216657(device_type, device_name):
    # V-216657 -  The Cisco router must be configured to have Internet Control Message Protocol (ICMP) redirect messages disabled on all external interfaces.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    check.comments = "V-216657 -  The Cisco router must be configured to have Internet Control Message Protocol (ICMP) redirect messages disabled on all external interfaces."
    command = "sh run | i snmp.*.location"
    result = exec_command(command, device_name)
    check.finding = result
    if result.find("RT1") > -1 or result.find("RT1") > -1:
        check.comments = "This router is a external facing router.\n"
        command = "sh run | i redirects|interface"
        result = exec_command(command, device_name)
        check.finding = check.finding + result
        if result.find("no ip redirects", len(device_name) + len(command)) > -1:
            check.status = "NF"
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
        check.status = "NF"
        check.comments = (
            check.comments + "  Because this is an internal router "
            "no ip redirects"
            " configuration is not required."
        )
    return check


def V216658(device_type, device_name):
    # V-216658 - The network device must log all access control lists (ACL) deny statements.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.set_vulid()
    check.comments = "V-2166580 - The network device must log all access control lists (ACL) deny statements."
    check.status = "OP"
    command = "sh access-lists | i log"
    result = exec_command(command, device_name)
    check.finding = result
    if result.find(" log", len(device_name) + len(command)) > -1:
        check.status = "NF"
        check.comments = "V-216658 - NAF - Propper logging has been configured."
    return check


def V216659(device_type, device_name):
    # V-216659 - The Cisco router must be configured to produce audit records containing information to establish where the events occurred.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.set_vulid()
    check.comments = "V-216659 - The Cisco router must be configured to produce audit records containing information to establish where the events occurred."
    check.status = "OP"
    command = "show run | i access-list|deny.*.log-input"
    result = exec_command(command, device_name)
    check.finding = result
    if result.find("log-input", len(device_name) + len(command)) > -1:
        check.status = "NF"
        check.comments = "V-216659 - NAF - logging-input has been configured."
    return check


def V216660(device_type, device_name):
    # V-216660 - The Cisco router must be configured to produce audit records containing information to establish the source of the events.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.set_vulid()
    check.comments = "V-216660 - The Cisco router must be configured to produce audit records containing information to establish the source of the events."
    check.status = "OP"
    command = "show run | i access-list|deny.*.log-input"
    result = exec_command(command, device_name)
    check.finding = result
    if result.find("log-input", len(device_name) + len(command)) > -1:
        check.status = "NF"
        check.comments = "V-216660 - NAF - logging-input has been configured."
    return check


def V216661(device_type, device_name):
    # V-216661 - The Cisco router must be configured to disable the auxiliary port unless it is connected to a secured modem providing encryption and authentication.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.set_vulid()
    check.comments = "V-216661 - The Cisco router must be configured to disable the auxiliary port unless it is connected to a secured modem providing encryption and authentication."
    check.status = "OP"
    command = "sh run | i no exec|aux"
    result = exec_command(command, device_name)
    check.finding = result
    if result.find("no exec", len(device_name) + len(command)) > -1:
        check.status = "NF"
        check.comments = "V-216661 - NAF - Aux exec mode has been disabled."
    return check


def V216662(device_type, device_name):
    # V-216662 -  The Cisco perimeter router must be configured to deny network traffic by default and allow network traffic by exception.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    check.comments = "V-216662 -  The Cisco perimeter router must be configured to deny network traffic by default and allow network traffic by exception."
    command = "sh run | i snmp.*.location"
    result = exec_command(command, device_name)
    check.finding = result
    if result.find("RT1") > -1:
        check.comments = "This router is a external facing router.\n"
        command = "sh run | i ip.access-group|interface.T|interface.G|interface.B"
        result = exec_command(command, device_name)
        check.finding = check.finding + result
        if (
            result.find("INGRESS", len(device_name) + len(command)) > -1
            and result.find("EGRESS", len(device_name) + len(command)) > -1
        ):
            check.status = "NF"
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
        check.status = "NF"
        check.comments = (
            check.comments
            + "  This is not a perimeter router, so transit traffic is allowed."
        )
    return check


def V216663(device_type, device_name):
    # V-216663 -  The Cisco perimeter router must be configured to deny network traffic by default and allow network traffic by exception.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    check.comments = "V-216663 -  The Cisco perimeter router must be configured to deny network traffic by default and allow network traffic by exception."
    command = "sh run | i snmp.*.location"
    result = exec_command(command, device_name)
    check.finding = result
    if result.find("RT1") > -1:
        check.comments = "This router is a external facing router.\n"
        command = "sh run | i ip.access-group|interface.T|interface.G|interface.B"
        result = exec_command(command, device_name)
        check.finding = check.finding + result
        if (
            result.find("INGRESS", len(device_name) + len(command)) > -1
            and result.find("EGRESS", len(device_name) + len(command)) > -1
        ):
            check.status = "NF"
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
        check.status = "NF"
        check.comments = (
            check.comments
            + "  This is not a perimeter router, so transit traffic is allowed."
        )
    return check


def V216664(device_type, device_name):
    # V-216664 -  The Cisco perimeter router must be configured to only allow incoming communications from authorized sources to be routed to authorized destinations.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    check.comments = "V-216664 -  The Cisco perimeter router must be configured to deny network traffic by default and allow network traffic by exception."
    command = "sh run | i snmp.*.location"
    result = exec_command(command, device_name)
    check.finding = result
    if result.find("RT1") > -1:
        check.comments = "This router is a external facing router.\n"
        command = "sh run | i ip.access-group|interface.T|interface.G|interface.B"
        result = exec_command(command, device_name)
        check.finding = check.finding + result
        if (
            result.find("INGRESS", len(device_name) + len(command)) > -1
            and result.find("EGRESS", len(device_name) + len(command)) > -1
        ):
            check.status = "NF"
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
        check.status = "NF"
        check.comments = (
            check.comments
            + "  This is not a perimeter router, so transit traffic is allowed."
        )
    return check


def V216665(device_type, device_name):
    # V-216665 -  The Cisco perimeter router must be configured to only allow incoming communications from authorized sources to be routed to authorized destinations.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    check.comments = "V-216665 -  The Cisco perimeter router must be configured to deny network traffic by default and allow network traffic by exception."
    command = "sh run | i snmp.*.location"
    result = exec_command(command, device_name)
    check.finding = result
    if result.find("RT1") > -1:
        check.comments = "This router is a external facing router.\n"
        command = "show ip access-lists INGRESS | i 192.168.|10.0.0|100.64|127.0.0|169.254|172.16.0|192.0|198.18|198.51|203.0|224.0"
        result = exec_command(command, device_name)
        check.finding = check.finding + result
        if result.find("10.0.0", len(device_name) + len(command)) > -1:
            check.status = "NF"
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
        check.status = "NF"
        check.comments = (
            check.comments
            + "  This is not a perimeter router, so transit traffic is allowed."
        )
    return check


def V216666(device_type, device_name):
    # V-216666 -  The Cisco perimeter router must be configured to protect an enclave connected to an alternate gateway by using an inbound filter that only permits packets with destination addresses within the sites address space.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    check.comments = "V-216666 -  The Cisco perimeter router must be configured to deny network traffic by default and allow network traffic by exception."
    command = "sh run | i snmp.*.location"
    result = exec_command(command, device_name)
    check.finding = result
    if result.find("RT1") > -1:
        check.comments = "This router is a external facing router.\n"
        command = "sh run | i ip.access-group|interface.T|interface.G|interface.B"
        result = exec_command(command, device_name)
        check.finding = check.finding + result
        if result.find("INGRESS", len(device_name) + len(command)) > -1:
            check.status = "NF"
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
        check.status = "NF"
        check.comments = (
            check.comments
            + "  This is not a perimeter router, so transit traffic is allowed."
        )
    return check


def V216667(device_type, device_name):
    # V-216667 -  The Cisco perimeter router must be configured to not be a Border Gateway Protocol (BGP) peer to an alternate gateway service provider.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    check.comments = "V-216667 -  The Cisco perimeter router must be configured to not be a Border Gateway Protocol (BGP) peer to an alternate gateway service provider.."
    command = "sh run | i snmp.*.location"
    result = exec_command(command, device_name)
    check.finding = result
    if result.find("RT1") > -1:
        check.comments = "This router is a external facing router.\n"
        command = "sh run | sec bgp"
        result = exec_command(command, device_name)
        check.status = "NF"
        check.comments = (
            check.comments
            + "V-216666: NAF - RCC-SWA perimeter routers only peer with DISA."
        )
    else:
        check.status = "NA"
        check.comments = (
            check.comments
            + "  This is not a perimeter router, and this check is not applicable.."
        )
    return check


def V216668(device_type, device_name):
    # V-216668 -  The Cisco perimeter router must be configured to not redistribute static routes to an alternate gateway service provider into BGP or an Interior Gateway Protocol (IGP) peering with the NIPRNet or to other autonomous systems.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    check.comments = "V-216668 -  The Cisco perimeter router must be configured to not redistribute static routes to an alternate gateway service provider into BGP or an Interior Gateway Protocol (IGP) peering with the NIPRNet or to other autonomous systems."
    command = "sh run | i snmp.*.location"
    result = exec_command(command, device_name)
    check.finding = result
    if result.find("RT1") > -1:
        check.comments = "This router is a external facing router.\n"
        command = "sh run | sec bgp"
        result = exec_command(command, device_name)
        check.status = "NF"
        check.comments = (
            check.comments
            + "V-216668: NAF - RCC-SWA perimeter routers only peer with DISA."
        )
    else:
        check.status = "NA"
        check.comments = (
            check.comments
            + "  This is not a perimeter router, and this check is not applicable.."
        )
    return check


def V216670(device_type, device_name):
    # V-216670 -  The Cisco perimeter router must be configured to filter traffic destined to the enclave in accordance with the guidelines contained in DoD Instruction 8551.1
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    check.comments = "V-216670 -  The Cisco perimeter router must be configured to not redistribute static routes to an alternate gateway service provider into BGP or an Interior Gateway Protocol (IGP) peering with the NIPRNet or to other autonomous systems."
    command = "sh run | i snmp.*.location"
    result = exec_command(command, device_name)
    check.finding = result
    if result.find("RT1") > -1 or result.find("RT1") > -1:
        check.comments = "This router is a external facing router.\n"
        command = "sh run | i ip.access-group|interface.T|interface.G|interface.B"
        result = exec_command(command, device_name)
        check.finding = check.finding + result
        if result.find("INGRESS", len(device_name) + len(command)) > -1:
            check.status = "NF"
            check.comments = (
                check.comments
                + "V-216670: NAF - RCC-SWA perimeter router has an ingress ACL."
            )
    else:
        check.status = "NA"
        check.comments = (
            check.comments
            + "  This is not a perimeter router, and this check is not applicable.."
        )
    return check


def V216671(device_type, device_name):
    # V-216671 -  The Cisco perimeter router must be configured to filter ingress traffic at the external interface on an inbound direction.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    check.comments = "V-216671 -  The Cisco perimeter router must be configured to filter ingress traffic at the external interface on an inbound direction."
    command = "sh run | i snmp.*.location"
    result = exec_command(command, device_name)
    check.finding = result
    if result.find("RT1") > -1 or result.find("RT1") > -1:
        check.comments = "This router is a external facing router.\n"
        command = "sh run | i ip.access-group|interface.T|interface.G|interface.B"
        result = exec_command(command, device_name)
        check.finding = check.finding + result
        if result.find("INGRESS", len(device_name) + len(command)) > -1:
            check.status = "NF"
            check.comments = (
                check.comments
                + "V-216671: NAF - RCC-SWA perimeter router has an ingress ACL."
            )
    else:
        check.status = "NA"
        check.comments = (
            check.comments
            + "  This is not a perimeter router, and this check is not applicable.."
        )
    return check


def V216672(device_type, device_name):
    # V-216672 -  The Cisco perimeter router must be configured to filter ingress traffic at the external interface on an inbound direction.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    check.comments = "V-216672 -  The Cisco perimeter router must be configured to filter egress traffic at the internal interface on an inbound direction."
    command = "sh run | i snmp.*.location"
    result = exec_command(command, device_name)
    check.finding = result
    if result.find("RT1") > -1 or result.find("RT1") > -1:
        check.comments = "This router is a external facing router.\n"
        command = "sh run | i ip.access-group|interface.T|interface.G|interface.B"
        result = exec_command(command, device_name)
        check.finding = check.finding + result
        if result.find("EGRESS", len(device_name) + len(command)) > -1:
            check.status = "NF"
            check.comments = (
                check.comments
                + "V-216672: NAF - RCC-SWA perimeter router has an Egress ACL."
            )
    else:
        check.status = "NA"
        check.comments = (
            check.comments
            + "  This is not a perimeter router, and this check is not applicable.."
        )
    return check


def V216674(device_type, device_name):
    # V-216674 -  The Cisco perimeter router must be configured to have Link Layer Discovery Protocol (LLDP) disabled on all external interfaces.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    check.comments = "V-216674 -  The Cisco perimeter router must be configured to have Link Layer Discovery Protocol (LLDP) disabled on all external interfaces."
    command = "sh run | i snmp.*.location"
    result = exec_command(command, device_name)
    check.finding = result
    if result.find("RT1") > -1 or result.find("RT1") > -1:
        check.comments = "This router is a external facing router.\n"
        command = "sh lldp"
        result = exec_command(command, device_name)
        check.finding = check.finding + "\n" + result
        if result.find("not enabled", len(device_name) + len(command)) > -1:
            check.status = "NF"
            check.comments = (
                check.comments
                + "V-216674: NAF - LLDP is disabled on the RCC-SWA perimeter router."
            )
    else:
        check.status = "NA"
        check.comments = (
            check.comments
            + "  This is not a perimeter router, and this check is not applicable.."
        )
    return check


def V216675(device_type, device_name):
    # V-216675 -  The Cisco perimeter router must be configured to have Link Layer Discovery Protocol (LLDP) disabled on all external interfaces.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    check.comments = "V-216675 -  The Cisco perimeter router must be configured to have Cisco Discovery Protocol (CDP) disabled on all external interfaces."
    command = "sh run | i snmp.*.location"
    result = exec_command(command, device_name)
    check.finding = result
    if result.find("RT1") > -1 or result.find("RT1") > -1:
        check.comments = "This router is an external facing , perimeter outer.\n"
        command = "sh cdp"
        result = exec_command(command, device_name)
        check.finding = check.finding + "\n" + result
        if result.find("not enabled", len(device_name) + len(command)) > -1:
            check.status = "NF"
            check.comments = (
                check.comments
                + "V-216675: NAF - CDP is disabled on the RCC-SWA perimeter router."
            )
    else:
        check.status = "NA"
        check.comments = (
            check.comments
            + "  This is not a perimeter router, and this check is not applicable.."
        )
    return check


def V216676(device_type, device_name):
    # V-216676 -  The Cisco perimeter router must be configured to have Proxy ARP disabled on all external interfaces.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    check.comments = "V-216676 -  The Cisco perimeter router must be configured to have Proxy ARP disabled on all external interfaces.."
    command = "sh run | i snmp.*.location"
    result = exec_command(command, device_name)
    check.finding = result
    strExtInterface = "NA"
    if result.find("RT1") > -1 or result.find("RT1") > -1:
        check.comments = "This router is an external facing, perimeter router.\n"
        # Find the interface we egress out to Google with.
        command = "show ip cef 172.217.23.100"
        result = exec_command(command, device_name)
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
            result = exec_command(command, device_name)
            check.finding = check.finding + "\n" + result
            if result.find("no ip proxy") > -1:
                check.status = "NF"
                check.comments = (
                    check.comments
                    + "V-216676: NAF - Proxy-arp is disabled on the external interface.."
                )
            else:
                check.comments = "V-216676 -  The Cisco perimeter router must be configured to have Proxy ARP disabled on all external interfaces.."
    else:
        check.status = "NA"
        check.comments = (
            check.comments
            + "  This is not a perimeter router, and this check is not applicable."
        )
    return check


def V216677(device_type, device_name):
    # V-216677 -  The Cisco perimeter router must be configured to block all outbound management traffic.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    check.comments = "V-216677 -  The Cisco perimeter router must be configured to block all outbound management traffic."
    command = "sh run | i snmp.*.location"
    result = exec_command(command, device_name)
    check.finding = result
    strExtInterface = "NA"
    if result.find("RT1") > -1 or result.find("RT1") > -1:
        check.comments = "This router is an external facing , perimeter router.\n"
        # Find the interface we egress out to Google with.
        command = "show ip access-lists EGRESS | i eq.22.log|eq.tacacs|eq.snmp|eq.syslog|eq.www|deny.ip.any.any"
        result = exec_command(command, device_name)
        check.finding = check.finding + "\n" + result
        if result.find("eq 22 log", len(device_name) + len(command)) > -1:
            check.status = "NF"
            check.comments = (
                check.comments
                + "V-216676: NAF - Egress ACLs are blockng management traffic.."
            )
    else:
        check.status = "NA"
        check.comments = (
            check.comments
            + "  This is not a perimeter router, and this check is not applicable."
        )
    return check


def V216678(device_type, device_name):
    # V-216678 - The Cisco out-of-band management (OOBM) gateway router must be configured to transport management traffic to the Network Operations Center (NOC) via dedicated circuit, MPLS/VPN service, or IPsec tunnel.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.set_vulid()
    check.comments = "V-216678 - This is not a dedicated OOB gateway router."
    check.status = "NA"
    # command = "show ip access-li"
    # result = exec_command(command, device_name)
    check.finding = "N/A"
    return check


def V216679(device_type, device_name):
    # V-216679 - The Cisco out-of-band management (OOBM) gateway router must be configured to transport management traffic to the Network Operations Center (NOC) via dedicated circuit, MPLS/VPN service, or IPsec tunnel.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.set_vulid()
    check.comments = "V-216679 - This is not a dedicated OOB gateway router."
    check.status = "NA"
    check.finding = "N/A"
    return check


def V216680(device_type, device_name):
    # V-216680 - The Cisco out-of-band management (OOBM) gateway router must be configured to have separate Interior Gateway Protocol (IGP) instances for the managed network and management network.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.set_vulid()
    check.comments = "V-216680 - This is not a dedicated OOB gateway router."
    check.status = "NA"
    check.finding = "N/A"
    return check


def V216681(device_type, device_name):
    # V-216681 - The Cisco out-of-band management (OOBM) gateway router must be configured to not redistribute routes between the management network routing domain and the managed network routing domain.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.set_vulid()
    check.comments = "V-216681 - This is not a dedicated OOB gateway router."
    check.status = "NA"
    check.finding = "N/A"
    return check


def V216682(device_type, device_name):
    # V-216682 - The Cisco out-of-band management (OOBM) gateway router must be configured to block any traffic destined to itself that is not sourced from the OOBM network or the Network Operations Center (NOC)
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.set_vulid()
    check.comments = "V-216682 - This is not a dedicated OOB gateway router."
    check.status = "NA"
    check.finding = "N/A"
    return check


def V216683(device_type, device_name):
    # V-216683 - The Cisco router must be configured to only permit management traffic that ingresses and egresses the out-of-band management (OOBM) interface.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.set_vulid()
    check.comments = "V-216683 - This is not a dedicated OOB gateway router."
    check.status = "NA"
    check.finding = "N/A"
    return check


def V216684(device_type, device_name):
    # V-216684 - The Cisco router providing connectivity to the Network Operations Center (NOC) must be configured to forward all in-band management traffic via an IPsec tunnel.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.set_vulid()
    check.comments = "V-216684 - This is not a dedicated OOB gateway router."
    check.status = "NA"
    check.finding = "N/A"
    return check


def V216687(device_type, device_name):
    # V-216687 -  The Cisco BGP router must be configured to reject inbound route advertisements for any Bogon prefixes.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    check.comments = (
        check.vulid
        + " - The Cisco BGP router must be configured to reject inbound route advertisements for any Bogon prefixes."
    )
    strBGP_AS = "0"
    command = "show ip proto | i Routing.Protoc"
    result = exec_command(command, device_name)
    check.finding = result
    strPeerfinding = "NF"
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
        result = exec_command(command, device_name)
        # If we're running MP-BGP then the results will be empty.  If so we need to run the ipv4 command
        if len(result.splitlines()) <= 3:
            command = (
                "show ip bgp sum | exc memory|BGP| 65...| path|Neighbor|" + strBGP_AS
            )
            result = exec_command(command, device_name)
        check.finding = check.finding + "\n" + result
        if len(result.splitlines()) <= 4:
            check.comments = (
                check.comments + "NAF: This router does not have any eBGP peers.\n"
            )
            check.status = "NF"
        else:
            # Create a list of external BGP peers
            for line in result.splitlines():
                if len(line) > 1:
                    if line.split()[0].find(".") > -1:
                        strBGP_Peers.append(line.split()[0])
            # Lets loop through the peers, associated route maps, and the prefix lists used.
            if len(strBGP_Peers) > 0:
                # initial assumption is we're going to pass.  if we can't find an appropriate prefix list blocking networks we'll raise up a finding.
                check.status = "NF"
                # check.comments = check.comments + check.vulid +':NAF - Ingress route maps only allow expected and defined prefixes.\n'
                for peer in strBGP_Peers:
                    command = "show run | i nei.*." + peer + ".*.oute-map.*.in"
                    result = exec_command(command, device_name)
                    check.finding = check.finding + "\n" + result
                    for line in result.splitlines():
                        if line.find("route-map") > -1:
                            command = "show run | sec route-map " + line.split()[3]
                            result = exec_command(command, device_name)
                            check.finding = check.finding + "\n" + result
                            strAllowsAny = "No"
                            for configline in result.splitlines():
                                if configline.find("prefix-list") > -1:
                                    command = (
                                        "show ip prefix-list " + configline.split()[-1]
                                    )
                                    result = exec_command(command, device_name)
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
                                        strPeerfinding = "OP"
                                        check.comments = (
                                            check.comments
                                            + "Prefix list "
                                            + configline.split()[-1]
                                            + " filtering peer "
                                            + peer
                                            + " appears to allow all routes.\n"
                                        )
            # Now we'll check if there was a finding during any peer check.
            if strPeerfinding != "NF":
                check.status = "OP"
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
                check.status = "NF"
    else:
        check.comments = check.comments + "NAF: This router is not running BGP.\n"
        check.status = "NA"
    return check


def V216688(device_type, device_name):
    # V-216688 -  The Cisco BGP router must be configured to reject inbound route advertisements for any prefixes belonging to the local autonomous system (AS).
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    check.comments = "V-216688 - The Cisco BGP router must be configured to reject inbound route advertisements for any prefixes belonging to the local autonomous system (AS)."
    command = "sh run | i snmp.*.location"
    strBGP_Peers = []
    result = exec_command(command, device_name)
    check.finding = result
    if result.find("RT1") > -1 or result.find("RT2") > -1:
        check.comments = "This router appears to be a perimeter router.  It likely has external BGP peerings.\n"
        # Find the external bgp peers.
        command = (
            "show ip bgp vpnv4 all summary | exc memory|BGP| 65... |path|Neighbor"
        )
        result = exec_command(command, device_name)
        # If we're running MP-BGP then the results will be empty.  If so we need to run the ipv4 command
        if len(result.splitlines()) <= 3:
            command = "show ip bgp sum | exc 65...|memory|BGP|path|Neighbor"
            result = exec_command(command, device_name)
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
                result = exec_command(command, device_name)
                check.finding = check.finding + "\n" + result
                for line in result.splitlines():
                    if line.find("route-map") > -1:
                        command = "show run | sec route-map " + line.split()[3]
                        result = exec_command(command, device_name)
                        check.finding = check.finding + "\n" + result
                        for configline in result.splitlines():
                            if configline.find("prefix-list") > -1:
                                command = (
                                    "show ip prefix-list " + configline.split()[-1]
                                )
                                result = exec_command(command, device_name)
                                check.finding = check.finding + "\n" + result
            check.status = "NF"
            check.comments = (
                check.comments
                + "V-216688: NAF - Ingress route maps only allow expected and defined prefixes."
            )
        else:
            check.status = "NF"
            check.comments = check.comments + "V-216688: NAF - There are no EBGP peers."
    else:
        check.status = "NA"
        check.comments = (
            check.comments
            + "  This is not a router that peers with external BGP neighbors."
        )
    return check


def V216689(device_type, device_name):
    # V-216689 -  The Cisco BGP router must be configured to reject outbound route advertisements for any prefixes belonging to the IP core.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    check.comments = (
        check.vulid
        + " - The Cisco BGP router must be configured to reject outbound route advertisements for any prefixes belonging to the IP core."
    )
    strBGP_AS = "0"
    command = "show ip proto | i Routing.Protoc"
    result = exec_command(command, device_name)
    check.finding = result
    strPeerfinding = "NF"
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
        result = exec_command(command, device_name)
        # If we're running MP-BGP then the results will be empty.  If so we need to run the ipv4 command
        if len(result.splitlines()) <= 3:
            command = (
                "show ip bgp sum | exc memory|BGP| 65...| path|Neighbor|" + strBGP_AS
            )
            result = exec_command(command, device_name)
        check.finding = check.finding + "\n" + result
        if len(result.splitlines()) <= 4:
            check.comments = (
                check.comments + "NAF: This router does not have any eBGP peers.\n"
            )
            check.status = "NF"
        else:
            # Create a list of external BGP peers
            for line in result.splitlines():
                if len(line) > 1:
                    if line.split()[0].find(".") > -1:
                        strBGP_Peers.append(line.split()[0])
            # Lets loop through the peers, associated route maps, and the prefix lists used.
            if len(strBGP_Peers) > 0:
                # initial assumption is we're going to pass.  if we can't find an appropriate prefix list blocking networks we'll raise up a finding.
                check.status = "NF"
                # check.comments = check.comments + check.vulid +':NAF - Ingress route maps only allow expected and defined prefixes.\n'
                for peer in strBGP_Peers:
                    command = "show run | i nei.*." + peer + ".*.oute-map.*.in"
                    result = exec_command(command, device_name)
                    check.finding = check.finding + "\n" + result
                    for line in result.splitlines():
                        if line.find("route-map") > -1:
                            command = "show run | sec route-map " + line.split()[3]
                            result = exec_command(command, device_name)
                            check.finding = check.finding + "\n" + result
                            for configline in result.splitlines():
                                if configline.find("prefix-list") > -1:
                                    command = (
                                        "show ip prefix-list " + configline.split()[-1]
                                    )
                                    result = exec_command(command, device_name)
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
                                        strPeerfinding = "OP"
                                        check.comments = (
                                            check.comments
                                            + "Prefix list "
                                            + configline.split()[-1]
                                            + " filtering peer "
                                            + peer
                                            + " appears to allow all routes.\n"
                                        )
            # Now we'll check if there was a finding during any peer check.
            if strPeerfinding != "NF":
                check.status = "OP"
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
                check.status = "NF"
    else:
        check.comments = check.comments + "NAF: This router is not running BGP.\n"
        check.status = "NA"
    return check


def V216690(device_type, device_name):
    # V-216690 -  The Cisco BGP router must be configured to reject outbound route advertisements for any prefixes belonging to the IP core.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    check.comments = (
        check.vulid
        + " - The Cisco BGP router must be configured to reject outbound route advertisements for any prefixes belonging to the IP core."
    )
    strBGP_AS = "0"
    command = "show ip proto | i Routing.Protoc"
    result = exec_command(command, device_name)
    check.finding = result
    strPeerfinding = "NF"
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
        result = exec_command(command, device_name)
        # If we're running MP-BGP then the results will be empty.  If so we need to run the ipv4 command
        if len(result.splitlines()) <= 3:
            command = (
                "show ip bgp sum | exc memory|BGP| 65...| path|Neighbor|" + strBGP_AS
            )
            result = exec_command(command, device_name)
        check.finding = check.finding + "\n" + result
        if len(result.splitlines()) <= 5:
            check.comments = (
                check.comments + "NAF: This router does not have any eBGP peers.\n"
            )
            check.status = "NF"
        else:
            # Create a list of external BGP peers
            for line in result.splitlines():
                if len(line) > 1:
                    if line.split()[0].find(".") > -1:
                        strBGP_Peers.append(line.split()[0])
            # Lets loop through the peers, associated route maps, and the prefix lists used.
            if len(strBGP_Peers) > 0:
                # initial assumption is we're going to pass.  if we can't find an appropriate prefix list blocking networks we'll raise up a finding.
                check.status = "NF"
                # check.comments = check.comments + check.vulid +':NAF - Ingress route maps only allow expected and defined prefixes.\n'
                for peer in strBGP_Peers:
                    command = "show run | i nei.*." + peer + ".*.oute-map.*.in"
                    result = exec_command(command, device_name)
                    check.finding = check.finding + "\n" + result
                    for line in result.splitlines():
                        if line.find("route-map") > -1:
                            command = "show run | sec route-map " + line.split()[3]
                            result = exec_command(command, device_name)
                            check.finding = check.finding + "\n" + result
                            for configline in result.splitlines():
                                if configline.find("prefix-list") > -1:
                                    command = (
                                        "show ip prefix-list " + configline.split()[-1]
                                    )
                                    result = exec_command(command, device_name)
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
                                        strPeerfinding = "OP"
                                        check.comments = (
                                            check.comments
                                            + "Prefix list "
                                            + configline.split()[-1]
                                            + " filtering peer "
                                            + peer
                                            + " appears to allow all routes.\n"
                                        )
            # Now we'll check if there was a finding during any peer check.
            if strPeerfinding != "NF":
                check.status = "OP"
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
        check.status = "NA"
    return check


def V216691(device_type, device_name):
    # V-216691 -  The Cisco BGP router must be configured to reject outbound route advertisements for any prefixes belonging to the IP core.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    check.comments = "V-216691 - The Cisco BGP router must be configured to reject outbound route advertisements for any prefixes belonging to the IP core."
    strBGP_AS = "0"
    command = "show ip proto | i Routing.Protoc"
    result = exec_command(command, device_name)
    check.finding = result
    strPeerfinding = "NF"
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
        result = exec_command(command, device_name)
        # If we're running MP-BGP then the results will be empty.  If so we need to run the ipv4 command
        if len(result.splitlines()) <= 3:
            command = (
                "show ip bgp sum | exc memory|BGP| 65...| path|Neighbor|" + strBGP_AS
            )
            result = exec_command(command, device_name)
        check.finding = check.finding + "\n" + result
        if len(result.splitlines()) <= 5:
            check.comments = (
                check.comments + "NAF: This router does not have any eBGP peers.\n"
            )
            check.status = "NF"
        else:
            # Create a list of external BGP peers
            for line in result.splitlines():
                if len(line) > 1:
                    if line.split()[0].find(".") > -1:
                        strBGP_Peers.append(line.split()[0])
            # Lets loop through the peers, associated route maps, and the prefix lists used.
            if len(strBGP_Peers) > 0:
                # initial assumption is we're going to pass.  if we can't find an appropriate prefix list blocking networks we'll raise up a finding.
                check.status = "NF"
                # check.comments = check.comments + check.vulid +':NAF - Ingress route maps only allow expected and defined prefixes.\n'
                for peer in strBGP_Peers:
                    command = "show run | i nei.*." + peer + ".*.oute-map.*.in"
                    result = exec_command(command, device_name)
                    check.finding = check.finding + "\n" + result
                    for line in result.splitlines():
                        if line.find("route-map") > -1:
                            command = "show run | sec route-map " + line.split()[3]
                            result = exec_command(command, device_name)
                            check.finding = check.finding + "\n" + result
                            for configline in result.splitlines():
                                if configline.find("prefix-list") > -1:
                                    command = (
                                        "show ip prefix-list " + configline.split()[-1]
                                    )
                                    result = exec_command(command, device_name)
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
                                        strPeerfinding = "OP"
                                        check.comments = (
                                            check.comments
                                            + "Prefix list "
                                            + configline.split()[-1]
                                            + " filtering peer "
                                            + peer
                                            + " appears to allow all routes.\n"
                                        )
            # Now we'll check if there was a finding during any peer check.
            if strPeerfinding != "NF":
                check.status = "OP"
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
        check.status = "NA"
    return check


def V216692(device_type, device_name):
    # V-216692 -  verify the router is configured to deny updates received from eBGP peers that do not list their AS number as the first AS in the AS_PATH attribute..
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NF"
    check.comments = (
        check.vulid
        + " - Verify the router is configured to deny updates received from eBGP peers that do not list their AS number as the first AS in the AS_PATH attribute.\n"
    )
    strBGP_AS = "0"
    command = "show ip proto | i Routing.Protoc"
    result = exec_command(command, device_name)
    check.finding = result
    strPeerfinding = "NF"
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
        result = exec_command(command, device_name)
        check.finding = check.finding + "\n" + result
        # If we have a no then we're in violation...
        if result.find("no") > -1:
            check.status = "OP"
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
        check.status = "NA"
        check.comments = (
            check.comments + "\n" + check.vulid + ":NA - Router is not running BGP."
        )
    return check


def V216693(device_type, device_name):
    # V-216693 - The Cisco BGP router must be configured to reject route advertisements from CE routers with an originating AS in the AS_PATH attribute that does not belong to that customer.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.finding = "N/A"
    check.set_vulid()
    check.status = "NA"
    check.comments = (
        check.vulid
        + " - The Cisco BGP router must be configured to reject route advertisements from CE routers with an originating AS in the AS_PATH attribute that does not belong to that customer.\n NAF - There is no peering with CE devices."
    )
    return check


def V216694(device_type, device_name):
    # V-216694 -  The Cisco BGP router must be configured to use the maximum prefixes feature to protect against route table flooding and prefix de-aggregation attacks..
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NF"
    check.comments = (
        check.vulid
        + " - The Cisco BGP router must be configured to use the maximum prefixes feature to protect against route table flooding and prefix de-aggregation attacks..\n"
    )
    strBGP_AS = "0"
    command = "show ip proto | i Routing.Protoc"
    result = exec_command(command, device_name)
    check.finding = result
    strPeerfinding = "NF"
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
        result = exec_command(command, device_name)
        if result.find("Invalid") > -1 or len(result.splitlines()) < 3:
            # Look for all the BGP neighbors on Colored routers
            command = "sh bgp ipv4 unicast summ | b Neighbor"
            result = exec_command(command, device_name)

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
            result = exec_command(command, device_name)
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
                check.status = "OP"
                check.comments = (
                    check.comments
                    + "\n"
                    + check.vulid
                    + ":OPEN - The number of received prefixes from each eBGP neighbor is NOT controlled.."
                )
    else:
        check.status = "NA"
        check.comments = (
            check.comments + "\n" + check.vulid + ":NA - Router is not running eBGP."
        )
    return check


def V216695(device_type, device_name):
    # V-216695 - The Cisco BGP router must be configured to limit the prefix size on any inbound route advertisement to /24, or the least significant prefixes issued to the customer.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.set_vulid()
    check.finding = "N/A"
    check.status = "NA"
    check.comments = (
        check.vulid
        + " - The Cisco BGP router must be configured to limit the prefix size on any inbound route advertisement to /24, or the least significant prefixes issued to the customer.\nNAF - There is no peering with CE devices."
    )
    return check


def V216696(device_type, device_name):
    # V-216696 -  The Cisco BGP router must be configured to use its loopback address as the source address for iBGP peering sessions.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    strBGP_status = "NF"
    # check.comments = check.vulid + " -The Cisco BGP router must be configured to use its loopback address as the source address for iBGP peering sessions."
    strBGP_AS = "0"
    command = "show ip proto | i Routing.Protoc"
    result = exec_command(command, device_name)
    check.finding = result
    strPeerfinding = "NF"
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
        result = exec_command(command, device_name)
        strBGP_Findings = strBGP_Findings + result + "\n"
        for session in result.splitlines():
            if session.find("peer-session") > -1:
                command = "show run | sec " + session
                #
                # Replace password with ***REMOVED***
                strClean = ""
                result = ""
                temp = exec_command(command, device_name)
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
        result = exec_command(command, device_name)
        # If we're not running MP-BGP then the results will be empty.  If so we need to run the ipv4 command
        if len(result.splitlines()) <= 3:
            command = "sh ip bgp neighbors | inc " + strBGP_AS
            result = exec_command(command, device_name)
        strBGP_Findings = strBGP_Findings + "\n" + result
        if len(result.splitlines()) > 2:
            strBGP_neighbor_status = "OP"
            for neighbor in result.splitlines():
                strBGP_neighbor_status = "OP"
                if neighbor.find("#") == -1:
                    neighborIP = neighbor.split()[3]
                    neighborIP = neighborIP.replace(",", "")
                    command = "show run | i neighbor.*." + neighborIP
                    # Replace password with ***REMOVED***
                    strClean = ""
                    result = ""
                    temp = exec_command(command, device_name)
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
                        strBGP_neighbor_status = "NF"
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
                                strBGP_neighbor_status = "NF"
                                check.comments = (
                                    check.comments
                                    + " - BGP neighbor "
                                    + neighborIP
                                    + " has a loopback for an update-source through peer-session "
                                    + peersession
                                    + ".\n"
                                )
                    if strBGP_neighbor_status == "OP":
                        strBGP_status = "OP"
                        check.comments = (
                            check.comments
                            + "Could not match a configuration for neighbor "
                            + neighborIP
                            + ".\n"
                        )

            if strBGP_status != "NF":
                check.status = "OP"
            else:
                check.status = "NF"
            check.finding = strBGP_Findings
            # check.comments = "V-216696 - CAT II - The Cisco router must be configured to use encryption for routing protocol authentication."
        else:
            check.status = "NF"
            check.comments = check.comments + "There are no iBGP neighbors."
    else:
        check.status = "NA"
        check.comments = (
            check.comments + "\n" + check.vulid + ":NA - Router is not running BGP."
        )
    return check


def V216697(device_type, device_name):
    # V-216697 -  The Cisco MPLS router must be configured to use its loopback address as the source address for LDP peering sessions.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NF"
    check.comments = (
        check.vulid
        + " -The Cisco MPLS router must be configured to use its loopback address as the source address for LDP peering sessions.\n"
    )
    strPeerfinding = "NF"
    strLDP = "NA"
    command = "show mpls ldp igp sync"
    result = exec_command(command, device_name)
    check.finding = result
    # Find out if we're running MPLS
    if result.find("LDP configured") > -1:
        strLDP = "enabled"
    # If we're running BGP lets get busy...
    if strLDP == "enabled":
        check.comments = "This router seems to be running MPLS.\n"
        # Find the external bgp peers.
        command = "show run | i mpls.*.uter-id"
        result = exec_command(command, device_name)
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
            check.status = "OP"
            check.comments = (
                check.comments
                + "\n"
                + check.vulid
                + ":OPEN - The router is not configured to use its loopback address for LDP peering."
            )
    else:
        check.status = "NA"
        check.comments = (
            check.comments
            + "\n"
            + check.vulid
            + ":NA - Router is not running LDP/MPLS so this check is not applicable."
        )
    return check


def V216698(device_type, device_name):
    # V-216698 -  The Cisco MPLS router must be configured to synchronize Interior Gateway Protocol (IGP) and LDP to minimize packet loss.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NF"
    check.comments = (
        check.vulid
        + " -The Cisco MPLS router must be configured to synchronize Interior Gateway Protocol (IGP) and LDP to minimize packet loss.\n"
    )
    strPeerfinding = "NF"
    strLDP = "NA"
    command = "show mpls ldp igp sync"
    result = exec_command(command, device_name)
    check.finding = result
    # Find out if we're running MPLS
    if result.find("LDP configured") > -1:
        strLDP = "enabled"
    # If we're running BGP lets get busy...
    if strLDP == "enabled":
        check.comments = "This router seems to be running MPLS.\n"
        # Find the external bgp peers.
        command = "show run all | i mpls.*.sync"
        result = exec_command(command, device_name)
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
            check.status = "OP"
            check.comments = (
                check.comments
                + "\n"
                + check.vulid
                + ":OPEN -  The router is not configured to synchronize IGP and LDP."
            )
    else:
        check.status = "NA"
        check.comments = (
            check.comments
            + "\n"
            + check.vulid
            + ":NA - Router is not running LDP/MPLS so this check is not applicable."
        )
    return check


def V216699(device_type, device_name):
    # V-216699 -  The MPLS router with RSVP-TE enabled must be configured with message pacing to adjust maximum burst and maximum number of RSVP messages to an output queue based on the link speed and input queue size of adjacent core routers.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NF"
    check.comments = (
        check.vulid
        + " -The MPLS router with RSVP-TE enabled must be configured with message pacing to adjust maximum burst and maximum number of RSVP messages to an output queue based on the link speed and input queue size of adjacent core routers.\n"
    )
    strPeerfinding = "NF"
    strLDP = "NA"
    command = "show run | i mpls.traff.*.tunnels"
    result = exec_command(command, device_name)
    check.finding = result
    # Find out if we're running MPLS
    if result.find("mpls traffic-eng tunnels") > -1:
        strLDP = "enabled"
    # If we're running BGP lets get busy...
    if strLDP == "enabled":
        check.comments = "This router seems to be running MPLS-TE.\n"
        # Find the external bgp peers.
        command = "show run all | i ip.rsvp.*.rate-limit"
        result = exec_command(command, device_name)
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
            check.status = "OP"
            check.comments = (
                check.comments
                + "\n"
                + check.vulid
                + ":OPEN -  The router is not configured to rate limit RSVP messages."
            )
    else:
        check.status = "NA"
        check.comments = (
            check.comments + "\n" + check.vulid + ":NA - Router is not running MPLS-TE."
        )
    return check


def V216700(device_type, device_name):
    # V-216700 -  The Cisco MPLS router must be configured to have TTL Propagation disabled.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NF"
    check.comments = (
        check.vulid
        + " -The Cisco MPLS router must be configured to have TTL Propagation disabled.\n"
    )
    strPeerfinding = "NF"
    strLDP = "NA"
    command = "show mpls ldp discovery"
    result = exec_command(command, device_name)
    check.finding = result
    # Find out if we're running MPLS
    if result.find("Local LDP Identifier") > -1:
        strLDP = "enabled"
    # If we're running LDP lets get busy...
    if strLDP == "enabled":
        check.comments = "This router seems to be running MPLS.\n"
        # Find mpls configs.
        command = "show run all | i mpls.*.propagate-ttl"
        result = exec_command(command, device_name)
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
            check.status = "OP"
            check.comments = (
                check.comments
                + "\n"
                + check.vulid
                + ":OPEN -  The router is not configured to disable TTL propagation."
            )
    else:
        check.status = "NA"
        check.comments = (
            check.comments + "\n" + check.vulid + ":NA - Router is not running MPLS."
        )
    return check


def V216701(device_type, device_name):
    # V-216701 -  The Cisco PE router must be configured to have each Virtual Routing and Forwarding (VRF) instance bound to the appropriate physical or logical interfaces .
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NF"
    check.comments = (
        check.vulid
        + " -The Cisco PE router must be configured to have each Virtual Routing and Forwarding (VRF) instance bound to the appropriate physical or logical interfaces.\n"
    )
    strLDP = "NA"
    command = "show mpls ldp discovery"
    result = exec_command(command, device_name)
    check.finding = result
    # Find out if we're running MPLS
    if result.find("Local LDP Identifier") > -1:
        strLDP = "enabled"
    # If we're running LDP lets get busy...
    if strLDP == "enabled":
        check.comments = "This router seems to be running MPLS.\n"
        # Find the cef configs.
        command = "show vrf"
        result = exec_command(command, device_name)
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
            check.status = "OP"
            check.comments = (
                check.comments
                + "\n"
                + check.vulid
                + ":OPEN -  Each CE-facing interface is NOT associated to one VRF"
            )
    else:
        check.status = "NA"
        check.comments = (
            check.comments + "\n" + check.vulid + ":NA - Router is not running MPLS."
        )
    return check


def V216702(device_type, device_name):
    # V-216702 -  The Cisco PE router must be configured to have each Virtual Routing and Forwarding (VRF) instance with the appropriate Route Target .
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NF"
    check.comments = (
        check.vulid
        + " -The Cisco PE router must be configured to have each Virtual Routing and Forwarding (VRF) instance with the appropriate Route Target .\n"
    )
    strLDP = "NA"
    command = "show mpls ldp discovery"
    result = exec_command(command, device_name)
    check.finding = result
    # Find out if we're running MPLS
    if result.find("Local LDP Identifier") > -1:
        strLDP = "enabled"
    # If we're running LDP lets get busy...
    if strLDP == "enabled":
        check.comments = "This router seems to be running MPLS.\n"
        # Find the cef configs.
        command = "show run | sec vrf.definition"
        result = exec_command(command, device_name)
        check.finding = check.finding + "\n" + result
        # If we have a no then we're in violation...
        if result.find("route-target export") > -1:
            check.comments = (
                check.comments + "\n" + check.vulid + ":NAF -  The router"
                "s RT is configured for each VRF."
            )
        else:
            check.status = "OP"
            check.comments = (
                check.comments + "\n" + check.vulid + ":OPEN -  The router"
                "s RT is NOT configured for each VRF"
            )
    else:
        check.status = "NA"
        check.comments = (
            check.comments + "\n" + check.vulid + ":NA - Router is not running MPLS."
        )
    return check


def V216703(device_type, device_name):
    # V-216703 -  The Cisco PE router must be configured to have each VRF with the appropriate Route Distinguisher (RD).
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NF"
    check.comments = (
        check.vulid
        + " -The Cisco PE router must be configured to have each VRF with the appropriate Route Distinguisher (RD).\n"
    )
    strLDP = "NA"
    command = "show mpls ldp discovery"
    result = exec_command(command, device_name)
    check.finding = result
    # Find out if we're running MPLS
    if result.find("Local LDP Identifier") > -1:
        strLDP = "enabled"
    # If we're running LDP lets get busy...
    if strLDP == "enabled":
        check.comments = "This router seems to be running MPLS.\n"
        # Find the cef configs.
        command = "show run | sec vrf.definition"
        result = exec_command(command, device_name)
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
            check.status = "OP"
            check.comments = (
                check.comments
                + "\n"
                + check.vulid
                + ":OPEN -  The Cisco PE router is NOT configured to have each VRF with the appropriate Route Distinguisher (RD)"
            )
    else:
        check.status = "NA"
        check.comments = (
            check.comments + "\n" + check.vulid + ":NA - Router is not running MPLS."
        )
    return check


def V216704(device_type, device_name):
    # V-216704 - The Cisco PE router providing MPLS Layer 2 Virtual Private Network (L2VPN) services must be configured to authenticate targeted Label Distribution Protocol (LDP) sessions.
    check = Stig()
    check.set_vulid()
    check.status = "NF"  # Default status
    # Initial comment about the STIG ID and description
    check.comments = (f"{check.vulid} - The Cisco PE router providing MPLS L2VPN services must authenticate targeted LDP sessions.\n")
    command = "show mpls ldp discovery"
    result = exec_command(command, device_name)
    check.finding = result
    # Determine MPLS usage status based on 'Local LDP Identifier' presence in output
    strLDP = "NA" if "Local LDP Identifier" not in result else "enabled"
    # Proceed if MPLS is enabled
    if strLDP == "enabled":
        check.comments += "This router seems to be running MPLS.\n"
        command = "show run | include mpls ldp neighbor"
        result = exec_command(command, device_name)
        check.finding += "\n" + result
        # Evaluate the presence of 'password' to determine the compliance status
        if "password" in result:
            check.comments += f"{check.vulid}: NAF - The router is configured to authenticate LDP neighbors."
        else:
            check.status = "OP"
            check.comments += f"{check.vulid}: OPEN - The router is NOT configured to authenticate LDP neighbors."
    else:
        check.status = "NA"
        check.comments += f"{check.vulid}: NA - Router is not running MPLS."

    return check


def V216705(device_type, device_name):
    # V-216705 -  the correct VC ID is configured for each attachment circuit.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NF"
    check.comments = (
        check.vulid
        + " - Verify the correct VC ID is configured for each attachment circuit.\n"
    )
    strLDP = "NA"
    command = "show xconnect pwmib | i up|VC"
    result = exec_command(command, device_name)
    check.finding = result
    # Find out if we're running MPLS
    if len(result.splitlines()) > 5:
        strLDP = "enabled"
    # If we're running LDP lets get busy...
    if strLDP == "enabled":
        check.comments = "This router seems to be running MPLS.\n"
        # Find the cef configs.
        command = "show xconnect pwmib | exc pw"
        result = exec_command(command, device_name)
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
            check.status = "OP"
            check.comments = (
                check.comments
                + "\n"
                + check.vulid
                + ":OPEN - The CE-facing interface that is configured for VPWS is NOT unique."
            )
    else:
        check.status = "NA"
        check.comments = (
            check.comments
            + "\n"
            + check.vulid
            + ":NA - Router is not terminating any Virtual Private Wire Service (VPWS)."
        )
    return check


def V216706(device_type, device_name):
    # V-216706 -  The Cisco PE router providing Virtual Private LAN Services (VPLS) must be configured to have all attachment circuits defined to the virtual forwarding instance (VFI) with the globally unique VPN ID assigned for each customer VLAN.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NF"
    check.comments = (
        check.vulid
        + " - The Cisco PE router providing Virtual Private LAN Services (VPLS) must be configured to have all attachment circuits defined to the virtual forwarding instance (VFI) with the globally unique VPN ID assigned for each customer VLAN.\n"
    )
    strLDP = "NA"
    command = "show run | sec l2.vfi"
    result = exec_command(command, device_name)
    check.finding = result
    # Find out if we're running MPLS
    if len(result.splitlines()) > 2:
        strLDP = "enabled"
    # If we're running LDP lets get busy...
    if strLDP == "enabled":
        check.comments = "This router seems to be running VPLS VFI.\n"
        # Find the cef configs.
        command = "show xconnect pwmib | exc pw"
        result = exec_command(command, device_name)
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
            check.status = "OP"
            check.comments = (
                check.comments
                + "\n"
                + check.vulid
                + ":OPEN - Attachment circuits are NOT associated to the appropriate VFI."
            )
    else:
        check.status = "NA"
        check.comments = (
            check.comments
            + "\n"
            + check.vulid
            + ":NA - Router is not providing L2 VFI services."
        )
    return check


def V216707(device_type, device_name):
    # V-216707 -  The Cisco PE router providing Virtual Private LAN Services (VPLS) must be configured to have all attachment circuits defined to the virtual forwarding instance (VFI) with the globally unique VPN ID assigned for each customer VLAN.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NF"
    check.comments = (
        check.vulid
        + " - The Cisco PE router providing Virtual Private LAN Services (VPLS) must be configured to have all attachment circuits defined to the virtual forwarding instance (VFI) with the globally unique VPN ID assigned for each customer VLAN.\n"
    )
    strLDP = "NA"
    command = "show run | sec l2.vfi"
    result = exec_command(command, device_name)
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
            check.status = "OP"
            check.comments = (
                check.comments
                + "\n"
                + check.vulid
                + ":OPEN - If split horizon is not enabled, this is a finding.."
            )
    else:
        check.status = "NA"
        check.comments = (
            check.comments
            + "\n"
            + check.vulid
            + ":NA - Router is not providing L2 VFI services."
        )
    return check


def V216708(device_type, device_name):
    # V-216708 -  The Cisco PE router providing Virtual Private LAN Services (VPLS) must be configured to have traffic storm control thresholds on CE-facing interfaces.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NF"
    check.comments = (
        check.vulid
        + " - The Cisco PE router providing Virtual Private LAN Services (VPLS) must be configured to have traffic storm control thresholds on CE-facing interfaces.\n"
    )
    strLDP = "NA"
    strVPLS = "NF"
    command = "show xconnect pwmib | exc pw"
    result = exec_command(command, device_name)
    check.finding = result
    # Find out if we have local ports terminating VPWS
    if len(result.splitlines()) > 5:
        strLDP = "enabled"
        command = "show run | sec service.instance|bridge"
        result = exec_command(command, device_name)
        check.finding = check.finding + result
        if len(result.splitlines()) > 3:
            for line in result.splitlines():
                if line.find("MPLS") > -1:
                    command = "show run int " + line.split()[-1]
                    result = exec_command(command, device_name)
                    check.finding = check.finding + result
                    if result.find("storm-control") == -1:
                        strVPLS = "OP"
                        check.comments = (
                            check.comments
                            + "OPEN: Missing storm control on VPLS interface "
                            + line.split()[-1]
                            + "\n"
                        )
            if strVPLS != "NF":
                check.status = "OP"
                check.comments = (
                    check.comments
                    + "OPEN: Private LAN Services (VPLS) must be configured to have traffic storm control thresholds on CE-facing interfaces.\n"
                )
            else:
                check.status = "NF"
                check.comments = check.comments + "NAF: Storm control is in place.\n"
        else:
            check.status = "NF"
            check.comments = (
                check.comments
                + "NAF: There is no service instance or bridge group configured.\n"
            )
    else:
        check.status = "NA"
        check.comments = (
            check.comments
            + "\n"
            + check.vulid
            + ":NA - Router is not providing L2 VFI services."
        )
    return check


def V216709(device_type, device_name):
    # V-216709 -  The Cisco PE router must be configured to implement Internet Group Management Protocol (IGMP) or Multicast Listener Discovery (MLD) snooping for each Virtual Private LAN Services (VPLS) bridge domain.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NF"
    check.comments = (
        check.vulid
        + " - The Cisco PE router must be configured to implement Internet Group Management Protocol (IGMP) or Multicast Listener Discovery (MLD) snooping for each Virtual Private LAN Services (VPLS) bridge domain.\n"
    )
    strLDP = "NA"
    strVPLS = "NF"
    command = "show xconnect pwmib | exc pw"
    result = exec_command(command, device_name)
    check.finding = result
    # Find out if we have local ports terminating VPWS
    if len(result.splitlines()) > 5:
        strLDP = "enabled"
        # If we're running LDP lets get busy...
        # Find out if igmp snooping configured
        command = "show run | sec bridge-domain"
        result = exec_command(command, device_name)
        check.finding = check.finding + result
        if len(result.splitlines()) > 3:
            command = "show run | i igmp.snoop"
            result = exec_command(command, device_name)
            check.finding = check.finding + result
            if result.find("ip igmp snooping") == -1:
                check.status = "OP"
                check.comments = (
                    check.comments
                    + "OPEN: Missing IGMP or MLD snooping for IPv4 and IPv6 multicast traffic respectively for each VPLS bridge domain.\n"
                )
            else:
                check.status = "NF"
                check.comments = (
                    check.comments
                    + "NAF: Found IGMP or MLD snooping for IPv4 and IPv6 multicast traffic respectively for each VPLS bridge domain.\n"
                )
        else:
            check.status = "NF"
            check.comments = check.comments + "NAF: No bridge domain configured.\n"

    else:
        check.status = "NA"
        check.comments = (
            check.comments
            + "\n"
            + check.vulid
            + ":NA - Router is not providing L2 VFI services."
        )
    return check


def V216710(device_type, device_name):
    # V-216710 - The Cisco PE router must be configured to limit the number of MAC addresses it can learn for each Virtual Private LAN Services (VPLS) bridge domain.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NF"
    check.comments = (
        check.vulid
        + " - The Cisco PE router must be configured to limit the number of MAC addresses it can learn for each Virtual Private LAN Services (VPLS) bridge domain.\n"
    )
    strLDP = "NA"
    strVPLS = "NF"
    command = "show xconnect pwmib | exc pw"
    result = exec_command(command, device_name)
    check.finding = result
    # Find out if we have local ports terminating VPWS
    if len(result.splitlines()) > 5:
        # If we're running LDP lets get busy...
        # Find out if igmp snooping configured
        command = "show run | sec bridge-domain"
        result = exec_command(command, device_name)
        check.finding = check.finding + result
        if len(result.splitlines()) > 3:
            if result.find("mac limit maximum") == -1:
                check.status = "OP"
                check.comments = (
                    check.comments
                    + "OPEN: Missing IGMP or MLD snooping for IPv4 and IPv6 multicast traffic respectively for each VPLS bridge domain.\n"
                )
            else:
                check.status = "NF"
                check.comments = (
                    check.comments
                    + "NAF: Found IGMP or MLD snooping for IPv4 and IPv6 multicast traffic respectively for each VPLS bridge domain.\n"
                )
        else:
            check.status = "NF"
            check.comments = check.comments + "NAF: No bridge domain configured.\n"

    else:
        check.status = "NA"
        check.comments = (
            check.comments
            + "\n"
            + check.vulid
            + ":NA - Router is not providing L2 VFI services."
        )
    return check

def V216711(device_type, device_name):
    # V-216711 -  The Cisco PE router must be configured to block any traffic that is destined to IP core infrastructure.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NA"
    # Find all physical interfaces that could be CE facig
    command = "show int desc | i up"
    result = exec_command(command, device_name)
    check.finding = result
    strIntStatus = "NA"
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
                result = exec_command(command, device_name)
                check.finding = check.finding + result
                if result.find("SWAB") > -1:
                    bolHasSWAB = 1
                    strVRF = ""
                    strIntStatus = "NF"
                    # Right now this will always pass.  We can add a check for ACLs later if needed.
                    if result.find("SWAB") == -1:
                        strIntStatus = "OP"

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
                    if strIntStatus == "OP":
                        check.comments = (
                            check.comments + " and does NOT have a VRF configured.\n"
                        )
                    else:
                        check.comments = (
                            check.comments
                            + ", which prevents core network elements from being accessible from any external hosts.\n"
                        )
    if bolHasSWAB == 0:
        check.status = "NA"
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


def V216712(device_type, device_name):
    # V-216712 -  The Cisco PE router must be configured with Unicast Reverse Path Forwarding (uRPF) loose mode enabled on all CE-facing interfaces.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NA"
    # Find all physical interfaces that could be CE facig
    command = "show int desc | i up"
    result = exec_command(command, device_name)
    check.finding = result
    strIntStatus = "NA"
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
                result = exec_command(command, device_name)
                check.finding = check.finding + result
                if result.find("SWAB") > -1:
                    bolHasSWAB = 1
                    strVRF = ""
                    strIntStatus = "NF"

                    if result.find("ip verify unicast source") == -1:
                        strIntStatus = "OP"
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
                    if strIntStatus == "OP":
                        check.comments = (
                            check.comments + " and does NOT have uRPF configured.\n"
                        )
                    else:
                        check.comments = check.comments + " and has uRPF configured.\n"
    if bolHasSWAB == 0:
        check.status = "NA"
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


def V216714(device_type, device_name):
    # V-216714 - The Cisco P router must be configured to implement a Quality-of-Service (QoS) policy in accordance with the QoS DODIN Technical Profile.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    # Find all physical interfaces that could be configured for QoS
    command = "show int desc | i up"
    result = exec_command(command, device_name)
    check.finding = result
    strIntStatus = "OP"
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
                result = exec_command(command, device_name)
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
                        check.status = "NF"
                        check.comments = (
                            check.comments
                            + "Found QoS policy on interface "
                            + line.split()[0]
                            + ".\n"
                        )

    if check.status == "OP":
        check.comments = (
            check.vulid
            + " -OPEN - The Cisco PE router must be configured to implement a Quality-of-Service (QoS) policy in accordance with the QoS DODIN Technical Profile."
        )
    else:
        for policy in strPolicies:
            command = "show run | sec policy-map." + policy.strip()
            result = exec_command(command, device_name)
            check.finding = check.finding + result
        check.comments = (
            check.comments
            + check.vulid
            + " -NAF - The Cisco PE router is configured to enforce a Quality-of-Service (QoS) policy."
        )
    return check


def V216715(device_type, device_name):
    # V-216715 - The Cisco P router must be configured to implement a Quality-of-Service (QoS) policy in accordance with the QoS DODIN Technical Profile.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    # Find all physical interfaces that could be configured for QoS
    command = "show int desc | i up"
    result = exec_command(command, device_name)
    check.finding = result
    strIntStatus = "OP"
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
                result = exec_command(command, device_name)
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
                        check.status = "NF"
                        check.comments = (
                            check.comments
                            + "Found QoS policy on interface "
                            + line.split()[0]
                            + ".\n"
                        )

    if check.status == "OP":
        check.comments = (
            check.vulid
            + " -OPEN - The Cisco P router must be configured to implement a Quality-of-Service (QoS) policy in accordance with the QoS DODIN Technical Profile."
        )
    else:
        for policy in strPolicies:
            command = "show run | sec policy-map." + policy.strip()
            result = exec_command(command, device_name)
            check.finding = check.finding + result
        check.comments = (
            check.comments
            + check.vulid
            + " -NAF - The Cisco P router is configured to implement a Quality-of-Service (QoS) policy."
        )
    return check


def V216716(device_type, device_name):
    # V-216716 - The Cisco PE router must be configured to enforce a Quality-of-Service (QoS) policy to limit the effects of packet flooding denial of service (DoS) attacks.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    command = "sh run class-map | in class-map|dscp.cs1"
    result = exec_command(command, device_name)
    check.finding = result
    if result.find("cs1") > -1:
        check.status = "NF"
        check.comments = (
            check.vulid + " -NAF - QoS is configured to enforce a QoS policy to limit the effects of packet flooding DoS attacks."
        )
    else:
        check.comments = check.vulid + " -OPEN - QoS is NOT configured to enforce a QoS policy to limit the effects of packet flooding DoS attacks."
    return check


def V216717(device_type, device_name):
    # V-216717 -  The Cisco multicast router must be configured to disable Protocol Independent Multicast (PIM) on all interfaces that are not required to support multicast routing.
    check = Stig()
    result = ""
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    strPIMInterfaces = []
    # Find all physical interfaces running PIM
    command = "show ip pim interface | exc Tunn|Loop"
    result = exec_command(command, device_name)
    check.finding = result
    strIntStatus = "NF"
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
                    result = exec_command(command, device_name)
                    check.finding = check.finding + result
                    if (
                        result.find("shutdown") == -1
                        and result.find("TIER0") == -1
                    ):
                        strIntStatus = "OP"
                        check.comments = (
                            check.comments
                            + "PIM appears to be on an EGRESS interface "
                            + interface.split()[1]
                            + ".\n"
                        )
        if strIntStatus == "NF":
            check.comments = (
                check.vulid
                + "- NAF - The Cisco multicast router either has (PIM) neighbor filter configured or a disabled interface."
            )
            check.status = "NF"
        else:
            check.comments = (
                check.comments
                + check.vulid
                + "- OPEN - The Cisco multicast router must be configured to disable Protocol Independent Multicast (PIM) on all interfaces that are not required to support multicast routing.."
            )
            check.status = "OP"
    else:
        check.status = "NA"
        check.comments = (
            check.comments
            + check.vulid
            + "- NA - Router does not have multicast configured"
        )
    return check


def V216718(device_type, device_name):
    # V-216718 -  The Cisco multicast router must be configured to bind a Protocol Independent Multicast (PIM) neighbor filter to interfaces that have PIM enabled..
    check = Stig()
    result = ""
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    strPIMInterfaces = []
    # Find all physical interfaces running PIM
    command = "show ip pim interface | exc Tunn|Loop"
    result = exec_command(command, device_name)
    check.finding = result
    strIntStatus = "NF"
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
                    result = exec_command(command, device_name)
                    check.finding = check.finding + result
                    if (
                        result.find("shutdown") == -1
                        and result.find("ip pim neighbor-filter") == -1
                    ):
                        strIntStatus = "OP"
                        check.comments = (
                            check.comments
                            + "Could not find a pim filter on interface "
                            + interface.split()[1]
                            + ".\n"
                        )
        if strIntStatus == "NF":
            check.comments = (
                check.vulid
                + "- NAF - The Cisco multicast router either has (PIM) neighbor filter configured or a disabled interface."
            )
            check.status = "NF"
        else:
            check.comments = (
                check.comments
                + check.vulid
                + "- OPEN - The Cisco multicast router must have a (PIM) neighbor filter applied to interfaces that have PIM enabled."
            )
            check.status = "OP"
    else:
        check.status = "NA"
        check.comments = (
            check.comments
            + check.vulid
            + "- NA - Router does not have multicast configured"
        )
    return check


def V216719(device_type, device_name):
    # V-216719 -  The Cisco multicast edge router must be configured to establish boundaries for administratively scoped multicast traffic.
    check = Stig()
    result = ""
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    command = "sh run | i snmp.*.location"
    result = exec_command(command, device_name)
    check.finding = result
    if result.find("RT1") > -1 or result.find("RT1") > -1:
        check.comments = "This router is a external facing router.\n"
        command = "show run | i ip.pim"
        result = exec_command(command, device_name)
        check.finding = check.finding + result
        # Find the interface egressing the network.
        # Then check if it has PIM configured.
        # Still TBD!!!!!!!!!!!!!!
        if result.find("pim rp-address") > -1:
            command = "sh run  | inc ip.pim.accept-register.list"
            if result.find("pim accept-register list") > -1:
                check.status = "NF"
                check.comments = (
                    check.vulid
                    + "- OPEN - The Cisco multicast edge router must be configured to establish boundaries for administratively scoped multicast traffic.."
                )
            else:
                check.status = "OP"
                check.comments = (
                    check.vulid
                    + "- NAF - The Cisco multicast edge router is configured to establish boundaries for administratively scoped multicast traffic."
                )
        else:
            check.status = "NA"
            check.comments = (
                check.comments
                + check.vulid
                + "- NA - Router  does not have multicast configured.."
            )
    else:
        check.status = "NA"
        check.comments = (
            check.vulid
            + "- NA - Router is not a multicast edge or it does not have multicast configured.."
        )
    check.finding = result
    return check


def V216720(device_type, device_name):
    # V-216720 -  router must be configured to limit the multicast forwarding cache so that its resources are not saturated.
    check = Stig()
    result = ""
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    command = "sh run | in pim.rp"
    result = exec_command(command, device_name)
    # Find the DR interfaces
    if result.find("pim rp-address") > -1:
        command = "sh run  | inc ip.pim.accept-register.list"
        if result.find("pim accept-register list") > -1:
            check.status = "NF"
            check.comments = (
                check.vulid
                + "- OPEN - The router must be configured to limit the multicast forwarding cache so that its resources are not saturated."
            )
        else:
            check.status = "OP"
            check.comments = (
                check.vulid
                + "- NAF - router is configured to limit the multicast forwarding cache so that its resources are not saturated."
            )
    else:
        check.status = "NA"
        check.comments = (
            check.vulid + "- NA - Router does not have multicast configured"
        )
    check.finding = result
    return check


def V216721(device_type, device_name):
    # V-216721 -  The Cisco multicast Rendezvous Point (RP) router must be configured to filter Protocol Independent Multicast (PIM) Register messages received from the Designated Router (DR) for any undesirable multicast groups and sources.
    check = Stig()
    result = ""
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    command = "sh run | in pim.rp"
    result = exec_command(command, device_name)
    # Find the DR interfaces
    if result.find("pim rp-address") > -1:
        command = "sh run  | inc ip.pim.accept-register.list"
        if result.find("pim accept-register list") > -1:
            check.status = "NF"
            check.comments = (
                check.vulid
                + "- OPEN - router must be configured to filter Protocol Independent Multicast (PIM) Register messages "
            )
        else:
            check.status = "OP"
            check.comments = (
                check.vulid
                + "- NAF - router is configured to filter Protocol Independent Multicast (PIM) Register messages "
            )
    else:
        check.status = "NA"
        check.comments = (
            check.vulid + "- NA - Router does not have multicast configured"
        )
    check.finding = result
    return check


def V216722(device_type, device_name):
    # V-216722 - The Cisco multicast Designated Router (DR) must be configured to limit the number of mroute states resulting from Internet Group Management Protocol (IGMP) and Multicast Listener Discovery (MLD) Host Membership Reports.
    check = Stig()
    result = ""
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    command = "sh run | in pim.rp"
    result = exec_command(command, device_name)
    # Find the DR interfaces
    if result.find("pim rp-address") > -1:
        command = "sh run  | inc pim.accept-rp"
        if result.find("pim accept-rp") > -1:
            check.status = "NF"
            check.comments = (
                check.vulid
                + "- OPEN - RP is configured to filter join messages received from the DR for any undesirable multicast groups"
            )
        else:
            check.status = "OP"
            check.comments = (
                check.vulid
                + "- NAF - RP is not configured to filter join messages received from the DR for any undesirable multicast groups"
            )
    else:
        check.status = "NA"
        check.comments = (
            check.vulid + "- NA - Router does not have multicast configured"
        )
    check.finding = result
    return check


def V216723(device_type, device_name):
    # V-216723 - The Cisco multicast Rendezvous Point (RP) must be configured to rate limit the number of Protocol Independent Multicast (PIM) Register messages.
    check = Stig()
    temp = ""
    result = ""
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    command = "sh run | in igmp.join"
    temp = exec_command(command, device_name)
    # Find the DR interfaces
    if len(temp.splitlines()) > 4:
        for pimneigh in temp.splitlines():
            if pimneigh.find("Address") == -1 and pimneigh.find("DR") > -1:
                # If a PIM neighbor is a DR, check the interface for IGMP limit.
                command = (
                    "sh run interface " + pimneigh.split()[1] + " | inc igmp.limit"
                )
                result = result + "\r" + exec_command(command, device_name)
                if result.find("igmp limit") > -1:
                    check.status = "NF"
                    check.comments = (
                        check.comments
                        + check.vulid
                        + "- NAF - DR interface "
                        + pimneigh.split()[1]
                        + " RP is limiting PIM register messages.\n"
                    )
                else:
                    check.status = "OP"
                    check.comments = (
                        check.comments
                        + check.vulid
                        + "- OPEN - DR interface "
                        + pimneigh.split()[1]
                        + " RP is not limiting PIM register messages.\n"
                    )
    else:
        check.status = "NA"
        check.comments = check.vulid + "- NA - Router is not configured for multicast."
    check.finding = temp + result
    return check


def V216724(device_type, device_name):
    # V-216724 - The Cisco multicast Designated Router (DR) must be configured to filter the Internet Group Management Protocol (IGMP) and Multicast Listener Discovery (MLD) Report messages to allow hosts to join only multicast groups that have been approved by the organization.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NA"
    command = "sh run | in igmp.join"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-216724 - NA - COMMENTS: This requirement is only applicable to Source Specific Multicast (SSM) implementation."
    return check


def V216725(device_type, device_name):
    # V-216725 - The Cisco multicast Designated Router (DR) must be configured to filter the Internet Group Management Protocol (IGMP) and Multicast Listener Discovery (MLD) Report messages to allow hosts to join a multicast group only from sources that have been approved by the organization.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NA"
    command = "sh run | in igmp.join"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-216725 - NA - COMMENTS: This requirement is only applicable to Source Specific Multicast (SSM) implementation."
    return check


def V216726(device_type, device_name):
    # V-216726 - The Cisco multicast Designated Router (DR) must be configured to limit the number of mroute states resulting from Internet Group Management Protocol (IGMP) and Multicast Listener Discovery (MLD) Host Membership Reports.
    check = Stig()
    temp = ""
    result = ""
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "OP"
    command = "sh run | in igmp.join"
    temp = exec_command(command, device_name)
    # Find the DR interfaces
    if len(temp.splitlines()) > 4:
        for pimneigh in temp.splitlines():
            if pimneigh.find("Address") == -1 and pimneigh.find("DR") > -1:
                # If a PIM neighbor is a DR, check the interface for IGMP limit.
                command = (
                    "sh run interface " + pimneigh.split()[1] + " | inc igmp.limit"
                )
                result = result + "\r" + exec_command(command, device_name)
                if result.find("igmp limit") > -1:
                    check.status = "NF"
                    check.comments = (
                        check.comments
                        + check.vulid
                        + "- NAF - DR interface "
                        + pimneigh.split()[1]
                        + " is configured to limit the number of mroute states.\n"
                    )
                else:
                    check.status = "OP"
                    check.comments = (
                        check.comments
                        + check.vulid
                        + "- OPEN - DR interface "
                        + pimneigh.split()[1]
                        + " is not configured to limit the number of mroute states.\n"
                    )
    else:
        check.status = "NA"
        check.comments = check.vulid + "- NA - Router is not configured for multicast."
    check.finding = temp + result
    return check


def V216727(device_type, device_name):
    # V-216727 - The Cisco multicast Designated Router (DR) must be configured to limit the number of mroute states resulting from Internet Group Management Protocol (IGMP) and Multicast Listener Discovery (MLD) Host Membership Reports.
    check = Stig()
    temp = ""
    result = ""
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    command = "sh run | in pim.rp"
    temp = exec_command(command, device_name)
    # Find the DR interfaces
    if len(temp.splitlines()) > 2:
        command = "sh run  | inc pim.spt-threshold"
        result = result + "\r" + exec_command(command, device_name)
        if result.find("pim spt-threshold infinity") > -1:
            check.status = "NF"
            check.comments = (
                check.vulid
                + "- NAF - DR is configured to increase the SPT threshold or set to infinity to minimalize (S, G) state"
            )
        if result.find("pim spt-threshold infinity") == -1:
            check.status = "OP"
            check.comments = (
                check.vulid
                + "- OPEN - DR is not configured to increase the SPT threshold or set to infinity to minimalize (S, G) state"
            )
        else:
            check.status = "NA"
            check.comments = check.vulid + "- NA - Router is not a DR."
    else:
        check.status = "NA"
        check.comments = check.vulid + "- NA - Router does not have a PIM RP configured"
    check.finding = temp + result
    return check


def V216728(device_type, device_name):
    # V-216728 -  The Cisco Multicast Source Discovery Protocol (MSDP) router must be configured to only accept MSDP packets from known MSDP peers.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = ""
    check.comments = ""
    command = "sh run | in ip.msdp"
    result = exec_command(command, device_name)
    check.finding = result
    if result.find("password") == -1:
        check.status = "OP"
        check.comments = "V-216728 - OPEN - The router is not configured to only accept MSDP packets from known MSDP peers"
    if result.find("password") > -1:
        check.status = "NF"
        check.comments = "V-216728 - NAF - The router is configured to only accept MSDP packets from known MSDP peers"
    else:
        check.status = "NA"
        check.comments = "V-216728 - NA - The router is not configured as a MSDP router"
    return check


def V216729(device_type, device_name):
    # V-216729 -  The Cisco Multicast Source Discovery Protocol (MSDP) router must be configured to authenticate all received MSDP packets.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = ""
    check.comments = ""
    command = "sh run | in ip.msdp"
    result = exec_command(command, device_name)
    check.finding = result
    if result.find("password") == -1:
        check.status = "OP"
        check.comments = (
            "V-216729 - OPEN - The router does not require MSDP authentication"
        )
    if result.find("password") > -1:
        check.status = "NF"
        check.comments = "V-216729 - NAF - The router does require MSDP authentication"
    else:
        check.status = "NA"
        check.comments = "V-216729 - NA - The router is not configured as a MSDP router"
    return check


def V216730(device_type, device_name):
    # V-216730 -  The Cisco Multicast Source Discovery Protocol (MSDP) router must be configured to filter received source-active multicast advertisements for any undesirable multicast groups and sources.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = ""
    check.comments = ""
    command = "sh run | in ip.msdp"
    result = exec_command(command, device_name)
    check.finding = result
    if result.find("msdp sa-filter") == -1:
        check.status = "OP"
        check.comments = "V-216730 - OPEN - The router is not configured with an import policy to filter undesirable SA multicast advertisements"
    if result.find("msdp sa-filter") > -1:
        check.status = "NF"
        check.comments = "V-216730 - NAF - The router is configured with an import policy to filter undesirable SA multicast advertisements"
    else:
        check.status = "NA"
        check.comments = "V-216730 - NA - The router is not configured as a MSDP router"
    return check


def V216731(device_type, device_name):
    # V-216731 -  The Cisco Multicast Source Discovery Protocol (MSDP) router must be configured to filter source-active multicast advertisements to external MSDP peers to avoid global visibility of local-only multicast sources and groups.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = ""
    check.comments = ""
    command = "sh run | in ip.msdp"
    result = exec_command(command, device_name)
    check.finding = result
    if result.find("msdp sa-filter") == -1:
        check.status = "OP"
        check.comments = "V-216731 - OPEN - The router is not configured with an export policy to filter local source-active multicast advertisements"
    if result.find("msdp sa-filter") > -1:
        check.status = "NF"
        check.comments = "V-216731 - NAF - The router is configured with an export policy to filter local source-active multicast advertisements"
    else:
        check.status = "NA"
        check.comments = "V-216731 - NA - The router is not configured as a MSDP router"
    return check


def V216732(device_type, device_name):
    # V-216732 -  The Cisco Multicast Source Discovery Protocol (MSDP) router must be configured to limit the amount of source-active messages it accepts on a per-peer basis.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = ""
    check.comments = ""
    command = "sh run | in ip.msdp"
    result = exec_command(command, device_name)
    check.finding = result
    if result.find("msdp sa-limit") == -1:
        check.status = "OP"
        check.comments = "V-216732 - OPEN - The router is not configured to limit the source-active messages it accepts"
    if result.find("msdp sa-limit") > -1:
        check.status = "NF"
        check.comments = "V-216732 - NAF - The router is configured to limit the source-active messages it accepts"
    else:
        check.status = "NA"
        check.comments = "V-216732 - NA - The router is not configured as a MSDP router"
    return check


def V216733(device_type, device_name):
    # V-216733 -  The Cisco Multicast Source Discovery Protocol (MSDP) router must be configured to use a loopback address as the source address when originating MSDP traffic.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = ""
    check.comments = ""
    command = "sh run | in ip.msdp"
    result = exec_command(command, device_name)
    check.finding = result
    if result.find("loopback") == -1:
        check.status = "OP"
        check.comments = "V-216733 - OPEN - The router does not use its loopback address as the source address when originating MSDP traffic"
    if result.find("loopback") > -1:
        check.status = "NF"
        check.comments = "V-216733 - NAF - The router does use its loopback address as the source address when originating MSDP traffic"
    else:
        check.status = "NA"
        check.comments = "V-216733 - NA - The router is not configured as a MSDP router"
    return check


def V216997(device_type, device_name):
    # V-216997 -  The Cisco perimeter router must be configured to restrict it from accepting outbound IP packets that contain an illegitimate address in the source address field via egress filter or by enabling Unicast Reverse Path Forwarding (uRPF).
    check = Stig()
    check.set_vulid()
    check.comments = "V-216997 - OPEN - uRPF or an egress ACL has not been configured on all internal interfaces to restrict the router from accepting outbound IP packets"
    check.status = "OP"
    command = "show run | i snmp.*.location"
    result = exec_command(command, device_name)
    check.finding = result
    # Check if we're a perimeter router.
    if result.find("RT1") == -1:
        check.status = "NF"
        check.comments = (
            check.vulid + " - NAF as this device is not a perimeter router."
        )
    else:
        command = "sh run | in unicast.source"
        result = exec_command(command, device_name)
        check.finding = check.finding + result
        if result.find("unicast", len(device_name) + len(command)) > -1:
            check.status = "NF"
            check.comments = "V-216997 - NAF - uRPF or an egress ACL has not been configured on all internal interfaces to restrict the router from accepting outbound IP packets"
    return check


def V216998(device_type, device_name):
    # V-216998 -  The Cisco perimeter router must be configured to block all packets with any IP options.
    check = Stig()
    check.set_vulid()
    check.comments = "V-216998 - OPEN - The router is not configured to drop all packets with IP options"
    check.status = "OP"
    command = "show run | i snmp.*.location"
    result = exec_command(command, device_name)
    # Check if we're a perimeter router.  If not no ACLs are required
    if result.find("RT1", len(device_name) + len(command)) == -1:
        check.status = "NF"
        check.comments = (
            check.vulid + " - NAF as this device is not a perimeter router."
        )
    else:
        command = "sh access-lists | i option"
        result = exec_command(command, device_name)
        check.finding = result
        if result.find("option", len(device_name) + len(command)) > -1:
            check.status = "NF"
            check.comments = "V-216998 - NAF - The router is configured to drop all packets with IP options"
    return check


def V216999(device_type, device_name):
    # V-216999-  The Cisco BGP router must be configured to enable the Generalized TTL Security Mechanism (GTSM).
    check = Stig()
    MsgBox = crt.Dialog.MessageBox
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NF"
    strBGP_AS = "0"
    check.comments = ""
    # Lets find out if the BGP routing protocols is in use
    command = "show ip proto | i Routing.Protoc"
    result = exec_command(command, device_name)
    # Identify BGP routing protocols is in use and save applicable AS
    for line in result.splitlines():
        line = line.replace('"', "")
        if line.find("bgp") > -1:
            strBGP_AS = line.replace('"', "").split()[-1]
    # Time to verify all eBGP neighbors are using ttl-security hops
    # strBGP_neighbor = []
    # strBGP_sessions = []2266
    strBGP_Findings = ""
    strBGP_status = "NF"
    if int(strBGP_AS) > 0:
        # Look for all the mBGP neighbors on BlackCore routers
        command = "sh bgp vpnv4 unicast all summ | b Neighbor"
        result = exec_command(command, device_name)
        if result.find("Invalid") > -1:
            # Look for all the eBGP neighbors on Colored routers
            command = "sh bgp ipv4 unicast summ | b Neighbor"
            result = exec_command(command, device_name)
        strBGP_Findings = strBGP_Findings + result + "\n"
        strBGP_neighbor_status = "OP"
        for neighbor in result.splitlines():
            strBGP_neighbor_status = "OP"
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
                    result = exec_command(command, device_name)
                    strBGP_Findings = strBGP_Findings + result + "\n"
                    # If there's a ttl-security hop defined then we can clear this neighbor
                    if result.find("ttl-security hops") > -1:
                        strBGP_neighbor_status = "NF"
                        check.comments = (
                            check.comments
                            + "BGP neighbor "
                            + neighbor.split()[0]
                            + " is configured to use ttl-security hop.\n"
                        )
                if neighbor.find(strBGP_AS) > -1:
                    # If a host is an internal BGP neighbor, ttl-security hop is not required.
                    strBGP_neighbor_status = "NF"
                    check.comments = (
                        check.comments
                        + "BGP neighbor "
                        + neighbor.split()[0]
                        + " is an internal BGP neighbor.\n"
                    )
                if strBGP_neighbor_status == "OP":
                    strBGP_status = "OP"
                    check.comments = (
                        check.comments
                        + "Could not find ttl-security hop for neighbor "
                        + neighbor.split()[0]
                        + ".\n"
                    )
        if strBGP_status != "NF":
            check.status = "OP"
        check.finding = strBGP_Findings
        # check.comments = "V-216999 - CAT II - The Cisco router must be configured to use encryption for routing protocol authentication."
    return check


def V217000(device_type, device_name):
    # V-217000 - The Cisco BGP router must be configured to use a unique key for each autonomous system (AS) that it peers with.
    check = Stig()
    check.set_vulid()
    check.vulid = "V-217000"
    bolPassword = 0
    strBGP_Findings = ""
    
    # Lets find out if the BGP routing protocols is in use
    command = "show ip proto | i Routing.Protoc"
    result = exec_command(command, device_name)
    
    # Identify if BGP routing protocols is in use
    if "bgp" not in result:
        check.comments = "V-217000 - NAF - BGP not running."
        check.status = "NF"
    else:
        # Look for BGP IPv4 neighbors first
        command = "sh bgp ipv4 unicast summ | b Neighbor"
        result = exec_command(command, device_name)
        strBGP_Findings += result + "\n"
        
        if len(result.splitlines()) >= 3: 
            for neighbor in result.splitlines():
                if "#" not in neighbor and "Neighbor" not in neighbor and len(neighbor.split()) > 3:
                    neighbor_ip = neighbor.split()[0]
                    command = f"sh run | in ^_neighbor {neighbor_ip} password"
                    temp_result = exec_command(command, device_name)
                    
                    if len(temp_result.splitlines()) >= 3:
                        strBGP_Findings += f"Neighbor {neighbor_ip} is using a unique key\n"
                    else:
                        command = f"sh run | in {neighbor_ip}.*.peer-session"
                        temp_result = exec_command(command, device_name)
                        
                        if len(temp_result.splitlines()) >= 3:
                            for peerSession in temp_result.splitlines():
                                if "#" not in peerSession:
                                    command = f"sh run | sec template.*.{peerSession.split()[4]}"
                                    temp_result_2 = exec_command(command, device_name)
                                    
                                    if "password" in temp_result_2:
                                        strBGP_Findings += f"Neighbor {neighbor_ip} in peer-session {peerSession.split()[4]} is using a unique key\n"
                        else:
                            command = f"sh run | in {neighbor_ip}.peer-group"
                            temp_result = exec_command(command, device_name)
                            
                            if len(temp_result.splitlines()) >= 3:
                                for peerGroup in temp_result.splitlines():
                                    if "#" not in peerGroup:
                                        command = f"sh run | in {peerGroup.split()[3]}.password"
                                        temp_result_2 = exec_command(command, device_name)
                                        
                                        if "password" in temp_result_2:
                                            strBGP_Findings += f"Neighbor {neighbor_ip} in peer-group {peerGroup.split()[3]} is using a unique key\n"
                            else:
                                bolPassword += 1
                                strBGP_Findings += f"Neighbor {neighbor_ip} is not using a unique key\n"

        # Look for BGP VPNv4 neighbors
        command = "sh bgp vpnv4 unicast all summ | b Neighbor"
        result = exec_command(command, device_name)
        strBGP_Findings += result + "\n"        
        
        if len(result.splitlines()) >= 3: 
            for neighbor in result.splitlines():
                if "#" not in neighbor and "Neighbor" not in neighbor and len(neighbor.split()) > 3:
                    neighbor_ip = neighbor.split()[0]
                    
                    command = f"sh run | in ^_neighbor {neighbor_ip} password"
                    temp_result = exec_command(command, device_name)
                    
                    if len(temp_result.splitlines()) >= 3:
                        strBGP_Findings += f"Neighbor {neighbor_ip} is using a unique key\n"
                    else:
                        command = f"sh run | in ^_ neighbor {neighbor_ip} password"
                        temp_result = exec_command(command, device_name)
                        
                        if len(temp_result.splitlines()) >= 3:
                            strBGP_Findings += f"Neighbor {neighbor_ip} is using a unique key\n"
                        else:
                            command = f"sh run | in {neighbor_ip}.*.peer-session"
                            temp_result = exec_command(command, device_name)
                            
                            if len(temp_result.splitlines()) >= 3:
                                for peerSession in temp_result.splitlines():
                                    if "#" not in peerSession:
                                        command = f"sh run | sec template.*.{peerSession.split()[4]}"
                                        temp_result_2 = exec_command(command, device_name)
                                        
                                        if "password" in temp_result_2:
                                            strBGP_Findings += f"Neighbor {neighbor_ip} in peer-session {peerSession.split()[4]} is using a unique key\n"
                                        elif "ao" in temp_result_2:
                                            strBGP_Findings += f"Neighbor {neighbor_ip} in peer-session {peerSession.split()[4]} is using a unique key\n"
                                        else:
                                            bolPassword += 1
                                            strBGP_Findings += f"Neighbor {neighbor_ip} is not using a unique key\n"

        if bolPassword == 0:
            check.comments += "V-217000 - NAF - The router is using unique keys within the same or between autonomous systems (AS)."
            check.status = "NF"
        else:
            check.comments += "V-217000 - OPEN - The router is not using unique keys within the same or between autonomous systems (AS)."
            check.status = "OP"
        
        check.finding = strBGP_Findings
    
    return check




def V217001(device_type, device_name):
    # V-217001 - The Cisco PE router must be configured to ignore or drop all packets with any IP options.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    MsgBox = crt.Dialog.MessageBox
    check.set_vulid()
    check.status = "OP"
    check.comments = "V-217001 - OPEN - The router is not configured to drop or block all packets with IP options"
    command = "sh run | in ip options"
    result = exec_command(command, device_name)
    # Find services that are not disabled
    if (
        result.find("ip options ignore", len(device_name) + len(command))
        or result.find("ip options drop", len(device_name) + len(command)) > -1
    ):
        check.status = "NF"
        check.comments = "V-217001 - NAF -The router is configured to drop or block all packets with IP options"
    check.finding = result
    return check


def V229031(device_type, device_name):
    # V-229031 - The Cisco router must be configured to have Cisco Express Forwarding enabled.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    MsgBox = crt.Dialog.MessageBox
    check.set_vulid()
    check.status = "OP"
    check.comments = "V-229031 - OPEN - The router does not have CEF enabled."
    command = "sh ip cef summ"
    result = exec_command(command, device_name)
    # Find services that are not disabled
    if result.find("IPv4 CEF is enabled", len(device_name) + len(command)) > -1:
        check.status = "NF"
        check.comments = "V-229031 - NAF -The router has CEF enabled."
    check.finding = result
    return check


def V230039(device_type, device_name):
    # V-230039 - The Cisco router must be configured to advertise a hop limit of at least 32 in Router Advertisement messages for IPv6 stateless auto-configuration deployments.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    MsgBox = crt.Dialog.MessageBox
    check.set_vulid()
    check.status = "OP"
    check.comments = "V-230039 - OPEN - The router has not been configured and has not been set to at least 32."
    command = "sh run | in ipv6.hop-limit"
    result = exec_command(command, device_name)
    # Find services that are not disabled
    if result.find("ipv6 hop-limit", len(device_name) + len(command)) > -1:
        check.status = "NF"
        check.comments = "V-230039 - NAF - The router has been configured and has been set to at least 32."
    check.finding = result
    return check


def V230042(device_type, device_name):
    # V-230042 - The Cisco router must not be configured to use IPv6 Site Local Unicast addresses.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    MsgBox = crt.Dialog.MessageBox
    check.set_vulid()
    check.status = "OP"
    check.comments = "V-230042 - OPEN -  IPv6 Site Local Unicast addresses are defined"
    command = "sh run | in FEC0::"
    result = exec_command(command, device_name)
    # Find services that are not disabled
    if result.find("FEC0::", len(device_name) + len(command)) == -1:
        check.status = "NF"
        check.comments = (
            "V-230042 - NAF -  IPv6 Site Local Unicast addresses are not defined"
        )
    check.finding = result
    return check


def V230045(device_type, device_name):
    # V-230045 - The Cisco perimeter router must be configured to suppress Router Advertisements on all external IPv6-enabled interfaces.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NA"
    command = "sh ipv6 access-list"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-230045 - NA - COMMENTS: No external interface is configured with ipv6 on this router."
    return check


def V230048(device_type, device_name):
    # V-230048 - The Cisco perimeter router must be configured to drop IPv6 undetermined transport packets.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NA"
    command = "sh ipv6 access-list"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-230048 - NA - COMMENTS: No inbound interface is configured with ipv6 on this router."
    return check


def V230051(device_type, device_name):
    # V-230051 - The Cisco perimeter router must be configured drop IPv6 packets with a Routing Header type 0, 1, or 3–255.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NA"
    command = "sh ipv6 access-list"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-230051 - NA - COMMENTS: No inbound interface is configured with ipv6 on this router."
    return check


def V230146(device_type, device_name):
    # V-230146 - The Cisco perimeter router must be configured to drop IPv6 packets containing a Hop-by-Hop header with invalid option type values.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NA"
    command = "sh ipv6 access-list"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-230146 - NA - COMMENTS: No inbound interface is configured with ipv6 on this router."
    return check


def V230150(device_type, device_name):
    # V-230150 - The Cisco perimeter router must be configured to drop IPv6 packets containing a Destination Option header with invalid option type values.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NA"
    command = "sh ipv6 access-list"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-230150 - NA - COMMENTS: No inbound interface is configured with ipv6 on this router."
    return check


def V230153(device_type, device_name):
    # V-230153 - The Cisco perimeter router must be configured to drop IPv6 packets containing an extension header with the Endpoint Identification option.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NA"
    command = "sh ipv6 access-list"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-230153 - NA - COMMENTS: No inbound interface is configured with ipv6 on this router."
    return check


def V230156(device_type, device_name):
    # V-230156 - The Cisco perimeter router must be configured to drop IPv6 packets containing the NSAP address option within Destination Option header.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NA"
    command = "sh ipv6 access-list"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-230156 - NA - COMMENTS: No inbound interface is configured with ipv6 on this router."
    return check


def V230159(device_type, device_name):
    # V-230159 - The Cisco perimeter router must be configured to drop IPv6 packets containing a Hop-by-Hop or Destination Option extension header with an undefined option type.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.set_vulid()
    check.status = "NA"
    command = "sh ipv6 access-list"
    result = exec_command(command, device_name)
    check.finding = result
    check.comments = "V-230159 - NA - COMMENTS: No inbound interface is configured with ipv6 on this router."
    return check


def Vtemplate(device_type, device_name):
    # Info about Vulnerability.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check = Stig()
    check.set_vulid()
    check.status = "NF"
    command = "sh run| i aaa authentic"
    # if device_type == "NXOS":
    #    command = "sh run | i \"aaa authentic\""
    result = exec_command(command, device_name)
    check.finding = result
    # Time to check the results of the command...   save check status to check.status and commants to check.comments
    # if len(result1.splitlines()) < 3 and len(result2.splitlines()) < 3:
    # 	check.status = "NF"
    # 	check.comments = "NAF - There are no community or user accounts."
    # if result.find("logging level", len(device_name + "#" + command)) > -1:
    #        check.status = "NF"
    #        check.comments = "NXOS logging enabled."
    #
    return check


# ----------------------------------------------------------------------------------------


#Main Processing Functions
def process_host(host, checklist_file, auth_method, current_host_number, total_hosts_count, stig_instance, command_cache_instance):
    """
    Connects to a host device, executes STIG checks, logs the results, and updates the checklist file.

    Args:
    - host (str): The hostname or IP of the target device.
    - checklist_file (str): The filename of the CKL or CKLB template to be used based on the file type.
    - auth_method (str): The authentication method ('2FA' or 'un').
    - current_host_number (int): The current count of the host being processed in the sequence.
    - total_hosts_count (int): The total number of hosts that will be processed.

    Returns:
    - bool: True if the process is successful, False otherwise.
    """
    host = host.replace("\n", "").strip()
    device_type = "IOS"
    connection_type_map = {'2FA': 'pki', 'un': 'user_pass'}
    connection_type = connection_type_map.get(auth_method, 'default')
    
    # Try to establish a connection to the host
    device_name, common_name = connect_to_host(host, connection_type, current_host_number, total_hosts_count)
    
    if device_name is None:
        # Connection failed, return False
        return False

    # Initialize the flag for success to False
    process_success = False

    try:
        # Read the function names and create STIG list
        stig_list = create_stig_list_from_host(device_name, checklist_file, device_type)

        # Log the STIG results to the CSV file
        log_stig_results_to_csv(stig_list, host, device_name)

        # Update and write CKL/CKLB
        update_and_write_checklist(stig_list, device_name, host, checklist_file)
        process_success = True  # Set the flag to True if all steps are successful
    except Exception as e:
        # Exception handling (might want to include more detailed logging or handling here)
        exc_type, exc_value, exc_traceback = sys.exc_info()
        tb_info = traceback.extract_tb(exc_traceback)[-1]
        line_number, function_name = tb_info[1], tb_info[2]
        # Handle the exception as needed
    finally:
        # Disconnect session, regardless of success or failure
        crt.Session.Disconnect()
        # Clear the Stig and Commandcache instances for the next host
        stig_instance.clear()
        command_cache_instance.clear()
        return process_success




#Here may want to add a lookup/call to map the Vul number to the severity of Vul
#This way it can be used in logs and other looks up, maybe even a setting for Scans to scan for
#CATI, CATII, CATIII or mix there of
def create_stig_list_from_host(device_name, checklist_file, device_type):
    """
    Creates a list of STIG objects for the given host device, handling any exceptions.
    It logs any errors that occur during the execution of vulnerability check functions 
    both to a CSV file and within the Stig object for CKL/CKLB inclusion.

    Args:
    - device_name (str): The name of the device.
    - checklist_file (str): The filename of the CKL/CKLB template.
    - device_type (str): The type of device (e.g., 'IOS').

    Returns:
    list: A list of STIG objects.
    """
    checklist_manager = ChecklistManager()
    vuln_info = checklist_manager.read_vuln_info(checklist_file)
    stig_list = []

    for original_vuln_num, (function_name, severity) in vuln_info.items():
        try:
            func = globals()[function_name]
            stig_instance = func(device_type, device_name.strip())
            stig_instance.severity = severity  # Assign severity to the stig instance, if applicable
            stig_list.append(stig_instance)
        except Exception as e:
            error_stig = Stig()
            error_stig.device_name = device_name
            error_stig.device_type = device_type
            error_stig.handle_error(function_name, e)
            stig_list.append(error_stig)

    return stig_list


def update_and_write_checklist(stig_list, device_name, host, checklist_file):
    """
    Updates and writes the checklist based on the file extension.
    If no extension is provided, it writes both .ckl and .cklb files.

    Args:
    - stig_list (list): A list of STIG check results.
    - device_name (str): The name of the device.
    - host (str): The hostname or IP of the device.
    - checklist_file (str): The file path of the checklist to be updated.

    Returns:
    None: The function will write to a file directly.
    """
    checklist_manager = ChecklistManager()
    file_extension = os.path.splitext(checklist_file)[1].lower()


    if file_extension == '.ckl':
        checklist_manager.update_and_write_ckl(stig_list, device_name, host, checklist_file)
    elif file_extension == '.cklb':
        checklist_manager.update_and_write_cklb(stig_list, device_name, host, checklist_file)
    elif file_extension == '':
        # Process both .ckl and .cklb if no specific extension is provided
        base_filename = os.path.splitext(checklist_file)[0]
        checklist_manager.update_and_write_ckl(stig_list, device_name, host, base_filename + '.ckl')
        checklist_manager.update_and_write_cklb(stig_list, device_name, host, base_filename + '.cklb')
    else:
        raise ValueError("Unsupported checklist file format. Provide a .ckl, .cklb, or no extension for both.")

#noticed an issue with this on if you try to 'x' of the auth it loops and keeps asking.
#Need to find a way to stop the looping, this is likely do to it being called in a loop in another function
#Need to add support that allows a user to provide other username/password per device if they mark it
#in the CSV file, this will help with device that may not be on TACACS or is using another auth source
#Maybe use getpass here to get the password?
def get_credentials():
    """
    Prompts the user for 'un' authentication only once and stores it globally.
    """
    global stored_username, stored_password
    stored_username = crt.Dialog.Prompt("Enter your username for 'un' authentication:", "Login", "", False).strip()
    stored_password = crt.Dialog.Prompt("Enter your password for 'un' authentication:", "Login", "", True).strip()


def process_all_hosts(hosts_data, stig_instance, command_cache_instance):
    """
    Processes all hosts and returns the count of failed hosts.
    """
    int_failed_hosts = 0
    processed_hosts_count = 0
    int_total_hosts = len(hosts_data)

    for host_info in hosts_data:
        # Increment only for hosts that will be processed
        processed_hosts_count += 1
        host = host_info['host']
        checklist_file = host_info['checklist']
        auth_method = host_info['auth']

        # Use the preloaded checklist information
        if not process_host(host, checklist_file, auth_method, processed_hosts_count, int_total_hosts, stig_instance, command_cache_instance):
            int_failed_hosts += 1
    return int_failed_hosts, processed_hosts_count


def display_summary(processed_hosts_count, int_failed_hosts):
    """
    Displays the summary of the script's execution.
    """
    t2 = time.perf_counter()
    elapsed_time = t2 - t1
    elapsed_minutes, elapsed_seconds = divmod(elapsed_time, 60)
    summary_message = f"The script finished executing in {int(elapsed_minutes)} minutes and {int(elapsed_seconds)} seconds with {processed_hosts_count - int_failed_hosts} hosts scanned and {int_failed_hosts} failed."
    crt.Dialog.MessageBox(summary_message)


#Main Execution
def Main():
    """
    The main function that orchestrates the entire script.
    """
    global t1, stored_username, stored_password, command_cache
    t1 = time.perf_counter()
    command_cache = Commandcache()

    # Initialize credentials with default values
    stored_username = ""
    stored_password = ""
    # Add file select box for this file, it just needs to state host and end in csv
    csv_filename = "host.csv"
    hosts_data = read_hosts_and_templates_from_csv(csv_filename)  # Updated function call

    # Check if 'un' authentication is needed and prompt for it once
    if any(host_info['auth'] == 'un' for host_info in hosts_data):
        get_credentials()

    stig_instance = Stig()
    command_cache_instance = Commandcache()

    int_failed_hosts, processed_hosts_count = process_all_hosts(hosts_data, stig_instance, command_cache_instance)

    display_summary(processed_hosts_count, int_failed_hosts)

Main()

"""
 In a typical Python environment, the following guard is used to ensure that
 the code is only executed when the script is run directly. However, in SecureCRT,
 each script runs in its own isolated environment, and this guard may not behave as expected.
 Therefore, it is commented out.

 if __name__ == '__main__':
     Main()
"""