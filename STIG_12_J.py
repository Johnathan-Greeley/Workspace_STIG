# $language = "python3"
# $interface = "1.0"


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


class Commandcache:
    def __init__(self):
        self.cache = {}

    def add(self, device_name, command, output):
        self.cache[(device_name, command)] = output

    def get(self, device_name, command):
        return self.cache.get((device_name, command))


command_cache = Commandcache()

#sample of vul check functions, there are over 80 or more of this type of function START#
def V220518(device_type, device_name):
    """
    V-220518 - CAT II - The Cisco switch must be configured to limit the number of concurrent management sessions to an organization-defined number.
    """
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"
    str_model = "unknown"
    str_model_version = "unknown"

    command = "show inventory | i PID"
    result = exec_command(command, device_name)

    # Extract model information from the result
    int_start = result.splitlines()[1].find(" ")
    int_end = result.splitlines()[1].find(" ", int_start + 1)
    str_model = result.splitlines()[1][int_start:int_end].strip()

    command = "show ver | beg Ports.Model"
    result = exec_command(command, device_name)

    # Extract model version if available
    if len(result.splitlines()) > 2:
        str_model_version = result.splitlines()[3][32:46]

    command = "sh run | i http.secure-server"
    temp = exec_command(command, device_name)

    # Check if the model is Catalyst 9300
    if "C9300" in str_model:
        check.status = "Not_Applicable"
        check.finding = f"{temp}\r{result}"
        check.comments = "V-220518 - NA - Catalyst 9300 switches no longer have the session-limit command."
    else:
        command = "sh run | i \line.vty.*.*|session-limit"
        result = exec_command(command, device_name)

        # Check if session limit is set
        if "session-limit" in result[len(device_name) + len(command):]:
            check.status = "NotAFinding"
        check.finding = f"{temp}\r{result}"
        check.comments = "V-220518 - CAT II - NAF as long as the VTY lines have session-limit >=2"

    return check


def V220519(device_type, device_name):
    """
    V-220519 - CAT II - The Cisco switch must be configured to automatically audit account creation.
    """
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"

    command = "sh run | sec log.config"
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
    """
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"

    command = "sh run | sec log.config"
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
    """
    check = Stig()
    check.vulid = format_vulid()
    check.status = "Open"

    command = "sh run | sec log.config"
    result = exec_command(command, device_name)

    # Default comments and finding
    check.comments = "V-220521 - CAT II - OPEN - no logging"
    check.finding = result

    # Check if "log config" is present in the result
    if re.search(r'log config', result[len(device_name) + len(command):]):
        check.status = "NotAFinding"
        check.comments = "V-220521 - CAT II - NAF - Logging enabled"

    return check


#sample of vul check functions, there are over 80 or more of this type of function END#

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
    return os.path.dirname(os.path.abspath(__file__)) + "\\"

strFilePath = get_script_path()

def read_function_names_from_ckl(filename):
    """Reads the Vuln_Num values from the CKL file and returns them in the V###### format."""
    function_names = []
    tree = ET.parse(filename)
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
    with open(filename, "r") as file:
        reader = csv.reader(file)
        # Skip the header
        next(reader, None)
        # Get the first element from each row
        return [row[0] for row in reader if row]

def read_function_names():
    stig_csv_file = strFilePath + "stig_vul.csv"
    stig_ckl_file = strFilePath + "Stigtemplate-XE-Switch-NDM-L2S-v2r6_07_Jun_2023.ckl"
    
    # First, try reading from the CSV file
    function_names = read_function_names_from_csv(stig_csv_file)
    
    # If no function names are found in the CSV, read from the CKL file
    if not function_names:
        function_names = read_function_names_from_ckl(stig_ckl_file)
    
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

#this is a STIG CKL file in a XML format
def load_template(template_name):
    with open(
        strFilePath + template_name, "r", encoding="utf-8"
    ) as objStigTemplateFile:
        return objStigTemplateFile.read()


def open_hosts_file():
    # Look for files in the strFilePath directory with "host" in the name and a ".txt" extension
    matching_files = [f for f in os.listdir(strFilePath) if "host" in f and f.endswith(".txt")]

    # If there is exactly one matching file, use it
    if len(matching_files) == 1:
        return open(strFilePath + matching_files[0])

    # Otherwise, open the dialog box
    strStigDevielist = crt.Dialog.FileOpenDialog(
        title="   ----------Please select a file containing Stig targets----------",
        filter="Text Files (*.txt)|*.txt||",
    )
    return open(strStigDevielist)


def create_log_file():
    log_file = (
        strFilePath
        + "scriptoutput-StigCheck-XE-switch-NDM-L2S-v3r4-"
        + str(today)
        + ".csv"
    )
    return open(log_file, "a")


def log_error(message):
    """Utility function to log errors to a file."""
    log_filename = "error_log.txt"
    log_path = os.path.join(strFilePath, log_filename)
    with open(log_path, "a") as error_log:
        error_log.write(f"{message}\n")


def connect_to_host(strHost):
    """Connect to a host and set terminal settings."""
    # Define the connection string and terminal settings
    connect_string = f"/SSH2 /ACCEPTHOSTKEYS /Z 4 {strHost}"
    term_len = "term len 0"
    term_width = "term width 400"
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
        elif found_index == 0:  # Neither "#" nor ">" prompts were found within 15 seconds
            log_error(f"Connection lost or failed to authenticate with host {strHost}.")
            log_file.write(f"Connection lost or failed to authenticate with host {strHost}\r")
            return None, None

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



def process_host(host, stig_template, log_file):
    host = host.replace("\n", "")
    device_type = "IOS"
    stig_list = []
    
    stig_vul_list = read_function_names()  # Corrected this line

    if host and "#" not in host:
        ckl = stig_template
        device_name, device_name = connect_to_host(host)

        if device_name is not None:
            for func_name in stig_vul_list:
                func = globals()[func_name]
                stig_list.append(func(device_type, device_name.strip()))

            for obj in stig_list:
                log_to_csv(obj, host, device_name, device_name, log_file)
                ckl = update_ckl_template(obj, ckl)

            # Parse the CKL XML and replace the placeholders
            root = ET.fromstring(ckl)
            root.find('.//ASSET/HOST_NAME').text = str(device_name)
            root.find('.//ASSET/HOST_IP').text = str(host)
            ckl = ET.tostring(root, encoding='utf-8').decode('utf-8')

            ckl_file = device_name + "_" + strDateTime + ".ckl"
            with open(strFilePath + ckl_file, "w", encoding="utf-8") as objCKLFile:
                objCKLFile.write(ckl)

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
    # Load the STIG template
    stig_template_name = "Stigtemplate-XE-Switch-NDM-L2S-v2r6_07_Jun_2023.ckl"
    stig_template = load_template(stig_template_name)

    # Open the hosts file and log file
    hosts_file = open_hosts_file()
    log_file = create_log_file()

    # Write the header to the log file
    log_file.write("Date,Hostname,CommonName,DeviceName,VulnID,Status,Finding,Comments,,\n")

    # Initialize a counter for total hosts (currently unused)
    int_total_hosts = 0

    # Process each host
    for strHost in hosts_file:
        process_host(strHost, stig_template, log_file)

    # Write the total number of hosts checked to the log file
    log_file.write(f"{strDateTime},Total Hosts Checked: {int_total_hosts},,\n")

    # Close the hosts file
    hosts_file.close()


Main()
t2 = time.perf_counter()
ShowTimer = crt.Dialog.MessageBox(f'The script finished executing in {round(t2-t1,2)} seconds.')