# $language = "python3"
# $interface = "1.0"


import os, datetime, SecureCRT, array, sys, re, html, string, csv, inspect, time
from datetime import date
from collections import OrderedDict
from packaging import version

today = date.today()
strDateTime = str(today.strftime("%b-%d-%Y"))

t1 = time.perf_counter()

class StringAttribute:
    """A class representing a string attribute."""
    
    def __init__(self, value):
        self.value = value

    def __get__(self, instance, owner):
        return self.value

    def __set__(self, instance, value):
        if not isinstance(value, str):
            value = str(value)
        self.value = value


class Stig:
    """A class representing a STIG check."""
    
    vulid = StringAttribute("V-111111")
    devicetype = StringAttribute("undefined")
    finding = StringAttribute("undefined")
    status = StringAttribute("Open")
    severity = StringAttribute("default")
    comments = StringAttribute("")


class Command:
    """A class representing a command."""
    
    command = StringAttribute("undefined")
    output = StringAttribute("undefined")
    devicename = StringAttribute("undefined")
    status = StringAttribute("0")


class IntStatus:
    """A class representing an interface status."""
    
    interface = StringAttribute("undefined")
    description = StringAttribute("undefined")
    vlan = StringAttribute("undefined")


class CommandCache:
    """A class representing a command cache."""
    
    def __init__(self):
        self.cache = {}

    def add(self, device_name, command, output):
        self.cache[(device_name, command)] = output

    def get(self, device_name, command):
        return self.cache.get((device_name, command))


command_cache = CommandCache()


#sample of vul check functions, there are over 80 or more of this type of function START#
def V220518(devicetype, devicename):
    # Legacy IDs: V-101369; SV-110473
    # V-220518 - CAT II - The Cisco switch must be configured to limit the number of concurrent management sessions to an organization-defined number.
    check = Stig()
    # The vulnerability ID MUST match what the stig file has.  We're going to search the .ckl for it.
    check.vulid = format_vulid()
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
        check.comments = "V-220518 - NA - Catalyst 9300 switches no longer have the session-limit command."
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
    check.vulid = format_vulid()
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
    check.vulid = format_vulid()
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
    check.vulid = format_vulid()
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

def read_function_names(filename):
    with open(filename, "r") as file:
        reader = csv.reader(file)
        # Skip the header
        next(reader, None)
        # Get the first element from each row
        return [row[0] for row in reader if row]


def send_command(command, device_name):
    if device_name.find(".") > -1:
        prompt = "#"
    else:
        prompt = device_name + "#"
    crt.Screen.WaitForStrings([prompt], 1)
    crt.Screen.Send(command + "\r")
    return crt.Screen.ReadString(prompt, 30)


def handle_errors(result, command, device_name):
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

    return result


def exec_command(command, device_name):
    output = command_cache.get(device_name, command)

    if output is None:
        result = send_command(command, device_name)
        result = handle_errors(result, command, device_name)

        if "." in device_name:
            output = result.strip().replace(device_name, "")
        else:
            output = f"{device_name}#{result.replace('\r', '')}{device_name}#"

        if "Invalid" not in output:
            command_cache.add(device_name, command, output)

    return output



def load_template(template_name):
    with open(
        strFilePath + template_name, "r", encoding="utf-8"
    ) as objStigTemplateFile:
        return objStigTemplateFile.read()


def open_hosts_file():
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


def connect_to_host(strHost):
    # Define the connection string and terminal settings
    connect_string = f"/SSH2 /ACCEPTHOSTKEYS /Z 4 {strHost}"
    term_len = "term len 0"
    term_width = "term width 400"

    try:
        # Attempt to connect to the host
        crt.Session.Connect(connect_string, False)
    except ScriptError:
        # Log any errors that occur during connection
        error = crt.GetLastErrorMessage()
        log_file.write(f"Error accessing host {strHost} {error}\r")

    if crt.Session.Connected:
        crt.Screen.Synchronous = True
        crt.Screen.WaitForStrings(["#", ">"], 15)
        exec_command(f"{term_len}\r", strHost)
        crt.Screen.WaitForStrings(["#", ">"], 15)
        exec_command(f"{term_width}\r", strHost)

        # Get the device name from the current screen
        device_name = crt.Screen.Get(crt.Screen.CurrentRow, 0, crt.Screen.CurrentRow, crt.Screen.CurrentColumn - 2).replace("#", "")
        return device_name, device_name
    else:
        return None, None




def process_host(host, stig_template, log_file):
    host = host.strip()
    device_type = "IOS"
    stig_list = []
    stig_vul_list_file = "stig_vul.csv"
    stig_vul_list = read_function_names(strFilePath + stig_vul_list_file)

    if host and "#" not in host:
        ckl = stig_template
        device_name, _ = connect_to_host(host)
        if device_name:
            for func_name in stig_vul_list:
                func = globals()[func_name]
                stig_list.append(func(device_type, device_name.strip()))

            for obj in stig_list:
                ckl = log_check_results(obj, ckl, host, device_name, device_name, log_file)

            ckl = ckl.replace("<HOST_NAME>", str(device_name), 1)
            ckl = ckl.replace("<HOST_IP>", str(host), 1)
            ckl_file = f"{device_name}_{strDateTime}.ckl"

            with open(strFilePath + ckl_file, "w", encoding="utf-8") as objCKLFile:
                objCKLFile.write(ckl)

    crt.Session.Disconnect()




def log_check_results(obj, ckl, host, device_name, common_name, log_file):
    finding_details = html.escape(obj.finding).replace("\b", " ")
    comments = html.escape(obj.comments)

    log_file.write(
        f"{strDateTime},{host},{common_name.strip()},{device_name.strip()},{obj.vulid},{obj.status},\"{finding_details}\",\"{comments}\",,\n"
    )

    index = ckl.find(obj.vulid)
    if index > -1:
        status_index = ckl.find("<STATUS>", index) + len("<STATUS>")
        finding_details_index = ckl.find("<FINDING_DETAILS>", index) + len("<FINDING_DETAILS>")
        comments_index = ckl.find("<COMMENTS>", index) + len("<COMMENTS>")

        ckl = ckl[:status_index] + obj.status + ckl[status_index + len("Not_Reviewed"):]
        ckl = ckl[:finding_details_index] + finding_details + ckl[finding_details_index:]
        ckl = ckl[:comments_index] + comments + ckl[comments_index:]

    return ckl



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