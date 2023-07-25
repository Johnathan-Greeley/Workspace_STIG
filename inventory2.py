# $language = "Python3"
# $interface = "1.0"

import os, platform, time, re, errno, csv, SecureCRT, string, html

#html
# import os
# import re
# import csv
# import crt
# import securecrt_tools

def main():
    # Read IP addresses from a text file
    script_dir = os.path.dirname(os.path.realpath(__file__))
    devices_file = os.path.join(script_dir, 'devices.txt')

    with open(devices_file, 'r') as f:
        devices = [line.strip() for line in f]

    # Create the CSV file in the same directory as the script
    inventory_file = os.path.join(script_dir, 'inventory.csv')

    with open(inventory_file, 'w', newline='') as csvfile:
        fieldnames = ['location', 'SN', 'model', 'IOS', 'hostname', 'IP', 'output', 'notes']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for device in devices:
            crt.Session.Connect("/SSH2 {}".format(device))
            crt.Screen.Send('terminal length 0\n')
            crt.Screen.WaitForString("#", 30)
            crt.Screen.Send('show version\n')
            crt.Screen.WaitForString("#", 30)
            output = crt.Screen.ReadString('#')

            # Parse the output
            sn, model, ios, hostname = parse_show_version(output)

            # Write the inventory information to the CSV file
            writer.writerow({
                'SN': sn,
                'model': model,
                'IOS': ios,
                'hostname': hostname,
                'IP': device,
                'output': "",
                'notes': ""
            })

            crt.Session.Disconnect()

def parse_show_version(output):
    sn_regex = r"Processor board ID (\S+)"
    model_regex = r"Model Number\s+:\s+(\S+)"
    ios_regex = r"Cisco IOS Software.*Version (\d+\.\d+\.\d+)"
    hostname_regex = r"^(\S+) uptime is"

    sn_match = re.search(sn_regex, output, re.MULTILINE)
    model_match = re.search(model_regex, output, re.MULTILINE)
    ios_match = re.search(ios_regex, output, re.MULTILINE)
    hostname_match = re.search(hostname_regex, output, re.MULTILINE)

    sn = sn_match.group(1) if sn_match else "N/A"
    model = model_match.group(1) if model_match else "N/A"
    ios = ios_match.group(1) if ios_match else "N/A"
    hostname = hostname_match.group(1) if hostname_match else "N/A"

    return sn, model, ios, hostname

main()
