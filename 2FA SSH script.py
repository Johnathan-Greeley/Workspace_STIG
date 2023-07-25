import csv
import time
import logging
import paramiko
from getpass import getpass
from ciscoconfparse import CiscoConfParse
from netmiko import ConnectHandler
import concurrent.futures
import datetime

logging.basicConfig(filename='network_log.log', level=logging.INFO)

# Load private key
with open('path_to_your_private_key', 'r') as key_file:
    private_key = paramiko.RSAKey.from_private_key(key_file)

# Read CSV file
with open('devices.csv', 'r') as file:
    devices = csv.reader(file)

# Function to backup router configuration
def backup_rtr_configuration(row):
    ip, auth_type = row
    ios_device_info = {
        "device_type": "cisco_ios",
        "ip": ip,
        "username": username,
        "password": password,
        "pkey": private_key if auth_type == '2FA' else None,
        "verbose": True,
    }
    try:
        start_time = time.time()
        ssh_connection = ConnectHandler(**ios_device_info)
    except Exception as e:
        logging.error(f'Failed to connect to {ip} with 2FA: {e}')
        ios_device_info['pkey'] = None  # Remove private key to try with username and password
        try:
            ssh_connection = ConnectHandler(**ios_device_info)
        except Exception as e:
            logging.error(f'Failed to connect to {ip} with username and password: {e}')
            return
    for cmd in show_commands:
        output = ssh_connection.send_command(cmd)
        # Parse the output
        parse = CiscoConfParse(output.splitlines())
        for obj in parse.find_objects(r'^interface'):
            print(obj.text)
            for child in obj.children:
                print(child.text)
    end_time = time.time()
    logging.info(f'Successfully connected to {ip} in {end_time - start_time} seconds.')
    ssh_connection.disconnect()

# Multithreading
with concurrent.futures.ThreadPoolExecutor() as executor:
    executor.map(backup_rtr_configuration, devices)

print(f'The script finished executing in {round(time.time()-start_time, 2)} seconds.')
