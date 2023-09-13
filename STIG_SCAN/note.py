'''
The function "proccess_ host" and "update_ckl_template" in "STIG_12_J.py" work with a ckl file that is in XML format
Disa is changing from an xml format to a JSON format with STIG viewer 3.0
I have created a black .cklb (new Json format) file that is replaceing the .ckl file xml file
its called "New Checklist.cklb"
To see how the JSON file looks I made a script called "Json_to_Txt.py" that puts the Json tree in a reable format for me to understand
These files are in the STIG_SCAN folder
How would I update the "process_host" and "update_ckl_template" functions to work with the new JSON format?
can you write an updated version of the "process_host" and "update_ckl_template" functions that work with the new JSON format?
'''

'''
base off the info below and in our direcotry can you update the "process_host" and "update_ckl_template" to do the correct updates to the 
Json file "New Checklist.cklb"?
Below are the functions that need to be updated
'''

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