import json
import os

def print_json_tree(data, file, indent=0, parent_key=None):
    if isinstance(data, dict):
        for key, value in data.items():
            if key in ["fix_text", "rule_title", "group_title", "check_content", "discussion"]:
                file.write('  ' * indent + f'{key}: ***REMOVED***\n')
            else:
                file.write('  ' * indent + f'{key}:\n')
                print_json_tree(value, file, indent + 1, key)
    elif isinstance(data, list):
        for idx, item in enumerate(data):
            file.write('  ' * indent + f'[{idx}]:\n')
            print_json_tree(item, file, indent + 1)
    else:
        if parent_key not in ["fix_text", "rule_title", "group_title"]:
            file.write('  ' * indent + f'{data}\n')

def main():
    input_file = 'New Checklist.cklb'
    output_file = 'json-tree.txt'

    # Check if the input file exists
    if not os.path.exists(input_file):
        print(f"Error: {input_file} does not exist in the current directory!")
        return

    # Try to read the JSON file
    try:
        with open(input_file, 'rb') as file:
            # Decoding using utf-8 and replacing any problematic characters
            file_content = file.read().decode('utf-8', 'replace')
            data = json.loads(file_content)
    except json.JSONDecodeError:
        print(f"Error: {input_file} contains invalid JSON!")
        return
    except Exception as e:
        print(f"Error reading {input_file}: {e}")
        return

    # Try to print the JSON tree structure to an output text file
    try:
        with open(output_file, 'w') as file:
            print_json_tree(data, file)
        print(f"Tree structure written to {output_file}!")
    except Exception as e:
        print(f"Error writing to {output_file}: {e}")

if __name__ == '__main__':
    main()
