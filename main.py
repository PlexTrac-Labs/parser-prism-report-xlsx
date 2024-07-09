from operator import itemgetter
from typing import Union, List
import yaml
import json

import utils.log_handler as logger
log = logger.log
import settings
from utils.auth_handler import Auth
from csv_parser import CSVParser
import utils.input_utils as input
from utils.input_utils import LoadedCSVData, LoadedJSONData
import api


# determines type of script execution
# can either take in a dynamic header CSV file that determines data mapping outside script
# otherwise can have static mapping defined in script
predefined_csv_headers_mapping = False


def handle_load_api_version(api_version: str, parser: CSVParser) -> None:
    if api_version == "":
        api_version = input.prompt_user(f'The Api Version of the PT instance you want to import a .ptrac to is required for successful generation.\nEnter the API Version of your instance. This can be found at the bottom right of the Account Admin page in PT')
    if len(api_version.split(".")) == 3:
        parser.doc_version = api_version
        return
    else:
        if input.retry(f'The entered value {api_version} was not a valid version'):
            return handle_load_api_version("", parser)
    

def load_header_file(headers_file_path:str = "") -> LoadedCSVData:
    return input.load_csv_data("Enter file path to the CSV mapping headers to Plextrac data types", csv_file_path=headers_file_path)


def verify_header_file(loaded_file_data: LoadedCSVData, csv_parser: CSVParser) -> bool:
    # TEMPLATE - checks that the loaded file is valid for the script
    return True


def load_data_file(data_file_path:str = "") -> LoadedCSVData:
    # TEMPLATE - change based on script need and data file type
    return input.load_csv_data("Enter file path to CSV data to import", csv_file_path=data_file_path)


def verify_data_file(loaded_file_data: LoadedCSVData, csv_parser: CSVParser) -> bool:
    # TEMPLATE - checks that the loaded file is valid for the script - correct report fields - has findings - correct finding fields
    
    # has correct field/headers
    if loaded_file_data.headers != csv_parser.get_csv_headers():
        log.warning(f'CSV headers read from file\n{loaded_file_data.headers}')
        log.warning(f'Expected headers\n{csv_parser.get_csv_headers()}')
        return False
    
    # has findings
    if len(loaded_file_data.data) < 1:
        log.error(f'Did not find any findings in loaded data file')
        return False
    
    return True


# # duplicate of load data and verify data functions
# def handle_load_csv_data_verify(path, parser: CSVParser):
#     """
#     takes a filepath to a csv, and a list of expected headers and returned the csv data if the headers match
#     used as basic error checking that we have the correct csv
#     """
#     csv = input.load_csv_data("Enter file path to CSV data to import", csv_file_path=path)

#     if csv.headers != parser.get_csv_headers():
#         log.warning(f'CSV headers read from file\n{csv.headers}')
#         log.warning(f'Expected headers\n{parser.get_csv_headers()}')
#         if input.retry(f'Loaded {csv.file_path} CSV headers don\'t match headers in Headers Mapping CSV.'):
#             return handle_load_csv_data_verify("Enter file path to CSV data to import", "", parser.get_csv_headers())

#     parser.csv_data = csv.data
#     log.success(f'Loaded csv data')


def load_parser_mappings_from_header_file(csv: LoadedCSVData, parser: CSVParser):
    csv_headers_mapping = {}

    for index, header in enumerate(csv.headers):
        mapping_key = csv.data[0][index]
        if mapping_key in parser.get_data_mapping_ids():
            csv_headers_mapping[header] = {
                "header": header,
                "mapping_key": mapping_key,
                "col_index": index
            }
            continue
        
        if mapping_key == "":
            csv_headers_mapping[header] = {
                "header": header,
                "mapping_key": "no_mapping",
                "col_index": index
            }
        else:
            if input.continue_anyways( f'ERR: Key <{mapping_key}> selected for header <{header}> is not an valid key'):
                csv_headers_mapping[header] = {
                    "header": header,
                    "mapping_key": "no_mapping",
                    "col_index": index
                }
            else:
                exit()

    parser.csv_headers_mapping = csv_headers_mapping
    log.success(f'Loaded csv headers mapping')
    
    
def load_parser_mappings_from_data_file(csv: List[list], parser: CSVParser) -> bool:
    # setup JSON finding keys/headers into CSVParser > csv_headers_mapping dict
    headers = csv[0]

    for index, header in enumerate(headers):
        if index == 0: # handle the BOM char added to the beginning of the CSV IF it exists
            if "Title" in header and header != "Title":
                header = header[1:]
        key = parser.get_mapping_key_from_header(header)
        if key in parser.get_data_mapping_ids():
            if parser.csv_headers_mapping[header].get("matched") == None: # if there are dup column headers, use the first col found and don't override when looking at the dup
                parser.csv_headers_mapping[header]["col_index"] = index
                parser.csv_headers_mapping[header]["matched"] = True
        else:
            log.error( f'Do not have mapping object created for header <{header}>. Check csv_parser.py > csv_headers_mapping_template to add. Marking as \'no_mapping\'')

    log.success(f'Loaded column headings from temp CSV')
    return True


def create_temp_data_csv(loaded_file_data) -> List[list]:
    # determine temp CSV headers - TODO add more than just finding headers
    finding_keys = list(loaded_file_data['Vulnerabilities'][0].keys())
    temp_csv = []
    temp_csv.append(finding_keys)
    
    for vuln in loaded_file_data['Vulnerabilities']:
        # seed finding with number of possible columns determined from number of keys
        finding = []
        for i in range(len(finding_keys)):
            finding.append("")
        # parse vuln fields from JSON of finding, and add to list
        for key, value in vuln.items():
            index = finding_keys.index(key) if key in finding_keys else None
            if index != None:
                if key == "References":
                    new_value = ""
                    for item in value:
                        new_value = f'{new_value}\n{item}'
                    new_value = new_value[1:]
                    finding.insert(index, new_value)
                    finding.pop(index+1)
                elif key == "Cvss":
                    new_value = value['Score']
                    finding.insert(index, new_value)
                    finding.pop(index+1)
                else:
                    finding.insert(index, value)
                    finding.pop(index+1)
        # add parsed list of finding fields to CSV
        temp_csv.append(finding)

    # with open("temp_csv.csv",'w', newline="") as file:
    #     writer = csv.writer(file)
    #     writer.writerows(temp_csv)
    
    return temp_csv


def load_data_into_parser(csv: List[list], parser: CSVParser):
    parser.csv_data = csv[1:]
    log.success(f'Loaded data from temp CSV')
    return True


def handle_add_report_template_name(report_template_name, parser: CSVParser):
    """
    Checks if the given the report_template_name value from the config.yaml file matches the name of an existing
    Report Template in Plextrac. If the template exists in platform, adds this report template UUID to the template
    for reports created with this script. The result being a Report Template is selected in the proper dropdown
    in platform for all reports created.
    """
    report_templates = []

    try:
        response = api._templates.report_templates.list_report_templates(auth.base_url, auth.get_auth_headers(), auth.tenant_id)
    except Exception as e:
        log.exception(e)
    if type(response.json) == list:
        report_templates = list(filter(lambda x: x['data']['template_name'] == report_template_name, response.json))

    if len(report_templates) > 1:
        if not input.continue_anyways(f'report_template_name value \'{report_template_name}\' from config matches {len(report_templates)} Report Templates in platform. No Report Template will be added to reports.'):
            exit()
        return

    if len(report_templates) == 1:
        parser.report_template['template'] = report_templates[0]['data']['doc_id']
        return
    
    if not input.continue_anyways(f'report_template_name value \'{report_template_name}\' from config does not match any Report Templates in platform. No Report Template will be added to reports.'):
        exit()


def handle_add_findings_template_name(findings_template_name, parser: CSVParser):
    """
    Checks if the given the findings_template_name value from the config.yaml file matches the name of an existing
    Finding Layouts in Plextrac. If the layout exists in platform, adds this findings template UUID to the template
    for reports created with this script. The result being a Finding Layout is selected in the proper dropdown
    in platform for all reports created.
    """
    findings_templates = []

    try:
        response = api._templates.findings_templateslayouts.list_findings_templates(auth.base_url, auth.get_auth_headers())
    except Exception as e:
        log.exception(e)
    if type(response.json) == list:
        findings_templates = list(filter(lambda x: x['data']['template_name'] == findings_template_name, response.json))

    if len(findings_templates) > 1:
        if not input.continue_anyways(f'findings_template_name value \'{findings_template_name}\' from config matches {len(findings_templates)} Finding Layouts in platform. No Findings Layout will be added to reports.'):
            exit()
        return

    if len(findings_templates) == 1:
        parser.report_template['fields_template'] = findings_templates[0]['data']['doc_id']
        return
    
    if not input.continue_anyways(f'findings_template_name value \'{findings_template_name}\' from config does not match any Finding Layouts in platform. No Finding Layout will be added to reports.'):
        exit()



if __name__ == '__main__':
    for i in settings.script_info:
        print(i)
    
    with open("config.yaml", 'r') as f:
        args = yaml.safe_load(f)

    auth = Auth(args)
    auth.handle_authentication()

    # create parser instance
    parser = CSVParser()
    log.info(f'---Starting data loading---')
    api_version = ""
    if args.get('api_version') != None and args.get('api_version') != "":
        api_version = str(args.get('api_version'))
        log.info(f'Set API Version to \'{api_version}\' from config...')
    handle_load_api_version(api_version, parser)

    # switch 1: header file
    if not predefined_csv_headers_mapping:
        log.info(f'Running script with additional CSV Headers file...')
        
        # get header file_path
        csv_headers_file_path = ""
        if args.get('csv_headers_file_path') != None and args.get('csv_headers_file_path') != "":
            csv_headers_file_path = args.get('csv_headers_file_path')
            log.info(f'Using csv header file path \'{csv_headers_file_path}\' from config...')

        # load header file
        loaded_file = load_header_file(csv_headers_file_path)

        # verify header file
        if not verify_header_file(loaded_file, parser):
            exit()

        # load headers into parser
        load_parser_mappings_from_header_file(loaded_file, parser)

    # switch 2: no header file - mapping already in parser, just need to find columns

        # get data file_path

        # load file

        # verify file

        # create temp csv header file

        # verify headers in file

        # load temp headers file into parser
    
    # process data file

        # get data file path
    csv_data_file_path = ""
    if args.get('csv_data_file_path') != None and args.get('csv_data_file_path') != "":
        csv_data_file_path = args.get('csv_data_file_path')
        log.info(f'Using csv data file path \'{csv_data_file_path}\' from config...')
    
        # load data file
    loaded_file = load_data_file(csv_data_file_path)

        # verify data file
    if not verify_data_file(loaded_file, parser):
        exit()

        # load data into parser instance
    load_data_into_parser(loaded_file.csv, parser)

    # handle report templates
    report_template_name = ""
    if args.get('report_template_name') != None and args.get('report_template_name') != "":
        report_template_name = args.get('report_template_name')
        log.info(f'Using report template \'{report_template_name}\' from config...')
        handle_add_report_template_name(report_template_name, parser)

    # handle finding layouts
    findings_layout_name = ""
    if args.get('findings_layout_name') != None and args.get('findings_layout_name') != "":
        findings_layout_name = args.get('findings_layout_name')
        log.info(f'Using findings layout \'{findings_layout_name}\' from config...')
        handle_add_findings_template_name(findings_layout_name, parser)

    # parser data
    if not parser.parse_data():
        exit()

    # print result
    parser.display_parser_results()

    # save file
    if input.continue_anyways(f'IMPORTANT: Data will be imported into Plextrac.\nPlease view the log file generated from parsing to see if there were any errors.\nIf the data was not parsed correctly, please exit the script, fix the data, and re-run.\nThis will import data into {len(parser.clients)} client(s). The more clients you have the harder it will be to undo this import.'):
        parser.import_data(auth)
        log.info(f'Import Complete. Additional logs were added to {log.LOGS_FILE_PATH}')

    if input.continue_anyways(f'IMPORTANT: Data will be saved to Ptrac(s).\nYou can save each parsed report as a Ptrac. You cannot import client data from a Ptrac.\nWould you like to create and save a Ptrac for {len(parser.reports)} report(s).'):
        parser.save_data_as_ptrac()
        log.info(f'Ptrac(s) creation complete. File(s) can be found in \'exported-ptracs\' folder. Additional logs were added to {log.LOGS_FILE_PATH}')
