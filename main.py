from operator import itemgetter
from typing import Union, List
import yaml
import json
import os

import openpyxl

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
# otherwise can have static mapping defined in script, but only works for a single type of data file
predefined_csv_headers_mapping = True


def handle_load_api_version(api_version:str, parser:CSVParser) -> None:
    """
    Handles prompting the user and setting the API version in the CSVParser. This is required for PTRAC generation.

    :param api_version: version of Plextrac instance a generated PTRAC will be importing into
    :type api_version: str
    :param parser: instance of CSVParser
    :type parser: CSVParser
    """
    if api_version == "":
        api_version = input.prompt_user(f'The Api Version of the PT instance you want to import a .ptrac to is required for successful generation.\nEnter the API Version of your instance. This can be found at the bottom right of the Account Admin page in PT')
    if len(api_version.split(".")) == 3:
        parser.doc_version = api_version
        return
    else:
        if input.retry(f'The entered value {api_version} was not a valid version'):
            return handle_load_api_version("", parser)


def load_data_file(data_file_path:str = "") -> LoadedCSVData:
    """
    Loads the file containing data to be imported in the script

    Loads and converts XLSX file into CSV like data. There is no formatting that needs to be preserved in the XLSX.

    :param data_file_path: filepath to file containing data to import, defaults to ""
    :type data_file_path: str, optional - will prompt user if filepath is not supplied
    :return: raw data loaded from file
    :rtype: LoadedCSVData
    """
    if data_file_path == "":
        data_file_path = input.prompt_user("Enter file path to Prism report XLSX file" + " (relative file path, including file extension)")

    if not os.path.exists(data_file_path):
        if input.retry(f'Specified file \'{data_file_path}\' does not exist.'):
            return load_data_file()

    try:
        workbook = openpyxl.load_workbook(data_file_path, data_only=True)
        sheet = workbook.active

        data = []
        for row in sheet.iter_rows(values_only=True):
            data.append(list(row))

        csv_headers = data[0]
        csv_data = data[1:]

        return LoadedCSVData(file_path=data_file_path, csv=data, headers=csv_headers, data=csv_data)

    except Exception as e:
        if input.retry(f'Error loading file: {e}'):
            return load_data_file()    


def verify_data_file(loaded_file_data:LoadedCSVData, csv_parser:CSVParser) -> bool:
    """
    Checks that the loaded data file is valid for the script
    
    TEMPLATE
    When using this script as a base template, can add custom validation to make sure the data file is valid
    - correct report fields
    - correct finding fields
    - file contains findings

    :param loaded_file_data: object of returned loaded data from `load_data_file()`
    :type loaded_file_data: LoadedCSVData if CSV, LoadedJSONData if Json, custom object if another filetype
    :param csv_parser: instance of CSVParser - used to validate against data mapping loaded in the `csv_headers_mapping_template` dict in the CSVParser
    :type csv_parser: CSVParser
    :return: whether the file is valid
    :rtype: bool
    """    
    # has correct field/headers
    if loaded_file_data.csv[0][0] != "Phase Name:" and loaded_file_data.csv[8][0] != "Phase Status:":
        log.error(f'File does not have Project and Phase data. Is this a valid Prism Report XLSX export?')
        return False
    
    if loaded_file_data.csv[11][0:24] != parser.get_csv_headers()[6:]:
        log.error(f'File does not have correct Vulnerability headers. Is this a valid Prism Report XLSX export?')
        log.warning(f'Headers read from file\n{loaded_file_data.csv[11][0:24]}')
        log.warning(f'Expected headers\n{csv_parser.get_csv_headers()}')
        return False

    # has findings
    if len(loaded_file_data.data) < 13:
        log.error(f'Did not find any findings in loaded Prism Report XLSX file')
        return False
    
    return True
    
    
def load_parser_mappings_from_data_file(csv:List[list], parser:CSVParser) -> bool:
    """
    There are 2 cases of loading mapping data in CSVParser based on `predefined_csv_headers_mapping`
    1) `csv_headers_mapping_template` dict in the CSVParser is empty
    2) `csv_headers_mapping_template` dict in the CSVParser is pre-populated and only needs to have indexes matched

    Function for case 2:
    Data mapping will be parsed from a temp CSV file. This CSV file is generated in `create_temp_data_csv()` to emulate
    the additional headers CSV file that could be used in the script
    
    For each mapping a pre-existing object in `csv_headers_mapping_template` will be updated. This method of not predefining
    the `col_index` allows the mapping to be defined in the script, but the order of columns on the CSV can still be variable.

    :param csv: array with 2 arrays - 2 row generated temp CSV with headers on row 1 and mapping keys on row 2
    :type csv: List[list] - [List[headers], List[mapping_keys]]
    :param parser: instance of CSVParser that data mapping will be loaded into
    :type parser: CSVParser
    :return: did the function update `predefined_csv_headers_mapping` objects - will still return True if some keys were invalid
    :rtype: bool
    """
    # CUSTOM updating CSVParser > csv_headers_mapping dict based on custom generated temp CSV file
    # setup JSON finding keys/headers into CSVParser > csv_headers_mapping dict
    headers = csv[0]

    for index, header in enumerate(headers):
        mapping_key = parser.get_mapping_key_from_header(header)
        if mapping_key in parser.get_data_mapping_ids():
            if parser.csv_headers_mapping[header].get("matched") == None: # if there are dup column headers, use the first col found and don't override when looking at the dup
                parser.csv_headers_mapping[header]["col_index"] = index
                parser.csv_headers_mapping[header]["matched"] = True
        else:
            log.error(f'Invalid mapping key \'{mapping_key}\' for header \'{header}\'. Check csv_parser.py > csv_headers_mapping_template to correct or add. Marking as \'no_mapping\'')
            parser.csv_headers_mapping[header]["mapping_key"] = "no_mapping"

    log.success(f'Loaded column headings from temp CSV')
    return True


def create_temp_data_csv(loaded_file_data:LoadedCSVData, parser:CSVParser) -> List[list]:
    """
    To be able to handle non CSV data files, this function converts the inputted data file into
    a temp CSV that can be handled by CSVParser.

    TEMPLATE
    When using this script as a base template, can customize this function to create a CSV like
    list from the data file the script needs to parse.

    :param loaded_file_data: object of returned loaded data from `load_data_file()`
    :type loaded_file_data: LoadedCSVData
    :param parser: instance of CSVParser that data will be loaded into
    :type parser: CSVParser
    :return: temp generated CSV
    :rtype: List[list]
    """
    temp_csv = []

    # determine temp CSV headers - client, report, finding, and asset headers
    headers = parser.get_csv_headers()
    temp_csv.append(headers)

    # non finding properties
    project_number = loaded_file_data.csv[2][1]
    project_status = loaded_file_data.csv[4][1]
    start_date = loaded_file_data.csv[5][1]
    end_date = loaded_file_data.csv[6][1]
    leader_tester = loaded_file_data.csv[7][1]
    phase_status = loaded_file_data.csv[8][1]

    # get finding info
    finding_only_data = loaded_file_data.csv[12:]
    for finding in finding_only_data:
        row = []

        # add non finding properties info
        row.append(project_number)
        row.append(project_status)
        row.append(start_date)
        row.append(end_date)
        row.append(leader_tester)
        row.append(phase_status)
        
        # parse finding fields from data file
        for value in finding:
            row.append(value)

        # add parsed list of fields to CSV
        temp_csv.append(row)

    # DEBUG - save generated CSV to file
    # with open("temp_csv.csv",'w', newline="") as file:
    #     writer = csv.writer(file)
    #     writer.writerows(temp_csv)
    
    return temp_csv


def load_data_into_parser(csv:List[list], parser:CSVParser) -> None:
    """
    Loads CSV like data into the instance of the CSVParser that will parser and transform the data into a format that Plextrac can import.

    CSV data file or temp generated CSV data file to import data from

    :param csv: CSV like data to import data from
    :type csv: List[list]
    :param parser: instance of CSVParser to load data into
    :type parser: CSVParser
    """
    parser.csv_data = csv[1:]
    log.success(f'Loaded data into parser instance')


def handle_add_report_template_name(report_template_name:str, parser:CSVParser) -> None:
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


def handle_add_findings_template_name(findings_template_name:str, parser:CSVParser) -> None:
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

    # get header file_path
    csv_headers_file_path = ""
    if args.get('csv_headers_file_path') != None and args.get('csv_headers_file_path') != "":
        csv_headers_file_path = args.get('csv_headers_file_path')
        log.info(f'Using csv header file path \'{csv_headers_file_path}\' from config...')

    # get data file path
    csv_data_file_path = ""
    if args.get('csv_data_file_path') != None and args.get('csv_data_file_path') != "":
        csv_data_file_path = args.get('csv_data_file_path')
        log.info(f'Using csv data file path \'{csv_data_file_path}\' from config...')

    # create parser instance
    parser = CSVParser()
    log.info(f'---Starting data loading---')
    api_version = ""
    if args.get('api_version') != None and args.get('api_version') != "":
        api_version = str(args.get('api_version'))
        log.info(f'Set API Version to \'{api_version}\' from config...')
    handle_load_api_version(api_version, parser)

    # switch 2: no header file - mapping already in parser, just need to find columns
    if predefined_csv_headers_mapping:
        log.info(f'Running script for Prism Report XlSX file export (data mapping defined in script)...')

        # load file
        loaded_file = load_data_file(csv_data_file_path)

        # verify file
        if not verify_data_file(loaded_file, parser):
            exit()

        # create temp csv data file
        temp_csv = create_temp_data_csv(loaded_file, parser)

        # load temp CSV file headers into parser
        load_parser_mappings_from_data_file(temp_csv, parser)
    
        # load temp CSV file data into parser
        load_data_into_parser(temp_csv, parser)

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
    if input.continue_anyways(f'IMPORTANT: Data will be saved to Ptrac(s).\nYou can save each parsed report as a Ptrac. You cannot import client data from a Ptrac.\nWould you like to create and save a Ptrac for {len(parser.reports)} report(s).'):
        parser.save_data_as_ptrac()
        log.info(f'Ptrac(s) creation complete. File(s) can be found in \'exported-ptracs\' folder. Additional logs were added to {log.LOGS_FILE_PATH}')
