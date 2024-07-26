# prism-report-xlsx-import
This script is meant to help move data from Rootshell's Prism application. In Prism, data is broken down into Companies, Projects, and Phases. This is similar to Plextrac's Clients and Reports. This similarity makes the simpler, but note that this script will turn each phase from Prism into an individual report in Plextrac.

The file input for this script comes from the report XLSX export in Prism. Within a specific Project you can click export results and select Excel. This creates the XLSX file that can be parsed by this script. This does mean you will have to download each Project you want to add into Plextrac individually.

Once the file is downloaded from Prism this script can parse it into the data structure that Plextrac can handle importing. This script will only convert Prism's XLSX file into a PTRAC file that Plextrac can import.

This script can be used with 2 purposes in mind. Moving a single report, or migrating all report data from Prism to Plextrac. The script supports the input of a single XLSX file or a folder path to a directory containing multiple XLSX files from Prism. If you only need to move a single report, the generated PTRAC can be imported directly into the client you want to move the report to in the Plextrac platform. If you are doing a bulk migration of data you can use our [instance-data-backup-migration](https://github.com/PlexTrac-Labs/instance-data-backup-migration) script to bulk import all the generated PTRACs into Plextrac at once. In the instance-data-backup-migration script you will use the Reports workflow and bulk select all the PTRACs to import.

# Requirements
- [Python 3+](https://www.python.org/downloads/)
- [pip](https://pip.pypa.io/en/stable/installation/)
- [pipenv](https://pipenv.pypa.io/en/latest/install/)

# Installing
After installing Python, pip, and pipenv, run the following commands to setup the Python virtual environment.
```bash
git clone this_repo
cd path/to/cloned/repo
pipenv install
```

# Setup
After setting up the Python environment, you will need to setup a few things before you can run the script.

## CSV with Data to Import
In the `config.yaml` file you should add the file path to the CSV with data you're trying to import.

## Credentials
In the `config.yaml` file you should add the full URL to your instance of Plextrac.

The config also can store your username and password. Plextrac authentication lasts for 15 mins before requiring you to re-authenticate. The script is set up to do this automatically. If these 3 values are set in the config, and MFA is not enable for the user, the script will take those values and authenticate automatically, both initially and every 15 mins. If any value is not saved in the config, you will be prompted when the script is run and during re-authentication.

## Report Template & Findings Layout
In the `config.yaml` file you can add the name of an existing Report Template and Findings Layout. If these values are present, it will verify the template exists and link it to all reports created. Upon navigating to the Report Details tab of a report, you will see the respective dropdown pre-populated.

In the platform there can be duplicate names for report templates and findings layouts. For this script to know which template you want to add, there can only be a single template with the same name you added to the config file.

## API Version
The Api Version of the Plextrac instance you plan to import .ptrac files to is required for successful .ptrac generation. The API Version can be found at the bottom right of the Account Admin page in Plextrac. This value can be entered in the `config.yaml` file.

# Usage
After setting everything up you can run the script with the following command. You should be in the folder where you cloned the repo when running the following.
```bash
pipenv run python main.py
```
You can also add values to the `config.yaml` file to simplify providing the script with the data needed to run. Values not in the config will be prompted for when the script is run.

## Required Information
The following values can either be added to the `config.yaml` file or entered when prompted for when the script is run.
- PlexTrac Top Level Domain e.g. https://yourapp.plextrac.com
- Username
- Password
- MFA Token (if enabled)
- API version
- File path to Prism XLSX containing data to import
    OR
- Folder path to directory containing multiple Prism XLSX files

## Script Execution Flow
When the script starts it will load in config values and try to:
- Authenticates user
- Read and verify XLSX data

Once this setup is complete it will start looping through each `Vulnerability` in the XLSX and try to:
- Determine which client the row belongs to based on the `Company Name`
- Determine which report the row belongs to based on the `Phase Name`
- Add all report information if creating a new report
- Create a new finding and add all finding information

After parsing the XLSX, a .ptrac file will be generated. Generated .ptrac files can be imported into a client in Plextrac to create a new report that includes all report information that was parsed from the file. You can also import a .ptrac into an existing report in Plextrac to import the findings it contains.

## Logging
The script is run in INFO mode so you can see progress on the command line. A log file will be created when the script is run and saved to the root directory where the script is. You can search this file for "WARNING", "EXCEPTION, or "ERROR" to see if something did not get parsed or imported correctly. Any critical level issue will stop the script immediately.
