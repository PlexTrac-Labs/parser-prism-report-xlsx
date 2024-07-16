import logging


# LOGGING
console_log_level = logging.INFO
file_log_level = logging.INFO
save_logs_to_file = True

# REQUESTS
# if the Plextrac instance is running on https without valid certs, requests will respond with cert error
# change this to false to override verification of certs
verify_ssl = True
# number of times to retry a request before throwing an error. will only throw the last error encountered if
# number of retries is exceeded. set to 0 to disable retrying requests
retries = 0

# description of script that will be print line by line when the script is run
script_info = ["====================================================================",
               "= Prism XLSX Import Script                                         =",
               "=------------------------------------------------------------------=",
               "= Takes 1 or multiple Prism Report XLSX export files and parses    =",
               "= them to generated a PTRAC file that can be imported into         =",
               "= Plextrac.                                                        =",
               "=                                                                  =",
               "= Can use a separate script to bulk import PTRAC files.            =",
               "= https://github.com/PlexTrac-Labs/instance-data-backup-migration  =",
               "=                                                                  =",
               "===================================================================="
            ]
