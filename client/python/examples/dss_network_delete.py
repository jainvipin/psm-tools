import click
import os
import pensando_dss
import pensando_dss.psm
from pensando_dss.psm.api import network_v1_api
from pensando_dss.psm.models.network import *
from pprint import pprint
    
# Defining the host is optional and defaults to http://localhost
# See configuration.py for a list of all supported configuration parameters.
configuration = pensando_dss.psm.Configuration(
    psm_config_path = os.environ["HOME"] + "/.psm/config.json",
    interactive_mode=True
)
configuration.verify_ssl = False

@click.command()
@click.option('--name', help='name of the Network to be deleted')

def delete_network_policy(name): 
    # Enter a context with an instance of the API client
    with pensando_dss.psm.ApiClient(configuration) as api_client:
        # Create an instance of the API class
        api_instance = network_v1_api.NetworkV1Api(api_client)
        o_name = name # str | 

        # example passing only required values which don't have defaults set
        try:
            # Delete Network object
            api_response = api_instance.delete_network1(o_name)
            pprint(api_response)
        except pensando_dss.psm.ApiException as e:
            print("Exception when calling NetworkV1Api->delete_network1: %s\n" % e)

if __name__ == '__main__':
    delete_network_policy()
