from google.cloud import resource_manager
import google.auth
from googleapiclient import discovery

credentials, project = google.auth.default()
client = resource_manager.Client()
service = discovery.build('compute', 'v1', credentials=credentials)

find_ports = ['80'] # <- searching for 'tcp' based ports only
# always ensure IPProtocol = 'tcp' if only checking for tcp ports (such as HTTP on TCP:80)
# additionally check for IPProtocol = 'all'

f = open("output.txt", "w")

def output(output_msg,output_type):
    # type: p/f/a (print/file/all) [blank = all]
    if output_type == 'p' or output_type == 'a' or output_type is None:
        print(output_msg)
    if output_type == 'f' or output_type == 'a' or output_type is None:
        f.write(output_msg)


output('\nSearching for HTTP Firewall EGRESS rules','p')
output('\n=============\n\n\n','p')

for project in client.list_projects():
    project = project.project_id
    found_port = False
    output(f'\nChecking project [{project}]...\n','p')
    try:
        request = service.firewalls().list(project=project, filter='direction=EGRESS')
        while request is not None:
            response = request.execute()

            for firewall in response['items']:

                for dest_range in firewall["destinationRanges"]:

                    if dest_range.find('0.0.0.0') != -1:
                        output(f'Project: {project}\t\tAllowed to 0.0.0.0\t\tRule: [{firewall["name"]}] allowing egress to public internet\n','a')
                
                for allow in firewall["allowed"]:
                    
                    current_ipprotocol = allow['IPProtocol']

                    try:
                        if allow['ports'] != None:
                            ports_listed = allow['ports']
                    except:
                        ports_listed = None

                    # Look for IPProtocol = 'all' or IPProtocol = 'tcp' (but no ports specified, i.e. 'all')
                    if current_ipprotocol == 'all':
                        output(f'Project: {project}\t\tAllowed to "tcp/udp:all"\t\tRule: [{firewall["name"]}] allowing egress to all ports\n','a')
                    elif current_ipprotocol == 'tcp' and ports_listed is None:
                        output(f'Project: {project}\t\tAllowed to "tcp:all"\t\tRule: [{firewall["name"]}] allowing egress to {firewall["allowed"]}\n','a')
                    
                    # Look for IPProtocol = 'tcp' AND ports = '80'
                    try: 
                        bad_ports_found = [] 
                        for port in allow['ports']:

                            for port_check in find_ports:

                                if current_ipprotocol == 'tcp' and port == port_check:
                                    #found_port = True
                                    bad_ports_found.append(port)

                                if port.find('-') != -1:
                                    port_range = port.split('-')
                                    if current_ipprotocol == 'tcp' and port_range is not None and int(port_range[0]) < int(port_check) and int(port_range[1]) > int(port_check):
                                        #found_port = True
                                        bad_ports_found.append(port)
                                    
                        if len(bad_ports_found) != 0:
                            output(f'Project: {project}\t\tAllowed port "tcp:80"\t\tRule: [{firewall["name"]}] allowing egress to {firewall["allowed"]}\n','a')

                    except:
                        pass
                            
            #if found_port is True:
                #output(f'\n\n\t*** POTENTIALLY NON-COMPLIANT HTTP (TCP:80) FLOWS ALLOWED IN THIS PROJECT ***\n','p')
                #output('-------------','p')

            request = service.firewalls().list_next(previous_request=request, previous_response=response)
    except:
        # None found in this project

        output('-------------','p')

output('\n\n\n\nComplete!!!\n','p')

f.close()
