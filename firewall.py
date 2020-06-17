from google.cloud import resource_manager
import google.auth
from googleapiclient import discovery

credentials, project = google.auth.default()
client = resource_manager.Client()
service = discovery.build('compute', 'v1', credentials=credentials)

find_ports = ['80']

print('\nSearching for Firewall EGRESS rules')
print('\n-------------')

for project in client.list_projects():
    project = project.project_id
    found_port = False
    print(f'\nChecking project [{project}]...\n')
    try:
        request = service.firewalls().list(project=project, filter='direction=EGRESS')
        while request is not None:
            response = request.execute()

            for firewall in response['items']:

                print(f'     Rule: {firewall["name"]} allowing egress to {firewall["allowed"]}')

                for allow in firewall["allowed"]:
                    
                    try:
                        bad_ports_found = []
                        for port in allow['ports']:
                            
                            for port_check in find_ports:
                                
                                if port == port_check:
                                    found_port = True
                                    bad_ports_found.append(port)
                                    #print(bad_ports_found)
                                    #print(len(bad_ports_found))
                                    
                        if len(bad_ports_found) != 0:
                            print('         ^ bad port')

                    except:
                        pass
                            
            if found_port is True:
                print(f'\n     *** BAD PORT FOUND IN THIS PROJECT ***\n')
                #print(f'Found Bad Ports: {found_port}')

            request = service.firewalls().list_next(previous_request=request, previous_response=response)
    except:
        print('    None found within this project\n')

    print('-------------')

print('\nComplete!!!\n')

