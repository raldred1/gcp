from google.cloud import resource_manager
import google.auth
from googleapiclient import discovery

# *** CURRENTLY SCANNING EGRESS ONLY ***

credentials, project = google.auth.default()
client = resource_manager.Client()
#service = discovery.build('compute', 'v1', credentials=credentials)

f = open("vpc_firewall_noncomp_output.csv", "w")
find_bad_ports = ['80', '21'] # Provide as strings (not var)

def output(output_msg,output_type):
    # type: p/f/a (print/file/all) [blank = all]
    if output_type == 'p' or output_type == 'a' or output_type is None:
        print(output_msg)
    if output_type == 'f' or output_type == 'a' or output_type is None:
        f.write(output_msg)


def welcome():
    output('\n---\n','p')
    output('VPC Firewall Non-Compliance Script','p')
    output('\n---\n\n','p')
    output(f'Project,Rule,Failed Control\n','f')
    output('Scanning...\n\n','p')


def main():
    service = discovery.build('compute', 'v1', credentials=credentials)
    for project in client.list_projects():
        project = project.project_id
        #found_port = False
        # Temp: Just check the RA project (seceng-ra-001) whilst testing...
        if project.upper() == 'seceng-ra-001'.upper():
            try:
                #request = service.firewalls().list(project=project, filter='direction=EGRESS')
                request = service.firewalls().list(project=project)
                response = request.execute()
                
                for firewall in response['items']:
                    if firewall["direction"] == 'EGRESS':
                        firewall_ip_range = firewall["destinationRanges"]
                    elif firewall["direction"] == 'INGRESS':
                        firewall_ip_range = firewall["sourceRanges"]

                    for ip_range in firewall_ip_range:
                        ip_ip_split = ip_range.split('.') # Split for 172.x.x.x query
                        if ip_range.find('0.0.0.0') != -1:
                            output(f'{project},{firewall["name"]},ip_range: 0.0.0.0\n','a')
                        elif ip_range.startswith('10.') is False and ip_range.startswith('192.168.') is False:
                            if ip_range.startswith('172.') and (int(ip_ip_split[1]) < 16 or int(ip_ip_split[1]) > 31): # i.e. not between 172.16.0.0 – 172.31.255.255
                                    output(f'{project},{firewall["name"]},public target: {ip_range}\n','a')
                            elif ip_range.startswith('172.') is False:
                                output(f'{project},{firewall["name"]},public target: {ip_range}\n','a')
                
                    for allow in firewall["allowed"]:
                        current_ipprotocol = allow['IPProtocol']

                        try:
                            if allow['ports'] != None:
                                ports_listed = allow['ports']
                        except:
                            ports_listed = None

                        # Look for IPProtocol = 'all' or IPProtocol = 'tcp/udp' (but no ports specified, i.e. 'all')
                        if current_ipprotocol == 'all':
                            output(f'{project},{firewall["name"]},tcp/udp:all ports\n','a')
                        elif current_ipprotocol == 'tcp' and ports_listed is None:
                            output(f'{project},{firewall["name"]},tcp:all ports\n','a')
                        elif current_ipprotocol == 'udp' and ports_listed is None:
                            output(f'{project},{firewall["name"]},udp:all ports\n','a')

                        # Look for IPProtocol = 'tcp' AND ports = (find_bad_ports list)
                        try: 
                            bad_ports_found = [] 
                            for port in allow['ports']:

                                for port_check in find_bad_ports:
                                    if current_ipprotocol == 'tcp' and port == port_check:
                                        # Found a bad port...
                                        bad_ports_found.append(port)

                                    if port.find('-') != -1:
                                        port_range = port.split('-')
                                        if current_ipprotocol == 'tcp' and port_range is not None and int(port_range[0]) < int(port_check) and int(port_range[1]) > int(port_check):
                                            # Found a bad port (in range)...
                                            bad_ports_found.append(port)
                                        
                            if len(bad_ports_found) != 0:
                                output(f'{project},{firewall["name"]},bad port found: {bad_ports_found}\n','a')

                        except:
                            pass
                    
            except:
                output('*Exception*','a')
            
    

if __name__ == "__main__":
    welcome()
    main()
    f.close() # Close output file when finsihed.
    output('\n\nFinished!\n\n', 'p')
