from google.cloud import resource_manager
import google.auth
from googleapiclient import discovery
import sys
from googleapiclient.errors import HttpError

credentials, project = google.auth.default()
client = resource_manager.Client()

# *** TO DO: When 1-65535 bad ports, multiple outputs. ***

f = open("vpc_firewall_noncomp_output.csv", "w")

# Bad Port Lists (TCP and UDP) -> Warning & Block
find_bad_ports_tcp_block = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '109', '110', '137', '143', '220']
find_bad_ports_tcp_warning = ['20', '21', '22', '23', '25', '53', '80', '111', '119', '135', '139', '389', '445', '1494', '3389']
find_bad_ports_udp_block = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '137', '138']
find_bad_ports_udp_warning = ['53', '123', '139', '161', '162', '389', '445']

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
        #if project.upper() == '**SPECIFIC PROJECT HERE IF REQUIRED'.upper(): #<--- USE TO TEST JUST ONE PROJECT
        try:
            request = service.firewalls().list(project=project, filter='disabled=False')
            response = request.execute()
            
            if response.get('items','no_items') != 'no_items': # Ensure 'items' exists
                for firewall in response['items']:
                    if firewall["direction"] == 'EGRESS':
                        firewall_ip_range = firewall["destinationRanges"]
                    elif firewall["direction"] == 'INGRESS':
                        firewall_ip_range = firewall["sourceRanges"]

                    if firewall.get('allowed','must_be_deny') != 'must_be_deny': # If can't find 'allowed' then must be a deny.

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

                            # Look for IPProtocol = 'tcp' AND ports = (find_bad_ports_tcp_block_block list)
                            try: 
                                bad_ports_found = [] 
                                for port in allow['ports']:

                                    # ** Section to be restructured to loop through found ports against the lists, rather than the 4 lists separately **

                                    # Find Bad TCP Ports (Block)
                                    for port_check in find_bad_ports_tcp_block:
                                        if current_ipprotocol == 'tcp' and port == port_check:
                                            # Found a bad port...
                                            bad_ports_found.append(f'tcp:{port}_x')

                                        if port.find('-') != -1:
                                            port_range = port.split('-')
                                            if current_ipprotocol == 'tcp' and port_range is not None and int(port_range[0]) < int(port_check) and int(port_range[1]) > int(port_check):
                                                # Found a bad port (in range)...
                                                bad_ports_found.append(f'tcp:{port}_x')
                                    
                                    # Find Bad UDP Ports (Block)
                                    for port_check in find_bad_ports_udp_block:
                                        if current_ipprotocol == 'udp' and port == port_check:
                                            # Found a bad port...
                                            bad_ports_found.append(f'udp:{port}_x')

                                        if port.find('-') != -1:
                                            port_range = port.split('-')
                                            if current_ipprotocol == 'udp' and port_range is not None and int(port_range[0]) < int(port_check) and int(port_range[1]) > int(port_check):
                                                # Found a bad port (in range)...
                                                bad_ports_found.append(f'udp:{port}_x')

                                    # Find Bad TCP Ports (Warning)
                                    for port_check in find_bad_ports_tcp_warning:
                                        if current_ipprotocol == 'tcp' and port == port_check:
                                            # Found a bad port...
                                            bad_ports_found.append(f'tcp:{port}')

                                        if port.find('-') != -1:
                                            port_range = port.split('-')
                                            if current_ipprotocol == 'tcp' and port_range is not None and int(port_range[0]) < int(port_check) and int(port_range[1]) > int(port_check):
                                                # Found a bad port (in range)...
                                                bad_ports_found.append(f'tcp:{port}')
                                    
                                    # Find Bad UDP Ports (Warning)
                                    for port_check in find_bad_ports_udp_warning:
                                        if current_ipprotocol == 'udp' and port == port_check:
                                            # Found a bad port...
                                            bad_ports_found.append(f'udp:{port}')

                                        if port.find('-') != -1:
                                            port_range = port.split('-')
                                            if current_ipprotocol == 'udp' and port_range is not None and int(port_range[0]) < int(port_check) and int(port_range[1]) > int(port_check):
                                                # Found a bad port (in range)...
                                                bad_ports_found.append(f'udp:{port}')
                                            
                                if len(bad_ports_found) != 0:
                                    output(f'{project},{firewall["name"]},bad port(s) found: {bad_ports_found}\n','a')

                            except:
                                pass
                    
        except HttpError as e:
            if e.resp.status == 403:
                #output(f'Project [{project}] Compute API not enabled','a')
                pass # Do nothing as this means there aren't any non-compliance FW rules
            #else:
                #print(e.resp.status)
        except:
            output(f"Project: {project} | Unexpected error: {sys.exc_info()[0]}","a")



if __name__ == "__main__":
    welcome()
    main()
    f.close() # Close output file when finsihed.
    output('\n\n------------', 'p')
    output("\nNote: [Bad ports] identified with a trailing '_x' (e.g. 'tcp:110_x') will NOT be supported.  Those without are subject to further clarification based on their use-case.",'p')
    output('\nFINISHED!\n\n', 'p')
