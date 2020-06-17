# Code to find bad ports.  To be applied to firewall.py

find_port = '80'
found_port = False

for allow in allowed:
    #print(allow)
    #print(allow['ports'])
    
    try:
        for port in allow['ports']:
            if port == '80':
                found_port = True
    except:
        pass
            
print(f'Found Bad Ports: {found_port}')