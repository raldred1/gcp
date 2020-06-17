from google.cloud import resource_manager
import google.auth
from googleapiclient import discovery
from pprint import pprint

credentials, project = google.auth.default()
client = resource_manager.Client()
service = discovery.build('compute', 'v1', credentials=credentials)

print('\nSearching for GCLB instances\n')

for project in client.list_projects():
    project = project.project_id
    print(f'Checking project [{project}]...')
    try:
        request = service.urlMaps().list(project=project)
        while request is not None:
            response = request.execute()

            for url_map in response['items']:
                #pprint(url_map)
                print(f'    GCLB: {url_map["name"]}')

            request = service.urlMaps().list_next(previous_request=request, previous_response=response)
    except:
        print('    None found within this project\n')

print('\nComplete!!!\n')

