from google.cloud import resource_manager
import google.auth

credentials, project = google.auth.default()
client = resource_manager.Client()

#try:
    # List all projects you have access to
for project in client.list_projects():
    print(f'Project: ' + project.project_id)
#except:
  #print("An exception occurred")
  

