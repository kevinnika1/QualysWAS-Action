import sys, argparse
import requests
import json

def getArgs():
    parser = argparse.ArgumentParser(description='Add sonarcloud detials', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument( "--org", type=str, help="organisation name in sonarcloud" )
    parser.add_argument( "--projectkey", type=str, help="project key in sonarcloud" )
    return parser, parser.parse_args()


def run(org,project):

    query = {'organization': org, 'statuses':'OPEN', 'types':'VULNERABILITY'}
    response = requests.get('https://sonarcloud.io/api/issues/search', params=query) 
    issuesJSON = response.json()

    result= []
    for x in issuesJSON['issues']:
        if (x['project']== project):
            thisdict= {}
            thisdict['path']=x['component'].replace(project+":", '')
            thisdict['title']=str("SAST: "+x.get('component'))
            thisdict['message']=x.get('message')
            thisdict['annotation_level']="failure" #x.get('severity')#thisdict['annotation_level']=x.get('severity')
            for y in x['flows']:
                thisdict['start_line']= y['locations'][0]['textRange']['startLine']
                thisdict['end_line']= y['locations'][0]['textRange']['endLine']
            for z in x['flows']:
                thisdict['raw_details']=str(z['locations'])#['locations'] 
            result.append(thisdict)
     

    with open("sonarresults.json", "w") as outfile:
        json.dump(result, outfile, indent=4)


if __name__ == '__main__':
    myParser, myargs = getArgs()
    sys.exit(run(myargs.org,myargs.projectkey))
