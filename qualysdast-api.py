import sys, argparse, time
import zipfile
import requests
import xmltodict
from requests.structures import CaseInsensitiveDict
from requests.auth import HTTPBasicAuth

def getArgs():
    parser = argparse.ArgumentParser(description='Add authentication key to work with the APIs of qualys and future edition might include groups too.', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument( "--qualysuser", type=str, help="qualys username" )
    parser.add_argument( "--qualyspass", type=str, help="qualys password" )
    parser.add_argument( "--website", type=str, help="website you are testing" )
    parser.add_argument( "--project", type=str, help="website you are testing" )
    return parser, parser.parse_args()


def run(username,password,website,project):
    
    try:
        #create option profile for the web app and scan
        url_option= "https://qualysapi.qg2.apps.qualys.eu:443/qps/rest/3.0/create/was/optionprofile/"
        data = """
        <ServiceRequest>
        <data>
        <OptionProfile>
        <name><![CDATA[{project_placeholder} WAS Options]]></name>
        <maxCrawlRequests>8000</maxCrawlRequests>
        <smartScanSupport>true</smartScanSupport>
        <smartScanDepth>1</smartScanDepth>
        <bruteforceOption>DISABLED</bruteforceOption>
        <performance>MEDIUM</performance>
        </OptionProfile>
        </data>
        </ServiceRequest>
        """.format(project_placeholder=project)

        response = requests.post(url_option, auth=HTTPBasicAuth(username,password), data=data)
        dict_data = xmltodict.parse(response.content)
        option_id= dict_data['ServiceResponse']['data']['OptionProfile']['id']
        print(dict_data)

        #create auth record and get its id to use for the scan and report this can vaary from project to project
        url= "https://qualysapi.qg2.apps.qualys.eu:443/qps/rest/3.0/create/was/webappauthrecord"
        data = """
        <ServiceRequest>
        <data>
        <WebAppAuthRecord>
        <name><![CDATA[{project_placeholder}Auth]]></name>
        <formRecord>
        <type>CUSTOM</type>
        <sslOnly>true</sslOnly>
        <fields>
        <set>
        <WebAppAuthFormRecordField>
        <name>name</name>
        <value>kevin</value>
        </WebAppAuthFormRecordField>
        <WebAppAuthFormRecordField>
        <name>tablenumber</name>
        <value>23</value>
        </WebAppAuthFormRecordField>
        <WebAppAuthFormRecordField>
        <name>code</name>
        <value>budapest</value>
        </WebAppAuthFormRecordField>
        </set>
        </fields>
        </formRecord>
        </WebAppAuthRecord>
        </data>
        </ServiceRequest>
        """.format(project_placeholder=project)

        response = requests.post(url, auth=HTTPBasicAuth(username,password), data=data)
        dict_data = xmltodict.parse(response.content)
        auth_id= dict_data['ServiceResponse']['data']['WebAppAuthRecord']['id']
        print(dict_data)

        #create web app and get its id to use for scan and report
        url_webapp="https://qualysapi.qg2.apps.qualys.eu:443/qps/rest/3.0/create/was/webapp/"
        data= """
        <ServiceRequest>
        <data>
        <WebApp>
        <name><![CDATA[{project_placeholder}]]></name>
        <url><![CDATA[{website_placeholder}]]></url>
        <uris>
        <set>
        <Url><![CDATA[{website_placeholder}]]></Url>
        </set>
        </uris>
        <authRecords>
        <set>
        <WebAppAuthRecord>
        <id>{auth_id_placeholder}</id>
        </WebAppAuthRecord>
        </set>
        </authRecords>
        <defaultProfile>
        <id>{option_id_placeholder}</id>
        </defaultProfile>
        </WebApp>
        </data>
        </ServiceRequest>
        """.format(website_placeholder=website,project_placeholder=project,option_id_placeholder=option_id,auth_id_placeholder=auth_id)

        response = requests.post(url_webapp, auth=HTTPBasicAuth(username,password), data=data) #post request
        dict_data = xmltodict.parse(response.content) #convert into an xml response
        print(dict_data)
        web_app_id= dict_data['ServiceResponse']['data']['WebApp']['id'] #get the web app id from the xml response
        time.sleep(1)


        #create scan and get the id of this scan
        url_scan= "https://qualysapi.qg2.apps.qualys.eu:443/qps/rest/3.0/launch/was/wasscan"
        data = """
        <ServiceRequest>
        <data>
        <WasScan>
        <name>{project_placeholder} WAS VULNERABILITY Scan launched from the API</name>
        <type>VULNERABILITY</type>
        <target>
        <webApp>
        <id>{webapp_id_placeholder}</id>
        </webApp>
        <webAppAuthRecord>
        <id>{auth_id_placeholder}</id>
        </webAppAuthRecord>
        <scannerAppliance>
        <type>EXTERNAL</type>
        </scannerAppliance>
        </target>
        <profile>
        <id>{option_id_placeholder}</id>
        </profile>
        </WasScan>
        </data>
        </ServiceRequest>
        """.format(webapp_id_placeholder=web_app_id,auth_id_placeholder=auth_id,option_id_placeholder=option_id,project_placeholder=project)

        response = requests.post(url_scan, auth=HTTPBasicAuth(username, password), data=data)
        dict_data = xmltodict.parse(response.content)
        print(dict_data)
        scan_id= dict_data['ServiceResponse']['data']['WasScan']['id']
        
        scan_bool= False #just for the while loop to run until scan finished
        while scan_bool==False:
            url_scan_status= "https://qualysapi.qg2.apps.qualys.eu:443/qps/rest/3.0/status/was/wasscan/"+scan_id
            response = requests.get(url_scan_status, auth=HTTPBasicAuth(username, password))
            dict_data = xmltodict.parse(response.content)
            scan_status= str(dict_data['ServiceResponse']['data']['WasScan']['status'])
            if scan_status== "FINISHED":
                scan_bool=True        
            #timeout after a while maybe?
    

        #create a report from the scan
        url_report="https://qualysapi.qg2.apps.qualys.eu:443/qps/rest/3.0/create/was/report"
        data= """
        <ServiceRequest>
        <data>
        <Report>
        <name><![CDATA[{project_placeholder} WAS report]]></name>
        <description><![CDATA[A simple scan report for {project_placeholder}]]></description>
        <format>HTML_ZIPPED</format>
        <type>WAS_SCAN_REPORT</type>
        <config>
        <scanReport>
        <target>
        <scans>
        <WasScan>
        <id>{scan_id_placeholder}</id>
        </WasScan>
        </scans>
        </target>
        <display>
        <contents>
        <ScanReportContent>DESCRIPTION</ScanReportContent>
        <ScanReportContent>SUMMARY</ScanReportContent>
        <ScanReportContent>GRAPHS</ScanReportContent>
        <ScanReportContent>RESULTS</ScanReportContent>
        <ScanReportContent>INDIVIDUAL_RECORDS</ScanReportContent>
        <ScanReportContent>RECORD_DETAILS</ScanReportContent>
        <ScanReportContent>ALL_RESULTS</ScanReportContent>
        <ScanReportContent>APPENDIX</ScanReportContent>
        </contents>
        <graphs>
        <ScanReportGraph>VULNERABILITIES_BY_SEVERITY</ScanReportGraph>
        <ScanReportGraph>VULNERABILITIES_BY_GROUP</ScanReportGraph>
        <ScanReportGraph>VULNERABILITIES_BY_OWASP</ScanReportGraph>
        <ScanReportGraph>VULNERABILITIES_BY_WASC</ScanReportGraph>
        <ScanReportGraph>SENSITIVE_CONTENTS_BY_GROUP</ScanReportGraph>
        </graphs>
        <groups>
        <ScanReportGroup>URL</ScanReportGroup>
        <ScanReportGroup>GROUP</ScanReportGroup>
        <ScanReportGroup>OWASP</ScanReportGroup>
        <ScanReportGroup>WASC</ScanReportGroup>
        <ScanReportGroup>STATUS</ScanReportGroup>
        <ScanReportGroup>CATEGORY</ScanReportGroup>
        <ScanReportGroup>QID</ScanReportGroup>
        </groups>
        <options>
        <rawLevels>true</rawLevels>
        </options>
        </display>
        <filters>
        <status>
        <ScanFindingStatus>NEW</ScanFindingStatus>
        <ScanFindingStatus>ACTIVE</ScanFindingStatus>
        <ScanFindingStatus>REOPENED</ScanFindingStatus>
        <ScanFindingStatus>FIXED</ScanFindingStatus>
        </status>
        </filters>
        </scanReport>
        </config>
        </Report>
        </data>
        </ServiceRequest>
        """.format(scan_id_placeholder=scan_id,project_placeholder=project)

        response = requests.post(url_report, auth=HTTPBasicAuth(username, password), data=data)
        dict_data = xmltodict.parse(response.content)
        print(dict_data)
        report_id= dict_data['ServiceResponse']['data']['Report']['id']
        time.sleep(10) #give time for the report to be fully created before downloading
        

        # download and extract report  
        url_report_download= "https://qualysapi.qg2.apps.qualys.eu:443/qps/rest/3.0/download/was/report/"+report_id
        response = requests.get(url_report_download, auth=HTTPBasicAuth(username, password))
        open('scanreport.zip', 'wb').write(response.content)
        with zipfile.ZipFile('scanreport.zip', 'r') as zip_ref:
            zip_ref.extractall('reports')


        #delete scan from qualys when done
        url_delete_scan="https://qualysapi.qg2.apps.qualys.eu:443/qps/rest/3.0/delete/was/wasscan/"+scan_id
        response = requests.post(url_delete_scan, auth=HTTPBasicAuth(username, password))
        dict_data = xmltodict.parse(response.content)
        print(dict_data)


        #delete report when done
        url_delete_report="https://qualysapi.qg2.apps.qualys.eu:443/qps/rest/3.0/delete/was/report/"+report_id
        response = requests.post(url_delete_report, auth=HTTPBasicAuth(username, password))
        dict_data = xmltodict.parse(response.content)
        print(dict_data)


        #delete webapp when done
        url_delete_webapp="https://qualysapi.qg2.apps.qualys.eu:443/qps/rest/3.0/delete/was/webapp/"+web_app_id
        response = requests.post(url_delete_webapp, auth=HTTPBasicAuth(username, password))
        dict_data = xmltodict.parse(response.content) #even though these arent needed , leave them in incase of future debugging 
        print(dict_data)
    
        #delete asset when done
        url_delete_asset= "https://qualysapi.qg2.apps.qualys.eu:443/qps/rest/2.0/delete/am/asset/"+web_app_id
        response = requests.post(url_delete_asset, auth=HTTPBasicAuth(username,password))
        dict_data = xmltodict.parse(response.content)
        print(dict_data)
        
        #delete option profile when done
        url_delete_option= "https://qualysapi.qg2.apps.qualys.eu:443/qps/rest/3.0/delete/was/optionprofile/"+option_id
        response = requests.post(url_delete_option, auth=HTTPBasicAuth(username,password))
        dict_data = xmltodict.parse(response.content) #even though these arent needed , leave them in incase of future debugging 
        print(dict_data)

        #delete auth record when done
        url_delete_auth= "https://qualysapi.qg2.apps.qualys.eu:443/qps/rest/3.0/delete/was/webappauthrecord/"+auth_id
        response = requests.post(url_delete_auth, auth=HTTPBasicAuth(username,password))
        dict_data = xmltodict.parse(response.content) #even though these arent needed , leave them in incase of future debugging 
        print(dict_data)
    
    except:
        #delete option profile when done
        url_delete_option= "https://qualysapi.qg2.apps.qualys.eu:443/qps/rest/3.0/delete/was/optionprofile/"+option_id
        response = requests.post(url_delete_option, auth=HTTPBasicAuth(username,password))
        dict_data = xmltodict.parse(response.content) #even though these arent needed , leave them in incase of future debugging 
        print(dict_data)

        #delete auth record when done
        url_delete_auth= "https://qualysapi.qg2.apps.qualys.eu:443/qps/rest/3.0/delete/was/webappauthrecord/"+auth_id
        response = requests.post(url_delete_auth, auth=HTTPBasicAuth(username,password))
        dict_data = xmltodict.parse(response.content) #even though these arent needed , leave them in incase of future debugging 
        print(dict_data)

        #delete webapp when done
        url_delete_webapp="https://qualysapi.qg2.apps.qualys.eu:443/qps/rest/3.0/delete/was/webapp/"+web_app_id
        response = requests.post(url_delete_webapp, auth=HTTPBasicAuth(username, password))
        dict_data = xmltodict.parse(response.content) #even though these arent needed , leave them in incase of future debugging 
        print(dict_data)

        #delete asset when done
        url_delete_asset= "https://qualysapi.qg2.apps.qualys.eu:443/qps/rest/2.0/delete/am/asset/"+web_app_id
        response = requests.post(url_delete_asset, auth=HTTPBasicAuth(username,password))
        dict_data = xmltodict.parse(response.content)
        print(dict_data)

        #delete scan from qualys when done
        url_delete_scan="https://qualysapi.qg2.apps.qualys.eu:443/qps/rest/3.0/delete/was/wasscan/"+scan_id
        response = requests.post(url_delete_scan, auth=HTTPBasicAuth(username, password))
        dict_data = xmltodict.parse(response.content)
        print(dict_data)

        #delete report when done
        url_delete_report="https://qualysapi.qg2.apps.qualys.eu:443/qps/rest/3.0/delete/was/report/"+report_id
        response = requests.post(url_delete_report, auth=HTTPBasicAuth(username, password))
        dict_data = xmltodict.parse(response.content)
        print(dict_data)        
        
        
if __name__ == '__main__':
    myParser, myargs = getArgs()
    try:
        request = requests.get(myargs.website)
        if request.status_code == 200:
            print("Website exists")
        else:
            sys.exit("Website does not exist, create the lounge before testing :)")
    except:
        sys.exit("Website does not exist, create the lounge before testing :)")
        
    sys.exit(run(myargs.qualysuser,myargs.qualyspass,myargs.website,myargs.project))
