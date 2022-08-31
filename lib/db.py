import requests,json
from dateutil import parser

def hosts(headers, cursor, cb_tenant, cb_url):
    # Dados dos hosts
    criteria = {
        "criteria": {
            "status": ["ALL"]
            }, 
        "rows": 10000
        }
    hosts = requests.post(cb_url + "/appservices/v6/orgs/" + cb_tenant + "/devices/_search", headers=headers, json=criteria)
    response = json.loads(hosts.content)
    for host in response["results"]:
        id = str(host["id"])
        device_name = host["name"]
        device_os = host["os"]
        device_os_version = host["os_version"]
        sensor_version = host["sensor_version"]
        sensor_status = host["status"]
        registered = parser.parse(host["registered_time"])
        data = str(registered.date())
        tempo = str(registered.time().strftime("%H:%M:%S"))
        registered_time = data + " " + tempo
        last_contact = parser.parse(host["last_contact_time"])
        data = str(last_contact.date())
        tempo = str(last_contact.time().strftime("%H:%M:%S"))
        last_contact_time = data + " " + tempo
        # Dados de vulnerabilidades
        try:
            vuln = requests.get(cb_url + "/vulnerability/assessment/api/v1/orgs/" + cb_tenant + "/devices/" + id + "/vulnerabilities/summary", headers=headers)
            response = json.loads(vuln.content)
            low = response["severity_counts"]["low"]
            moderate = response["severity_counts"]["moderate"]
            important = response["severity_counts"]["important"]
            critical = response["severity_counts"]["critical"]
        except:
            low = 0
            moderate = 0
            important = 0
            critical = 0
        query_insert = f"""INSERT INTO dashboard_hosts(orgkey, device_name, device_os, device_os_version, sensor_version, sensor_status, registered_time, last_contact, vuln_critical, vuln_Important, vuln_moderate, vuln_low) 
                    VALUES 
                    ({cb_tenant}, '{device_name}', '{device_os}', '{device_os_version}', {sensor_version}, {sensor_status}, '{registered_time}', {last_contact_time}, {critical}, {moderate}, {important}, {low})"""
        cursor.execute(query_insert)
        cursor.commit()
        print("Host ID: " + id + " inserido no DW")
