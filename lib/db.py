import requests,json
from dateutil import parser

def hosts(headers, cursor, cb_tenant, cb_url):
    # Limpando Banco
    query_insert = f"""truncate table dashboard_hosts"""
    cursor.execute(query_insert)
    cursor.commit()
    # Dados dos hosts
    criteria = {
        "criteria": {
            "status": ["ALL"]
            },
        "rows": 10000
        }
    hosts = requests.post(cb_url + "/appservices/v6/orgs/" + cb_tenant + "/devices/_search", headers=headers, json=criteria)
    response = json.loads(hosts.content)
    found = (response['num_found'])
    for host in response["results"]:
        id = str(host["id"])
        try:
            device = host["name"]
            splited = device.split("\\")
            splited = splited[1]
            device_name = splited.lower()
        except:
            device = host["name"]
            device_name = device.lower()
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
        # Inserindo dados
        query_insert = f"""INSERT INTO dashboard_hosts(orgkey, device_id, device_name, device_os, device_os_version, sensor_version, sensor_status, registered_time, last_contact, vuln_critical, vuln_Important, vuln_moderate, vuln_low) 
                    VALUES 
                    ('{cb_tenant}', {id}, '{device_name}', '{device_os}', '{device_os_version}', '{sensor_version}', '{sensor_status}', '{registered_time}', '{last_contact_time}', {critical}, {moderate}, {important}, {low})"""
        cursor.execute(query_insert)
        cursor.commit()
    print(str(found) + " hosts inseridos!")


def alarms(headers, cursor, cb_tenant, cb_url):
    # Limpando Banco
    query_insert = f"""truncate table dashboard_alarms"""
    cursor.execute(query_insert)
    cursor.commit()
    # Dados dos alarmes
    criteria = {
        "criteria": {
            "minimum_severity": 1
            }, 
        }
    hosts = requests.post(cb_url + "/appservices/v6/orgs/" + cb_tenant + "/alerts/_search", headers=headers, json=criteria)
    response = json.loads(hosts.content)
    found = (response['num_found'])
    for alarm in response["results"]:
        id = str(alarm["id"])
        try:
            device = alarm["device_name"]
            splited = device.split("\\")
            splited = splited[1]
            device_name = splited.lower()
        except:
            device = alarm["device_name"]
            device_name = device.lower()
        device_os = alarm["device_os"]
        device_os_version = alarm["device_os_version"]
        alarm_status = alarm["workflow"]["state"]
        reason_code = alarm["reason_code"]
        description = alarm["reason"]
        process_name = alarm["process_name"]
        policy_id = alarm["policy_id"]
        policy_name = alarm["policy_name"]
        severity = alarm["severity"]
        create = parser.parse(alarm["create_time"])
        data = str(create.date())
        tempo = str(create.time().strftime("%H:%M:%S"))
        create_time = data + " " + tempo
        # Inserindo dados
        query_insert = f"""INSERT INTO dashboard_alarms(orgkey, alarm_id, device_name, device_os, device_os_version, alarm_status, reason_code, description, process_name, policy_id, policy_name, severity, create_time) 
                    VALUES 
                    ('{cb_tenant}', '{id}', '{device_name}', '{device_os}', '{device_os_version}', '{alarm_status}', '{reason_code}', '{description}', '{process_name}', {policy_id}, '{policy_name}', {severity}, '{create_time}')"""
        cursor.execute(query_insert)
        cursor.commit()
    print(str(found) + " alarmes inseridos!")

def vulns(headers, cursor, cb_tenant, cb_url):
    # Limpando Banco
    query_insert = f"""truncate table dashboard_vulnerability"""
    cursor.execute(query_insert)
    cursor.commit()
    # Dados dos alarmes
    criteria = {
        "start": 0
        }
    hosts = requests.post(cb_url + "/vulnerability/assessment/api/v1/orgs/" + cb_tenant + "/devices/vulnerabilities/_search", headers=headers, json=criteria)
    response = json.loads(hosts.content)
    found = (response['num_found'])
    for vuln in response["results"]:
        device_os = vuln["os_info"]["os_name"]
        device_os_version = vuln["os_info"]["os_version"]
        vuln_type = vuln["category"]
        vuln_app = vuln["product_info"]["product"]
        vuln_app_version = vuln["product_info"]["version"]
        vulnerability = vuln["vuln_info"]["cve_id"]
        desc = vuln["vuln_info"]["cve_description"]
        splited = desc.replace('"', "")
        description = splited.replace("'", "")
        try:
            resolution = vuln["vuln_info"]["resolution"]
        except:
            resolution = "No Resolution Set"
        vuln_url = vuln["vuln_info"]["nvd_link"]
        endpoints = vuln["device_count"]
        severity = vuln["vuln_info"]["severity"]
        risk = vuln["vuln_info"]["risk_meter_score"]
        # Inserindo dados
        query_insert = f"""INSERT INTO dashboard_vulnerability(orgkey, device_os, device_os_version, vuln_type, vuln_app, vuln_app_version, vulnerability, description, resolution, vuln_url, endpoints, severity, risk) 
                    VALUES 
                    ('{cb_tenant}', '{device_os}', '{device_os_version}', '{vuln_type}', '{vuln_app}', '{vuln_app_version}', '{vulnerability}', '{description}', '{resolution}', '{vuln_url}', {endpoints}, '{severity}', '{risk}')"""
        cursor.execute(query_insert)
        cursor.commit()
    print(str(found) + " vulnerabilidades inseridas!")