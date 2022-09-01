#!/usr/bin/python3
import sys
import pyodbc
from lib.db import *

# SQL vars
funcao              = (sys.argv[1])
db_hostname         = (sys.argv[2])
db_username         = (sys.argv[3])
db_password         = (sys.argv[4])
db_name             = "carbonblack_stg"

# CB vars
cb_api_id           = (sys.argv[5])
cb_api_secret_key   = (sys.argv[6])
cb_tenant           = (sys.argv[7])
cb_url              = "https://defense-prod05.conferdeploy.net"

try:
    conexao = pyodbc.connect("DRIVER={ODBC Driver 17 for SQL Server};SERVER=%s;DATABASE=%s;UID=%s;PWD=%s" % (db_hostname, db_name, db_username, db_password))
    cursor = conexao.cursor()
    headers = {
    'content-type': "application/json",
    'X-AUTH-TOKEN': cb_api_secret_key + "/" + cb_api_id,
    }
    funcao(headers, cursor, cb_tenant, cb_url)
except BaseException as e:
    print("Falha na conexão com o banco de dados. Erro: " + str(e))

