from provisioning_handler import ProvisioningHandler
from config_loader import Config
from pyfiglet import Figlet
from provisioning_handler import *
import os

from flask import Flask, jsonify, request, render_template, flash
import datetime
from datetime import datetime
from flask_cors import CORS
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity
from flask_jwt_extended import (create_access_token)
from flask_api import status
import pyodbc 

from os import scandir

import glob

import boto3
from botocore.exceptions import NoCredentialsError

app = Flask(__name__)
app.config["DEBUG"] = True
app.config['SECRET_KEY'] = 'secret'
app.config['JWT_SECRET_KEY'] = 'secretkey'

CORS(app)

cnxn = pyodbc.connect('DRIVER={SQL Server};SERVER=JAYJHA;DATABASE=iot;UID=;PWD=')

jwt = JWTManager(app)

@app.route('/registration', methods = ['POST'])
def registration():
    Name=request.get_json()["Name"]
    Username =request.get_json()["Username"]
    Password=request.get_json()["Password"]
    cur = cnxn.cursor()
    cur.execute("Insert into Employee values ('"+str(Name)+"','"+str(Username)+"','"+str(Password)+"')")
    cnxn.commit()
    
    return jsonify({"status":"Ok"}), status.HTTP_200_OK

@app.route('/userlogin', methods = ['POST'])
def userlogin():
    email =request.get_json()["Username"]
    password = request.get_json()["Password"]

    cursor = cnxn.cursor()
    cursor.execute("Select * from Employee where Username = '" + str(email) + "' and Password = '" + str(password) + "'")
    row = cursor.fetchone()
    if row == None:
        return jsonify({"error":"Invalid Username or Password"}), status.HTTP_403_FORBIDDEN
    else:
        access_token = create_access_token(email,row[0])
        return jsonify({"token":access_token}), status.HTTP_200_OK
    


@app.route('/car-registration', methods = ['POST'])
def userhome():
    card = request.get_json(['card'])
    print(card['email'])
    if(card == None):
        return jsonify({"error"}), status.HTTP_406_NOT_ACCEPTABLE
    else:
        username = card['email']
        carName=card['carName']
        carId=card['carId']
        noOfThings=1
        pending=1
        cur = cnxn.cursor()
        #create_time = datetime.now()
        cur.execute("Insert into Thing values ('"+str(carName)+"','"+str(carId)+"','"+str(pending)+"','"+str(username)+"','"+str(noOfThings)+"')")
        
        cnxn.commit()
        return jsonify({'status':'Ok'}), status.HTTP_200_OK


@app.route('/adminhome', methods = ['GET'])
def adminhome():
    cur = cnxn.cursor()
    result = cur.execute("Select * from Thing")
    rows = result.fetchall()
    data = []
    for row in rows:
        data.append(list(row))
    
    return jsonify({'result':data}), status.HTTP_200_OK

######### Provisioning certificate #####################

#Set Config path
CONFIG_PATH = 'config.ini'

# config = Config(CONFIG_PATH)
# config_parameters = config.get_section('SETTINGS')
# secure_cert_path = config_parameters['SECURE_CERT_PATH']
# bootstrap_cert = config_parameters['CLAIM_CERT']


# def callback(payload):
#     print(payload)

# card = ""
# @app.route('/provisioning-cert',methods=['POST'])
# def run_provisioning(isRotation=False):
    
#     provisioner = ProvisioningHandler(CONFIG_PATH)

#     if isRotation:
#         provisioner.get_official_certs(callback, isRotation=True)  
#     else:
#         try:
#              with open("{}/{}".format(secure_cert_path, bootstrap_cert)):
#                 provisioner.get_official_certs(callback)
#                 card = request.get_json(['card'])
#                 search_dir = "C:/Users/jayjha/Desktop/BackendIoT/aws-iot-fleet-provisioning-master/certs"
 
#                 files = list(filter(os.path.isfile, glob.glob(search_dir + "/*.key")))
#                 files.sort(key=lambda x: os.path.getmtime(x))

#                 certi = list(filter(os.path.isfile, glob.glob(search_dir + "/*.crt")))
#                 certi.sort(key=lambda x: os.path.getmtime(x))

                   
#                 value = 1
#                 val = 1


#                 while val!=0:
#                     p = files[-val]
#                     c = certi[-val]
#                     val-=1
                    
#                     cur = cnxn.cursor()  
#                     email = card['user']
#                     carId=card['carId']
#                     print(carId)
#                     insert_stmt = (
#                     "Insert into certificate_table(priv_key,cert_crt,Username) values (?,?,?)"
#                     "INSERT INTO  certificate_table(user_Input,priv_key,cert_crt) "
#                     "VALUES (%s,%s,%s) where email = '" + str(email) + "' and no_of_things = '" + str(no_of_things) + "'"
#                     )

                    
#                     data = (p, c,email)
#                     print("iiiiiiiiiiiiiiiiiiii")
#                     print(data)
                    
#                     cur.execute(insert_stmt, data)
                    
#                     cur.execute("UPDATE Thing SET pending = 0 WHERE carId = '" + str(carId) + "'")

#                     cnxn.commit()

#              return jsonify({'status':"complete"}), status.HTTP_200_OK

#         except IOError:
#             print("### Bootstrap cert non-existent. Official cert may already be in place.")


# Set Config path
# CONFIG_PATH = 'config.ini'

config = Config(CONFIG_PATH)
config_parameters = config.get_section('SETTINGS')
secure_cert_path = config_parameters['SECURE_CERT_PATH']
bootstrap_cert = config_parameters['CLAIM_CERT']


def callback(payload):
    print(payload)

# card = ""
@app.route('/provisioning-cert',methods=['POST'])
def run_provisioning(isRotation=False):
    
    provisioner = ProvisioningHandler(CONFIG_PATH)

    if isRotation:
        provisioner.get_official_certs(callback, isRotation=True)  
    else:
        #Check for availability of bootstrap cert 
        try:
             with open("{}/{}".format(secure_cert_path, bootstrap_cert)):
                # Call super-method to perform aquisition/activation
                # of certs, creation of thing, etc. Returns general
                # purpose callback at this point.
                # Instantiate provisioning handler, pass in path to config
                provisioner.get_official_certs(callback)

                #Certificates Uploading to S3 Bucket
                BUCKET_NAME = 'provisioning-certificates'
                FOLDER_KEY = 'Certificates.key'
                FOLDER_CRT = 'Certificates.pem'

                session = boto3.Session(profile_name='nikhilbains')
                s3 = session.client('s3')

                # key_files = glob.glob("D:/certs/*.key")
                # crt_files = glob.glob("D:/certs/*.crt")
                key_files=glob.glob("C:/Users/jayjha/Desktop/BackendIoT/aws-iot-fleet-provisioning-master/certs")
                crt_files=glob.glob("C:/Users/jayjha/Desktop/BackendIoT/aws-iot-fleet-provisioning-master/certs")

                for filename in key_files:
                    key_priv = "%s/%s" % (FOLDER_KEY, os.path.basename(filename))
                    print("Putting %s as %s" % (filename,key_priv))
                    s3.upload_file(filename, BUCKET_NAME, key_priv)

                for filename in crt_files:
                    key_crt = "%s/%s" % (FOLDER_CRT, os.path.basename(filename))
                    print("Putting %s as %s" % (filename,key_crt))
                    s3.upload_file(filename, BUCKET_NAME, key_crt)

                print("All_Done")


########################Certificates paths and S3 Bucket URL storing in database##########################

                card = request.get_json(['card'])
                search_dir = "C:/Users/jayjha/Desktop/BackendIoT/aws-iot-fleet-provisioning-master/certs"
 
                files = list(filter(os.path.isfile, glob.glob(search_dir + "/*.key")))
                files.sort(key=lambda x: os.path.getmtime(x))

                certi = list(filter(os.path.isfile, glob.glob(search_dir + "/*.crt")))
                certi.sort(key=lambda x: os.path.getmtime(x))

                   
                value = 1
                val = 1


                while val!=0:
                    p = files[-val]
                    c = certi[-val]
                    val-=1

                    stringPriv = p[9:]
                    stringCert = c[9:]
                    key_certificate = f"https://provisioning-certificates.s3.us-east-2.amazonaws.com/Certificates.key/{stringPriv}"
                    crt_certificate = f"https://provisioning-certificates.s3.us-east-2.amazonaws.com/Certificates.pem/{stringCert}"
                    
                    cur = cnxn.cursor()  
                    email = card['user']
                    no_of_things=1
                    carId=card['carId']
                    insert_stmt = (
                    "Insert into certificate_table(priv_key,cert_crt,username) values (?,?,?,?,?)"
                    # "INSERT INTO  certificate_table(user_Input,priv_key,cert_crt,s3_key,s3_crt) "
                    # "VALUES (%s,%s,%s) where email = '" + str(email) + "' and no_of_things = '" + str(no_of_things) + "'"
                    )

                    
                    data = (p, c,email,key_certificate,crt_certificate)
                    print("iiiiiiiiiiiiiiiiiiii")
                    print(data)
                    
                    cur.execute(insert_stmt, data)
                    
                    cur.execute("UPDATE Thing SET pending = 0 WHERE carId = '" + str(carId) + "'")

                    cnxn.commit()
                arr = [p,c]
                return arr

             return jsonify({'status':"complete"}), status.HTTP_200_OK

        except IOError:
            print("### Bootstrap cert non-existent. Official cert may already be in place.")


############Publishing messages to AWS IOT Core##########################################

def publish_messages():
# Define ENDPOINT, CLIENT_ID, PATH_TO_CERT, PATH_TO_KEY, PATH_TO_ROOT, MESSAGE, TOPIC, and RANGE
    ENDPOINT = "a828ya1baox7v-ats.iot.us-east-2.amazonaws.com"
    CLIENT_ID = "testDevice"
    arr = run_provisioning()
    PATH_TO_KEY = arr[0]
    PATH_TO_CERT = arr[1]
    PATH_TO_ROOT = "D:/aws-iot-fleet-provisioning-master/aws-iot-fleet-provisioning-master/certs/root.ca.pem"
    TOPIC = "test/location"
    RANGE = 5

    myAWSIoTMQTTClient = AWSIoTPyMQTT.AWSIoTMQTTClient(CLIENT_ID)
    myAWSIoTMQTTClient.configureEndpoint(ENDPOINT, 8883)
    myAWSIoTMQTTClient.configureCredentials(PATH_TO_ROOT, PATH_TO_KEY, PATH_TO_CERT)

    myAWSIoTMQTTClient.connect()
    print('Begin Publish')
    for i in range (RANGE):
        precision = 0.000001
        f = 1/precision
        data = random.randrange(28.395348*f, 28.417421*f, 1)/f, random.randrange(77.040013*f, 77.046344*f, 1)/f
        message = {"vehicle_number": "1",
             "latitude" : data[0],
             "longitude" : data[1],
            "recordedat": datetime. now().strftime("%H:%M:%S")}
        myAWSIoTMQTTClient.publish(TOPIC, json.dumps(message), 1) 
        print("Location: " + json.dumps(message))
        t.sleep(0.1)
    print('Publish End')
    myAWSIoTMQTTClient.disconnect()


app.run()