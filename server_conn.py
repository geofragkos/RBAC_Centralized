from ldap3 import Connection, Server, ALL, NTLM, SUBTREE, MODIFY_REPLACE, LEVEL
from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
import subprocess
import time
import rbac_generation
import sys
import random
import string
import hashlib
import base64
import rbac_der_demo_getterv2 as getter


log_file = open("./log.txt","a")
sys.stdout = log_file

# Configuration
DEBUG = False

# Instantiate the application
app = Flask(__name__)
app.config.from_object(__name__)

# Enable CORS
CORS(app, resources={r'/*': {'origins': '*'}})

# Main Operations
# conn.modify_dn('cn=Akins,o=Utility 1,dc=my-domain,dc=com', 'cn=Test')
# conn.delete('cn=Utility Auditing,cn=Test,o=Utility 1,dc=my-domain,dc=com')
# c.modify_dn('cn=user2,ou=users,o=company', 'cn=user2', new_superior='ou=admins,o=company') # Move under new superior

# dn_string = 'cn='+name_list[1]+',o=Utility '+str(u+1)+',dc=my-domain,dc=com'
# conn.add(dn_string,'organizationalPerson',{'sn':name_list[0],'userPassword':"{MD5}" + passwd.decode('utf-8')})
# dn_string = 'cn='+value+',cn='+name_list[1]+',o=Utility '+str(u+1)+',dc=my-domain,dc=com'
# conn.add(dn_string, 'organizationalRole')



class Ldap_Connector:
    def __init__(self, ip, port, domain, password):
        self.ip = ip
        self.domain = domain
        self.password = password
        self.port = port  # Default LDAP port
        self.server = Server(self.ip, self.port, get_info = ALL)
        self.connection = Connection(self.server, self.domain, self.password, collect_usage=True)
        self.bind_response = self.connection.bind()

        print('------------------------------------------------------------------------------')
        print(' You are connected as: ')
        print(self.connection.extend.standard.who_am_i())
        print()
        print(' The connection details are: ')
        print(self.connection)
        print()
        print(' Server Information: ')
        print(self.server.info)
        print('------------------------------------------------------------------------------')


def update_profile_util(new_firstname, new_lastname, new_role, old_firstname, old_lastname, old_role, utility, check):
    if(check == 'fn'):     #DER
        ldap_con.connection.modify_dn('ou='+old_firstname+',o='+utility+',dc=my-domain,dc=com','ou='+new_firstname)
    else:
        if(old_role != new_role):
            if(old_role != ''):
                ldap_con.connection.modify_dn('cn='+old_role+',cn='+old_lastname+',o='+utility+',dc=my-domain,dc=com','cn='+new_role)
            else:
                dn_string = 'cn='+new_role+',cn='+old_lastname+',o='+utility+',dc=my-domain,dc=com'
                ldap_con.connection.add(dn_string, 'organizationalRole')


        if(old_lastname != new_lastname):
            ldap_con.connection.modify_dn('cn='+old_lastname+',o='+utility+',dc=my-domain,dc=com','cn='+new_lastname)
            old_lastname = new_lastname

        if(old_firstname != new_firstname):
            ldap_con.connection.modify('cn='+old_lastname+',o='+utility+',dc=my-domain,dc=com',{'sn': [(MODIFY_REPLACE, [new_firstname])]})

def revoke_role_util(last_name, old_role, new_role, utility):
    entry_dn = 'cn='+last_name+',o='+utility+',dc=my-domain,dc=com'
    if(('Utility' in str(utility))):
        for (model, perms) in getter.perm_dict['utility_or_dso'].items():
            for (perm_id, valuee) in perms[0].items():
                if valuee == '':
                    continue
                else:
                    dn_string = 'cn='+perm_id+','+'cn='+str(model)+',cn='+old_role+','+str(entry_dn)
                    ldap_con.connection.delete(dn_string)
            ldap_con.connection.delete('cn='+str(model)+',cn='+old_role+','+str(entry_dn))

    if('Service Provider' in str(utility)):
        for (model, perms) in getter.perm_dict['der_vendor_or_service_provider'].items():
            for (perm_id, valuee) in perms[0].items():
                if valuee == '':
                    continue
                else:
                    dn_string = 'cn='+perm_id+','+'cn='+str(model)+',cn='+old_role+','+str(entry_dn)
                    ldap_con.connection.delete(dn_string)
            ldap_con.connection.delete('cn='+str(model)+',cn='+old_role+','+str(entry_dn))

    if('DER Owners' in str(utility)):
        for (model, perms) in getter.perm_dict['der_owner'].items():
            for (perm_id, valuee) in perms[0].items():
                if valuee == '':
                    continue
                else:
                    dn_string = 'cn='+perm_id+','+'cn='+str(model)+',ou='+role+','+str(entry_dn)
                    ldap_con.connection.delete(dn_string)
            ldap_con.connection.delete('cn='+str(model)+',ou='+old_role+','+str(entry_dn))

    if('DER Owners' in str(utility)):
        ldap_con.connection.delete('ou='+old_role+','+str(entry_dn))
        ldap_con.connection.delete(str(entry_dn))

        item = {
            'firstName': name_list[0],
            'lastName': name_list[1],
            'role': der_device
        }
        DEROWNERS.remove(item)
    else:
        ldap_con.connection.delete('cn='+old_role+','+str(entry_dn))


def revoke_role_derowners(last_name, old_role, new_role, utility):
    entry_dn = 'cn='+last_name+',o='+utility+',dc=my-domain,dc=com'
    if(('Utility' in str(utility))):
        for (model, perms) in getter.perm_dict['utility_or_dso'].items():
            for (perm_id, valuee) in perms[0].items():
                if valuee == '':
                    continue
                else:
                    dn_string = 'cn='+perm_id+','+'cn='+str(model)+',cn='+old_role+','+str(entry_dn)
                    ldap_con.connection.delete(dn_string)
            ldap_con.connection.delete('cn='+str(model)+',cn='+old_role+','+str(entry_dn))

    if('Service Provider' in str(utility)):
        for (model, perms) in getter.perm_dict['der_vendor_or_service_provider'].items():
            for (perm_id, valuee) in perms[0].items():
                if valuee == '':
                    continue
                else:
                    dn_string = 'cn='+perm_id+','+'cn='+str(model)+',cn='+old_role+','+str(entry_dn)
                    ldap_con.connection.delete(dn_string)
            ldap_con.connection.delete('cn='+str(model)+',cn='+old_role+','+str(entry_dn))

    if('DER Owners' in str(utility)):
        old_role = 'DER Owner'
        for (model, perms) in getter.perm_dict['der_owner'].items():
            for (perm_id, valuee) in perms[0].items():
                if valuee == '':
                    continue
                else:
                    dn_string = 'cn='+perm_id+','+'cn='+str(model)+',ou='+old_role+','+str(entry_dn)
                    ldap_con.connection.delete(dn_string)
            ldap_con.connection.delete('cn='+str(model)+',ou='+old_role+','+str(entry_dn))

    if('DER Owners' in str(utility)):
        ldap_con.connection.delete('ou='+old_role+','+str(entry_dn))
        ldap_con.connection.delete(str(entry_dn))
    else:
        if('Security Admins' in str(utility)):
            ldap_con.connection.delete(entry_dn)

        elif('Security Auditors' in str(utility)):
            ldap_con.connection.delete(entry_dn)
        else:
            ldap_con.connection.delete('cn='+old_role+','+str(entry_dn))



def remove_entity_util1(entity_id, check):
    for entity in UTILITY1:
        if(check == 'fn'):
            if entity['firstName'] == entity_id:
                UTILITY1.remove(entity)
                return True
        else:
            if entity['lastName'] == entity_id:
                UTILITY1.remove(entity)
                return True
    return False

def remove_entity_util2(entity_id, check):
    for entity in UTILITY2:
        if(check == 'fn'):
            if entity['firstName'] == entity_id:
                UTILITY2.remove(entity)
                return True
        else:
            if entity['lastName'] == entity_id:
                UTILITY2.remove(entity)
                return True
    return False

def remove_entity_util3(entity_id, check):
    for entity in UTILITY3:
        if(check == 'fn'):
            if entity['firstName'] == entity_id:
                UTILITY3.remove(entity)
                return True
        else:
            if entity['lastName'] == entity_id:
                UTILITY3.remove(entity)
                return True
    return False

def remove_entity_util4(entity_id, check):
    for entity in UTILITY4:
        if(check == 'fn'):
            if entity['firstName'] == entity_id:
                UTILITY4.remove(entity)
                return True
        else:
            if entity['lastName'] == entity_id:
                UTILITY4.remove(entity)
                return True
    return False

def remove_entity_util5(entity_id, check):
    for entity in UTILITY5:
        if(check == 'fn'):
            if entity['firstName'] == entity_id:
                UTILITY5.remove(entity)
                return True
        else:
            if entity['lastName'] == entity_id:
                UTILITY5.remove(entity)
                return True
    return False

def remove_entity_sp1(entity_id, check):
    for entity in SP1:
        if(check == 'fn'):
            if entity['firstName'] == entity_id:
                SP1.remove(entity)
                return True
        else:
            if entity['lastName'] == entity_id:
                SP1.remove(entity)
                return True
    return False

def remove_entity_sp2(entity_id, check):
    for entity in SP2:
        if(check == 'fn'):
            if entity['firstName'] == entity_id:
                SP2.remove(entity)
                return True
        else:
            if entity['lastName'] == entity_id:
                SP2.remove(entity)
                return True
    return False

def remove_entity_sp3(entity_id, check):
    for entity in SP3:
        if(check == 'fn'):
            if entity['firstName'] == entity_id:
                SP3.remove(entity)
                return True
        else:
            if entity['lastName'] == entity_id:
                SP3.remove(entity)
                return True
    return False

def remove_entity_sp4(entity_id, check):
    for entity in SP4:
        if(check == 'fn'):
            if entity['firstName'] == entity_id:
                SP4.remove(entity)
                return True
        else:
            if entity['lastName'] == entity_id:
                SP4.remove(entity)
                return True
    return False

def remove_entity_sp5(entity_id, check):
    for entity in SP5:
        if(check == 'fn'):
            if entity['firstName'] == entity_id:
                SP5.remove(entity)
                return True
        else:
            if entity['lastName'] == entity_id:
                SP5.remove(entity)
                return True
    return False

def remove_entity_derowners(entity_id, check):
    for entity in DEROWNERS:
        if entity['lastName'] == entity_id:
            DEROWNERS.remove(entity)
            return True
    return False

def remove_entity_secadmins(entity_id, check):
    for entity in SECADMINS:
        if entity['lastName'] == entity_id:
            SECADMINS.remove(entity)
            return True
    return False

def remove_entity_secauditors(entity_id, check):
    for entity in SECAUDITORS:
        if entity['lastName'] == entity_id:
            SECAUDITORS.remove(entity)
            return True
    return False

@app.route('/showperm', methods=['PUT'])
def show_perm():
    start = time.time()
    response_object = {'status': 'success'}
    response_object['flag'] = 'True'
    response_object['answer'] = 'No'
    response_object['answer_op'] = ''
    if request.method == 'PUT':
        post_data = request.get_json()
        first_name = post_data.get('firstName')
        last_name = post_data.get('lastName')
        organization = post_data.get('parent')
        role = post_data.get('role')
        model = post_data.get('model')
        print(model)
        operation = post_data.get('operation')
        print(organization)
        if('DER' in first_name):
            response_object['flag'] = 'False'
        else:
            if(('Utility' in organization) or ('Service Provider' in organization)):
                base_domain = 'dc=my-domain,dc=com'
                organization = 'o=' + organization
                role_domain = 'cn='+ role
                model_domain = 'cn='+model

                if(role == ''):
                    response_object['flag'] = 'False'
                else:
                    # Level Query to get VMax, WMaxRtg, Manufacturer Permission
                    perm_query = ldap_con.connection.search(model_domain + ','+role_domain + ',' + 'cn=' + last_name + ',' + organization + ',' +  base_domain, '(&(cn=*))',search_scope=LEVEL, attributes=['*'])
                    print(model_domain + ',' + role_domain + ',' + organization + ',' + 'cn=' + last_name + ',' + base_domain)
                    for entry in ldap_con.connection.entries:
                        entry_cn = str(entry['cn'])
                        print(entry_cn)
                        print(operation)
                        entry_sn = str(entry['sn'])
                        if(entry_cn == operation):
                            response_object['answer'] = 'Yes'
                            response_object['answer_op'] = entry_sn

            else:
                base_domain = 'dc=my-domain,dc=com'
                organization = 'o=DER Owners'
                model_domain = 'cn='+model
                # Level Query to get VMax, WMaxRtg, Manufacturer Permission
                perm_query = ldap_con.connection.search(model_domain+','+'ou=DER Owner' + ',' + 'cn=' + last_name + ',' + organization + ',' +  base_domain, '(&(cn=*))',search_scope=LEVEL, attributes=['*'])
                for entry in ldap_con.connection.entries:
                    entry_cn = str(entry['cn'])
                    entry_sn = str(entry['sn'])
                    if(entry_cn == operation):
                        response_object['answer'] = 'Yes'
                        response_object['answer_op'] = entry_sn

        end = time.time()
        print('Show Permissions Query Time: '+ str(end-start))
        return jsonify(response_object)




@app.route('/showperm2', methods=['PUT'])
def show_perm2():
    start = time.time()
    response_object = {'status': 'success'}
    response_object['flag'] = 'True'
    if request.method == 'PUT':
        post_data = request.get_json()
        first_name = post_data.get('firstName')
        last_name = post_data.get('lastName')
        organization = post_data.get('parent')
        role = post_data.get('role')
        if('DER' in first_name):
            response_object['flag'] = 'False'
        else:
            if(('Utility' in organization) or ('Service Provider' in organization)):
                base_domain = 'dc=my-domain,dc=com'
                organization = 'o=' + organization
                role_domain = 'cn='+ role

                if(role == ''):
                    response_object['flag'] = 'False'
                else:
                    # Level Query to get VMax, WMaxRtg, Manufacturer Permission
                    for (model, perms) in getter.perm_dict['utility_or_dso'].items():
                        dn_string = 'cn='+str(model)+',cn='+value+',cn='+last_name+',o='+organization+',dc=my-domain,dc=com'
                        temp_str = ''
                        for (perm_id, valuee) in perms[0].items():
                            if valuee == '':
                                continue
                            else:
                                temp_str += str(perm_id) + ':' + str(valuee) + ','
                        response_object[str(model)] = temp_str
            else:
                base_domain = 'dc=my-domain,dc=com'
                organization = 'o=DER Owners'

                # Level Query to get VMax, WMaxRtg, Manufacturer Permission
                for (model, perms) in getter.perm_dict['der_owner'].items():
                    dn_string = 'cn='+str(model)+',cn='+value+',cn='+last_name[1]+',o='+organization+',dc=my-domain,dc=com'
                    temp_str = ''
                    for (perm_id, valuee) in perms[0].items():
                        if valuee == '':
                            continue
                        else:
                            temp_str += str(perm_id) + ':' + str(valuee) + ','
                    response_object[str(model)] = temp_str


        end = time.time()
        print('Show Permissions Query Time: '+ str(end-start))
        return jsonify(response_object)


@app.route('/get_entity_info', methods=['PUT'])
def get_entity_info():
    start = time.time()
    response_object = {'status': 'success'}
    response_object['flag'] = 'True'
    if request.method == 'PUT':
        post_data = request.get_json()
        original_username = post_data.get('username')
        username = original_username
        username = username.split(' ')
        first_name = username[0]
        last_name = username[1]
        role = 'DER Owner'
        if(ldap_con.connection.search('dc=my-domain,dc=com', '(&(cn='+last_name+')(sn='+first_name+'))', attributes=['*'])):
            for entry in ldap_con.connection.entries:
                entity = entry.entry_dn.split(',')
                entity = entity[1].split('=')
                entity = entity[1]

                ldap_con.connection.search('cn='+last_name+',o='+entity+',dc=my-domain,dc=com', '(&(objectClass=organizationalRole))',search_scope=SUBTREE,attributes=['*'])
                for sub_entry in ldap_con.connection.entries:
                    role = sub_entry.entry_dn.split(',')
                    role = role[0].split('=')
                    role = role[1]
                    print(role)


        else:
            entity = ''
            role = ''
            response_object['flag'] = 'False'

        response_object['entity'] = entity
        response_object['role'] = role
        end = time.time()
        print('Search User Query Time: '+ str(end-start))
        return jsonify(response_object)

@app.route('/check_entity_info', methods=['PUT'])
def check_entity_info():
    start = time.time()
    response_object = {'status': 'success'}
    response_object['flag'] = 'True'
    if request.method == 'PUT':
        post_data = request.get_json()
        original_username = post_data.get('username')
        username = original_username
        username = username.split(' ')
        first_name = username[0]
        last_name = username[1]
        role = 'DER Owner'
        if(ldap_con.connection.search('dc=my-domain,dc=com', '(&(cn='+last_name+'))', attributes=['*'])):
            for entry in ldap_con.connection.entries:
                entity = entry.entry_dn.split(',')
                entity = entity[1].split('=')
                entity = entity[1]

                ldap_con.connection.search('cn='+last_name+',o='+entity+',dc=my-domain,dc=com', '(&(objectClass=organizationalRole))',search_scope=SUBTREE,attributes=['*'])
                for sub_entry in ldap_con.connection.entries:
                    role = sub_entry.entry_dn.split(',')
                    role = role[0].split('=')
                    role = role[1]
                    print(role)


        else:
            entity = ''
            role = ''
            response_object['flag'] = 'False'

        response_object['entity'] = entity
        response_object['role'] = role
        end = time.time()
        print('Search User Query Time: '+ str(end-start))
        return jsonify(response_object)



def add_owner_device(username, role, device):
    name_list = username.split(' ')
    dn_string = 'cn='+name_list[1]+',o=DER Owners,dc=my-domain,dc=com'
    passwd = ''.join(random.choice(string.ascii_uppercase + string.digits + string.punctuation) for _ in range(6))
    passwd = passwd.encode('utf-8')
    original = passwd
    hashPassword = hashlib.md5()
    hashPassword.update(passwd)
    passwd = base64.b64encode(hashPassword.digest())
    ldap_con.connection.add(dn_string,'organizationalPerson',{'sn':name_list[0],'userPassword':'{MD5}' + passwd.decode('utf-8')})

    value = 'DER Owner'
    dn_string = 'ou='+'DER Owner'+',cn='+name_list[1]+',o=DER Owners,dc=my-domain,dc=com'
    ldap_con.connection.add(dn_string, 'organizationalUnit',{'description':device})

    for (model, perms) in getter.perm_dict['der_owner'].items():
        dn_string = 'cn='+str(model)+',cn='+value+',cn='+name_list[1]+',o=DER Owners,dc=my-domain,dc=com'
        ldap_con.connection.add(dn_string,'organizationalPerson',{'sn': ' '})

        for (perm_id, valuee) in perms[0].items():
            if valuee == '':
                continue
            else:
                dn_string = 'cn='+perm_id+','+'cn='+str(model)+',cn='+value+',cn='+name_list[1]+',o=DER Owners,dc=my-domain,dc=com'
                ldap_con.connection.add(dn_string,'organizationalPerson',{'sn':valuee})



    item = {
        'firstName': name_list[0],
        'lastName': name_list[1],
        'role': device
    }
    DEROWNERS.append(item)


def add_owner(username, role, association):
    name_list = username.split(' ')
    dn_string = 'cn='+name_list[1]+',o='+association+',dc=my-domain,dc=com'
    passwd = ''.join(random.choice(string.ascii_uppercase + string.digits + string.punctuation) for _ in range(6))
    original = passwd
    passwd = passwd.encode('utf-8')
    hashPassword = hashlib.md5()
    hashPassword.update(passwd)
    passwd = base64.b64encode(hashPassword.digest())
    ldap_con.connection.add(dn_string,'organizationalPerson',{'sn':name_list[0],'userPassword':"{MD5}" + passwd.decode('utf-8')})
    # Roles under Users
    dn_string = 'cn='+role+',cn='+name_list[1]+',o='+association+',dc=my-domain,dc=com'
    ldap_con.connection.add(dn_string, 'organizationalRole')
    print(association)
    if('Utility' in association):
        for (model, perms) in getter.perm_dict['utility_or_dso'].items():
            dn_string = 'cn='+str(model)+',cn='+role+',cn='+name_list[1]+',o='+association+',dc=my-domain,dc=com'
            ldap_con.connection.add(dn_string,'organizationalPerson',{'sn': ' '})

            for (perm_id, valuee) in perms[0].items():
                if valuee == '':
                    continue
                else:
                    dn_string = 'cn='+perm_id+','+'cn='+str(model)+',cn='+role+',cn='+name_list[1]+',o='+association+',dc=my-domain,dc=com'
                    ldap_con.connection.add(dn_string,'organizationalPerson',{'sn':valuee})

    elif('Service Provider' in association):
        for (model, perms) in getter.perm_dict['der_vendor_or_service_provider'].items():
            dn_string = 'cn='+str(model)+',cn='+role+',cn='+name_list[1]+',o='+association+',dc=my-domain,dc=com'
            ldap_con.connection.add(dn_string,'organizationalPerson',{'sn': ' '})

            for (perm_id, valuee) in perms[0].items():
                if valuee == '':
                    continue
                else:
                    dn_string = 'cn='+perm_id+','+'cn='+str(model)+',cn='+role+',cn='+name_list[1]+',o='+association+',dc=my-domain,dc=com'
                    ldap_con.connection.add(dn_string,'organizationalPerson',{'sn':valuee})



    item = {
        'firstName': name_list[0],
        'lastName': name_list[1],
        'role': role
    }

    print(association)
    if(association == 'Utility 1'):
        UTILITY1.append(item)
    elif(association == 'Utility 2'):
        print('MPIKAAAAA')
        print(item)
        UTILITY2.append(item)
    elif(association == 'Utility 3'):
        UTILITY3.append(item)
    elif(association == 'Utility 4'):
        UTILITY4.append(item)
    elif(association == 'Utility 5'):
        UTILITY5.append(item)
    elif(association == 'Service Provider 1'):
        SP1.append(item)
    elif(association == 'Service Provider 2'):
        SP2.append(item)
    elif(association == 'Service Provider 3'):
        SP3.append(item)
    elif(association == 'Service Provider 4'):
        SP4.append(item)
    elif(association == 'Service Provider 5'):
        SP5.append(item)
    elif(association == 'Security Auditor'):
        SECAUDITORS.append(item)
    else:
        SECADMINS.append(item)



@app.route('/add_user', methods=['PUT'])
def add_user():
    start = time.time()
    response_object = {'status': 'success'}
    if request.method == 'PUT':
        post_data = request.get_json()
        first_name = post_data.get('firstName')
        last_name = post_data.get('lastName')
        role = post_data.get('role')
        association = post_data.get('association')
        device = post_data.get('device')
        username = first_name + ' ' + last_name

        if (role == 'DER Owner'):
            user_query = ldap_con.connection.search('dc=my-domain,dc=com', '(&(cn='+last_name+')(sn='+first_name+'))', attributes=['*'])
            device_query = ldap_con.connection.search('dc=my-domain,dc=com', '(&(ou='+device+'))', attributes=['*'])
            if(user_query):
                response_object['sent_response'] = 'Existing User'

            if (device_query):
                response_object['sent_response'] = 'Existing DER Device'

            if((not user_query) and (not device_query)):
                add_owner_device(username, role, device)

        else:
            user_query = ldap_con.connection.search('dc=my-domain,dc=com', '(&(cn='+last_name+')(sn='+first_name+'))', attributes=['*'])
            if (user_query):
                response_object['sent_response'] = 'Existing User'
            else:
                add_owner(username,role,association)
    end = time.time()
    print('Add User Query Time: '+str(end-start))
    return jsonify(response_object)


@app.route('/get_der_info', methods=['PUT'])
def get_der_info():
    start = time.time()
    response_object = {'status': 'success'}
    response_object['flag'] = 'True'
    if request.method == 'PUT':
        post_data = request.get_json()
        username = post_data.get('username')

        device_query = ldap_con.connection.search('dc=my-domain,dc=com', '(&(ou='+username+'))',search_scope=SUBTREE,attributes=['*'])

        if(device_query):
            final_parent_string = ''
            for entry in ldap_con.connection.entries:
                entity = entry.entry_dn.split(',')
                entity = entity[1].split('=')
                entity = entity[1]
                final_parent_string += entity + ','

            owner_query = ldap_con.connection.search('o=DER Owners,dc=my-domain,dc=com', '(&(description='+username+'))',search_scope=SUBTREE,attributes=['*'])
            for entry in ldap_con.connection.entries:
                entity = entry.entry_dn.split(',')
                entity = entity[1].split('=')
                entity = entity[1]
                final_parent_string += entity


            response_object['sent_parent'] = final_parent_string

        else:
            response_object['sent_parent'] = ''
            response_object['flag'] = 'False'
    end = time.time()
    print('Search DER Info Query Time: '+str(end-start))
    return jsonify(response_object)

@app.route('/verify_utr',methods=['PUT'])
def verify_utr():
    start = time.time()
    response_object = {'status': 'success'}
    response_object['flag'] = 'True'
    if request.method == 'PUT':
        post_data = request.get_json()
        username = post_data.get('username')
        role = post_data.get('role')

        name_list = username.split(' ')
        user_query = ldap_con.connection.search('dc=my-domain,dc=com', '(&(cn='+name_list[1]+')(sn='+name_list[0]+'))', attributes=['*'])
        if(not user_query):
            response_object['flag'] = 'False'
        else:
            for entry in ldap_con.connection.entries:
                entity = entry.entry_dn.split(',')
                entity = entity[1].split('=')
                entity = entity[1]
                if(entity == 'DER Owners'):
                    asked_role = 'DER Owner'

                ldap_con.connection.search('cn='+name_list[1]+',o='+entity+',dc=my-domain,dc=com', '(&(objectClass=organizationalRole))',search_scope=SUBTREE,attributes=['*'])
                for sub_entry in ldap_con.connection.entries:
                    asked_role = sub_entry.entry_dn.split(',')
                    asked_role = asked_role[0].split('=')
                    asked_role = asked_role[1]

            print(role)
            print(asked_role)
            if(role == asked_role):
                response_object['sent_verification'] = True
                response_object['sent_parent'] = entity
            else:
                response_object['sent_verification'] = False
                response_object['sent_parent'] = ''

    end = time.time()
    print('Verify User Query Time: '+ str(end-start))
    return jsonify(response_object)


@app.route('/download', methods=['POST'])
def download():
    f = '/home/george/Desktop/Sandia_RBAC/Centralized_OpenLDAP/log.txt'
    return send_file(f,attachment_filename='test.txt',as_attachment=True)

@app.route('/find_info', methods=['PUT'])
def find_info():
    start = time.time()
    response_object = {'status': 'success'}
    if request.method == 'PUT':
        response_object['modify'] = ldap_con.connection.usage.modify_dn_operations + ldap_con.connection.usage.modify_operations
        response_object['add'] = ldap_con.connection.usage.add_operations
        response_object['delete'] = ldap_con.connection.usage.delete_operations
        response_object['transmitted'] = ldap_con.connection.usage.bytes_transmitted

    end = time.time()
    print('Information Query Time: '+ str(end-start))
    return jsonify(response_object)



@app.route('/delete_user', methods=['PUT'])
def delete_user():
    start = time.time()
    response_object = {'status': 'success'}
    response_object['flag'] = 'True'
    if request.method == 'PUT':
        post_data = request.get_json()
        username = post_data.get('username')
        if (not 'DER' in username):
            name_list = username.split(' ')
            user_query = ldap_con.connection.search('dc=my-domain,dc=com', '(&(cn='+name_list[1]+')(sn='+name_list[0]+'))',search_scope=SUBTREE, attributes=['*'])
            print(user_query)
            for entry in ldap_con.connection.entries:
                entity = entry.entry_dn.split(',')
                entity = entity[1].split('=')
                entity = entity[1]
                print(entity)
                if entity == 'DER Owners':
                    role = 'DER Owner'
                    ldap_con.connection.search('cn='+name_list[1]+',o='+entity+',dc=my-domain,dc=com', '(&(objectClass=organizationalUnit))',search_scope=SUBTREE,attributes=['*'])
                    der_device = str(ldap_con.connection.entries[0].description)
                else:
                    ldap_con.connection.search('cn='+name_list[1]+',o='+entity+',dc=my-domain,dc=com', '(&(objectClass=organizationalRole))',search_scope=SUBTREE,attributes=['*'])
                for sub_entry in ldap_con.connection.entries:
                    role = sub_entry.entry_dn.split(',')
                    role = role[0].split('=')
                    role = role[1]
            user_query = ldap_con.connection.search('dc=my-domain,dc=com', '(&(cn='+name_list[1]+')(sn='+name_list[0]+'))', search_scope=SUBTREE,attributes=['*'])
        else:
            user_query = ldap_con.connection.search('dc=my-domain,dc=com', '(&(ou='+username+'))', attributes=['*'])


        if(not user_query):
            response_object['flag'] = 'False'
        else:
            if 'DER' in username:
                final_parent = []
                for entry in ldap_con.connection.entries:
                    entity = entry.entry_dn.split(',')
                    entity = entity[1].split('=')
                    entity = entity[1]
                    final_parent.append(entity)

                # Delete all entries
                for parent in final_parent:
                    ldap_con.connection.delete('ou='+username+',o='+parent+',dc=my-domain,dc=com')

                    item = {
                        'firstName': username,
                        'lastName': '',
                        'role': ''
                    }

                    if(parent == 'Utility 1'):
                        UTILITY1.remove(item)
                    elif(parent == 'Utility 2'):
                        UTILITY2.remove(item)
                    elif(parent == 'Utility 3'):
                        UTILITY3.remove(item)
                    elif(parent == 'Utility 4'):
                        UTILITY4.remove(item)
                    elif(parent == 'Utility 5'):
                        UTILITY5.remove(item)
                    elif(parent == 'Service Provider 1'):
                        SP1.remove(item)
                    elif(parent == 'Service Provider 2'):
                        SP2.remove(item)
                    elif(parent == 'Service Provider 3'):
                        SP3.remove(item)
                    elif(parent == 'Service Provider 4'):
                        SP4.remove(item)
                    elif(parent == 'Service Provider 5'):
                        SP5.remove(item)



                owner_query = ldap_con.connection.search('o=DER Owners,dc=my-domain,dc=com', '(&(ou='+username+'))',search_scope=SUBTREE,attributes=['*'])
                for entry in ldap_con.connection.entries:
                    entity = entry.entry_dn.split(',')
                    entity = entity[1].split('=')
                    entity = entity[1]

                    query = ldap_con.connection.search('o=DER Owners,dc=my-domain,dc=com', '(&(cn='+entity+'))',search_scope=SUBTREE,attributes=['*'])

                    firstname=ldap_con.connection.entries[0]['sn']

                    ldap_con.connection.delete(entry.entry_dn)


                    item = {
                        'firstName': firstname,
                        'lastName': entity,
                        'role': username
                    }
                    print(item)

                    DEROWNERS.remove(item)

            else:
                print(ldap_con.connection.entries)
                for entry in ldap_con.connection.entries:
                    entity = entry.entry_dn.split(',')
                    entity = entity[1].split('=')
                    entity = entity[1]
                    print(entry.entry_dn)
                    if(('Utility' in str(entry.entry_dn))):
                        for (model, perms) in getter.perm_dict['utility_or_dso'].items():
                            for (perm_id, valuee) in perms[0].items():
                                if valuee == '':
                                    continue
                                else:
                                    dn_string = 'cn='+perm_id+','+'cn='+str(model)+',cn='+role+','+str(entry.entry_dn)
                                    ldap_con.connection.delete(dn_string)
                            ldap_con.connection.delete('cn='+str(model)+',cn='+role+','+str(entry.entry_dn))

                    if('Service Provider' in str(entry.entry_dn)):
                        for (model, perms) in getter.perm_dict['der_vendor_or_service_provider'].items():
                            for (perm_id, valuee) in perms[0].items():
                                if valuee == '':
                                    continue
                                else:
                                    dn_string = 'cn='+perm_id+','+'cn='+str(model)+',cn='+role+','+str(entry.entry_dn)
                                    ldap_con.connection.delete(dn_string)
                            ldap_con.connection.delete('cn='+str(model)+',cn='+role+','+str(entry.entry_dn))

                    if('DER Owners' in str(entry.entry_dn)):
                        for (model, perms) in getter.perm_dict['der_owner'].items():
                            for (perm_id, valuee) in perms[0].items():
                                if valuee == '':
                                    continue
                                else:
                                    dn_string = 'cn='+perm_id+','+'cn='+str(model)+',ou='+role+','+str(entry.entry_dn)
                                    ldap_con.connection.delete(dn_string)
                            ldap_con.connection.delete('cn='+str(model)+',ou='+role+','+str(entry.entry_dn))

                    if('DER Owners' in str(entry.entry_dn)):
                        ldap_con.connection.delete('ou='+role+','+str(entry.entry_dn))
                        ldap_con.connection.delete(str(entry.entry_dn))

                        item = {
                            'firstName': name_list[0],
                            'lastName': name_list[1],
                            'role': der_device
                        }
                        DEROWNERS.remove(item)
                    else:
                        ldap_con.connection.delete('cn='+role+','+str(entry.entry_dn))
                        ldap_con.connection.delete(str(entry.entry_dn))

                        item = {
                            'firstName': name_list[0],
                            'lastName': name_list[1],
                            'role': role
                        }

                        if(entity == 'Utility 1'):
                            UTILITY1.remove(item)
                        elif(entity == 'Utility 2'):
                            UTILITY2.remove(item)
                        elif(entity == 'Utility 3'):
                            UTILITY3.remove(item)
                        elif(entity == 'Utility 4'):
                            UTILITY4.remove(item)
                        elif(entity == 'Utility 5'):
                            UTILITY5.remove(item)
                        elif(entity == 'Service Provider 1'):
                            SP1.remove(item)
                        elif(entity == 'Service Provider 2'):
                            SP2.remove(item)
                        elif(entity == 'Service Provider 3'):
                            SP3.remove(item)
                        elif(entity == 'Service Provider 4'):
                            SP4.remove(item)
                        elif(entity == 'Service Provider 5'):
                            SP5.remove(item)
                        elif(entity == 'Security Auditor'):
                            SECAUDITORS.remove(item)
                        elif (entity == 'Security Admins'):
                            SECADMINS.remove(item)
                        else:
                            pass


        end = time.time()
        print('Delete User Query Time: '+str(end-start))
        return jsonify(response_object)


def add_der(username, association):

    dn_string = 'ou='+username+',o='+association+',dc=my-domain,dc=com'
    ldap_con.connection.add(dn_string,'organizationalUnit')

    item = {
        'firstName': username,
        'lastName': '',
        'role': ''
    }

    if(association == 'Utility 1'):
        UTILITY1.append(item)
    elif(association == 'Utility 2'):
        UTILITY2.append(item)
    elif(association == 'Utility 3'):
        UTILITY3.append(item)
    elif(association == 'Utility 4'):
        UTILITY4.append(item)
    elif(association == 'Utility 5'):
        UTILITY5.append(item)
    elif(association == 'Service Provider 1'):
        SP1.append(item)
    elif(association == 'Service Provider 2'):
        SP2.append(item)
    elif(association == 'Service Provider 3'):
        SP3.append(item)
    elif(association == 'Service Provider 4'):
        SP4.append(item)
    else:
        SP5.append(item)


@app.route('/add_der_device', methods=['PUT'])
def add_der_device():
    start = time.time()
    response_object = {'status': 'success'}
    if request.method == 'PUT':
        post_data = request.get_json()
        username = post_data.get('device')
        associations = post_data.get('association')
        device_query = ldap_con.connection.search('dc=my-domain,dc=com', '(&(ou='+username+'))',search_scope=SUBTREE,attributes=['*'])

        if (device_query):
            response_object['sent_response'] = 'Existing DER'
        else:
            for association in associations:
                add_der(username, association)

    end = time.time()
    print('Add DER Query Time: '+str(end-start))
    return jsonify(response_object)


@app.route('/utility1revoke', methods=['PUT'])
def entity1_revoke():
    start = time.time()
    response_object = {'status': 'success'}
    if request.method == 'PUT':
        post_data = request.get_json()
        first_name = post_data.get('firstName')
        last_name = post_data.get('lastName')
        remove_entity_util1(last_name, 'ln')

        # Update blockchain entries
        old_role = post_data.get('oldRole')
        new_role = ''
        revoke_role_util(last_name, old_role, new_role, 'Utility 1')
        UTILITY1.append({
            'firstName': first_name,
            'lastName': last_name,
            'role': new_role
        })
        response_object['message'] = 'Entity is updated!'
    end = time.time()
    print('Revoke Centralized:'+str(end-start))
    return jsonify(response_object)

@app.route('/utility2revoke', methods=['PUT'])
def entity2_revoke():
    response_object = {'status': 'success'}
    if request.method == 'PUT':
        post_data = request.get_json()
        first_name = post_data.get('firstName')
        last_name = post_data.get('lastName')
        remove_entity_util2(last_name, 'ln')

        # Update blockchain entries
        old_role = post_data.get('oldRole')
        new_role = ''
        revoke_role_util(last_name, old_role, new_role, 'Utility 2')
        UTILITY2.append({
            'firstName': first_name,
            'lastName': last_name,
            'role': new_role
        })
        response_object['message'] = 'Entity is updated!'
    return jsonify(response_object)

@app.route('/utility3revoke', methods=['PUT'])
def entity3_revoke():
    response_object = {'status': 'success'}
    if request.method == 'PUT':
        post_data = request.get_json()
        first_name = post_data.get('firstName')
        last_name = post_data.get('lastName')
        remove_entity_util3(last_name, 'ln')

        # Update blockchain entries
        old_role = post_data.get('oldRole')
        new_role = ''
        revoke_role_util(last_name, old_role, new_role, 'Utility 3')
        UTILITY3.append({
            'firstName': first_name,
            'lastName': last_name,
            'role': new_role
        })
        response_object['message'] = 'Entity is updated!'
    return jsonify(response_object)

@app.route('/utility4revoke', methods=['PUT'])
def entity4_revoke():
    response_object = {'status': 'success'}
    if request.method == 'PUT':
        post_data = request.get_json()
        first_name = post_data.get('firstName')
        last_name = post_data.get('lastName')
        remove_entity_util4(last_name, 'ln')

        # Update blockchain entries
        old_role = post_data.get('oldRole')
        new_role = ''
        revoke_role_util(last_name, old_role, new_role, 'Utility 4')
        UTILITY4.append({
            'firstName': first_name,
            'lastName': last_name,
            'role': new_role
        })
        response_object['message'] = 'Entity is updated!'
    return jsonify(response_object)

@app.route('/utility5revoke', methods=['PUT'])
def entity5_revoke():
    response_object = {'status': 'success'}
    if request.method == 'PUT':
        post_data = request.get_json()
        first_name = post_data.get('firstName')
        last_name = post_data.get('lastName')
        remove_entity_util5(last_name, 'ln')

        # Update blockchain entries
        old_role = post_data.get('oldRole')
        new_role = ''
        revoke_role_util(last_name, old_role, new_role, 'Utility 5')
        UTILITY5.append({
            'firstName': first_name,
            'lastName': last_name,
            'role': new_role
        })
        response_object['message'] = 'Entity is updated!'
    return jsonify(response_object)

@app.route('/sp1revoke', methods=['PUT'])
def sp1_revoke():
    response_object = {'status': 'success'}
    if request.method == 'PUT':
        post_data = request.get_json()
        first_name = post_data.get('firstName')
        last_name = post_data.get('lastName')
        remove_entity_sp1(last_name, 'ln')

        # Update blockchain entries
        old_role = post_data.get('oldRole')
        new_role = ''
        revoke_role_util(last_name, old_role, new_role, 'Service Provider 1')
        SP1.append({
            'firstName': first_name,
            'lastName': last_name,
            'role': new_role
        })
        response_object['message'] = 'Entity is updated!'
    return jsonify(response_object)

@app.route('/sp2revoke', methods=['PUT'])
def sp2_revoke():
    response_object = {'status': 'success'}
    if request.method == 'PUT':
        post_data = request.get_json()
        first_name = post_data.get('firstName')
        last_name = post_data.get('lastName')
        remove_entity_sp2(last_name, 'ln')

        # Update blockchain entries
        old_role = post_data.get('oldRole')
        new_role = ''
        revoke_role_util(last_name, old_role, new_role, 'Service Provider 2')
        SP2.append({
            'firstName': first_name,
            'lastName': last_name,
            'role': new_role
        })
        response_object['message'] = 'Entity is updated!'
    return jsonify(response_object)

@app.route('/sp3revoke', methods=['PUT'])
def sp3_revoke():
    response_object = {'status': 'success'}
    if request.method == 'PUT':
        post_data = request.get_json()
        first_name = post_data.get('firstName')
        last_name = post_data.get('lastName')
        remove_entity_sp3(last_name, 'ln')

        # Update blockchain entries
        old_role = post_data.get('oldRole')
        new_role = ''
        revoke_role_util(last_name, old_role, new_role, 'Service Provider 3')
        SP3.append({
            'firstName': first_name,
            'lastName': last_name,
            'role': new_role
        })
        response_object['message'] = 'Entity is updated!'
    return jsonify(response_object)

@app.route('/sp4revoke', methods=['PUT'])
def sp4_revoke():
    response_object = {'status': 'success'}
    if request.method == 'PUT':
        post_data = request.get_json()
        first_name = post_data.get('firstName')
        last_name = post_data.get('lastName')
        remove_entity_sp4(last_name, 'ln')

        # Update blockchain entries
        old_role = post_data.get('oldRole')
        new_role = ''
        revoke_role_util(last_name, old_role, new_role, 'Service Provider 4')
        SP4.append({
            'firstName': first_name,
            'lastName': last_name,
            'role': new_role
        })
        response_object['message'] = 'Entity is updated!'
    return jsonify(response_object)

@app.route('/sp5revoke', methods=['PUT'])
def sp5_revoke():
    response_object = {'status': 'success'}
    if request.method == 'PUT':
        post_data = request.get_json()
        first_name = post_data.get('firstName')
        last_name = post_data.get('lastName')
        remove_entity_sp5(last_name, 'ln')

        # Update blockchain entries
        old_role = post_data.get('oldRole')
        new_role = ''
        revoke_role_util(last_name, old_role, new_role, 'Service Provider 5')
        SP5.append({
            'firstName': first_name,
            'lastName': last_name,
            'role': new_role
        })
        response_object['message'] = 'Entity is updated!'
    return jsonify(response_object)

@app.route('/derownersrevoke', methods=['PUT'])
def derowners_revoke():
    response_object = {'status': 'success'}
    if request.method == 'PUT':
        post_data = request.get_json()
        first_name = post_data.get('firstName')
        last_name = post_data.get('lastName')
        remove_entity_derowners(last_name, 'ln')

        new_role = ''
        revoke_role_derowners(last_name, '', new_role, 'DER Owners')
        response_object['message'] = 'Entity is updated!'
    return jsonify(response_object)

@app.route('/secadminsrevoke', methods=['PUT'])
def secadmins_revoke():
    response_object = {'status': 'success'}
    if request.method == 'PUT':
        post_data = request.get_json()
        first_name = post_data.get('firstName')
        last_name = post_data.get('lastName')
        remove_entity_secadmins(last_name, 'ln')

        new_role = ''
        revoke_role_derowners(last_name, '', new_role, 'Security Admins')
        response_object['message'] = 'Entity is updated!'
    return jsonify(response_object)

@app.route('/secauditorsrevoke', methods=['PUT'])
def secauditors_revoke():
    response_object = {'status': 'success'}
    if request.method == 'PUT':
        post_data = request.get_json()
        first_name = post_data.get('firstName')
        last_name = post_data.get('lastName')
        remove_entity_secauditors(last_name, 'ln')

        new_role = ''
        revoke_role_derowners(last_name, '', new_role, 'Security Auditors')
        response_object['message'] = 'Entity is updated!'
    return jsonify(response_object)

@app.route('/utility1modify', methods=['PUT'])
def modify_entity1():
    start = time.time()
    response_object = {'status': 'success'}
    if request.method == 'PUT':
        post_data = request.get_json()
        old_firstname = post_data.get('oldFirstName')
        old_lastname = post_data.get('oldLastname')
        old_role = post_data.get('oldRole')
        print(old_role)

        new_firstname = post_data.get('firstName')
        print(new_firstname)
        new_lastname = post_data.get('lastName')
        print(new_lastname)
        new_role = post_data.get('role')

        if(old_lastname == ''):     # DER
            remove_entity_util1(old_firstname,'fn')
            update_profile_util(new_firstname, new_lastname, new_role, old_firstname, old_lastname, old_role, 'Utility 1', 'fn')
        else:
            remove_entity_util1(old_lastname, 'ln')
            update_profile_util(new_firstname, new_lastname, new_role, old_firstname, old_lastname, old_role, 'Utility 1','ln')

        UTILITY1.append({
            'firstName': new_firstname,
            'lastName': new_lastname,
            'role': new_role
        })
        response_object['message'] = 'Entity is updated!'
    end = time.time()
    print('Modify Time:'+str(end-start))
    return jsonify(response_object)

@app.route('/utility2modify', methods=['PUT'])
def modify_entity2():
    response_object = {'status': 'success'}
    if request.method == 'PUT':
        post_data = request.get_json()
        old_firstname = post_data.get('oldFirstName')
        old_lastname = post_data.get('oldLastname')
        old_role = post_data.get('oldRole')
        print(old_role)

        new_firstname = post_data.get('firstName')
        print(new_firstname)
        new_lastname = post_data.get('lastName')
        print(new_lastname)
        new_role = post_data.get('role')
        print(new_role)

        if(old_lastname == ''):     # DER
            remove_entity_util2(old_firstname,'fn')
            update_profile_util(new_firstname, new_lastname, new_role, old_firstname, old_lastname, old_role, 'Utility 2', 'fn')
        else:
            remove_entity_util2(old_lastname, 'ln')
            update_profile_util(new_firstname, new_lastname, new_role, old_firstname, old_lastname, old_role, 'Utility 2','ln')

        UTILITY2.append({
            'firstName': new_firstname,
            'lastName': new_lastname,
            'role': new_role
        })
        response_object['message'] = 'Entity is updated!'
    return jsonify(response_object)

@app.route('/utility3modify', methods=['PUT'])
def modify_entity3():
    response_object = {'status': 'success'}
    if request.method == 'PUT':
        post_data = request.get_json()
        old_firstname = post_data.get('oldFirstName')
        old_lastname = post_data.get('oldLastname')
        old_role = post_data.get('oldRole')
        print(old_role)

        new_firstname = post_data.get('firstName')
        print(new_firstname)
        new_lastname = post_data.get('lastName')
        print(new_lastname)
        new_role = post_data.get('role')

        if(old_lastname == ''):     # DER
            remove_entity_util3(old_firstname,'fn')
            update_profile_util(new_firstname, new_lastname, new_role, old_firstname, old_lastname, old_role, 'Utility 3', 'fn')
        else:
            remove_entity_util3(old_lastname, 'ln')
            update_profile_util(new_firstname, new_lastname, new_role, old_firstname, old_lastname, old_role, 'Utility 3','ln')

        UTILITY3.append({
            'firstName': new_firstname,
            'lastName': new_lastname,
            'role': new_role
        })
        response_object['message'] = 'Entity is updated!'
    return jsonify(response_object)

@app.route('/utility4modify', methods=['PUT'])
def modify_entity4():
    response_object = {'status': 'success'}
    if request.method == 'PUT':
        post_data = request.get_json()
        old_firstname = post_data.get('oldFirstName')
        old_lastname = post_data.get('oldLastname')
        old_role = post_data.get('oldRole')
        print(old_role)

        new_firstname = post_data.get('firstName')
        print(new_firstname)
        new_lastname = post_data.get('lastName')
        print(new_lastname)
        new_role = post_data.get('role')

        if(old_lastname == ''):     # DER
            remove_entity_util4(old_firstname,'fn')
            update_profile_util(new_firstname, new_lastname, new_role, old_firstname, old_lastname, old_role, 'Utility 4', 'fn')
        else:
            remove_entity_util4(old_lastname, 'ln')
            update_profile_util(new_firstname, new_lastname, new_role, old_firstname, old_lastname, old_role, 'Utility 4','ln')

        UTILITY4.append({
            'firstName': new_firstname,
            'lastName': new_lastname,
            'role': new_role
        })
        response_object['message'] = 'Entity is updated!'
    return jsonify(response_object)

@app.route('/utility5modify', methods=['PUT'])
def modify_entity5():
    response_object = {'status': 'success'}
    if request.method == 'PUT':
        post_data = request.get_json()
        old_firstname = post_data.get('oldFirstName')
        old_lastname = post_data.get('oldLastname')
        old_role = post_data.get('oldRole')
        print(old_role)

        new_firstname = post_data.get('firstName')
        print(new_firstname)
        new_lastname = post_data.get('lastName')
        print(new_lastname)
        new_role = post_data.get('role')

        if(old_lastname == ''):     # DER
            remove_entity_util5(old_firstname,'fn')
            update_profile_util(new_firstname, new_lastname, new_role, old_firstname, old_lastname, old_role, 'Utility 5', 'fn')
        else:
            remove_entity_util5(old_lastname, 'ln')
            update_profile_util(new_firstname, new_lastname, new_role, old_firstname, old_lastname, old_role, 'Utility 5','ln')

        UTILITY5.append({
            'firstName': new_firstname,
            'lastName': new_lastname,
            'role': new_role
        })
        response_object['message'] = 'Entity is updated!'
    return jsonify(response_object)

@app.route('/sp1modify', methods=['PUT'])
def modify_sp1():
    response_object = {'status': 'success'}
    if request.method == 'PUT':
        post_data = request.get_json()
        old_firstname = post_data.get('oldFirstName')
        old_lastname = post_data.get('oldLastname')
        old_role = post_data.get('oldRole')
        print(old_role)

        new_firstname = post_data.get('firstName')
        print(new_firstname)
        new_lastname = post_data.get('lastName')
        print(new_lastname)
        new_role = post_data.get('role')

        if(old_lastname == ''):     # DER
            remove_entity_sp1(old_firstname,'fn')
            update_profile_util(new_firstname, new_lastname, new_role, old_firstname, old_lastname, old_role, 'Service Provider 1', 'fn')
        else:
            remove_entity_sp1(old_lastname, 'ln')
            update_profile_util(new_firstname, new_lastname, new_role, old_firstname, old_lastname, old_role, 'Service Provider 1','ln')

        SP1.append({
            'firstName': new_firstname,
            'lastName': new_lastname,
            'role': new_role
        })
        response_object['message'] = 'Entity is updated!'
    return jsonify(response_object)

@app.route('/sp2modify', methods=['PUT'])
def modify_sp2():
    response_object = {'status': 'success'}
    if request.method == 'PUT':
        post_data = request.get_json()
        old_firstname = post_data.get('oldFirstName')
        old_lastname = post_data.get('oldLastname')
        old_role = post_data.get('oldRole')
        print(old_role)

        new_firstname = post_data.get('firstName')
        print(new_firstname)
        new_lastname = post_data.get('lastName')
        print(new_lastname)
        new_role = post_data.get('role')

        if(old_lastname == ''):     # DER
            remove_entity_sp2(old_firstname,'fn')
            update_profile_util(new_firstname, new_lastname, new_role, old_firstname, old_lastname, old_role, 'Service Provider 2', 'fn')
        else:
            remove_entity_sp2(old_lastname, 'ln')
            update_profile_util(new_firstname, new_lastname, new_role, old_firstname, old_lastname, old_role, 'Service Provider 2','ln')

        SP2.append({
            'firstName': new_firstname,
            'lastName': new_lastname,
            'role': new_role
        })
        response_object['message'] = 'Entity is updated!'
    return jsonify(response_object)

@app.route('/sp3modify', methods=['PUT'])
def modify_sp3():
    response_object = {'status': 'success'}
    if request.method == 'PUT':
        post_data = request.get_json()
        old_firstname = post_data.get('oldFirstName')
        old_lastname = post_data.get('oldLastname')
        old_role = post_data.get('oldRole')
        print(old_role)

        new_firstname = post_data.get('firstName')
        print(new_firstname)
        new_lastname = post_data.get('lastName')
        print(new_lastname)
        new_role = post_data.get('role')

        if(old_lastname == ''):     # DER
            remove_entity_sp3(old_firstname,'fn')
            update_profile_util(new_firstname, new_lastname, new_role, old_firstname, old_lastname, old_role, 'Service Provider 3', 'fn')
        else:
            remove_entity_sp3(old_lastname, 'ln')
            update_profile_util(new_firstname, new_lastname, new_role, old_firstname, old_lastname, old_role, 'Service Provider 3','ln')

        SP3.append({
            'firstName': new_firstname,
            'lastName': new_lastname,
            'role': new_role
        })
        response_object['message'] = 'Entity is updated!'
    return jsonify(response_object)

@app.route('/sp4modify', methods=['PUT'])
def modify_sp4():
    response_object = {'status': 'success'}
    if request.method == 'PUT':
        post_data = request.get_json()
        old_firstname = post_data.get('oldFirstName')
        old_lastname = post_data.get('oldLastname')
        old_role = post_data.get('oldRole')
        print(old_role)

        new_firstname = post_data.get('firstName')
        print(new_firstname)
        new_lastname = post_data.get('lastName')
        print(new_lastname)
        new_role = post_data.get('role')

        if(old_lastname == ''):     # DER
            remove_entity_sp4(old_firstname,'fn')
            update_profile_util(new_firstname, new_lastname, new_role, old_firstname, old_lastname, old_role, 'Service Provider 4', 'fn')
        else:
            remove_entity_sp4(old_lastname, 'ln')
            update_profile_util(new_firstname, new_lastname, new_role, old_firstname, old_lastname, old_role, 'Service Provider 4','ln')

        SP4.append({
            'firstName': new_firstname,
            'lastName': new_lastname,
            'role': new_role
        })
        response_object['message'] = 'Entity is updated!'
    return jsonify(response_object)

@app.route('/sp5modify', methods=['PUT'])
def modify_sp5():
    response_object = {'status': 'success'}
    if request.method == 'PUT':
        post_data = request.get_json()
        old_firstname = post_data.get('oldFirstName')
        old_lastname = post_data.get('oldLastname')
        old_role = post_data.get('oldRole')
        print(old_role)

        new_firstname = post_data.get('firstName')
        print(new_firstname)
        new_lastname = post_data.get('lastName')
        print(new_lastname)
        new_role = post_data.get('role')

        if(old_lastname == ''):     # DER
            remove_entity_sp5(old_firstname,'fn')
            update_profile_util(new_firstname, new_lastname, new_role, old_firstname, old_lastname, old_role, 'Service Provider 5', 'fn')
        else:
            remove_entity_sp5(old_lastname, 'ln')
            update_profile_util(new_firstname, new_lastname, new_role, old_firstname, old_lastname, old_role, 'Service Provider 5','ln')

        SP5.append({
            'firstName': new_firstname,
            'lastName': new_lastname,
            'role': new_role
        })
        response_object['message'] = 'Entity is updated!'
    return jsonify(response_object)

@app.route('/derownersmodify', methods=['PUT'])
def modify_derowners():
    response_object = {'status': 'success'}
    if request.method == 'PUT':
        post_data = request.get_json()
        old_firstname = post_data.get('oldFirstName')
        old_lastname = post_data.get('oldLastname')
        old_role = post_data.get('oldRole')
        print(old_role)

        new_firstname = post_data.get('firstName')
        print(new_firstname)
        new_lastname = post_data.get('lastName')
        print(new_lastname)
        new_role = post_data.get('role')

        remove_entity_derowners(old_lastname, 'ln')
        update_profile_util(new_firstname, new_lastname, new_role, old_firstname, old_lastname, old_role, 'DER Owners','ln')

        DEROWNERS.append({
            'firstName': new_firstname,
            'lastName': new_lastname,
            'role': new_role
        })
        response_object['message'] = 'Entity is updated!'
    return jsonify(response_object)

@app.route('/secadminsmodify', methods=['PUT'])
def modify_secadmins():
    response_object = {'status': 'success'}
    if request.method == 'PUT':
        post_data = request.get_json()
        old_firstname = post_data.get('oldFirstName')
        old_lastname = post_data.get('oldLastname')

        new_firstname = post_data.get('firstName')
        print(new_firstname)
        new_lastname = post_data.get('lastName')
        print(new_lastname)

        remove_entity_secadmins(old_lastname, 'ln')
        update_profile_util(new_firstname, new_lastname, '', old_firstname, old_lastname, '', 'Security Admins','ln')

        SECADMINS.append({
            'firstName': new_firstname,
            'lastName': new_lastname
        })
        response_object['message'] = 'Entity is updated!'
    return jsonify(response_object)

@app.route('/secauditorsmodify', methods=['PUT'])
def modify_secauditors():
    response_object = {'status': 'success'}
    if request.method == 'PUT':
        post_data = request.get_json()
        old_firstname = post_data.get('oldFirstName')
        old_lastname = post_data.get('oldLastname')

        new_firstname = post_data.get('firstName')
        print(new_firstname)
        new_lastname = post_data.get('lastName')
        print(new_lastname)

        remove_entity_secauditors(old_lastname, 'ln')
        update_profile_util(new_firstname, new_lastname, '', old_firstname, old_lastname, '', 'Security Auditors','ln')

        SECAUDITORS.append({
            'firstName': new_firstname,
            'lastName': new_lastname
        })
        response_object['message'] = 'Entity is updated!'
    return jsonify(response_object)

@app.route('/utility1', methods=['GET'])
def entities_utility1():
    response_object = {'status': 'success'}
    response_object['entities'] = UTILITY1
    return jsonify(response_object)

@app.route('/utility2', methods=['GET'])
def entities_utility2():
    response_object = {'status': 'success'}
    response_object['entities'] = UTILITY2
    return jsonify(response_object)

@app.route('/utility3', methods=['GET'])
def entities_utility3():
    response_object = {'status': 'success'}
    response_object['entities'] = UTILITY3
    return jsonify(response_object)

@app.route('/utility4', methods=['GET'])
def entities_utility4():
    response_object = {'status': 'success'}
    response_object['entities'] = UTILITY4
    return jsonify(response_object)

@app.route('/utility5', methods=['GET'])
def entities_utility5():
    response_object = {'status': 'success'}
    response_object['entities'] = UTILITY5
    return jsonify(response_object)

@app.route('/sp1', methods=['GET'])
def entities_sp1():
    response_object = {'status': 'success'}
    response_object['entities'] = SP1
    return jsonify(response_object)

@app.route('/sp2', methods=['GET'])
def entities_sp2():
    response_object = {'status': 'success'}
    response_object['entities'] = SP2
    return jsonify(response_object)

@app.route('/sp3', methods=['GET'])
def entities_sp3():
    response_object = {'status': 'success'}
    response_object['entities'] = SP3
    return jsonify(response_object)

@app.route('/sp4', methods=['GET'])
def entities_sp4():
    response_object = {'status': 'success'}
    response_object['entities'] = SP4
    return jsonify(response_object)

@app.route('/sp5', methods=['GET'])
def entities_sp5():
    response_object = {'status': 'success'}
    response_object['entities'] = SP5
    return jsonify(response_object)

@app.route('/derowners', methods=['GET'])
def entities_derowners():
    response_object = {'status': 'success'}
    response_object['entities'] = DEROWNERS
    return jsonify(response_object)

@app.route('/secadmins', methods=['GET'])
def entities_secadmins():
    response_object = {'status': 'success'}
    response_object['entities'] = SECADMINS
    return jsonify(response_object)

@app.route('/secauditors', methods=['GET'])
def entities_secauditors():
    response_object = {'status': 'success'}
    response_object['entities'] = SECAUDITORS
    return jsonify(response_object)

@app.route('/get_delete_operations', methods=['GET'])
def get_delete_operations():
    return jsonify(ldap_con.connection.usage.delete_operations)

@app.route('/get_bind_operations', methods=['GET'])
def get_bind_operations():
    return jsonify(ldap_con.connection.usage.bind_operations)

@app.route('/get_add_operations', methods=['GET'])
def get_add_operations():
    return jsonify(ldap_con.connection.usage.add_operations)

@app.route('/get_modify_operations', methods=['GET'])
def get_modify_operations():
    return jsonify(ldap_con.connection.usage.modify_dn_operations + ldap_con.connection.usage.modify_operations)

@app.route('/get_received_bytes', methods=['GET'])
def get_received_bytes():
    return jsonify(ldap_con.connection.usage.bytes_received)

@app.route('/get_transmitted_bytes', methods=['GET'])
def get_transmitted_bytes():
    return jsonify(ldap_con.connection.usage.bytes_transmitted)

@app.route('/get_receive_time', methods=['GET'])
def get_receive_time():
    return jsonify(ldap_con.connection.usage.last_received_time)

@app.route('/get_transmission_time', methods=['GET'])
def get_transmission_time():
    return jsonify(ldap_con.connection.usage.last_transmitted_time)

@app.route('/get_socket_time', methods=['GET'])
def get_socket_time():
    return jsonify(ldap_con.connection.usage.open_socket_start_time)

@app.route('/get_admin_port', methods=['GET'])
def get_admin_port():
    return jsonify(ldap_con.server.port)

@app.route('/get_admin_server', methods=['GET'])
def get_admin_server():
    return jsonify(ldap_con.server.host)

@app.route('/get_admin_domain', methods=['GET'])
def get_admin_domain():
    return jsonify(ldap_con.connection.user)

@app.route('/auth', methods=['POST'])
def auth():
    response_object = {'status': 'success'}
    post_data = request.get_json()
    if (post_data['user'] == '' and post_data['password'] == ''):
        response_object['token'] = 'Token Granted'
    else:
        response_object['token'] = ''
    print(response_object['token'])
    return jsonify(response_object)

if __name__ == '__main__':
    start = time.time()
    subprocess.Popen(['./ldap_starter.sh'], shell = True)
    t = 20
    ip = '127.0.0.1'
    domain = 'cn=admin,dc=my-domain,dc=com'
    password = 'root'
    port = 389

    ldap_con = Ldap_Connector(ip, port, domain, password)

    UTILITY1 = []
    for (entity,value) in rbac_generation.rbac['Utility 1'].items():
        if entity == 'DER':
            for der in value:
                item = {
                    'firstName': der,
                    'lastName': '',
                    'role': ''
                }
                UTILITY1.append(item)
        else:
            res = entity.split(' ')
            item = {
                'firstName': res[0],
                'lastName': res[1],
                'role': value
            }
            UTILITY1.append(item)

    # ---------------- Utility 2 - JSON Creation ------------------ #
    UTILITY2 = []
    for (entity,value) in rbac_generation.rbac['Utility 2'].items():
        if entity == 'DER':
            for der in value:
                item = {
                    'firstName': der,
                    'lastName': '',
                    'role': ''
                }
                UTILITY2.append(item)
        else:
            res = entity.split(' ')
            item = {
                'firstName': res[0],
                'lastName': res[1],
                'role': value
            }
            UTILITY2.append(item)
    # ---------------- Utility 3 - JSON Creation ------------------ #
    UTILITY3 = []
    for (entity,value) in rbac_generation.rbac['Utility 3'].items():
        if entity == 'DER':
            for der in value:
                item = {
                    'firstName': der,
                    'lastName': '',
                    'role': ''
                }
                UTILITY3.append(item)
        else:
            res = entity.split(' ')
            item = {
                'firstName': res[0],
                'lastName': res[1],
                'role': value
            }
            UTILITY3.append(item)
    # ---------------- Utility 4 - JSON Creation ------------------ #
    UTILITY4 = []
    for (entity,value) in rbac_generation.rbac['Utility 4'].items():
        if entity == 'DER':
            for der in value:
                item = {
                    'firstName': der,
                    'lastName': '',
                    'role': ''
                }
                UTILITY4.append(item)
        else:
            res = entity.split(' ')
            item = {
                'firstName': res[0],
                'lastName': res[1],
                'role': value
            }
            UTILITY4.append(item)
    # ---------------- Utility 5 - JSON Creation ------------------ #
    UTILITY5 = []
    for (entity,value) in rbac_generation.rbac['Utility 5'].items():
        if entity == 'DER':
            for der in value:
                item = {
                    'firstName': der,
                    'lastName': '',
                    'role': ''
                }
                UTILITY5.append(item)
        else:
            res = entity.split(' ')
            item = {
                'firstName': res[0],
                'lastName': res[1],
                'role': value
            }
            UTILITY5.append(item)
# ---------------- SP 1 - JSON Creation ------------------ #
    SP1 = []
    for (entity,value) in rbac_generation.rbac['Service Provider 1'].items():
        if entity == 'DER':
            for der in value:
                item = {
                    'firstName': der,
                    'lastName': '',
                    'role': ''
                }
                SP1.append(item)
        else:
            res = entity.split(' ')
            item = {
                'firstName': res[0],
                'lastName': res[1],
                'role': value
            }
            SP1.append(item)

# ---------------- SP 2 - JSON Creation ------------------ #
    SP2 = []
    for (entity,value) in rbac_generation.rbac['Service Provider 2'].items():
        if entity == 'DER':
            for der in value:
                item = {
                    'firstName': der,
                    'lastName': '',
                    'role': ''
                }
                SP2.append(item)
        else:
            res = entity.split(' ')
            item = {
                'firstName': res[0],
                'lastName': res[1],
                'role': value
            }
            SP2.append(item)

# ---------------- SP 3 - JSON Creation ------------------ #
    SP3 = []
    for (entity,value) in rbac_generation.rbac['Service Provider 3'].items():
        if entity == 'DER':
            for der in value:
                item = {
                    'firstName': der,
                    'lastName': '',
                    'role': ''
                }
                SP3.append(item)
        else:
            res = entity.split(' ')
            item = {
                'firstName': res[0],
                'lastName': res[1],
                'role': value
            }
            SP3.append(item)

# ---------------- SP 4 - JSON Creation ------------------ #
    SP4 = []
    for (entity,value) in rbac_generation.rbac['Service Provider 4'].items():
        if entity == 'DER':
            for der in value:
                item = {
                    'firstName': der,
                    'lastName': '',
                    'role': ''
                }
                SP4.append(item)
        else:
            res = entity.split(' ')
            item = {
                'firstName': res[0],
                'lastName': res[1],
                'role': value
            }
            SP4.append(item)

# ---------------- SP 5 - JSON Creation ------------------ #
    SP5 = []
    for (entity,value) in rbac_generation.rbac['Service Provider 5'].items():
        if entity == 'DER':
            for der in value:
                item = {
                    'firstName': der,
                    'lastName': '',
                    'role': ''
                }
                SP5.append(item)
        else:
            res = entity.split(' ')
            item = {
                'firstName': res[0],
                'lastName': res[1],
                'role': value
            }
            SP5.append(item)


# ---------------- DER Owners - JSON Creation ------------------ #
    DEROWNERS = []
    for (entity,value) in rbac_generation.rbac['DER Device'].items():
        res = entity.split(' ')
        item = {
            'firstName': res[0],
            'lastName': res[1],
            'role': value
        }
        DEROWNERS.append(item)

# ---------------- Security Administrators - JSON Creation ------------------ #
    SECADMINS = []
    for (entity,value) in rbac_generation.rbac['Security Administrator'].items():
        res = entity.split(' ')
        item = {
            'firstName': res[0],
            'lastName': res[1],
        }
        SECADMINS.append(item)

    SECAUDITORS = []
    for (entity,value) in rbac_generation.rbac['Security Auditor'].items():
        res = entity.split(' ')
        item = {
            'firstName': res[0],
            'lastName': res[1],
        }
        SECAUDITORS.append(item)

    end = time.time()
    print('Connection Instantiation: '+str(end-start))
    app.run(host='localhost', port=5001, threaded=True)
    print('End')


