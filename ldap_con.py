from ldap3 import Connection, Server, ALL, NTLM
import rbac_generation
import string
import random
import hashlib
import base64
import sys
import time
import subprocess
import rbac_der_demo_getterv2 as getter

'''
***** LDAP3 Connection Driver with OpenLDAP Server & RBAC Model Import to RBAC Model *****
@ Author: Georgios Fragkos
@ Connection as an Administrator to an openLDAP server
@ running at localhost:389 under the demo domain named:
@ my-domain.com (or dc=my-domain,dc=com)
'''


log_file = open("./log.txt","w")
sys.stdout = log_file

start = time.time()
subprocess.Popen(['./ldap_starter.sh'], shell = True)
t = 20
# ------ Connect as the OpenLDAP Administrator - Information ------
# Put the appropriate server name/ip and the admin credentials
server = Server('localhost', get_info = ALL)
conn   = Connection(server, 'cn=admin,dc=my-domain,dc=com','root',auto_bind=True)

# Check that you are connected as the administrator
print('---------------------------------------')
print('You are connected as:')
print(conn.extend.standard.who_am_i())
print
print('The connection details are:')
print(conn)
print('---------------------------------------')


# ------ Search for openLDAP entries (Example) ------- #
# TODO: Change this to show: Users, Roles and Permissions
conn.search('dc=my-domain,dc=com', '(objectclass=organizationalUnit)')
print
print('---------------------------------------')
print('The Organizational Units are:')
print(conn.entries)
print('---------------------------------------')


# ************************************** Automatic Import of RBAC model to the openLDAP **************************************

# -- Create all the utilities organizations in openLDAP --
for u in range(rbac_generation.n_utilities):
    org_string = 'o=Utility '+str(u+1)+',dc=my-domain,dc=com'
    conn.add(org_string,'organization')

    # Add DERs under Utilities in openLDAP
    utility_list_der = rbac_generation.rbac['Utility '+str(u+1)]['DER']
    for der in utility_list_der:
        dn_string = 'ou='+der+',o=Utility '+str(u+1)+',dc=my-domain,dc=com'
        conn.add(dn_string,'organizationalUnit')

    # Add Users and their Roles under Utilities in openLDAP
    dictionary_copy = rbac_generation.rbac['Utility '+str(u+1)].copy()
    # Keep only the users and their roles in the dictionary copy
    del dictionary_copy['DER']
    for (key, value) in dictionary_copy.items():
        key = str(key)
        value = str(value)

        # Users under Utilities
        # name_list[1] -> Surname (Unique - used as id), name_list[0] -> First name
        name_list = key.split(' ')
        dn_string = 'cn='+name_list[1]+',o=Utility '+str(u+1)+',dc=my-domain,dc=com'
        passwd = ''.join(random.choice(string.ascii_uppercase + string.digits + string.punctuation) for _ in range(6))
        original = passwd
        passwd = passwd.encode('utf-8')
        hashPassword = hashlib.md5()
        hashPassword.update(passwd)
        passwd = base64.b64encode(hashPassword.digest())
        conn.add(dn_string,'organizationalPerson',{'sn':name_list[0],'userPassword':"{MD5}" + passwd.decode('utf-8')})

        # Roles under Users
        dn_string = 'cn='+value+',cn='+name_list[1]+',o=Utility '+str(u+1)+',dc=my-domain,dc=com'
        conn.add(dn_string, 'organizationalRole')

        # Permissions under Roles
        for (model, perms) in getter.perm_dict['utility_or_dso'].items():
            dn_string = 'cn='+str(model)+',cn='+value+',cn='+name_list[1]+',o=Utility '+str(u+1)+',dc=my-domain,dc=com'
            conn.add(dn_string,'organizationalPerson',{'sn': ' '})

            for (perm_id, valuee) in perms[0].items():
                if valuee == '':
                    continue
                else:
                    dn_string = 'cn='+perm_id+','+'cn='+str(model)+',cn='+value+',cn='+name_list[1]+',o=Utility '+str(u+1)+',dc=my-domain,dc=com'
                    conn.add(dn_string,'organizationalPerson',{'sn':valuee})


# -- Create all the Service Providers in openLDAP --
for sp in range(2,rbac_generation.n_sp):
    org_string = 'o=Service Provider '+str(sp+1)+',dc=my-domain,dc=com'
    conn.add(org_string,'organization')

    # Add DERs under Service Providers in openLDAP
    sp_list_der = rbac_generation.rbac['Service Provider '+str(sp+1)]['DER']
    for der in sp_list_der:
        dn_string = 'ou='+der+',o=Service Provider '+str(sp+1)+',dc=my-domain,dc=com'
        conn.add(dn_string,'organizationalUnit')

    # Add Users and their Roles under Service Providers in openLDAP
    dictionary_copy = rbac_generation.rbac['Service Provider '+str(sp+1)].copy()
    # Keep only the users and their roles in the dictionary copy
    del dictionary_copy['DER']
    for (key,value) in dictionary_copy.items():
        key = str(key)
        value = str(value)

        # Users under Service Providers
        # name_list[1] -> Surname (Unique - user as id), name_list[0] -> First name
        name_list = key.split(' ')
        dn_string = 'cn='+name_list[1]+',o=Service Provider '+str(sp+1)+',dc=my-domain,dc=com'
        passwd = ''.join(random.choice(string.ascii_uppercase + string.digits + string.punctuation) for _ in range(6))
        original = passwd
        passwd = passwd.encode('utf-8')
        hashPassword = hashlib.md5()
        hashPassword.update(passwd)
        passwd = base64.b64encode(hashPassword.digest())
        conn.add(dn_string,'organizationalPerson',{'sn':name_list[0],'userPassword':"{MD5}" + passwd.decode('utf-8')})
        # Roles under Users
        dn_string = 'cn='+value+',cn='+name_list[1]+',o=Service Provider '+str(sp+1)+',dc=my-domain,dc=com'
        conn.add(dn_string, 'organizationalRole')

        # Permissions under Roles
        for (model, perms) in getter.perm_dict['der_vendor_or_service_provider'].items():
            dn_string = 'cn='+str(model)+',cn='+value+',cn='+name_list[1]+',o=Service Provider '+str(sp+1)+',dc=my-domain,dc=com'
            conn.add(dn_string,'organizationalPerson',{'sn': ' '})

            for (perm_id, valuee) in perms[0].items():
                if valuee == '':
                    continue
                else:
                    dn_string = 'cn='+perm_id+','+'cn='+str(model)+',cn='+value+',cn='+name_list[1]+',o=Service Provider '+str(sp+1)+',dc=my-domain,dc=com'
                    conn.add(dn_string,'organizationalPerson',{'sn':valuee})


# -- Create all the DER Owners in openLDAP --
org_string = 'o=DER Owners,dc=my-domain,dc=com'
conn.add(org_string,'organization')
dictionary_copy = rbac_generation.rbac['DER Owner'].copy()
# Keep only the users in the dictionary copy
for key,value in dictionary_copy.items():
    key = str(key)
    value = str(value)

    # Users under DER Owners
    # name_list[1] -> Surname (Unique - user as id), name_list[0] -> First name
    name_list = key.split(' ')
    dn_string = 'cn='+name_list[1]+',o=DER Owners,dc=my-domain,dc=com'
    passwd = ''.join(random.choice(string.ascii_uppercase + string.digits + string.punctuation) for _ in range(6))
    passwd = passwd.encode('utf-8')
    original = passwd
    hashPassword = hashlib.md5()
    hashPassword.update(passwd)
    passwd = base64.b64encode(hashPassword.digest())
    conn.add(dn_string,'organizationalPerson',{'sn':name_list[0],'userPassword':'{MD5}' + passwd.decode('utf-8')})
    # Roles under Users
    dn_string = 'ou='+value+',cn='+name_list[1]+',o=DER Owners,dc=my-domain,dc=com'
    conn.add(dn_string, 'organizationalUnit',{'description':rbac_generation.rbac['DER Device'][key]})

    # Permissions under Roles
    for (model, perms) in getter.perm_dict['der_owner'].items():
        dn_string = 'cn='+str(model)+',ou='+value+',cn='+name_list[1]+',o=DER Owners,dc=my-domain,dc=com'
        conn.add(dn_string,'organizationalPerson',{'sn': ' '})

        for (perm_id, valuee) in perms[0].items():
            if valuee == '':
                continue
            else:
                dn_string = 'cn='+perm_id+','+'cn='+str(model)+',ou='+value+',cn='+name_list[1]+',o=DER Owners,dc=my-domain,dc=com'
                conn.add(dn_string,'organizationalPerson',{'sn':valuee})


# Test a random user's password in openLDAP (Identity Server functionality)
print("DER Owner Name: "+str(name_list[1]))
print("Original Password: "+str(original))

# -- Create all the Security Administrators in openLDAP --
org_string = 'o=Security Admins,dc=my-domain,dc=com'
conn.add(org_string,'organization')
dictionary_copy = rbac_generation.rbac['Security Administrator'].copy()

for key,value in dictionary_copy.items():
    key = str(key)
    value = str(value)

    # Admins under Security Admins
    # name_list[1] -> Surname (Unique - user as id), name_list[0] -> First name
    name_list = key.split(' ')
    dn_string = 'cn='+name_list[1]+',o=Security Admins,dc=my-domain,dc=com'
    passwd = ''.join(random.choice(string.ascii_uppercase + string.digits + string.punctuation) for _ in range(6))
    original = passwd
    passwd = passwd.encode('utf-8')
    hashPassword = hashlib.md5()
    hashPassword.update(passwd)
    passwd = base64.b64encode(hashPassword.digest())
    conn.add(dn_string,'organizationalPerson',{'sn':name_list[0],'userPassword':"{MD5}" + passwd.decode('utf-8')})

# -- Create all the RBAC Auditors in openLDAP --
org_string = 'o=Security Auditors,dc=my-domain,dc=com'
conn.add(org_string,'organization')
dictionary_copy = rbac_generation.rbac['Security Auditor'].copy()

for key,value in dictionary_copy.items():
    key = str(key)
    value = str(value)

    # Admins under Security Admins
    # name_list[1] -> Surname (Unique - user as id), name_list[0] -> First name
    name_list = key.split(' ')
    dn_string = 'cn='+name_list[1]+',o=Security Auditors,dc=my-domain,dc=com'
    passwd = ''.join(random.choice(string.ascii_uppercase + string.digits + string.punctuation) for _ in range(6))
    original = passwd
    passwd = passwd.encode('utf-8')
    hashPassword = hashlib.md5()
    hashPassword.update(passwd)
    passwd = base64.b64encode(hashPassword.digest())
    conn.add(dn_string,'organizationalPerson',{'sn':name_list[0],'userPassword':"{MD5}" + passwd.decode('utf-8')})

conn.unbind()

end = time.time()
print('The overall elapsed time is: ' + str(end-start))