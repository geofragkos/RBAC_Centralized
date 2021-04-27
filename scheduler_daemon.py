import subprocess
import sys
import time
import schedule

def start():
    subprocess.Popen(['./ldap_starter.sh'], shell = True)
    t = 10
    time.sleep(t)
    subprocess.call(['/opt/anaconda3/bin/python ./ldap_con.py'], shell=True)
    subprocess.Popen(['/opt/anaconda3/bin/python ./server_conn.py'], shell=True)
    time.sleep(300)
    subprocess.Popen(['./client/vue_run.sh'], shell=True)
    time.sleep(20)
    print("Web Server is up and running...")


def end():
    script1 = './server_conn.py'
    script2 = './free_ports.sh'

    subprocess.check_call(['pkill','-9','-f', script1])
    time.sleep(30)

    subprocess.Popen([script2], shell = True)
    time.sleep(30)

    subprocess.call(['./deleter.sh'], shell = True)
    time.sleep(30)

schedule.every().day.at("00:00").do(end)
schedule.every().day.at("00:10").do(start)

while True:
    schedule.run_pending()
