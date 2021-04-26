import subprocess
import requests
import threading

print('''\033[1;36m
                                      010                                       
                                      010                                       
                            000000000 010 000000000                             
                       00000000000000 010 00000000000000                        
                    00000000000000000 010 00000000000000000                     
                 00000000000000       010        0000000000000                  
               00000000000       0    010    0          0000000000                
             00000000          00             00           000000000              
           00000000           000             000            00000000            
          00000000           0000             0000             00000000          
         0000000             0000   1111111   0000              00000000         
       0000000                0000111111111110000                0000000        
       000000                 0011111111111111100                 0000000       
      000000                   11111111111111111                   0000000      
     000000                   1111111111111111111                   000000      
     000000                  111111111111111111111                   000000     
    000000                  11111111111111111111111                  000000     
    000000         0000000011111111111111111111111110000000           00000     
    00000       00000000001111111111111111111111111110000000000       000000    
00000000000000 00000000000111111111111111111111111111100000000000 000000000000000
00000000000000           11111111111111111111111111111            000000000000000
    00000                11111111111111111111111111111                00000    
    000000         00000001111111111111111111111111111000000          00000     
    000000       0000000 11111111111111111111111111111 00000000      000000     
     000000    0000000   11111111111111111111111111111   0000000     00000    
     000000    00         111111111111111111111111111         00    000000      
      000000            00001111111111111111111111100000           000000       
       0000000        00000001111111111111111111110000000         0000000       
        0000000      000000  111111111111111111111   000000     00000000        
         0000000    000        11111111111111111        000    0000000          
          00000000                 111111111                 00000000           
            000000000                                      000000000            
             0000000000                                 000000000              
                00000000000           010           000000000000                
                  000000000000000     010     000000000000000                   
                     0000000000000000 010 0000000000000000                      
                         000000000000 010 0000000000000                         
                              0000000 010 0000000                               
                                      010                                       
                                      010                                      

                   -+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                   +      ..| Sub_Analyser v1.0 |..       +
                   -                                      -
                   -              By: Mesh3l              -
                   +         Twitter: Mesh3l_911          +
                   -+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                                                 
\033[1;m''')


def sub_analyser():

    try:
        sub_path = input("\n\033[1;37m [>]Input ur alive Sub-Domains list path : \033[1;m")
        print()
        with open(sub_path, 'r') as subs ,open('Vulnerable_SubDomains.txt', 'w') as results:
                vuln_count=0
                not_vuln_count=0
                sub_count=0

                for sub in subs.read().splitlines():
                    sub_count+=1
                    dig = str(subprocess.run(['dig', sub], capture_output=True))
                    vuln = ['.agilecrm.com','.netlify.com','.airee.ru','.animaapp.com','.amazonaws.com','.bitbucket.com','.createsend.com','.digitalocean.com','.ghost.io','.gemfury.com','.github.io','.cloudapp.net','.cloudapp.azure.com','.azurewebsites.net','.blob.core.windows.net','.cloudapp.azure.com','.azure-api.net','.azurehdinsight.net','.azureedge.net','.azurecontainer.io','.database.windows.net','.azuredatalakestore.net','.search.windows.net','.azurecr.io','.redis.cache.windows.net','.azurehdinsight.net','.servicebus.windows.net','.visualstudio.com','.helpscoutdocs.com','.ngrok.io','.pingdom.com','.readme.io','.smartjobboard.com','.mysmartjobboard.com','.strikinglydns.com','.surge.sh','.uberflip.com']

                    for i in vuln:
                        not_vuln=False
                        if ('CNAME' in dig) and (i in dig) and ('NXDOMAIN' in dig) and ('elb' not in dig) and ('compute' not in dig):
                            print("\033[1;32m if The Sub-Domain \033[1;m \033[1;37m{}\033[1;m\033[1;32m is available so it's 99.99% Vulnerable :) , The service is \033[1;m \033[1;37m{}\n\033[1;m".format(sub,i))
                            results.write("\n if The Sub-Domain ..| {} |.. is available so it's 99.99% Vulnerable :) , The service is ..| {} |.. \n".format(sub,i))
                            vuln_count+=1

                        elif ('CNAME' in dig) and (i in dig) and ('NXDOMAIN' not in dig) and ('elb' not in dig) and ('compute' not in dig):
                            try:
                                req = requests.get('https://' +sub)
                                status_https = req.status_code
                            except requests.exceptions.SSLError and requests.exceptions.ConnectionError:
                                status_https = 0

                            try:
                                req = requests.get('http://' +sub)
                                status_http = req.status_code
                            except requests.exceptions.SSLError and requests.exceptions.ConnectionError:
                                status_http = 0
                            if (status_https != 200 or status_https != 302 ) or (status_http != 200 or status_http != 302):
                                print("\033[1;32m id The Sub-Domain \033[1;m \033[1;37m{}\033[1;m\033[1;32m is available so it's 99.99% Vulnerable :) , The service is \033[1;m \033[1;37m{}\n\033[1;m".format(sub, i))
                                results.write("\n if The Sub-Domain ..| {} |.. is available so it's 80% Vulnerable :) , The service is ..| {} |.. \n".format(sub, i))
                                vuln_count+=1
                            else:
                                pass
                        else:
                            not_vuln=True
                    if not_vuln==True:
                        print("\033[1;31m Unfourtnalyy The Sub-Domain \033[1;m \033[1;37m{}\033[1;m\033[1;31m is 99.99% NOT Vulnerable :( \n\033[1;m".format(sub))
                        not_vuln_count+=1

                print("\033[1;36mSub-domains checked \033[1;m\033[1;37m{}\033[1;m\n\033[1;36mVulnerable:) \033[1;m\033[1;37m{}\033[1;m\n\033[1;36mNot Vulnerable:( \033[1;m\033[1;37m{}\033[1;m \n".format(sub_count,vuln_count,sub_count-vuln_count))
    except:
        print("\033[1;36m Please re-check the list's path :( \n \033[1;m")
        exit()
    results.close()


def main():
    sub_thread = threading.Thread(target=sub_analyser)
    sub_thread.start()
    sub_thread.join()
if __name__ == '__main__':
    main_thread = threading.Thread(target=main)
    main_thread.start()
    main_thread.join()

