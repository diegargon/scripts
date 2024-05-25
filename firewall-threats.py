version = 'v0.66'
"""
 Diego Garcia @ 2021-2024

This script downloads the specified IP/network/domain lists (blacklist), removes invalid
and duplicate entries, and IPs in existing networks, then merges them into two files (ip.txt and domains.txt).

This script ignore ipv6 address

The default used ip/domains list are checked for use in fortigate avoiding exceed limits, the script provide
other list (some very big). If you want use just uncomment. Anyways check the stats in debug mode.

Stats ouput default list config:

Stats: Number of lists:  40
Stats: Valid: 125875 Dup: 11285 Error 89 InNet Discards 2365
Total IPs: 57536 Total Networks: 1614 Total Domains: 66724

Breaking changes:
    None... i think
Lastest changes:
 Check if individual ips are in any other blacklisted network
 Add checks & clean
 Minor improve parsing
 add  10 lists
 Remove old files before download
 
Requeriments:
    linux with curl
    (optional) web server to expose the files if you want automate the download
    
TODO: 
    Split big files that exceed X lines into smaller ones.
    
Sources:
    - https://threatfeeds.io/
    - https://firebog.net/
    - http://iplists.firehol.org/ (list updates)
    - others

    Fortigate usage:
    WARNING: Fortigate has a maximum limit of 10 MB or 128 × 1024 (131072) entries.
    
    I have created a cronjob task on my internal web server (every 24 hours) to launch this script.
    Then, Fortigate must download the final files ips.txt ("Threats IP list") and domains.txt
    ("Threats Domain List") from your web server.
    
    Opnsense usage:
        Firewall->aliases 
            Type Url(table ip)
            Content http://mywebserver/ips.txt
            
        Add the rule
    


"""

import os
import ipaddress
from urllib.request import urlopen
from urllib.parse import urlparse

import re

######################################## START CONFIG ##################################################

# Show Debug Output (default 0)
pDebug = set()
pDebug = 0

# Debug Invalid Output (default 0)
pDebugInvalid = set()
pDebugInvalid = 0

# Download url lists(1)  or (0) use the already download files (testing purpose) (defeault 1)
pDowload = set()
pDownload = 1

#App/Working dir
app_path = '/opt/firewall-threat'

# Where we save downloaded files
output_dir =  app_path +'/downloads'

# Final dir  
# ip.txt domains.txt 
output_final_dir  = '/var/www/html/fw_rules/'
#output_final_dir  = './'


# URL list, ips or domains
# Warning: Think where you going to use the threads (rules)  before  place lists with bogons networks
# Fortigate: 130000 entrys max without split files , this script only split into one ip list  and one  domain list.

urls = [
# Custom Blacklist
    #('http://172.20.4.3/fw_rules/custom.txt', None),
    #('http://192.168.2.71/fw_rules/custom.txt', None),
# Added new last git update
    # Big ip list +300k need split for fortigate
    #('https://jamesbrine.com.au/csv', None),
    # 400 domains
    ('https://v.firebog.net/hosts/static/w3kbl.txt', None),
    # +300k domains Privacy need split for fortigate
    #('https://v.firebog.net/hosts/Easyprivacy.txt', None),   
    # 121 domains
    #('https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt', None),       
    #  8000 domains
    ('https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/generated/hosts', None),
    #  900 domains
    ('https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt', None),         
    #  78000 ips DDOS
    #('https://blocklist.net.ua/blocklist.csv', None),    
    # IPs Boyscot daily: 1000
    ('https://iplists.firehol.org/files/botscout_1d.ipset', None),        
    #  IPs Cleantal daily: 1000
    ('https://iplists.firehol.org/files/cleantalk_1d.ipset', None),        
    #  IPs Firehol daily: 7000
    ('https://iplists.firehol.org/files/firehol_abusers_1d.netset', None),        
    #  Blocklist ssh daily: 3500
    ('http://lists.blocklist.de/lists/ssh.txt', None),        
    #  Cybercrime 1500 ips
    ('https://iplists.firehol.org/files/cybercrime.ipset', None),
    #  gpf_comics - IPs 3000
    ('https://iplists.firehol.org/files/gpf_comics.ipset', None),
    # firehol webclient 2000
    ('https://iplists.firehol.org/files/firehol_webclient.netset', None),    
    
# Added (2023-12-00)
    # Binart Defense (7000)
    ('https://www.binarydefense.com/banlist.txt', None),
    # 42
    ('https://iplists.firehol.org/files/dyndns_ponmocup.ipset', None),
    # 1268
    ('https://iplists.firehol.org/files/firehol_webclient.netset', None),
# Checked they still work && update (2024-05-25)
    # 389
    ('http://lists.blocklist.de/lists/strongips.txt', None),
    # 326
    ('https://lists.blocklist.de/lists/bruteforcelogin.txt', None),
    # bruteforceblocker 274
    ('https://danger.rulez.sk/projects/bruteforceblocker/blist.php', None),
    # 43000 Big 24MAY2024
    ('https://v.firebog.net/hosts/Prigent-Malware.txt', None),
    # RPILIST Phising domains: Too Big 139000 
    # ('https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/Phishing-Angriffe', None),  
    # RPILIST Malware domains: Too Big Warning NOT work: need extra parsing 
    #('https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/malware', None),        
# Checked they still work && update (2023-12-00)
    # Cins 15000
    ('http://cinsscore.com/list/ci-badguys.txt', None),
    # Torlist 7000  (We block by app filter)
    #('https://www.dan.me.uk/torlist/', None),
    #  276
    ('http://rules.emergingthreats.net/blockrules/compromised-ips.txt', None),
    # 1300
    ('https://iplists.firehol.org/files/firehol_webclient.netset', None),
    # 1243
    ('https://iplists.firehol.org/files/sslproxies_30d.ipset', None),
    # We block by app filter
    #('https://iplists.firehol.org/files/socks_proxy_30d.ipset', None),
    # 1000
    ('https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt', None),
    # 2000 With Bogons, Smahouse Drop, dshield, malare lists
    # We don't use we use the separated list to avoid bogons
    #('https://iplists.firehol.org/files/firehol_level1.netset', None),
    # 972
    ('http://www.spamhaus.org/drop/drop.txt', None),
    # Dshield Original need parse we use  alt download link
    #('http://feeds.dshield.org/block.txt', None),
    ('https://iplists.firehol.org/files/dshield.netset', None),
    # 27
    ('https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt', None),
    # 87
    ('https://feodotracker.abuse.ch/downloads/ipblocklist.txt', None),
    # sslbl
    ('https://sslbl.abuse.ch/blacklist/sslipblacklist.txt', None),
    # 5000 (fall redirect)
    ('https://talosintelligence.com/documents/ip-blacklist', None),
    # 15000
    ('https://osint.digitalside.it/Threat-Intel/lists/latestips.txt', None),
    # We block by app
    #('https://www.dan.me.uk/torlist/', None),
    # 22000
    ('https://lists.blocklist.de/lists/all.txt', None),
    # Spam list
    #('https://www.spamhaus.org/drop/edrop.txt', None),
    # 16000
    #('https://v.firebog.net/hosts/Prigent-Crypto.txt', None),
    # 50
    ('https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt', None),
    # 2000
    ('https://bitbucket.org/ethanr/dns-blacklists/raw/8575c9f96e5b4a1308f2f12394abd86d0927a4a0/bad_lists/Mandiant_APT1_Report_Appendix_D.txt', None), 
    # 147000 (too big need ip split)
    #    ('https://phishing.army/download/phishing_army_blocklist_extended.txt', None),
    # 145000 (too big need ip split)
    #    ('https://phishing.army/download/phishing_army_blocklist.txt', None),
    # 1000
    ('https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-malware.txt', None),
    # 900 Stalkerware
    ('https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/generated/hosts', None), 
    # 150
    ('http://www.botvrij.eu/data/ioclist.hostname.raw', None),
    # 150
    ('http://www.botvrij.eu/data/ioclist.domain.raw', None),
    # 150
    ('http://www.botvrij.eu/data/ioclist.ip-dst.raw', None),
    #6000
    ('https://www.darklist.de/raw.php', None),
    #5000 (many false relevant blocks) 
    #('http://blocklist.greensnow.co/greensnow.txt', None),


# pay
#    ('http://osint.bambenekconsulting.com/feeds/c2-ipmasterlist.txt', None),
#    ('', None),
#    ('', None),
#    ('', None),
#    ('', None),
#    ('', None),


]


######################################## END CONFIG ##################################################


# Usado para evitar duplicados
lineas_procesadas = set()

# Usado para contar  duplicados
lineas_duplicadas = set()
lineas_duplicadas = 0

# Usado para contar validas
lineas_validas = set()
lineas_validas = 1

# Usado para contar lineas con errores
lineas_errores = set()
lineas_errores = 0

# Ips encontradas dentro de una red previa
lineas_in_net = set()
lineas_in_net = 0

ips = []
redes = []
dominios = []
invalidas = []

os.makedirs(output_dir, exist_ok=True)
os.makedirs(output_final_dir, exist_ok=True)

# Archivos de salida para IPs y dominios
ip_output_file =  output_final_dir +  'ips.txt'
domain_output_file = output_final_dir + 'domains.txt'
invalid_output_file = app_path + '/invalid.txt'


# Función para descargar un archivo y guardar su contenido en un archivo local
# Problema redirect
#def descargar_archivo(url, output_path):
#    with urlopen(url) as response:
#        with open(output_path, 'wb') as file:
#            file.write(response.read())

# Función para determinar si una cadena es una IP
def es_ip(cadena):
    ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d{1,2})?$')
    return ip_pattern.match(cadena)

# Función para determinar si una cadena es un dominio válido
def es_dominio_valido(cadena):
      return bool(re.match(r'^[a-zA-Z0-9.-]+$', cadena))

# Función adicional test1
def test1():
    print("Ejecutando test1")
    # Agrega aquí las tareas adicionales que deseas realizar

# Función adicional test2
def test2():
    print("Ejecutando test2")
    # Agrega aquí las tareas adicionales que deseas realizar

# Get files data, and split
def procesar_archivos(input_file):
    global ips
    global redes
    global dominios
    global invalidas
    global lineas_duplicadas
    global lineas_errores
    global lineas_validas
    
    #if pDebug: 
        #print(f"Processing file {input_file}")    
    for line in input_file:           
        line = line.strip() 
        # Ignore empty lines, comments and any ip that begin with 0.
        if line and not line.startswith('#') or line.startswith(';') or line.startswith("0."):
            # Limpiamos la linea de posibles comentarios  y otros antes de meterla [#;,|]
            line = re.split(r'#|;|,|\|', line)[0]
            
            # Line.strip  seems missing some supposed blank spaces
            #line.strip()
            line = ''.join(line.strip().split())           
            
            if line not in lineas_procesadas:
                lineas_procesadas.add(line)
                if es_ip(line):
                    lineas_validas += 1
                    if '/' in line:
                        red = ipaddress.ip_network(line, strict=False)
                        redes.append(ipaddress.ip_network(red))
                    else:
                        ips.append(ipaddress.ip_address(line))
                elif es_dominio_valido(line):
                    dominios.append(line)
                    lineas_validas += 1
                else:                    
                    lineas_errores += 1
                    invalidas.append(line)
                    if pDebug and pDebugInvalid:
                        print(f"Invalid line: :{line}:")
            else:
                lineas_duplicadas += 1

# Funcion para procesar los datos obtenidos de los archivos
def procesar_datos(ip_output, domain_output, invalid_output):
        global lineas_in_net

        if pDebug: 
            print(f"Processing ips and writing to disk")
        for ip in ips:
            en_red = False
            for red in redes:
                if ip in red:
                    en_red = True
                    break
            if not en_red:        
                ip_output.write(str(ip) + '\n')
            else:
                lineas_in_net += 1

        if pDebug: 
            print(f"Processing networks and writing to disk")
        for red in redes:
            ip_output.write(str(red) + '\n')
        
        # Write the domain names to the domain_output file
        if pDebug: 
            print(f"Processing domains names and writing to disk")
        for dominio in dominios:
            domain_output.write(str(dominio) + '\n')

        if pDebug: 
            print(f"Processing invalid and writing to disk")
        # Write the invalid entries to the invalid_output file
        for invalida in invalidas:
            invalid_output.write(str(invalida) + '\n')
    
    
#MAIN    
if pDebug:
    print(f"Version {version}")
    
# Debug Working mode (Download or with already download files
if pDebug and pDownload:
  print("Downloading url list")
elif pDebug:
  print("Working without download url list")

if not os.path.isdir(app_path):
    print(f"Directory not exists: {app_path}")
    sys.exit(1)        

if not os.path.isdir(output_final_dir):
    print(f"Directory not exists: {output_final_dir}")
    sys.exit(1)        
    
if not os.path.isdir(output_dir):
    print(f"Directory not exists: {output_dir}")
    sys.exit(1)
    
if not os.access(output_dir, os.W_OK):
    print(f"Download folder isn't writable: {output_dir}")
    sys.exit(1)
    
# Delete old download files
if pDownload:
    for root, _, files in os.walk(output_dir):    
        for file in files:        
            removed_file = output_dir + '/' + file 
            if pDebug:
                print(f"Removing old file {removed_file}");                    
            os.remove(removed_file)
            
for url, extra_function in urls:
    filename = os.path.join(output_dir, os.path.basename(url))
    basename = os.path.basename(url)

    if len(basename) == 0:
      parse_url = urlparse(url)
      filename = filename + parse_url.netloc
# We use curl due problems with redirects
#      descargar_archivo(url, filename)
#      subprocess.run(['curl', '-o', filename, url])


    if pDownload:
      if pDebug:
          print(f"Url: {url}")
          print(f"File/Dest: {filename}")
          os.system(f'curl -L --max-time 10 -o {filename} {url}')
      else:
          os.system(f'curl -L --max-time 10 -o   {filename} {url} > /dev/null 2>&1')

#      if extra_function:
#          if extra_function == 'test1':
#              test1()
#          elif extra_function == 'test2':
#              test2()

    

# Procesa los archivos y separa IPs, REDESm, dominios, ignorando líneas vacías y comentarios

for root, _, files in os.walk(output_dir):    
    for file in files:        
        with open(os.path.join(root, file), 'r') as input_file:
            procesar_archivos(input_file)
            
with open(ip_output_file, 'w') as ip_output, open(domain_output_file, 'w') as domain_output, open(invalid_output_file, 'w') as invalid_output:                
    procesar_datos(ip_output, domain_output, invalid_output)
    
    
if pDebug:
  print(f'Final files: Ips "{ip_output_file}" Domains {domain_output_file}')
  print(f'Stats: Number of lists: ', len(urls))
  print(f'Stats: Valid: {lineas_validas} Dup: {lineas_duplicadas} Error {lineas_errores} InNet Discards {lineas_in_net}')
  print(f"Total IPs: {len(ips)} Total Networks: {len(redes)} Total Domains: {len(dominios)}")  


