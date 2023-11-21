"""
 v0.54
 
 Diego Garcia @ 2021-2023
    
 Source:
        https://threatfeeds.io/, https://firebog.net/ 
        http://iplists.firehol.org/  (lista updates)        
        google,reddit, 
        
 Fortigate usage:
 WARNING: Fortigate max: 10 MB or 128 × 1024 (131072) entries
 I create a cronjob task in my internal webserver (24h) to launch this script
 Then your fortigate must download the final files ips.txt domains.txt from your 
 webserver.


 TODO: Split files

"""

import os
from urllib.request import urlopen
from urllib.parse import urlparse

import re

######################################## START CONFIG ##################################################
# Show Debug Output

pDebug = set()
pDebug = 0

# Show Invalid Output
pDebugInvalid = set()
pDebugInvalid = 0

# Download url lists(1)  or use the already download files (testing purpose)
pDowload = set()
pDownload = 1

#App/Working dir
app_path = '/opt/firewall-threat'

# Where we save downloaded files
output_dir =  app_path +'/downloads'

# Final dir  
# ip.txt domains.txt 
output_final_dir  = '/var/www/html/fw_rules/'



# URL list, ips or domains
# Warning: Think where you going to use the threads (rules)  before  place lists with bogons networks
# Fortigate: 130000 entrys max without split files , we only split into one ip list  and one  domain list.

urls = [
# Custom Blacklist
    ('http://172.20.4.3/fw_rules/custom.txt', None),
# New
    # Binart Defense (7000)
    ('https://www.binarydefense.com/banlist.txt', None),
    # bruteforceblocker 274
    ('https://danger.rulez.sk/projects/bruteforceblocker/blist.php', None),
    # 389
    ('http://lists.blocklist.de/lists/strongips.txt', None),
    # 326
    ('https://lists.blocklist.de/lists/bruteforcelogin.txt', None),
    # 42
    ('https://iplists.firehol.org/files/dyndns_ponmocup.ipset', None),
    # 1268
    ('https://iplists.firehol.org/files/firehol_webclient.netset', None),
# Checked they update
    # Cins 15000
    ('http://cinsscore.com/list/ci-badguys.txt', None),
    # 600
    ('https://iplists.firehol.org/files/cybercrime.ipset', None),
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
    # Dshield Original necesita reformateo, nos lo ahorramos usando alt
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
    # 600
    ('https://iplists.firehol.org/files/cybercrime.ipset', None),
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
    # 43000 Big
    ('https://v.firebog.net/hosts/Prigent-Malware.txt', None),
    # Too Big
    #('https://v.firebog.net/hosts/RPiList-Malware.txt', None),
    # Too Big 139000
    # ('https://v.firebog.net/hosts/RPiList-Phishing.txt', None),
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
    #5000
    ('http://blocklist.greensnow.co/greensnow.txt', None),

# Offline
#

#Probably Old
#    ('https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt', None),
#    ('https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt', None),
# Old
#    ('https://reputation.alienvault.com/reputation.generic', None),
#    ('http://reputation.alienvault.com/reputation.data', None),
# 4 months
#    ('https://raw.githubusercontent.com/blocklistproject/Lists/master/malware.ip', None),
#    ('https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt', None),
#    ('https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt', None),
#    ('https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt', None),
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
lineas_validas = 0

# Usado para contar lineas con errores
lineas_errores = set()
lineas_errores = 0

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
    #ip_pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    #ip_pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d{1,2})?')
    ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d{1,2})?$')
    return ip_pattern.match(cadena)

# Función para determinar si una cadena es un dominio válido
def es_dominio_valido(cadena):
#     return bool(re.match(r'^[a-zA-Z0-9.-_]+$', cadena))
#     return bool(re.match(r'^[a-zA-Z0-9.-_]+\.[a-zA-Z]{2,}$', cadena))
      return bool(re.match(r'^[a-zA-Z0-9.-]+$', cadena))

# Función adicional test1
def test1():
    print("Ejecutando test1")
    # Agrega aquí las tareas adicionales que deseas realizar

# Función adicional test2
def test2():
    print("Ejecutando test2")
    # Agrega aquí las tareas adicionales que deseas realizar

# Descarga los archivos y ejecuta funciones adicionales si es necesario
if pDebug and pDownload:
  print("Downloading url list")
elif pDebug:
  print("Working without download url list")

for url, extra_function in urls:
    filename = os.path.join(output_dir, os.path.basename(url))
    basename = os.path.basename(url)

    if len(basename) == 0:
      parse_url = urlparse(url)
      filename = filename + parse_url.netloc
# Utilizamos curl por los redirects
#      descargar_archivo(url, filename)
#      subprocess.run(['curl', '-o', filename, url])


    if pDownload:
      if pDebug:
          print(f"Url: {url}")
          print(f"File/Dest: {filename}")
          os.system(f'curl -L -o {filename} {url}')
      else:
          os.system(f'curl -L -o {filename} {url} > /dev/null 2>&1')

#      if extra_function:
#          if extra_function == 'test1':
#              test1()
#          elif extra_function == 'test2':
#              test2()


# Procesa los archivos y separa IPs de dominios, ignorando líneas vacías y comentarios
def procesar_archivo(input_file, ip_output, domain_output, invalid_output):
    global lineas_duplicadas
    global lineas_errores
    global lineas_validas

    for line in input_file:
        line = line.strip()  # Elimina espacios en blanco y saltos de línea al inicio y final
        if line and not line.startswith('#') or line.startswith(';') or line.startswith("0.0.0.0"):  # Ignora líneas vacías y comentarios
            # Limpiamos la linea de posibles comentarios antes de meterla 
            line = re.split(r'#|;', line)[0].strip()

            if line not in lineas_procesadas:

                lineas_procesadas.add(line)
                if es_ip(line):
                    ip_output.write(line + '\n')
                    lineas_validas += 1
                elif es_dominio_valido(line):
                    domain_output.write(line + '\n')
                    lineas_validas += 1
                else:
                    invalid_output.write(line + '\n')
                    lineas_errores += 1
                    if pDebug and pDebugInvalid:
                        print(f"Invalid line: {line}")
            else:
                lineas_duplicadas += 1

with open(ip_output_file, 'w') as ip_output, open(domain_output_file, 'w') as domain_output, open(invalid_output_file, 'w') as invalid_output:
    for root, _, files in os.walk(output_dir):
        for file in files:
            with open(os.path.join(root, file), 'r') as input_file:
                procesar_archivo(input_file, ip_output, domain_output, invalid_output)

if pDebug:
  print(f'Final files: Ips "{ip_output_file}" Domains {domain_output_file}')
  print(f'Stats: Valid: {lineas_validas} Dup: {lineas_duplicadas} Error {lineas_errores}')

