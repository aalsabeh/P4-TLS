from bs4 import BeautifulSoup
import urllib.request
import os

''' 
html_page = urllib.request.urlopen("https://mcfp.felk.cvut.cz/publicDatasets/")
soup = BeautifulSoup(html_page, "html.parser")
for link in soup.findAll('a'):

    link1 = link.get('href')
    if "CTU-Malware-Capture-Botnet-" in link1:
        abs_path1 = "https://mcfp.felk.cvut.cz/publicDatasets/" + link1

        html_page2 = urllib.request.urlopen(abs_path1)
        soup2 = BeautifulSoup(html_page2, "html.parser")
        for link2 in soup2.findAll('a'):
            link3 = link2.get('href')
            
            try:
                if link3.endswith(".pcap"): 
                    abs_path2 = abs_path1 + link3
                    # print(abs_path2)
                    # if not os.path.exists("zeek_output_botnet/" + link3):
                    

                    if not os.path.exists("zeek_output_botnet/" + link3):
                        os.system("mkdir zeek_output/" + link3)
                    else:
                        continue

                    os.system("wget -P zeek_output_botnet/" + link3 + " " + abs_path2)
                    os.system("zeek -C -r zeek_output_botnet/" + link3 + "/" + link3)
                    os.system("mv *.log zeek_output_botnet/" + link3 + "/")
                    os.system("rm zeek_output_botnet/" + link3 + "/" + link3)

            except:
                continue
        # break
            

        

NORMAL
base_url = "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Normal-"

for i in range(4, 33):
    try:
        url = base_url + str(i) + "/"
        print(url)
        html_page = urllib.request.urlopen(url)
        soup = BeautifulSoup(html_page, "html.parser")

        for link in soup.findAll('a'):
            link1 = link.get('href')
            print(link1)
            try:
                if link1.endswith(".pcap"): 
                    download_link = url + link1
                    
                    output_dir = "Data/Processed/Benign_pcap/"
                    output_file = output_dir + str(i) + ".pcap"
                    print()
                    # os.system("wget -P " + output_dir + " " + download_link)

                    # os.system("wget -P zeek_output_botnet/" + link1 + " " + abs_path2)
                    # os.system("zeek -C -r zeek_output_botnet/" + link1 + "/" + link1)
                    # os.system("mv *.log zeek_output_botnet/" + link1 + "/")
                    # os.system("rm zeek_output_botnet/" + link1 + "/" + link1)

            except Exception as e:
                print(e)
                continue
    except:
        continue
    # break
                
'''


html_page = urllib.request.urlopen("https://www.stratosphereips.org/datasets-normal")
soup = BeautifulSoup(html_page, "html.parser")
for link in soup.findAll('a'):
    try:
        link1 = link.get('href')
        if "CTU-Normal" in link1:
            abs_path1 = link1
            print(abs_path1)

            html_page2 = urllib.request.urlopen(abs_path1)
            soup2 = BeautifulSoup(html_page2, "html.parser")
            for link2 in soup2.findAll('a'):
                link3 = link2.get('href')
                

                try:
                    if link3.endswith(".pcap") and "only-dns" not in link3: 
                        abs_path2 = abs_path1 + "/" + link3

                        print(abs_path2)
                        os.system("wget -P Data/Processed/Benign_pcap/" + link3 + " " + abs_path2)
                        # break
                        # os.system("zeek -C -r zeek_output_botnet/" + link3 + "/" + link3)
                        # os.system("mv *.log zeek_output_botnet/" + link3 + "/")
                        # os.system("rm zeek_output_botnet/" + link3 + "/" + link3)

                except:
                    continue
    except:
        continue

            