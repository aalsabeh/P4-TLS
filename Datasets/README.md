# Dataset sources
## Virus Total Malware samples
Malware sample were obtained from VirusTotal using the academic subscription. Samples given dated from 2017 to 2021. Each metadata file of the sample was analyzed. If 'TLS' occurrence exists, the sample is ran in an isolated environment (tria.ge) and its network traffic behavior (pcap file) is taken. Eventually, only pcap files that have TLS packets were collected. I will share the pcap files of these malware samples. Each sample is named "HASHbehavior1.pcap", where HASH is the hash of the malware sample.

The pcap files of the malware samples can be found here: https://drive.google.com/drive/folders/1X0_8NObY1ATFeUESnAdtNp7DQyGeo-wm?usp=sharing

## Benign samples (CTU)
Normal benign samples were obtained from CTU public available traffic: https://mcfp.felk.cvut.cz/publicDatasets/. In particular, we enumerate this link to pick normal traffic (CTU-Normal-...) and get its Zeek log file (ssl.log). Additionally, we enumerate CTU-13 dataset (CTU-42 ... CTU-55), which contain a mix of normal and malicious traffic. From CTU-13, we filter only normal IPs. The resulting Zeek log files is saved and can be found here: https://drive.google.com/drive/folders/13uKaithrG4Dil5KklDpdMvVGxBHpyAoF?usp=sharing

## Other data (Cloudflare Top 1M)
This can be obtained from here: https://radar.cloudflare.com/domains

## Other data (CTU Malware)
This was obtained from CTU public dataset https://mcfp.felk.cvut.cz/publicDatasets/. In particular, we enumerate this link to pick only malware/botnet traffic and get its Zeek log file (ssl.log). The resulting Zeek log files is saved and can be found here: https://drive.google.com/drive/folders/1Y_MTq1rXAcfmA-z2jZ1k25pOQTd1aMLC?usp=sharing

# Scripts
ctu_web_crawler.py: this file crawls the datasets in CTU.
dataCollection_RF.py: this file retrieves the data and plots them.