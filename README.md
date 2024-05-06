

# :dart: Objectif

La ToolBox a pour objectif de fournir à son utilistateur un moyen simple et pratique de détecter et d'exploiter si possible les **CVE-2019-15107** & **CVE-2021-25646** sur uncou plusieurs hôtes présents sur un réseau local.
Elle embarque des fonctions de scan avancées grâce à l'outil nmap, ainsi que la possibilité pour l'utilisateur d'exporter un rapport PDF du scan qu'il vient d'effectuer.

Afin de parvenir à l'exploitation des dites CVE en lancant le script en mode 'exploit' (-e/--exploit), il est nécessaire pour l'utilisateur de disposer de l'outil [VIllain](https://github.com/t3l3machus/Villain) car ce dernier permet de récupérer les reverse-shells envoyés par la toolbox lors de l'exécution des exploit CVE.

# :gear: Configuration recommandée

Cette ToolBox a été concue et développée sur Kali Linux. Nous reccomandons donc l'utilisation de cette distribution pour limiter les erreurs lors de son exécution.


# :clipboard: Fonctionnalités 
Scan d'hôte via adresse IP (127.0.0.1)

![IP](https://github.com/SpiritixCS/ToolBox/assets/77000299/102d05b8-5e0d-43b5-a120-085cb60ab5a4)


Découverte réseau via range (192.168.1.0/24)

![RANGE](https://github.com/SpiritixCS/ToolBox/assets/77000299/44d3250a-9fde-427a-a3a4-1ff2311dd1d8)


Scan approfondi des ports 

![NETWORK DEEP](https://github.com/SpiritixCS/ToolBox/assets/77000299/c89e86f1-dbb9-49c2-90dd-7176fba60f3d)


Découverte des CVEs sans exploitation (-s/--scan)

![CVE SCAN](https://github.com/SpiritixCS/ToolBox/assets/77000299/be80b04d-c161-4b35-9f5c-ad758253e99d)


Découverte et exploitation des CVEs (-e/--eploit)

![REV SHELL SEND](https://github.com/SpiritixCS/ToolBox/assets/77000299/1676cfc7-a470-4ca5-9830-a4d01d85f1d6)


Réception automatique de reverse shell via l'outil Villain 

![VILLAIN](https://github.com/SpiritixCS/ToolBox/assets/77000299/5a6b264b-c954-4464-9494-d3fe21a25f79)


Exportation via PDF 
GIF 


# :computer: Preview 

# :mortar_board: Références

- Villain : https://github.com/t3l3machus/Villain 
- Python NMAP : https://pypi.org/project/python-nmap/ 
- CVE-2019-15107 : https://nvd.nist.gov/vuln/detail/cve-2019-15107 
- CVE-2021-25646 : https://nvd.nist.gov/vuln/detail/CVE-2021-25646 
