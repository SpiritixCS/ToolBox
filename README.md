

# Objectif :dart:

La ToolBox a pour objectif de fournir à son utilistateur un moyen simple et pratique de détecter et d'exploiter si possible les CVE-2019-15107 & CVE-2021-25646 sur uncou plusieurs hôtes présents sur un réseau local.
Elle embarque des fonctions de scan avancées grâce à l'outil nmap, ainsi que la possibilité pour l'utilisateur d'exporter un rapport PDF du scan qu'il vient d'effectuer.

Afin de parvenir à l'exploitation des dites CVE en lancant le script en mode 'exploit' (-e/--exploit), il est nécessaire pour l'utilisateur de disposer de l'outil [VIllain](https://github.com/t3l3machus/Villain) car ce dernier permet de récupérer les reverse-shells envoyés par la toolbox lors de l'exécution des exploit CVE.

# Fonctionnalités :clipboard:
Scan d'hôte via adresse IP (127.0.0.1)
GIF

Découverte réseau via range (192.168.1.0/24)
GIF

Scan approfondi des ports 
GIF

Découverte des CVEs sans exploitation (-s/--scan)
GIF

Découverte et Exploitation des CVEs (-e/--eploit)
GIF

Réception automatique de reverse shell via l'outil Villain 
GIF

Exportation via PDF 
GIF 


# Preview :computer:



# Références :mortar_board:

Python NMAP : https://pypi.org/project/python-nmap/
Villain : https://github.com/t3l3machus/Villain
CVE-2019-15107 : https://nvd.nist.gov/vuln/detail/cve-2019-15107
CVE-2021-25646 : https://nvd.nist.gov/vuln/detail/CVE-2021-25646
