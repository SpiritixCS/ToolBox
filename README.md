

# :dart: Objectif

La ToolBox a pour objectif de fournir à son utilistateur un moyen simple et pratique de détecter et d'exploiter si possible les **CVE-2019-15107** & **CVE-2021-25646** sur un ou plusieurs hôtes présents sur un réseau local.
Elle intègre des fonctions de scan avancées grâce à l'outil nmap, ainsi que la possibilité d'obtennir un accès sur les machines compromises de manière automatique. Enfin, elle offre la possibilité à l'utilisateur d'exporter un rapport PDF du scan qu'il vient d'effectuer.

Afin de parvenir à l'exploitation des dites CVE en lançant le script en mode 'exploit' (-e/--exploit), il est nécessaire pour l'utilisateur de disposer de l'outil [VIllain](https://github.com/t3l3machus/Villain) car ce dernier permet de récupérer les reverse-shells envoyés par la toolbox lors de l'exécution des exploits CVE.

# :gear: Configuration recommandée

Cette ToolBox a été conçue et développée sur Kali Linux. Nous recommandons donc l'utilisation de cette distribution pour limiter les erreurs lors de son exécution.

Outils nécessaires (cf /install.md) :
  - Python3
  - nmap
  - Villain
    
# :computer: vidéo de présentation

https://www.youtube.com/watch?v=EGLvzX8KiLU

# :clipboard: Fonctionnalités 
Scan d'hôte via l'adresse IP (127.0.0.1)

![IP](https://github.com/SpiritixCS/ToolBox/assets/77000299/a524e2d1-3b9e-4bb1-b87d-12247a411b05)


Découverte du réseau via range (192.168.1.0/24)

![range](https://github.com/SpiritixCS/ToolBox/assets/77000299/c12d208e-deca-4a28-8b82-b15e24b8d886)


Découverte des CVEs sans exploitation (-s/--scan)

![Vuln](https://github.com/SpiritixCS/ToolBox/assets/77000299/8a02d384-3b35-4f5c-8699-e6206715702a)


Découverte et exploitation des CVEs (-e/--eploit)

![Exploit](https://github.com/SpiritixCS/ToolBox/assets/77000299/6a141df1-82ec-424b-acf4-2fef08c925b0)


Réception automatique de reverse shell via l'outil Villain 

![villain](https://github.com/SpiritixCS/ToolBox/assets/77000299/10e1ec00-d9e7-4cd4-af17-02443303d4af)



# :mortar_board: Références

- Villain : https://github.com/t3l3machus/Villain 
- Python NMAP : https://pypi.org/project/python-nmap/ 
- CVE-2019-15107 : https://nvd.nist.gov/vuln/detail/cve-2019-15107 
- CVE-2021-25646 : https://nvd.nist.gov/vuln/detail/CVE-2021-25646

# :warning: Avertissement

L'utilisation de cette Toolbox pour attaquer des cibles sans consentement mutuel préalable est illégale. Il incombe à l'utilisateur final de respecter toutes les lois locales, nationales et fédérales applicables. Les développeurs n'assument AUCUNE responsabilité et ne sont PAS responsables de toute mauvaise utilisation ou de tout dommage causé par cet outil.
