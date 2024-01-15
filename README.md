# ac-rennes-eple-filter

ac-rennes-eple-filter est un outil de l'Académie de Rennes permettant des opérations liées au filtrage web en EPLE mis en œuvre par l'Académie et les collectivités, dans le cadre de la protection des mineur·es.

L’outil a été conçu pour faciliter l’assistance sur le filtrage en EPLE, il permet :
•	en assistance de niveau 1, aux personnels de la plateforme AMIGO de rapidement déterminer si un problème soumis est véritablement un problème de filtrage ;
•	en assistance de niveau 2, aux personnels de la CSN de simuler le comportement des pare-feu pour mettre au point et ajuster la politique académique de filtrage ;
•	Éventuellement en assistance de niveau 3, de repérer d’éventuelles incohérences entre la politique attendue et celles mises en place.

## Historique

| Date             | Version | Auteur·ice   | Modifications                                                          |
|------------------|---------|--------------|------------------------------------------------------------------------|
| 12 janvier 2024  | 1.7     | Pascal AUBRY | Correction d'un bug WHOIS<br/>Prise en charge des pare-feu Stormshield |
| 20 décembre 2023 | 1.6     | Pascal AUBRY | Prise en charge du pare-feu Artica du SIB                              |
| 10 octobre 2023  | 1.5     | Pascal AUBRY | Stockage DB2                                                           |
| 21 mars 2023     | 1.4     | Pascal AUBRY | Ajout du fichier de configuration proxy.yml                            |
| 13 décembre 2022 | 1.3     | Pascal AUBRY | Optimisation des téléchargements                                       |
| 9 décembre 2022  | 1.2     | Pascal AUBRY | Amélioration de la gestion des erreurs                                 |
| 5 décembre 2022  | 1.1     | Pascal AUBRY | Création automatique de la base de données au premier lancement        |
| 2 décembre 2022  | 1.0     | Pascal AUBRY | Version initiale                                                       |


## Fonctionnement général

![docs/images/fonctionnement.png](docs/images/fonctionnement.png)

## Installation

### Prérequis

- Une base de données MySQL ;
- Un poste de travail sous Windows (le programme est fourni sous forme d’un exécutable compilé).

### Programme

- Télécharger [la dernière version du programme](https://github.com/pascalaubry/ac-rennes-eple-filter/releases) ;
- Décompresser l’archive dans le répertoire de votre choix.

## Configuration

### Accès à la base de données

L’accès à la base de données se configure dans le fichier de configuration `database.yml`, au format YAML :

```
file: ac_rennes_eple_filter.db
```

### Politique de filtrage

La politique de filtrage académique est décrite dans le fichier de configuration policy.yml, également au format YAML (par défaut la configuration fournie est celle correspondant à la politique académique en cours) :

```
rules:
  -
    category: blacklist-CLG-LYC-PERS
    description: Sites bloqués par la politique académique pour tous les utilisateur.trice.s
    auth:
      all: deny
[...]
  -
    category: webmail
    description: Messagerie sur internet (hotmail, etc.)
```

### Proxy (≥ 1.4)

La configuration du proxy utilisé pour les téléchargements est indiquée dans le fichier de configuration proxy.yml, également au format YAML.

#### Appui sur la configuration définie au niveau système

```
type: system
```

#### Connexion directe

```
type: direct
```

#### Proxy pac

```
type: pac
pac_url: http://proxy.in.ac-rennes.fr/proxy.pac
```

#### Configuration manuelle

```
type: manual
proxies:
  http: educ-cd35-lbprx.colleges35.local:3128
  https: educ-cd35-lbprx.colleges35.local:3128
```

## Utilisation

### Syntaxe

```
$> ac_rennes_eple_filter-x.y.exe --help
ac-rennes-eple-filter x.y Copyright (c) 2022-2023 Région académique Bretagne
usage: ac_rennes_eple_filter.exe [-h] [--update] [--print] [--test TEST_URL]
                                 [--search PATTERN] [--control PROFILE]
                                 [--optimize]

options:
  -h, --help         show this help message and exit
  --update           update the database
  --print            print the policy rules
  --test TEST_URL    test a URL
  --search PATTERN   search for a pattern
  --control PROFILE  control the policy
  --optimize         optimize local rules
```

### Mise à jour des listes de filtrage

Les listes de filtrage sont téléchargées depuis le rectorat (listes maintenues par l’Académie) et l’université de Toulouse (listes du référentiel CARINE). 

La mise à jour des listes (téléchargement puis stockage dans la base de données) prend entre quelques minutes et quelques dizaines de minutes.

```
$> ac_rennes_eple_filter-x.y.exe --update
ac-rennes-eple-filter x.y Copyright (c) 2022-2023 Région académique Bretagne
Reading proxy config... OK
Initializing database... OK
Opening database connection sqlite://ac_rennes_eple_filter.db... ac_rennes_eple_filter.db not found, file will be created Creating tables... OK
Loading policy... Loaded 67 rules.
Analyzing the database... Database is empty, please update the database
Initializing web engine... OK
Downloading...
Downloading origin rennes...
Downloading category blacklist-CLG-LYC-PERS... >> https://www.toutatice.fr/toutatice-portail-cms-nuxeo/binary/blacklist-CLG-LYC-PERS.txt 200 OK
[...]
Downloading category whitelist-PERS... >> https://www.toutatice.fr/toutatice-portail-cms-nuxeo/binary/whitelist-PERS.txt 200 OK
Downloaded origin rennes.
Downloading origin toulouse...
Downloading category adult... 200 OK
Extracting adult.tar.gz... OK
[...]
Downloading category webmail... 200 OK
Extracting webmail.tar.gz... OK
Downloaded origin toulouse.
All downloads succeeded.
Resetting the database... OK
Filling the database...
Storing category blacklist-CLG-LYC-PERS... 285 domains added in 0 seconds
[...]
Storing category whitelist-PERS... 0 domains added in 0 seconds
Storing category adult................................................ 4513885 domains added in 12 seconds
[...]
Storing category webmail... 402 domains added in 0 seconds
5107849 total entries stored.
Reloading policy... Loaded 67 rules.
Analyzing the database... Found 65 categories and 5107849 domains.
```

> [!NOTE]
> Les listes ne sont téléchargées que si elles ont été mises à jour sur les sites de référence.

### Affichage de la politique

```
$> ac_rennes_eple_filter-x.y.exe --print
ac-rennes-eple-filter x.y Copyright (c) 2022-2023 Région académique Bretagne
Reading proxy config... OK
Initializing database... OK
Opening database connection sqlite://ac_rennes_eple_filter.db... OK
Loading policy... Loaded 67 rules.
Analyzing the database... Found 65 categories and 5107849 domains.
ACTIVE RULES:
+--------------------------+---------+-----+-----+-----+---------------------------------------------------------------------------------+
| Category                 |       # | clg | lyc | per | Description                                                                     |
+--------------------------+---------+-----+-----+-----+---------------------------------------------------------------------------------+
| blacklist-CLG-LYC-PERS   |     285 |  X  |  X  |  X  | Sites bloqués par l'Académique (tou·tes les utilisateur·ices)                   |
| blacklist-CLG-LYC        |       6 |  X  |  X  |  -  | Sites bloqués par l'Académique (collégien·nes et lycéen·nes)                    |
| blacklist-CLG            |       0 |  X  |  -  |  -  | Sites bloqués par l'Académique (collégien·nes)                                  |
| whitelist-PERS-LYC-CLG   |      64 |  A  |  A  |  A  | Sites autorisés par l'Académique (tou·tes les utilisateur·ices)                 |
| whitelist-PERS-LYC       |       2 |  -  |  A  |  A  | Sites autorisés par l'Académique (personnels et lycéen·nes)                     |
| whitelist-PERS           |       0 |  -  |  -  |  A  | Sites autorisés par l'Académique (personnels)                                   |
| liste_blanche            |     259 |  A  |  A  |  A  | Liste blanche de sites institutionnels                                          |
| examen_pix               |     440 |  A  |  A  |  A  | Sites utilisés pour la certification PIX                                        |
| adult                    | 4513885 |  X  |  X  |  X  | Sites adultes allant de l'érotique à la pornographie                            |
| agressif                 |     357 |  X  |  X  |  X  | Sites racistes, antisémites, incitant à la haine                                |
[...]
| warez                    |    1476 |  X  |  X  |  X  | Sites distribuant des logiciels ou vidéos pirates                               |
| arjel                    |      69 |  X  |  X  |  -  | Sites de paris en ligne certifiés par l'ARJEL                                   |
| associations_religieuses |       1 |  X  |  X  |  -  | Sites d'associations religieuses                                                |
[...]
| audio-video              |    3668 |  X  |  X  |  -  | Sites orientés vers l'audio et la vidéo                                         |
| social_networks          |     700 |  X  |  X  |  -  | Sites de réseaux sociaux                                                        |
| shopping                 |   36852 |  X  |  -  |  -  | Sites de vente et achat en ligne                                                |
+--------------------------+---------+-----+-----+-----+---------------------------------------------------------------------------------+
INACTIVE RULES:
+--------------------------+---------+-----+-----+-----+---------------------------------------------------------------------------------+
| Category                 |       # | clg | lyc | per | Description                                                                     |
+--------------------------+---------+-----+-----+-----+---------------------------------------------------------------------------------+
| blog                     |    1483 |  -  |  -  |  -  | Sites hébergeant des blogs                                                      |
[...]
| webmail                  |     402 |  -  |  -  |  -  | Messagerie sur internet (hotmail, etc.)                                         |
+--------------------------+---------+-----+-----+-----+---------------------------------------------------------------------------------+
Warning: categories used in rules but not found in database: blacklist-CLG, whitelist-PERS
All the categories found in the database are used in rules.
Writing HTML file \[ac_rennes_eple_filter-1.6-policy-20231222.html\]... OK
```

Le [fichier au format HTML](docs/ac_rennes_eple_filter-1.6-policy-20231222.html) créé permet de visualiser la politique de filtrage et la partager.

### Test de la politique sur une URL

Le test d'une URL permet de savoir la réponse attendue des pare-feu des EPLE en respect de la politique ed filtrage.

```
$> ac_rennes_eple_filter-x.y.exe --test https://www.credit-agricole.fr
ac-rennes-eple-filter x.y Copyright (c) 2022-2023 Région académique Bretagne
Reading proxy config... OK
Initializing database... OK
Opening database connection sqlite://ac_rennes_eple_filter.db... OK
Loading policy... Loaded 67 rules.
Analyzing the database... Found 65 categories and 5107849 domains.
Checking domain www.www.credit-agricole.fr...
Domains searched: www.credit-agricole.fr, credit-agricole.fr, fr
Found domain credit-agricole.fr in category bank
ACTIVE RULES:
| Category                 |       # | clg | lyc | per | Description                                                                     |
| blacklist-CLG-LYC-PERS   |     285 |  X  |  X  |  X  | Sites bloqués par l'Académique (tou·tes les utilisateur·ices)                   |
| blacklist-CLG-LYC        |       6 |  X  |  X  |  -  | Sites bloqués par l'Académique (collégien·nes et lycéen·nes)                    |
| blacklist-CLG            |       0 |  X  |  -  |  -  | Sites bloqués par l'Académique (collégien·nes)                                  |
| whitelist-PERS-LYC-CLG   |      64 |  A  |  A  |  A  | Sites autorisés par l'Académique (tou·tes les utilisateur·ices)                 |
| whitelist-PERS-LYC       |       2 |  -  |  A  |  A  | Sites autorisés par l'Académique (personnels et lycéen·nes)                     |
| whitelist-PERS           |       0 |  -  |  -  |  A  | Sites autorisés par l'Académique (personnels)                                   |
| liste_blanche            |     259 |  A  |  A  |  A  | Liste blanche de sites institutionnels                                          |
| examen_pix               |     440 |  A  |  A  |  A  | Sites utilisés pour la certification PIX                                        |
| adult                    | 4513885 |  X  |  X  |  X  | Sites adultes allant de l'érotique à la pornographie                            |
[...]
| warez                    |    1476 |  X  |  X  |  X  | Sites distribuant des logiciels ou vidéos pirates                               |
| arjel                    |      69 |  X  |  X  |  -  | Sites de paris en ligne certifiés par l'ARJEL                                   |
[...]
| astrology                |      28 |  X  |  X  |  -  | Sites d'astrologie                                                              |
| bank                     |    1868 |  X  |  X  |  -  | Sites de banques en ligne                                                       | MATCHED credit-agricole.fr
| bitcoin                  |     283 |  X  |  X  |  -  | Sites de bitcoin                                                                |
[...]
| shopping                 |   36852 |  X  |  -  |  -  | Sites de vente et achat en ligne                                                |
INACTIVE RULES:
| Category                 |       # | clg | lyc | per | Description                                                                     |
| blog                     |    1483 |  -  |  -  |  -  | Sites hébergeant des blogs                                                      |
[...]
| jobsearch                |     419 |  -  |  -  |  -  | Sites pour trouver un emploi                                                    |
| liste_bu                 |    2810 |  -  |  -  |  -  | Sites éducatifs pour la bibliothèque univ-tlse1.fr                              |
| manga                    |     638 |  -  |  -  |  -  | Sites liés à l'univers des mangas et de la bande dessinée                       |
[...]
| webmail                  |     402 |  -  |  -  |  -  | Messagerie sur internet (hotmail, etc.)                                         |
Access for CLG: denied (domain credit-agricole.fr in category bank)
Access for LYC: allowed (by default)
Access for PER: allowed (by default)
```

### Recherche dans la base de données

Il peut parfois être utile de chercher un motif dans la base de données pour comprendre pourquoi une URL est autorisée ou interdite.

```
$> ac_rennes_eple_filter-x.y.exe --search agricole
ac-rennes-eple-filter x.y Copyright (c) 2022-2023 Région académique Bretagne
Reading proxy config... OK
Initializing database... OK
Opening database connection sqlite://ac_rennes_eple_filter.db... OK
Loading policy... Loaded 67 rules.
Analyzing the database... Found 65 categories and 5107849 domains.
Searching pattern agricole...
Total domains for pattern agricole: 158
Pattern searched for: agricole
Category adult (114): agricolecredit.info, agricolefranceca.cloudaccess.host, agricolefre-947fcc.ingress-erytho.easywp.com, agricolepass.calamitata.com, agricolepass.cfoleverage.com.au, ... (5 shown, 109 more)
Category bank (1): credit-agricole.fr
Category financial (2): cabourse-2.credit-agricole.fr, cabourse-908.credit-agricole.fr
Category liste_bu (1): credit-agricole.fr
Category malware (20): agricoleregional2023.fr, creditagricoleespaceperso.fr, creditagricoleidf.fr, creditagricolenord.fr, creditagricoleparis.fr, ... (5 shown, 15 more)
Category phishing (20): agricoleregional2023.fr, creditagricoleespaceperso.fr, creditagricoleidf.fr, creditagricolenord.fr, creditagricoleparis.fr, ... (5 shown, 15 more)
Total domains for pattern agricole: 158
```

### Contrôle de la conformité de la mise en œuvre de la politique de filtrage

Cette fonctionnalité permet de contrôler la manière dont est mise en œuvre la politique de filtrage dans les EPLE.

```
$> ac_rennes_eple_filter-x.y.exe --search agricole
ac-rennes-eple-filter x.y Copyright (c) 2022-2023 Région académique Bretagne

```

### Optimisation des listes de l'Académie

Cette fonctionnalité permet de contrôler la non-redondance des listes locales de l'Académie avec celles de Toulouse, pour en faciliter la maintenance.

```
$> ac_rennes_eple_filter-x.y.exe --optimize
ac-rennes-eple-filter x.y Copyright (c) 2022-2023 Région académique Bretagne
Reading proxy config... OK
Initializing database... OK
Opening database connection sqlite://ac_rennes_eple_filter.db... OK
Loading policy... Loaded 67 rules.
Analyzing the database... Found 65 categories and 5107849 domains.
Verifying category blacklist-CLG-LYC-PERS...
### Domain 0w.pm is useless: Access already denied (domain 0w.pm matches category malware)
[...]
### Domain rule34.xxx is useless: Access already denied (domain xxx matches category adult)
[...]
### Domain clouddrive.infinityfreeapp.com is useless: Access already denied (domain clouddrive.infinityfreeapp.com matches category malware)
256 useless domains found.
Reading download\rennes\blacklist-CLG-LYC-PERS.txt... Read 314 lines.
Wrote blacklist-CLG-LYC-PERS-optimized.txt.
Verifying category blacklist-CLG-LYC...
File download\rennes\blacklist-CLG-LYC.txt already optimized.
Verifying category blacklist-CLG...
File download\rennes\blacklist-CLG.txt already optimized.
Verifying category whitelist-PERS-LYC-CLG...
### Domain youtube.com is useless: Access already allowed (domain youtube.com matches category examen_pix)
[...]
### Domain dailymotion.com is useless: Access already allowed (domain dailymotion.com matches category examen_pix)
[...]
]### Domain lafeteducourt.fr is useless: Access already allowed (by default)
[...]
### Domain education.fr is useless: Access already allowed (domain education.fr matches category liste_blanche)
38 useless domains found.
Reading download\rennes\whitelist-PERS-LYC-CLG.txt... Read 92 lines.
Wrote whitelist-PERS-LYC-CLG-optimized.txt.
Verifying category whitelist-PERS-LYC...
File download\rennes\whitelist-PERS-LYC.txt already optimized.
Verifying category whitelist-PERS...
File download\rennes\whitelist-PERS.txt already optimized.
```

### Mode interactif

Lancé sans paramètre, le programme propose un mode interactif permettant d'accéder à toutes les fonctionnalités précédentes.

```
$> ac_rennes_eple_filter-x.y.exe
ac-rennes-eple-filter x.y Copyright (c) 2022-2023 Région académique Bretagne
Reading proxy config... OK
Initializing database... OK
Opening database connection sqlite://ac_rennes_eple_filter.db... OK
Loading policy... Loaded 67 rules.
Analyzing the database... Found 65 categories and 5107849 domains.
[U]pdate the database
[P]rint the policy
[T]est URLS
[S]earch a pattern in the database
[C]ontrol the policy
[O]ptimize local rules
[Q]uit
Your choice:
```


