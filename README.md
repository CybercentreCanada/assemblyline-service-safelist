[![Discord](https://img.shields.io/badge/chat-on%20discord-7289da.svg?sanitize=true)](https://discord.gg/GUAy9wErNu)
[![](https://img.shields.io/discord/908084610158714900)](https://discord.gg/GUAy9wErNu)
[![Static Badge](https://img.shields.io/badge/github-assemblyline-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline)
[![Static Badge](https://img.shields.io/badge/github-assemblyline\_service\_safelist-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline-service-safelist)
[![GitHub Issues or Pull Requests by label](https://img.shields.io/github/issues/CybercentreCanada/assemblyline/service-safelist)](https://github.com/CybercentreCanada/assemblyline/issues?q=is:issue+is:open+label:service-safelist)
[![License](https://img.shields.io/github/license/CybercentreCanada/assemblyline-service-safelist)](./LICENSE)
# Safelist Service

This service will check the file hashes against Assemblyline's internal safelist infrastructure and mark files as safe accordingly.

## Service Details

### Format of Safelist data

#### SQL DB

If providing a SQL DB file, we expect the format to be similar to NSRL's (namely there is FILE and PKG tables) where the updater can load and query those tables to convert the output to CSV.

#### CSV

If providing a CSV file, we're expecting the format to be:

```
SHA-256,SHA-1,MD5,Filename,Filesize
<sha256>,<sha1>,<md5>,<filename>,<filesize>
...
```

Note that we're expecting a header as the first line of the CSV file.

### Trusted Distributors
Because we can't necessarily trust all the hashes that come from NSRL, we've elected to use the distributor
as a means of defining what files are deemed safe. To simplify this, you can use regex to set what distributors to trust.

For example, if I want to trust anything from 2K, I would set in the service manifest:
```yaml
config:
  ...
  trusted_distributors:
    - ^2K.* # This will capture 2K, 2K Australia, etc.
```

For a complete list of manufacturers, you can run `SELECT name FROM MFG` on each RDSv3 table from NSRL.

## Image variants and tags

Assemblyline services are built from the [Assemblyline service base image](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
which is based on Debian 11 with Python 3.11.

Assemblyline services use the following tag definitions:

| **Tag Type** | **Description**                                                                                  |      **Example Tag**       |
| :----------: | :----------------------------------------------------------------------------------------------- | :------------------------: |
|    latest    | The most recent build (can be unstable).                                                         |          `latest`          |
|  build_type  | The type of build used. `dev` is the latest unstable build. `stable` is the latest stable build. |     `stable` or `dev`      |
|    series    | Complete build details, including version and build type: `version.buildType`.                   | `4.5.stable`, `4.5.1.dev3` |

## Running this service

This is an Assemblyline service. It is designed to run as part of the Assemblyline framework.

If you would like to test this service locally, you can run the Docker image directly from the a shell:

    docker run \
        --name Safelist \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-safelist

To add this service to your Assemblyline deployment, follow this
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

General Assemblyline documentation can be found at: https://cybercentrecanada.github.io/assemblyline4_docs/

# Service Safelist

Ce service vérifiera les hashs des fichiers par rapport à l'infrastructure interne de la liste de sécurité d'Assemblyline et marquera les fichiers comme sûrs en conséquence.

## Détails du service

### Format des données de la liste de sauvegarde

#### SQL DB

Si vous fournissez un fichier SQL DB, nous nous attendons à ce que le format soit similaire à celui de NSRL (c'est-à-dire qu'il y a des tables FILE et PKG) où l'outil de mise à jour peut charger et interroger ces tables pour convertir le résultat en CSV.

#### CSV

Si vous fournissez un fichier CSV, nous nous attendons à ce que le format soit le suivant :

```
SHA-256,SHA-1,MD5,Nom de fichier,Taille de fichier
<sha256>,<sha1>,<md5>,<filename>,<filesize>
...
```

Notez que nous attendons un en-tête comme première ligne du fichier CSV.

### Distributeurs de confiance
Parce que nous ne pouvons pas nécessairement faire confiance à tous les hashs provenant de NSRL, nous avons choisi d'utiliser le distributeur
comme moyen de définir quels fichiers sont considérés comme sûrs. Pour simplifier les choses, vous pouvez utiliser des expressions rationnelles pour définir les distributeurs auxquels vous devez faire confiance.

Par exemple, si je veux faire confiance à tout ce qui vient de 2K, je mettrais dans le manifeste du service :
``yaml
config :
  ...
  trusted_distributors :
    - ^2K.* # Ceci capturera 2K, 2K Australia, etc.
```

Pour obtenir une liste complète des fabricants, vous pouvez exécuter `SELECT name FROM MFG` sur chaque table RDSv3 de NSRL.

## Variantes et étiquettes d'image

Les services d'Assemblyline sont construits à partir de l'image de base [Assemblyline service](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
qui est basée sur Debian 11 avec Python 3.11.

Les services d'Assemblyline utilisent les définitions d'étiquettes suivantes:

| **Type d'étiquette** | **Description**                                                                                                |  **Exemple d'étiquette**   |
| :------------------: | :------------------------------------------------------------------------------------------------------------- | :------------------------: |
|   dernière version   | La version la plus récente (peut être instable).                                                               |          `latest`          |
|      build_type      | Type de construction utilisé. `dev` est la dernière version instable. `stable` est la dernière version stable. |     `stable` ou `dev`      |
|        série         | Détails de construction complets, comprenant la version et le type de build: `version.buildType`.              | `4.5.stable`, `4.5.1.dev3` |

## Exécution de ce service

Il s'agit d'un service d'Assemblyline. Il est optimisé pour fonctionner dans le cadre d'un déploiement d'Assemblyline.

Si vous souhaitez tester ce service localement, vous pouvez exécuter l'image Docker directement à partir d'un terminal:

    docker run \
        --name Safelist \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-safelist

Pour ajouter ce service à votre déploiement d'Assemblyline, suivez ceci
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/fr/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

La documentation générale sur Assemblyline peut être consultée à l'adresse suivante: https://cybercentrecanada.github.io/assemblyline4_docs/
