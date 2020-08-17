<p align="center">
    <img src="freki/app/static/imgs/logo_dark.svg" width="150px" height="150px"/>
</p>

<p align="center">
    <a href="https://www.python.org/">
        <img src="https://img.shields.io/badge/Made%20with-Python-1f425f.svg"/>
    </a>
    <a href="https://www.gnu.org/licenses/agpl-3.0.html">
        <img src="https://img.shields.io/badge/License-AGPL%20v3-blue.svg"/>
    </a>
</p>

# Project Freki

Freki is a free and open-source malware analysis platform.

## Goals

1. Facilitate malware analysis and reverse engineering;
2. Provide an easy-to-use REST API for different projects;
3. Easy deployment (via Docker);
4. Allow the addition of new features by the community.

## Current features

- Hash extraction.
- VirusTotal API queries.
- Static analysis of PE files (headers, sections, imports, capabilities, and strings).
- Pattern matching with Yara.

Open an issue to suggest new features. All contributions are welcome.

## How to get the source code
`git clone https://github.com/crhenr/freki.git`

## Demo

Video demo: [https://youtu.be/AW4afoaogt0](https://youtu.be/AW4afoaogt0).

## Running

#### Before you start

Please **change the default secret keys** in [api/src/config.ini](api/src/config.ini) and [client/src/config.ini](client/src/config.ini). Other tweaks can be done in the same files.

If you want Freki to query VirusTotal for information, add your [VirusTotal API key](https://developers.virustotal.com/reference) in [api/src/config.ini](api/src/config.ini).

If you are using Docker, you might want to check the [docker-compose.yml](docker-compose.yml) file.

#### The easy way

1. Install [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/install/).
2. `cd freki && docker-compose up`.
3. Access the Freki client at `127.0.0.1` and the API at `127.0.0.1:5000`.

#### The hard way

1. Install the [client](client/requirements.txt) and the API [requirements](api/requirements.txt).
    - If running in a Linux environment, make sure `libfuzzy-dev` and `ssdeep` are pre-installed with `apt`: `sudo apt-get install libfuzz-dev ssdeep`
2. Start the API: `cd freki/api/src && python3 app.py`.
3. Start the client: `cd freki/client/src && python3 webapp.py`.
4. Access the Freki client at `127.0.0.1` and the API at `127.0.0.1:5000`.

## Acknowledgments

Thanks to [Flaticon](https://www.flaticon.com/) for the SVG logo.

## License

This project is licensed under the GNU Affero General Public License.
