<p align="center">
    <img src="freki/app/static/imgs/logos/dark_full.svg"/>
</p>

<p align="center">
    <a href="https://www.python.org/">
        <img src="https://img.shields.io/badge/python-3.x-blue?style=for-the-badge&logo=python"/>
    </a>
    <a href="https://www.codefactor.io/repository/github/crhenr/freki">
        <img src="https://img.shields.io/codefactor/grade/github/crhenr/freki?style=for-the-badge"/>
    </a>
    <a href="https://github.com/crhenr/freki/blob/master/LICENSE">
        <img src="https://img.shields.io/github/license/crhenr/freki?style=for-the-badge"/>
    </a>
    <img src="https://img.shields.io/badge/OS-GNU%2FLinux-red?style=for-the-badge&logo=linux"/>
</p>

---

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
- Web interface and REST API.
- User management.
- Community comments.
- Download samples.

Check our [online documentation](https://crhenr.github.io/freki) for more details.

Open an [issue](https://github.com/crhenr/freki/issues) to suggest new features. All contributions are welcome.

## How to get the source code
`git clone https://github.com/crhenr/freki.git`

## Demo

Video demo: [https://youtu.be/brvNUPgw7ho](https://youtu.be/brvNUPgw7ho).

## Running

#### The easy way: Docker
1. Install [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/install/).
2. Edit the [.env](.env) file.
3. If you are going to use it in production, edit [freki.conf](nginx/freki.conf) to enable HTTPS.
4. Run `docker-compose up` or `make`.

#### Other ways
If you want to use it locally (e.g., for development), please check our [online documentation](https://crhenr.github.io/freki) for more details.

## License

This project is licensed under the GNU Affero General Public License.
