<p align="center">
    <img src="freki/app/static/imgs/logos/dark_full.svg"/>
</p>

<p align="center">
    <a href="https://www.python.org/">
        <img src="https://img.shields.io/badge/python-3.x-blue?style=for-the-badge&logo=python"/>
    </a>
    <a href="https://www.codefactor.io/repository/github/cristianzsh/freki">
        <img src="https://img.shields.io/codefactor/grade/github/cristianzsh/freki?style=for-the-badge"/>
    </a>
    <a href="https://github.com/cristianzsh/freki/blob/master/LICENSE">
        <img src="https://img.shields.io/github/license/cristianzsh/freki?style=for-the-badge"/>
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

Check our [online documentation](https://cristianzsh.github.io/freki) for more details.

Open an [issue](https://github.com/cristianzsh/freki/issues) to suggest new features. All contributions are welcome.

## How to get the source code
`git clone https://github.com/cristianzsh/freki.git`

## Demo

Video demo: [https://youtu.be/brvNUPgw7ho](https://youtu.be/brvNUPgw7ho).

## Running

#### The easy way: Docker
1. Install [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/install/).
2. Edit the [.env](.env) file.
3. If you are going to use it in production, edit [freki.conf](nginx/freki.conf) to enable HTTPS.
4. Run `docker-compose up` or `make`.

#### Other ways
If you want to use it locally (e.g., for development), please check our [online documentation](https://cristianzsh.github.io/freki) for more details.

## How to cite this work

Freki was presented at the XXI Brazilian Symposium on Information and Computational Systems Security (SBSeg 2021).

```
@inproceedings{sbseg_estendido,
 author = {Cristian Souza and Felipe Silva},
 title = {Freki: Uma Ferramenta para Análise Automatizada de Malware},
 booktitle = {Anais do XXI Simpósio Brasileiro em Segurança da Informação e de Sistemas Computacionais},
 location = {Evento Online},
 year = {2021},
 pages = {58--65},
 publisher = {SBC},
 address = {Porto Alegre, RS, Brasil},
 doi = {10.5753/sbseg_estendido.2021.17340},
 url = {https://sol.sbc.org.br/index.php/sbseg_estendido/article/view/17340}
}
```

## License

This project is licensed under the GNU Affero General Public License.
