# FileScout
> Analisador binário que identifica o tipo real de arquivos através de suas assinaturas (magic numbers).

![Badge Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Badge License](https://img.shields.io/badge/License-MIT-green)
![Badge Status](https://img.shields.io/badge/Status-Active-success)


## Visão Geral

Esta ferramenta resolve um problema crítico em segurança: **a maioria das extensões de arquivo podem ser falsificadas**. Um arquivo malicioso pode ter extensão `.txt` mas ser na verdade um executável `.exe`.

A solução utiliza **magic numbers** (assinaturas binárias) para identificar o tipo real do arquivo, independentemente da extensão declarada. Isso é fundamental em:

- **Análise Forense**: Investigação de incidentes de segurança
- **Análise de Malware**: Identificação de arquivos suspeitos
- **Validação de Upload**: Proteção contra uploads maliciosos em aplicações web
- **Inspeção de Email**: Detecção de anexos perigosos
