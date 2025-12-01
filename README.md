
# FileScout

> Binary analyzer that identifies the real type of files through their signatures (magic numbers).

![Badge Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Badge License](https://img.shields.io/badge/License-MIT-green)
![Badge Status](https://img.shields.io/badge/Status-Active-success)

## Overview

This tool addresses a critical security problem: **most file extensions can be spoofed**. A malicious file may appear as `.txt` while actually being an `.exe`.

The solution uses **magic numbers** (binary signatures) to determine the file’s true type, regardless of the declared extension. This is essential for:

* **Forensic Analysis**: Security incident investigation
* **Malware Analysis**: Detection of suspicious files
* **Upload Validation**: Protection against malicious uploads in web applications
* **Email Inspection**: Identification of dangerous attachments

Segue explorando: ferramentas assim viram a cola invisível entre sistemas e a realidade binária que eles tentam esconder.

