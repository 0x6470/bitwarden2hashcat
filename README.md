# bitwarden2hashcat
A tool that converts Bitwarden's data into a hashcat-suitable hash

## Usage
`python3 bitwarden2hashcat.py` auto-extraction from local files

`python3 bitwarden2hashcat.py data.json` process the file data.json

`python3 bitwarden2hashcat.py *.json` process all files with a .json extension

## Examples
`python3 bitwarden2hashcat.py *.json > m23400_hashes.txt` saves all found hashes in `m23400_hashes.txt`

`hashcat -a 0 -m 23400 m23400_hashes.txt example.dict`

## Requirements
`Python >= 3.7`

`plyvel module`

## Installation
### Windows
`python -m pip install -r requirements_windows.txt`

### Linux
`pip3 install -r requirements_linux.txt`

## Bugs
Feel free to create an Issue if any bugs occur.
