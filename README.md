<!--
 Copyright (c) 2021 Burak Can
 
 This software is released under the MIT License.
 https://opensource.org/licenses/MIT
-->

# Biometric Access Control System Using ID Card / Passport
The proposed solution is a two-factor physical authentication system (something you have, something you are).

The first factor is an authentic ID card or passport, and the second factor is a biometric factor using a facial scan.

The first factor is verified using the ICAO e-passport applet available in the document. Cryptographic checks are performed according to ICAO Doc 9303 specification<sup>1</sup> to verify the integrity of the biometric data stored in the card and the authenticity of the document.

The second factor is verified by downloading the cardholder's facial image from the document and using face recognition technology to compare it to the picture taken from the webcam.

The proposed solution can be used on the entrances to buildings or self-checkout machines where strong identity verification is needed. In such cases, if biometric authentication is necessary it needs to be supervised. In cases where biometric verification is not necessary, just the first factor can be used.

<sup>1</sup>[https://www.icao.int/publications/pages/publication.aspx?docnum=9303](https://www.icao.int/publications/pages/publication.aspx?docnum=9303)

# Motivation
This is a Master Thesis project, this technology will be aimed at automated border control, but it could also be used for automated or semi-automated access control.

## In action

![a demo of the program](docs/images/demo.gif)
<sub>The image shown on the phone is taken from [https://thispersondoesnotexist.com/](https://thispersondoesnotexist.com/)</sub>

## Requirements
* Linux computer with python3.6 and above
* Contactless smart card reader
* Webcam
* Internet connection to manually update CRLs and perform document online validity check (only Estonian Documents)

## Dependencies
### On Debian/Ubuntu:
First, [enable the universe repository](https://help.ubuntu.com/community/Repositories/Ubuntu).
Then download the necessary packages:
```shell
sudo apt-get install git wget build-essential cmake python3-dev python3-venv python3-tk swig libpcsclite-dev pcscd libldap2-dev libsasl2-dev libssl-dev tesseract-ocr libtesseract-dev libleptonica-dev pkg-config
```
### On Arch Linux/Manjaro:
Download the necessary packages and enable the smart card service:
```shell
sudo pacman -S git wget python tk base-devel cmake swig ccid opensc tesseract openblas cblas
sudo systemctl enable --now pcscd.service
```

## Installation
```shell
git clone --recurse-submodules https://github.com/Fethbita/eMRTD_face_access.git
cd eMRTD_face_access
# Create virtualenv named '.venv'
python3 -m venv .venv
# Activate virtualenv
source .venv/bin/activate
# Upgrade pip
pip3 install --upgrade pip
# This last command is memory intensive because dlib is being built.
# Make sure you have available ram before attempting this command
pip3 install -r requirements.txt
# Download text detection and face detection assets
./download_assets.sh
```
Download each file from https://download.pkd.icao.int/ and put them in their respective folder.\
`icaopkd-001-dsccrl-xxxxxx.ldif` goes into `certs/icao_pkd_dsccrl`,\
`icaopkd-002-ml-xxxxxx.ldif` goes into `certs/icao_pkd_ml`,\
`icaopkd-003-nc-xxxxxx.ldif` goes into `certs/icao_pkd_nc`.

## Running

Before running, make sure you activate the virtual environment with
```shell
source .venv/bin/activate
```
You can run the main program by running the module (See Usage for program arguments or run `python3 -m emrtd_face_access -h`)
```shell
python3 -m emrtd_face_access -mrz
```
You can run individual modules, for example `face_compare.py` with
```shell
python3 -m emrtd_face_access.face_compare path_to_image_one path_to_image_two
```
`build_database.py` with
```shell
python3 -m emrtd_face_access.build_database [-h] [-add | -delete]
```
`small_demo.py` with
```shell
python3 -m emrtd_face_access.small_demo
```

## Usage
```
usage: __main__.py [-h] [-no-debug] [-online] (-ee | -mrz) [-bio | -no-bio] [--db DB] [--certs CERTS] [--crls CRLS] [--output OUTPUT]

Biometric (Facial) Access Control System Using ID Card

optional arguments:
  -h, --help            show this help message and exit
  -no-debug             Disable debug panel and print logging information on stdout.
  -online               Download crl and csca certificates online.
  -ee                   Estonian id card/passport
  -mrz                  MRZ info will be given
  -bio                  (default) Use biometric control (facial recognition)
  -no-bio               Do not use biometric control (facial recognition)
  --db DB               Database to be used for controlling
  --certs CERTS         Directory to CSCA certificates
  --crls CRLS           Directory to certificate revocation lists
  --output OUTPUT, --o OUTPUT
                        Directory to save read card files
```

## Database Builder Usage
```
usage: build_database.py [-h] [-add | -delete]

Build an allowed document database for emrtd_face_access

optional arguments:
  -h, --help  show this help message and exit
  -add        (default) Add a card to the database
  -delete     Remove a card from the database
```
