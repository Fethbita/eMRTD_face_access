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
sudo apt-get install git wget build-essential cmake python3-dev python3-venv python3-tk libopenblas-dev liblapack-dev swig pcscd libpcsclite-dev libssl-dev
```
### On Arch Linux/Manjaro:
Download the necessary packages and enable the smart card service:
```shell
sudo pacman -S git wget base-devel cmake python tk openblas cblas lapack swig ccid opensc 

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

## Running

Before running, make sure you activate the virtual environment with
```shell
source .venv/bin/activate
```
You can run the main program by running the module (See Usage for program arguments or run `python3 -m emrtd_face_access -h`)
```shell
python3 -m emrtd_face_access
```

## Usage
```
usage: __main__.py [-h] [-online] [--certs CERTS] [--crls CRLS] [--output OUTPUT] [--camera CAMERA] [--resolution RESOLUTION RESOLUTION] [--rotate ROTATE]

Biometric (Facial) Access Control System Using ID Card

optional arguments:
  -h, --help            show this help message and exit
  -online               Download crl and csca certificates online.
  --certs CERTS         Directory to CSCA certificates
  --crls CRLS           Directory to certificate revocation lists
  --output OUTPUT, --o OUTPUT
                        Directory to save read card files
  --camera CAMERA, --c CAMERA
                        Device id of the camera to be used
  --resolution RESOLUTION RESOLUTION, --r RESOLUTION RESOLUTION
                        Resolution to be run at, if not given the screen resolution is used (width height)
  --rotate ROTATE       Degrees to rotate clockwise (90, 180, 270)
```
