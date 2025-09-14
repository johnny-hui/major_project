# P2P (Client/Server App) - Authenticating and Verifying Users Using Blockchain Technology and Face Recognition

## Table of Contents
- [Overview](#overview)
- [Requirements](#requirements)
- [Installation](#installation)
- [Installation - Optional (Android Photo Uploader App)](#installation_android)
- [Quickstart](#quickstart)
- [Documentation](#documentation)

## Overview
This project is a concept design, a P2P (Client/Server) application that utilizes Blockchain technology, facial recognition, encryption, 
and peers within an existing P2P LAN-based network to securely and cooperatively authenticate and verify new users. 

When a new peer requests to join the network, they submit a facial photo for verification. Existing peers cooperatively validate the request 
using facial recognition (DeepFace) module against prior face photos of that peer. Prior face photos of that peer are stored within the network's
Blockchain (granted they have joined that network before).

Upon successful verification by peers among this network will result in a new Block being added to the network's Blockchain. The Blockchain 
(locally stored) will serve as a connection history ledger and securely store peers’ facial images upon each entry.

This application encompasses the following features:
  - Secure end-to-end communication between peers (using AES).
  - Cooperative synchronization of network information amongst all peers (Blockchain, current peers).
  - A custom voting mechanism during collaborative consensus and verification of the requesting peer.
  - Utilizes facial recognition (DeepFace) to scan and verify the requesting peer's face photo against prior photos.
  - Utilizes AES Encryption to encrypt the locally stored Blockchain.
  - Utilizes ECDSA signatures to ensure Blocks are properly signed by an Admin Node to prevent data tampering.
  - Offers an optional front-end visualization of Blockchain and application events (developed using React and WebSockets).

## Requirements
Ensure you have the following requirements:
  - **Operating System**
    - Ubuntu 22.04 (LTS)
  - **Android Device with a Camera (Optional)**
      - Minimum SDK: 28 (Android 9 - Pie)
      - Target SDK: 34 (Android 14 - Upside Down Cake)
  - **Python 3.12+**

## Installation
**1) Clone the project repository:**
```bash
git clone https://github.com/johnny-hui/major_project
```
**2) Download the P2P Photo-Uploader Android Application (Optional):**
- [Google Drive - APK File](https://drive.google.com/file/d/1DJLwPun_fCXht6jTUslsY0G_5j74IOTu/view)
- For an installation guide, see this [section](#installation_android).

**3) Open the Linux terminal and navigate to the project's root directory**

**4) Make a Python virtual environment with the following command:**
```bash
python3 -m venv .venv
```

**5) Activate the virtual environment with the following command:**
```bash
source .venv/bin/activate
```

**6) Install all required Python dependencies with the following command:**
```bash
pip3 install -r requirements.txt
```

**7) Determine the absolute path of the Python virtual environment:**
```bash
which python
```

**8) Start the application with the following command options:**
  - OPTION 1 - With Front-end GUI
  ```bash
  sudo <<output of which python>> node_main.py -s
  <<your_ip_address>> -f <<first_name>> -l <<last_name>>
  -m CBC -a True
  ```

  - OPTION 2 - No Front-end GUI
  ```bash
  sudo <<output of which python>> node_main.py -s
  <<your_ip_address>> -f <<first_name>> -l <<last_name>>
  -m CBC 
  ```

  - OPTION 3: As an Admin
  ```bash
  sudo <<output of which python>> admin_main.py -s
  <<your_ip_address>> -f <<first_name>> -l <<last_name>>
  -m CBC 
  ```

**9) OPTIONAL: To operate the front-end React app enter the following commands:**
  ```bash
  cd app/ui/
  npm install
  npm start
  Open browser and go to http://localhost:3000
  ```

## Installation - Optional (Android Photo Uploader App)
Installation is optional for the Android photo-uploader application. Instead of using the app,
you can simply drag and drop face photos into the main project’s ‘data/photos/’
directory and specify the path of the file when prompted by the application.

You can use a webcam or any other method to capture face photos or even use existing
photos for testing purposes. This flexibility allows you to test the application without an
Android device.

If you do want to install the Android camera app, perform the following steps:
  - 1) Download the APK file
  - 2) With a USB cable, connect your Android device to your PC
  - 3) Unlock your device
  - 4) On your device, tap the "Charging this device via USB" notification.
  - 5) Under "Use USB for," select File Transfer. A file transfer window will open.
  - 6) Once opened, drag the APK file to the “downloads” directory
  - 7) On your Android device, go open the Files app and open the “appdebug.apk” file
  - 8) Enter OK on any warnings or prompts that may appear during installation of
     the APK file
  - 9) When launching the app for the first time, you’ll be prompted to grant
     camera permissions to the app; enter “while using this app”
