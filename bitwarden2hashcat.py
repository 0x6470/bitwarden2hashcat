#!/usr/bin/env python3

"""Utility to convert Bitwarden hashes to hashcat-suitable hashes from browser data and local data.json files"""

# Currently supported: Chrome, Opera, Brave, Vivaldi, Edge on Windows; Chrome and Firefox on Linux
# OS X is currently not supported due to a lack of "test equipment"
# Tested with Firefox 79.0 (64-bit), Chromium 83.0.4250.0 (64-bit), Chrome 84.0.4147.105 (64-bit) on Windows 10 19042.421
# Tested with Firefox 79.0 (64-Bit) on Ubuntu 18.04 LTS
#
# Proudly brought to you by 0x6470 <https://github.com/0x6470/bitwarden2hashcat>
#
# The extraction process from browsers is buggy, errors are to be expected
#
# For licensing details, see LICENSE file
#
# Usage:
# python3 bitwarden2hashcat.py data.json
# python3 bitwarden2hashcat.py *.json


import json
import os
import sys
import base64


def extract_windows():
    userprofile = os.getenv("userprofile")
    locations = [
        "data.json",  # current directory
        "bitwarden-appdata\\data.json",  # portable installation
        "{}\\AppData\\Local\\Packages\\8bitSolutionsLLC.bitwardendesktop_h4e712dmw3xyy\\LocalCache\\Roaming\\Bitwarden\\data.json".format(userprofile),  # Windows 10 App
        "{}\\AppData\\Roaming\\Bitwarden\\data.json".format(userprofile),  # Bitwarden Windows
        "{}\\AppData\\Roaming\\Bitwarden CLI\\data.json".format(userprofile)  # Bitwarden CLI
    ]
    for i in locations:
        if os.path.exists(i):
            return get_data(i)
    else:
        return None


def manual_extraction():
    print("automatic data extraction failed")
    print("here are the manual steps\n")
    print("Firefox: navigate to about:debugging#/runtime/this-firefox")
    print("click \"inspect\" at the Bitwarden entry")
    print("click \"extension storage\" in the storage tab")
    print("")
    print("Chrome: navigate to chrome://extensions/")
    print("turn the developer mode on")
    print("click \"Inspect views background.html\" at the Bitwarden entry")
    print("open the console tab")
    print("enter \" chrome.storage.local.get(null, function (data) { console.info(data) }); \"")
    print("")
    print("those instructions apply to all chromium based browsers such as Vivaldi, Opera, Brave and the new Edge")
    print("\n\n")
    keyHash = input("search for the value of the \"keyHash\" key and enter it here: ")
    kdfIterations = input("search for the value of the \"kdfIterations\" key and enter it here: ")
    userEmail = input("search for the value of the \"userEmail\" key and enter it here: ")
    return userEmail, keyHash, kdfIterations


def extract_webbrowsers():
    if "nt" in os.name:
        userprofile = os.getenv("userprofile")
        paths = [
            "{}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\nngceckbapebfimnlniiiahkandclblb".format(userprofile),  # Chrome
            "{}\\AppData\\Roaming\\Opera Software\\Opera Stable\\Local Extension Settings\\ccnckbpmaceehanjmeomladnmlffdjgn".format(userprofile),  # Opera
            "{}\\AppData\\Local\\BraveSoftware\\Brave-browser\\User Data\\Default\\Local Extension Settings\\nngceckbapebfimnlniiiahkandclblb".format(userprofile),  # Brave
            "{}\\AppData\\Local\\Vivaldi\\User Data\\Default\\Local Extension Settings\\nngceckbapebfimnlniiiahkandclblb".format(userprofile),  # Vivaldi
            "{}\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Extensions\\jbkfoedolllekgbhcbcoahefnbanhhlh".format(userprofile)  # chromium-based Edge
        ]
    else:
        userprofile = os.getenv("HOME")
        paths = [
            "{}/.config/google-chrome/Default/Local Extension Settings/nngceckbapebfimnlniiiahkandclblb".format(userprofile),  # Chrome
            "{}/snap/chromium/common/chromium/Default/Local Extension Settings/nngceckbapebfimnlniiiahkandclblb".format(userprofile)  # Chromium snap

        ]

    try:
        import plyvel
    except ImportError:
        print("Please install the plyvel module")
        sys.exit()

    for path in paths:
        try:
            db = plyvel.DB(path, create_if_missing=False)
        except plyvel._plyvel.Error:
            continue
        except plyvel._plyvel.IOError:
            print("Please close the browser first")
            sys.exit()
        try:
            email = db.get(b"userEmail").decode().strip("\"")
            keyHash = db.get(b"keyHash").decode().strip("\"")
            iterations = db.get(b"kdfIterations").decode().strip("\"")
        except Exception:
            print("Something in the structure changed, try to open and close the browser and if that fails please create an issue\n")
            return None
        return email, keyHash, iterations

    else:
        import sqlite3
        print("It seems that you're using Firefox, please enter the path")
        if "nt" in os.name:
            print("by default, it looks like this: %AppData%\Mozilla\Firefox\Profiles\[your_profile]\storage\default\moz-extension+++[UUID]^userContextId=[integer]")
        else:
            print("by default, it looks like this: ~/.mozilla/firefox/your_profile/storage/default/moz-extension+++[UUID]^userContextID=[integer]")
        print("The UUID can be found by visiting  about:debugging#/runtime/this-firefox")
        path = (input("Please enter path (replace \\ with /  or with \\\\): ") + "/idb/3647222921wleabcEoxlt-eengsairo.sqlite").replace("~", os.getenv("HOME"))
        if not os.path.exists(path):
            print("Please enter a valid path")
            return None
        connection = sqlite3.connect(path)
        cursor = connection.cursor()
        try:
            data = cursor.execute("SELECT * FROM object_data;").fetchall()
        except sqlite3.OperationalError:
            print("Please close the browser first")
            sys.exit()
        try:
            iterations = int.from_bytes(data[9][4].strip(b"\xff").split(b"\xff")[-1].split(b"\x00")[0], byteorder="little")  # very strange structure, might vary in the future
            keyHash = data[10][4].strip(b"\xff").split(b"\xff")[-1].split(b"\x00")[0].decode()
            email = data[21][4].strip(b"\xff").split(b"\xff")[-1].split(b"\x00")[0].decode()
        except Exception:
            print("Something in the structure changed, try to open and close the browser and if that fails please create an issue\n")
            return None
        return email, keyHash, iterations


def get_data(file):
    with open(file) as f:
        data = json.load(f)
    email = data["userEmail"]
    keyHash = data["keyHash"]
    iterations = data["kdfIterations"]
    return email, keyHash, iterations


def process(path=None):
    data = None
    if path:
        try:
            data = get_data(path)
        except FileNotFoundError:
            print("File {} not found... trying other methods".format(path))

    if not data:
        data = extract_webbrowsers()
    if not data:
        data = manual_extraction()
    return data


def format_data(data):
    return "$bitwarden$1*{}*{}*{}".format(data[2], base64.b64encode(data[0].encode()).decode(), data[1])


if __name__ == "__main__":
    if len(sys.argv) > 1:
        if "*" in sys.argv[1]:
            from glob import glob
            for i in glob(sys.argv[1]):
                print(format_data(process(i)))

        if len(sys.argv) > 2:
            for i in sys.argv[1:]:
                print(format_data(process(i)))
        else:
            print(format_data(process(sys.argv[1])))

    else:
        print(format_data(process()))
