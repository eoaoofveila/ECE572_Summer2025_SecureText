#!/usr/bin/env python3
import socket
import threading
import json
import os
import sys
import time
from datetime import datetime
import hashlib
import bcrypt
from HashTools import new
def main():
    passwordtable = ["password","password2","password3","password4","password5"]
    for data in passwordtable:
        hash_object = hashlib.sha256(data.encode())  # convert string to bytes
        hex_dig = hash_object.hexdigest()
        #print("SHA-256 hash:", hex_dig)
    key= b"default_key"
    original_message = b"CMD=SET_QUOTA&USER=bob&LIMIT=100"
    original_message_key=key + original_message
    
    original_mac = hashlib.md5(original_message_key).hexdigest()
    print("md5 hash:", original_mac)
    key_length     = len(key)
    data_to_append = b"&padding&CMD=GRANT_ADMIN&USER=attacker"
    h = new(algorithm="md5")

    # Perform the extension attack
    forged_msg, forged_mac = h.extension(
        secret_length=key_length,
        original_data=original_message,
        append_data=data_to_append,
        signature=original_mac
    )

    print("Forged message (bytes):", forged_msg)
    print("Forged message (repr):", repr(forged_msg))
    print("Forged MAC (hex):", forged_mac)

if __name__ == "__main__":
    main()
