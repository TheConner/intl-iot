#!/usr/bin/env python3

#
# Analyze file results from previous tools (extract, analyze)
# @author Conner Bradley
#

import os
import argparse
import pathlib
import uuid
import pickle
import subprocess
import json
import pandas
from collections import Counter
import matplotlib.pyplot as plt

parser = argparse.ArgumentParser(description='Generate Charts')

PICKLE_FILE_CONST = "file_metadata.pickle"
ANAL_RESULTS_CONST = "bin_results.json"

parser.add_argument('input', type=str, help='Input dir')
#parser.add_argument('inputmeta', type=str, help='Input device metadata')
parser.add_argument('output', type=str, help='Output dir')

args = parser.parse_args()
input_file = args.input
#device_metadata_file = args.inputmeta

with open(os.path.join(input_file, ANAL_RESULTS_CONST), 'r') as f:
    data = json.load(f)
    print("Loaded packet JSON")

with open(os.path.join(input_file, PICKLE_FILE_CONST), 'rb') as f:
    device_metadata = pickle.load(f)
    print("Loaded metadata pickle")

def generate_mime_pie(data):
    mimelist = []
    file_desc_list = []

    for device in data:
        file_infos = device.get('file_infos')
        for info in file_infos:
            mimelist.append(info.get('mime'))
            file_desc_list.append(info.get('magic'))

    mime_counts = Counter(mimelist)
    magic_counts = Counter(file_desc_list)

    df_mime = pandas.DataFrame.from_dict(mime_counts, orient='index').sort_index(1)
    df_magic = pandas.DataFrame.from_dict(magic_counts, orient='index')
    #print(df_mime)
    df_mime_plot = df_mime.plot.bar()
    df_mime_plot.set_xlabel("Mime Type of Extracted Data")
    df_mime_plot.savefig('df_mime_plot.png')

def get_device_by_uuid(uuid):
    for device in device_metadata:
        if device['uuid'] == uuid:
            return device 
    print("Device with uuid not found", uuid)
    return None

def generate_update_endpoint_chart(data):
    update_meta_counts = {}
    update_device_counts = {}

    for device in data:
        DEVICE_UUID = device.get('uuid')
        # Get actual device info
        device_metadata=get_device_by_uuid(DEVICE_UUID)
        device_label = device_metadata['device']

        update_exchange_count = 0
        for info in device.get('file_infos'):
            for key,value in info.get('update_meta').items():
                if (value is True):
                    update_exchange_count += 1
                meta_key_name = key + '_' + str(value)
                meta_key_value = update_meta_counts.get(meta_key_name, 0)
                update_meta_counts[meta_key_name] = meta_key_value + 1

        update_device_counts[device_label] = update_exchange_count

    print(update_device_counts)

    update_meta_counts_keys = update_meta_counts.keys()
    update_meta_counts_values = update_meta_counts.values()

    plt.bar(update_meta_counts_keys, update_meta_counts_values)
    plt.savefig('df_meta_update_counts.png')

def generate_tls_charts(data):
    for device in data:
        DEVICE_UUID = device.get('uuid')
        device_metadata=get_device_by_uuid(DEVICE_UUID)
        device_label = device_metadata['device']

#generate_mime_pie(data['results'])
#generate_update_endpoint_chart(data['results'])