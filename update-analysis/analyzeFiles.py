#!/usr/bin/env python3

#
# Performs analysis on the PCAP files
#
import os
import sys
import pyshark
import argparse
import pathlib
import json
import base64
import uuid
import pickle
import subprocess
import magic
from joblib import Parallel, delayed
from collections import Counter


parser = argparse.ArgumentParser(description='Analyse extracted files from PCAP files')

parser.add_argument('dir', type=str, help='Base directory where files were extracted to')
#parser.add_argument('t', type=bool, help='include Text in results')

args = parser.parse_args()
walk_dir = args.dir
#ignore_text = args.t

extraction_data = None
with open(os.path.join(walk_dir, 'file_metadata.pickle'), 'rb') as f:
    extraction_data = pickle.load(f)
    print("Loaded extraction data", len(extraction_data))

if (extraction_data == None):
    print("Error: no extraction data found in ", walk_dir)
    exit(-1)

device_file_info = []
raw_file_infos = []

def printProgressBar (iteration, total, prefix = '', suffix = '', decimals = 1, length = 100, fill = '█', printEnd = "\r"):
    """
    Call in a loop to create terminal progress bar
    @params:
        iteration   - Required  : current iteration (Int)
        total       - Required  : total iterations (Int)
        prefix      - Optional  : prefix string (Str)
        suffix      - Optional  : suffix string (Str)
        decimals    - Optional  : positive number of decimals in percent complete (Int)
        length      - Optional  : character length of bar (Int)
        fill        - Optional  : bar fill character (Str)
        printEnd    - Optional  : end character (e.g. "\r", "\r\n") (Str)
    """
    print('\r')
    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filledLength = int(length * iteration // total)
    bar = fill * filledLength + '-' * (length - filledLength)
    print(f'\r{prefix} |{bar}| {percent}% {suffix}', end = printEnd)
    # Print New Line on Complete
    if iteration == total: 
        print()

def flatten(t):
    return [item for sublist in t for item in sublist]

def search_strs_in_file(file, strs):
    found_strs = {}
    with open(file, 'r') as f:
        content = f.read().lower()

        for str in strs:
            found_strs[str] = str.lower() in content

        return found_strs

def metadata_extract(files):
    mime = magic.Magic(mime=True)
    metadata_labels = []
    for filename in files:
        file_path = filename
        file_mime = mime.from_file(file_path)

        # Extracts file magic info
        file_magic = magic.from_file(file_path)

        update_strs = {}
        if ('text' in file_magic or 'json' in file_magic or 'xml' in 'file_magic' or 'plain' in file_magic or 'html' in file_magic):
            # Extract if the file contains update / upgrade / etc
            update_strs = search_strs_in_file(file_path, ['update', 'upgrade', 'firmware', 'software', 'download'])

        metadata_labels.append({
            'file': file_path,
            'mime': file_mime,
            'magic': file_magic,
            'update_meta': update_strs
        })
    return metadata_labels

def process_device(metadata, walk_dir):
    file_info_for_device = {
        'uuid': metadata['uuid'],
        'file_infos': []
    }
    
    all_targets = []
    for root, subdirs, files in os.walk(os.path.join(walk_dir, metadata['uuid'])):
        for file in files:
            all_targets.append(os.path.join(root,file))
    results = metadata_extract(all_targets)
    if (len(results) != 0):
        for result in results:
            file_info_for_device['file_infos'].append(result)

        return file_info_for_device

file_info_for_device = Parallel(n_jobs=32)(delayed(process_device)(metadata, walk_dir) for metadata in extraction_data)
#raw_file_infos += results_flat
for info in file_info_for_device:
    if (info is not None):
        device_file_info.append(info)

print("--- writing results ---")
with open(os.path.join(walk_dir, 'bin_results.json'), 'w') as file:
    json.dump({
        'results':device_file_info
    }, file, ensure_ascii=False, indent=4)
