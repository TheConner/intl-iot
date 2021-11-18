#!/usr/bin/env python3

#
# Extractor that is used for dumping PCAP file contents fotr the intl-iot dataset
# this tool dumps HTTP data only using tshark
# @author Conner Bradley
#

import os
import argparse
import pathlib
import uuid
import pickle
import subprocess
from joblib import Parallel, delayed

parser = argparse.ArgumentParser(description='Analyze Packet Files')

parser.add_argument('dir', type=str, help='Directory of pcaps to recursively search through')
parser.add_argument('out', type=str, help='Directory to dump result files to')

args = parser.parse_args()
walk_dir = args.dir
out_dir = args.out

# If your current working directory may change during script execution, it's recommended to
# immediately convert program arguments to an absolute path. Then the variable root below will
# be an absolute path as well. Example:
# walk_dir = os.path.abspath(walk_dir)
#root = us/lefun-cam-wired/android_wan_photo
#list_file_path = us/lefun-cam-wired/android_wan_photo/my-directory-list.txt
#	- file 2019-04-10_08:38:20.46s.pcap (full path: us/lefun-cam-wired/android_wan_photo/2019-04-10_08:38:20.46s.pcap)
#	- file 2019-04-09_21:21:29.45s.pcap (full path: us/lefun-cam-wired/android_wan_photo/2019-04-09_21:21:29.45s.pcap)
#	- file 2019-04-10_04:06:45.46s.pcap (full path: us/lefun-cam-wired/android_wan_photo/2019-04-10_04:06:45.46s.pcap)


# tshark -nr 2019-04-25_19:10:50.173s.pcap --export-objects http,destdir
PCAP_EXT='.pcap' 

# Output directory
EXTRACTED_OBJS_DIR=os.path.abspath(out_dir)
print("Extracting objects to ", EXTRACTED_OBJS_DIR)

pathlib.Path(EXTRACTED_OBJS_DIR).mkdir(parents=True, exist_ok=True) 

file_metadata=[]

jobs = []

def do_export(job):
    dir_uuid = job['dir_uuid']
    filename = job['filename']
    file_path = job['filepath']
    root_segments = job['root_segments']
    root_segments_len = len(root_segments)

    metadata = {
        'uuid': dir_uuid,
        'dataset': root_segments[root_segments_len-4],
        'region': root_segments[root_segments_len-3],
        'device': root_segments[root_segments_len-2],
        'action': root_segments[root_segments_len-1],
        'pcap': file_path
    }
    object_out_dir = os.path.join(EXTRACTED_OBJS_DIR, dir_uuid)
    
    # do the thing
    print("Exporting objects for ", file_path)
    subprocess.run(["tshark", "-nr", file_path, "--export-objects", "http," + object_out_dir],stdout=subprocess.DEVNULL)
    return metadata

def flatten(t):
    return [item for sublist in t for item in sublist]

for root, subdirs, files in os.walk(walk_dir):
    for filename in files:
        dir_uuid = str(uuid.uuid4())
        file_path = os.path.join(root, filename)
        jobs.append({
            'dir_uuid': str(uuid.uuid4()),
            'filename': filename,
            'filepath': file_path,
            'root_segments': root.split('/')
        })

print("JOBS:",len(jobs))

print("Begin parallel execution")
file_metadata = Parallel(n_jobs=32)(delayed(do_export)(job) for job in jobs)

with open(os.path.join(out_dir, 'file_metadata.pickle'), 'wb') as f:
    pickle.dump(file_metadata, f)
    print("The pickle has been tickled")