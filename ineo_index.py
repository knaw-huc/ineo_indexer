import os
import glob
import orjson as json
from typing import List, Dict, Any, Tuple, Union, Optional
from indexer import Indexer
from bimap import BidirectionalMap

config = {
    "url": "http://indexer:9200",
}
index_name = "ineo"

indexer = Indexer(config, index_name)

data_path = "../data"
property_path: str = "properties"
to_check = ["researchActivities", "researchDomains"]

import re
from urllib.parse import urlparse


def is_valid_url(url: str) -> bool:
    # Basic URL regex pattern
    pattern = re.compile(
        r'^(https?:\/\/)?'  # Optional HTTP or HTTPS scheme
        r'([\w\-]+\.)+'  # Subdomains and domain name
        r'[a-zA-Z]{2,}'  # Top-level domain
        r'(:\d+)?'  # Optional port
        r'(\/[^\s]*)?$'  # Optional path
    )

    if not re.match(pattern, url):
        return False

    # Additional validation using urllib.parse
    try:
        parsed = urlparse(url)
        return bool(parsed.netloc) and bool(parsed.scheme)
    except ValueError:
        return False


def load_properties(path: str) -> dict:
    """
    Load properties from the specified path.
    create a dict per file with file name as the key and the content as the value
    The content will be a dict with the properties of the file

    :param path:
    :return: properties as dict
    """
    properties: Dict = {}
    bmap = BidirectionalMap()
    files = get_files_with_extension(path, ".json")
    for file in files:
        k = os.path.basename(file).split(".")[0]
        with open(file, 'r') as f:
            data = json.loads(f.read())
            if not isinstance(data, list):
                raise ValueError("Invalid data format. Expected list")
            for d in data:
                bmap.insert(d["title"], d["link"])
        properties[k] = bmap

    return properties



def processFile(file):
    with open(file, 'r') as f:
        data = json.loads(f.read())[0].get("document")
    if data:
        for k in to_check:
            replace_values = data.get("properties").get(k)
            if replace_values:
                if isinstance(replace_values, list):
                    new_values = replace_values.copy()
                    for i in new_values:
                        if is_valid_url(i):
                            replace_values.remove(i)
                            replace_values.append(properties.get(k).get_by_value(i))
                else:
                    raise ValueError(f"Invalid data format for {k}. Expected list or string")
    # print(json.dumps(data))
    # exit()
    indexer.add_to_index(data)


def get_files_with_extension(folder, extension):
    """
    Get all files with the given extension from the specified folder.

    :param folder: The folder to search in.
    :param extension: The file extension to look for (e.g., '.json').
    :return: A list of file paths with the given extension.
    """
    search_pattern = os.path.join(folder, f"*{extension}")
    return glob.glob(search_pattern)


def processDir(data_path):
    files = get_files_with_extension(data_path, ".json")
    for file in files:
        processFile(file)


if __name__ == "__main__":
    properties: dict = load_properties(property_path)
    # processFile("../data/ucto-service_processed.json")
    processDir(data_path)
