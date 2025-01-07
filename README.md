# INEO indexer (scripts to add data to indexer)
This repository contains the code to add data into indexer.
The indexer is vanilla `elasticsearch` for now. This repository also serves the purpose of future expanding 
of the indexer.

### How to use
`ineo_index.py` is the main script to add data to the indexer. 

The following section in the script should be updated with the correct configuration:
```python
config = {
    "url": "http://localhost:9200", # url of the elasticsearch
    "index": "ineo" # index name
}
```

Please update the following section with the data to be added:
```python
data_path = "../data" # The path to the data PLEASE BE NOTED THAT THE DATA SHOULD BE IN INEO JSON FORMAT
property_path: str = "properties" # The path to the folder containing the properties
to_check = ["researchActivities", "researchDomains"] # Define which properties to be checked and replace with tag 
```

