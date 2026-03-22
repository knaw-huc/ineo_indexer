# INEO indexer (scripts to add data to indexer)
This repository contains the code to add data ineo indexer.
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

## Changes Made

### 1. Support for No-Auth Elasticsearch
The `elasticsearch_manager.py` script now supports Elasticsearch instances without authentication enabled via the `--no-auth` flag.

#### Examples:
```bash
# Create index without authentication
python elasticsearch_manager.py create-index --index my_index --no-auth

# Test access without authentication
python elasticsearch_manager.py test-access --index my_index --no-auth

# Search without authentication
python elasticsearch_manager.py search --index my_index --no-auth
```

### 2. Environment Variable Support
Both scripts now support reading configuration from environment variables via a `.env` file.

#### Setup:
1. Copy `.env.example` to `.env`
2. Edit `.env` with your Elasticsearch credentials and connection settings

#### Environment Variables:
- `ES_SCHEME`: Elasticsearch scheme (http or https, default: http)
- `ES_HOST`: Elasticsearch hostname (default: localhost)
- `ES_PORT`: Elasticsearch port (default: 9200)
- `ES_INDEX`: Default index name (default: ineo)
- `ES_USER`: Elasticsearch username (default: ineouser)
- `ES_PASSWORD`: Elasticsearch password (default: ineopassword)

### 3. Enhanced Error Handling
Both `ineo_index.py` and `elasticsearch_manager.py` now provide better error messages and connection validation.

## Usage Examples

### Using with Authentication (default)
```bash
cd indexer

# Create index with user credentials
python elasticsearch_manager.py create-index \
  --index my_data \
  --elastic-password changeme

# Create user with specific index access
python elasticsearch_manager.py create-index-user \
  --index sales_data \
  --username sales_user \
  --user-password sales123 \
  --elastic-password changeme

# Test user access
python elasticsearch_manager.py test-access \
  --username sales_user \
  --user-password sales123 \
  --index sales_data
```

### Using without Authentication
```bash
cd indexer

# Create index without auth
python elasticsearch_manager.py create-index --index my_data --no-auth

# Test index access without auth
python elasticsearch_manager.py test-access --index my_data --no-auth

# Search index without auth
python elasticsearch_manager.py search --index my_data --no-auth

# Run ineo_index.py (uses .env file)
python ineo_index.py
```

### Using Environment Variables
```bash
cd indexer

# Create .env file
cat > .env << EOF
ES_SCHEME=http
ES_HOST=localhost
ES_PORT=9200
ES_INDEX=ineo
ES_USER=ineouser
ES_PASSWORD=ineopassword
EOF

# Run ineo_index.py (automatically loads from .env)
python ineo_index.py
```

## Troubleshooting

### Error: AuthenticationException: missing authentication credentials
This error means:
1. Your Elasticsearch instance requires authentication but credentials are missing
2. The provided credentials are incorrect
3. The user doesn't have permission on the index

**Solutions:**
- Verify your credentials in the `.env` file
- Check Elasticsearch logs for authentication failures
- Ensure the user has the correct role with index permissions
- If using no-auth, ensure Elasticsearch security is disabled

### Error: Failed to connect to Elasticsearch
Check:
1. Elasticsearch is running: `docker ps | grep elasticsearch`
2. Host and port are correct in `.env`
3. Network connectivity: `curl http://localhost:9200`

### Error: User not authorized for index
The user needs the following permissions on the index:
- `read`: For search operations
- `write`: For indexing documents
- `view_index_metadata`: For viewing index information

Create the user with proper permissions:
```bash
python elasticsearch_manager.py create-index-user \
  --index ineo \
  --username ineouser \
  --user-password ineopassword \
  --elastic-password changeme \
  --privileges read write view_index_metadata
```

## Fixed Issues

1. **Elasticsearch Client Initialization**: Updated to use correct parameter format for Elasticsearch v8+
2. **Mutable Default Arguments**: Fixed default privilege list in `create_role_for_specific_index`
3. **Missing Environment Variable Loading**: Added `.env` file support
4. **Error Handling**: Added connection validation with helpful error messages

