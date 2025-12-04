#!/usr/bin/env python3
"""
Elasticsearch 8.x Security Manager
Manages users, roles, and index permissions
"""

import sys
import json
import argparse
from elasticsearch import Elasticsearch, exceptions as es_exceptions
from elasticsearch.client import SecurityClient, IndicesClient


class ElasticsearchSecurityManager:
    def __init__(self, scheme="http", host='localhost', port=9200, username='elastic', password=None):
        """
        Initialize Elasticsearch client
        """
        self.host = host
        self.port = port
        self.base_url = f"{scheme}://{host}:{port}"

        if password is None:
            raise ValueError("Password is required")

        self.client = Elasticsearch(
            hosts=[self.base_url],
            basic_auth=(username, password),
            request_timeout=30
        )

        self.security = SecurityClient(self.client)
        self.indices = IndicesClient(self.client)

    def enable_security_features(self):
        """
        Ensure security features are enabled (they should be by default in 8.x)
        """
        try:
            # Check security status
            response = self.client.perform_request('GET', '/_security/_authenticate')
            print("✓ Security is enabled and working")
            return True
        except Exception as e:
            print(f"✗ Security check failed: {e}")
            return False

    def create_user(self, username, password, full_name=None, email=None, roles=None):
        """
        Create a new user with password
        """
        try:
            user_body = {
                "password": password,
                "roles": roles or [],
                "full_name": full_name or username,
                "email": email or "",
                "enabled": True
            }

            self.security.put_user(username=username, body=user_body)
            print(f"✓ User '{username}' created successfully")
            return True

        except es_exceptions.RequestError as e:
            if "already exists" in str(e):
                print(f"⚠ User '{username}' already exists")
                return True
            else:
                print(f"✗ Failed to create user '{username}': {e}")
                return False
        except Exception as e:
            print(f"✗ Error creating user '{username}': {e}")
            return False

    def create_role(self, role_name, index_patterns, privileges=None):
        """
        Create a role with specific index permissions
        """
        try:
            role_body = {
                "cluster": [],
                "indices": [
                    {
                        "names": index_patterns,
                        "privileges": privileges or ["read", "view_index_metadata"],
                        "allow_restricted_indices": False
                    }
                ],
                "applications": [],
                "run_as": [],
                "global": {},
                "metadata": {
                    "version": 1
                }
            }

            self.security.put_role(name=role_name, body=role_body)
            print(f"✓ Role '{role_name}' created successfully")
            return True

        except es_exceptions.RequestError as e:
            if "already exists" in str(e):
                print(f"⚠ Role '{role_name}' already exists")
                return True
            else:
                print(f"✗ Failed to create role '{role_name}': {e}")
                return False

    def assign_role_to_user(self, username, role_name):
        """
        Assign a role to a user
        """
        try:
            # Get current user
            user = self.security.get_user(username=username)

            if username in user:
                current_roles = user[username].get('roles', [])

                if role_name not in current_roles:
                    current_roles.append(role_name)

                    update_body = {
                        "roles": current_roles
                    }

                    self.security.put_user(username=username, body=update_body)
                    print(f"✓ Role '{role_name}' assigned to user '{username}'")
                else:
                    print(f"⚠ User '{username}' already has role '{role_name}'")

                return True
            else:
                print(f"✗ User '{username}' not found")
                return False

        except Exception as e:
            print(f"✗ Error assigning role: {e}")
            return False

    def create_index(self, index_name, shards=1, replicas=1):
        """
        Create a new index
        """
        try:
            if not self.indices.exists(index=index_name):
                index_body = {
                    "settings": {
                        "number_of_shards": shards,
                        "number_of_replicas": replicas
                    }
                }

                self.indices.create(index=index_name, body=index_body)
                print(f"✓ Index '{index_name}' created successfully")
                return True
            else:
                print(f"⚠ Index '{index_name}' already exists")
                return True

        except Exception as e:
            print(f"✗ Error creating index '{index_name}': {e}")
            return False

    def create_role_for_specific_index(self, role_name, index_name,
                                       privileges=["read", "write", "view_index_metadata"]):
        """
        Create a role that only has access to a specific index
        """
        return self.create_role(role_name, [index_name], privileges)

    def test_user_access(self, username, password, index_name):
        """
        Test if a user can access a specific index
        """
        try:
            test_client = Elasticsearch(
                hosts=[self.base_url],
                basic_auth=(username, password),
                verify_certs=False,
                request_timeout=10
            )

            # Try to get index info
            response = test_client.search(index=index_name, size=1)
            if response and 'hits' in response:
                print(f"✓ User '{username}' can search index '{index_name}'")
                return True
            else:
                print(f"✗ User '{username}' cannot search index '{index_name}'")
                return False
        except es_exceptions.AuthorizationException:
            print(f"✗ User '{username}' is NOT authorized to access index '{index_name}'")
            return False
        except es_exceptions.NotFoundError:
            print(f"✗ Index '{index_name}' not found for user '{username}'")
            return False
        except Exception as e:
            print(f"✗ Error testing access: {e}")
            return False

    def list_users(self):
        """List all users"""
        try:
            users = self.security.get_user()
            print("\n=== Users ===")
            for username, info in users.items():
                print(f"{username}: {info.get('roles', [])}")
            return users
        except Exception as e:
            print(f"Error listing users: {e}")
            return {}

    def list_roles(self):
        """List all roles"""
        try:
            roles = self.security.get_role()
            print("\n=== Roles ===")
            for role_name, info in roles.items():
                indices = info.get('indices', [])
                index_names = [idx['names'] for idx in indices]
                print(f"{role_name}: {index_names}")
            return roles
        except Exception as e:
            print(f"Error listing roles: {e}")
            return {}

    def list_indices(self):
        """List all indices"""
        try:
            indices = self.indices.get(index="*")
            print("\n=== Indices ===")
            for index_name in indices.keys():
                print(f"- {index_name}")
            return indices
        except Exception as e:
            print(f"Error listing indices: {e}")
            return {}


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Elasticsearch 8.x Security Manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Enable security and set up a new user with index access
  python elasticsearch_manager.py setup --elastic-password changeme

  # Create a new index
  python elasticsearch_manager.py create-index --index my_data --elastic-password changeme

  # Create a user with access to specific index
  python elasticsearch_manager.py create-index-user \\
    --index sales_data \\
    --username sales_user \\
    --user-password sales123 \\
    --elastic-password changeme

  # Test user access
  python elasticsearch_manager.py test-access \\
    --username sales_user \\
    --user-password sales123 \\
    --index sales_data
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Command to execute')

    # Setup command
    setup_parser = subparsers.add_parser('setup', help='Initial setup and enable security')
    setup_parser.add_argument('--elastic-password', required=True, help='Elastic superuser password')

    # Create index command
    index_parser = subparsers.add_parser('create-index', help='Create a new index')
    index_parser.add_argument('--index', required=True, help='Index name')
    index_parser.add_argument('--elastic-password', required=True, help='Elastic superuser password')

    # Create user with index access command
    user_parser = subparsers.add_parser('create-index-user',
                                        help='Create user with access to specific index')
    user_parser.add_argument('--index', required=True, help='Index name')
    user_parser.add_argument('--username', required=True, help='New username')
    user_parser.add_argument('--user-password', required=True, help='New user password')
    user_parser.add_argument('--elastic-password', required=True, help='Elastic superuser password')
    user_parser.add_argument('--privileges', nargs='+',
                             default=["read", "write", "view_index_metadata"],
                             help='Privileges for the user')

    # Test access command
    test_parser = subparsers.add_parser('test-access', help='Test user access to index')
    test_parser.add_argument('--username', required=True, help='Username to test')
    test_parser.add_argument('--user-password', required=True, help='User password')
    test_parser.add_argument('--index', required=True, help='Index to test access to')

    # List command
    list_parser = subparsers.add_parser('list', help='List users, roles, or indices')
    list_parser.add_argument('--what', choices=['users', 'roles', 'indices', 'all'],
                             default='all', help='What to list')
    list_parser.add_argument('--elastic-password', required=True, help='Elastic superuser password')

    # Add document to index
    add_document_parser = subparsers.add_parser('add-document', help='Add a document to an index')
    add_document_parser.add_argument('--index', required=True, help='Index name')
    add_document_parser.add_argument('--username', required=True, help='User who can ingest into the index')
    add_document_parser.add_argument('--user-password', required=True, help='User password')
    add_document_parser.add_argument('--document', required=True, help='Path to JSON document')

    # Search command
    search_parser = subparsers.add_parser('search', help='Search an index')
    search_parser.add_argument('--index', required=True, help='Index name')
    search_parser.add_argument('--username', required=True, help='User who can search the index')
    search_parser.add_argument('--user-password', required=True, help='User password')
    search_parser.add_argument('--search_query', help='Search query (not implemented, defaults to match_all)')

    # Common arguments
    for subparser in [setup_parser, index_parser, user_parser, test_parser, list_parser, add_document_parser, search_parser]:
        subparser.add_argument('--scheme', default='http', help='Elasticsearch host scheme (http or https)')
        subparser.add_argument('--host', default='localhost', help='Elasticsearch host')
        subparser.add_argument('--port', type=int, default=9200, help='Elasticsearch port')
        subparser.add_argument('--elastic-user', default='elastic', help='Elastic superuser username')

    return parser.parse_args()


def main():
    args = parse_arguments()

    if not args.command:
        print("Error: No command specified. Use --help for usage information.")
        sys.exit(1)

    try:
        # Initialize manager with elastic superuser credentials
        if args.command not in ['add-document', 'test-access', 'search']:
            # For all commands except test-access, use elastic superuser
            manager = ElasticsearchSecurityManager(
                scheme=args.scheme,
                host=args.host,
                port=args.port,
                username=args.elastic_user,
                password=args.elastic_password,
            )
        else:
            # For test-access, we'll create a minimal manager with test user
            # (we still need elastic user to get base URL)
            manager = ElasticsearchSecurityManager(
                scheme=args.scheme,
                host=args.host,
                port=args.port,
                username=args.username,
                password=args.user_password,
            )

        # Execute command
        if args.command == 'setup':
            print("Performing initial security setup...")
            manager.enable_security_features()

            # Create example setup
            manager.create_index("logs-2024")
            manager.create_role_for_specific_index("logs_role", "logs-*",
                                                   ["read", "write", "delete"])
            manager.create_user("log_user", "log_password123", "Log User",
                                roles=["logs_role"])
            print("\n✓ Setup completed!")

        elif args.command == 'create-index':
            print(f"Creating index '{args.index}'...")
            manager.create_index(args.index)

        elif args.command == 'create-index-user':
            print(f"Creating user '{args.username}' with access to index '{args.index}'...")

            # Step 1: Create index if it doesn't exist
            manager.create_index(args.index)

            # Step 2: Create role for the index
            role_name = f"{args.index}_role"
            manager.create_role_for_specific_index(role_name, args.index, args.privileges)

            # Step 3: Create user
            manager.create_user(args.username, args.user_password,
                                full_name=args.username.capitalize())

            # Step 4: Assign role to user
            manager.assign_role_to_user(args.username, role_name)

            print(f"\n✓ User '{args.username}' setup complete!")
            print(f"  Index: {args.index}")
            print(f"  Role: {role_name}")
            print(f"  Privileges: {args.privileges}")

            # Test the access
            print("\nTesting access...")
            manager.test_user_access(args.username, args.user_password, args.index)

        elif args.command == 'test-access':
            print(f"Testing access for user '{args.username}' to index '{args.index}'...")
            manager.test_user_access(args.username, args.user_password, args.index)

        elif args.command == 'add-document':
            print(f"Adding document to index '{args.index}'...")
            try:
                with open(args.document, 'r') as f:
                    document = json.load(f)
                print(json.dumps(document[0], indent=2))
                manager.client.index(index=args.index, document=document[0])
            except Exception as e:
                print(f"✗ Failed to load document: {e}")
                sys.exit(1)
            print(f"✓ Document added to index '{args.index}'")

        elif args.command == 'search':
            print(f"Searching index '{args.index}'...")
            query_body = {
                "query": {
                    "match_all": {}
                }
            }
            response = manager.client.search(index=args.index, body=query_body)
            if response.meta.status == 200:
                print(f"✓ Search successful. Found {response.get("hits").get("total").get("value")} hits.")
            print(json.dumps(response.body, indent=2))

        elif args.command == 'list':
            if args.what in ['users', 'all']:
                manager.list_users()
            if args.what in ['roles', 'all']:
                manager.list_roles()
            if args.what in ['indices', 'all']:
                manager.list_indices()

        print("\nOperation completed successfully!")

    except Exception as e:
        print(f"\n✗ Error: {e}")
        print("\nTroubleshooting tips:")
        print("1. Ensure Elasticsearch is running: docker ps | grep elasticsearch")
        print("2. Check if security is enabled")
        print("3. Verify the elastic superuser password")
        print("4. Check network connectivity to Elasticsearch")
        sys.exit(1)


if __name__ == "__main__":
    main()