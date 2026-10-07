import requests
import urllib3
from urllib.parse import quote
from requests.auth import HTTPBasicAuth
import time

class fmc_api_communicator:

    def __init__(self, domain_uuid, fmc_ip, fmc_user, fmc_password, ssl_verify, ssl_cert):
        self._auth_token = None
        self.domain_uuid = domain_uuid or "0"
        self.fmc_ip = (fmc_ip or "127.0.0.1").rstrip('/')
        self.fmc_user = fmc_user or ""
        self.fmc_password = fmc_password or ""

        if not ssl_verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            self.ssl_verify = ssl_verify
        else:
            self.ssl_verify = ssl_cert

        self.getAuthToken()

    def getAuthToken(self):

        print('\nFetching Authentication Token from FMC...')

        # Build HTTP Authentication Instance
        auth = HTTPBasicAuth(self.fmc_user, self.fmc_password)

        # Build HTTP Headers
        auth_headers = {'Content-Type': 'application/json'}

        # Build URL for Authentication
        auth_url = "{}/api/fmc_platform/v1/auth/generatetoken".format(self.fmc_ip)

        try:
            http_req = requests.post(url=auth_url, auth=auth, headers=auth_headers, verify=self.ssl_verify)

            print('FMC Auth Response: ' + str(http_req.headers))

            # Set the Auth Token and FMC Domain UUID
            self._auth_token = http_req.headers.get('X-auth-access-token', default=None)
            self.domain_uuid = http_req.headers.get('DOMAIN_UUID', default=None)

            # If we didn't get a token, then something went wrong
            if self._auth_token is None:
                print('Authentication Token Not Found.  Exiting...')
                exit()

            print('Authentication Token Successfully Fetched.')

        except Exception as err:
            print('Error fetching auth token from FMC: ' + str(err))
            exit()

    def doApiCall(self, method, endpoint, json_data=None, object_id=None):

        # endpoint is a full, already-built URL. object_id, if given, is
        # appended as the final path segment.
        request_url = endpoint if object_id is None else endpoint.rstrip('/') + '/' + object_id



        # If there's no FMC Authentication Token, then fetch one
        if not self._auth_token:
            self.getAuthToken()

        headers = {
            'Content-Type': 'application/json',
            'X-auth-access-token': self._auth_token
        }

        retry_delays = [2, 4, 8, 8, 8]

        for attempt in range(5):
            try:
                print('\nSending ' + str(method) + ' request to ' + request_url + ' endpoint on the FMC.')
                if method == 'POST':
                    http_req = requests.post(
                        url=request_url,
                        headers=headers,
                        json=json_data,
                        verify=self.ssl_verify
                    )
                elif method == 'PUT':
                    http_req = requests.put(
                        url=request_url,
                        headers=headers,
                        json=json_data,
                        verify=self.ssl_verify
                    )
                elif method == 'DELETE':
                    http_req = requests.delete(
                        url=request_url,
                        headers=headers,
                        json=json_data,
                        verify=self.ssl_verify
                    )
                else:
                    http_req = requests.get(
                        url=request_url,
                        headers=headers,
                        json=json_data,
                        verify=self.ssl_verify
                    )

                if 200 <= http_req.status_code < 300:
                    print('Request successfully sent to FMC.')
                    return http_req.json()

                else:
                    print(
                        "FMC Connection Failure - HTTP Return Code: {}\nResponse: {}".format(
                            http_req.status_code,
                            http_req.json()
                        )
                    )

            except Exception as err:
                print('Error posting request to FMC: ' + str(err))

            # If this wasn't the final attempt, wait before retrying
            if attempt < 4:
                delay = retry_delays[attempt]
                print('Retrying in {} seconds... (Attempt {}/5)'.format(
                    delay, attempt + 2
                ))
                time.sleep(delay)

        # All 5 attempts failed
        print('FMC request failed after 5 attempts. Resuming')
        exit()

    def createObject(self, object_endpoint, object_json):

        print("\nCreating object at the following endpoint: " + object_endpoint)

        # Send the JSON to the FMC
        return_json = self.doApiCall('POST', object_endpoint, object_json)

        return return_json

    # Delete an object in the FMC by its object id
    def deleteObject(self, object_endpoint, object_id):

        print("\nDeleting object " + object_id + " from: " + object_endpoint)

        return_json = self.doApiCall('DELETE', object_endpoint, object_id=object_id)

        return return_json

    # Get a single object from the FMC by its object id
    def getObject(self, object_endpoint, object_id=None):

        print("\nRetrieving object from FMC: " + object_endpoint + (('/' + object_id) if object_id else ''))

        return_json = self.doApiCall('GET', object_endpoint, object_id=object_id)

        return return_json

    # Look up an object in a collection by exact name match.
    # Returns the matching object dict (with its 'id'), or None if not found.
    def getObjectByName(self, object_endpoint, name):

        query_url = object_endpoint.rstrip('/') + '?filter=nameOrValue:' + quote(name)

        print("\nLooking up object by name: " + name)

        response = self.doApiCall('GET', query_url) or {}

        for item in response.get('items', []):
            if item.get('name') == name:
                return item

        return None

    # Update an object in the FMC by its object id
    def updateObject(self, object_endpoint, object_id, object_json):

        print("\nUpdating object at the following endpoint: " + object_endpoint + '/' + object_id)

        return_json = self.doApiCall('PUT', object_endpoint, object_json, object_id=object_id)

        return return_json
