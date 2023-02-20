import unittest # Used to execute the unit tests
import requests # Used for HTTP & API Calls
from scapy.all import *
import json

def handle_json_packet(packet):
    # Decode the payload as a string
    payload_str = str(packet.payload, 'utf-8')

    # Parse the payload as a JSON object
    try:
        payload_json = json.loads(payload_str)
        print(payload_json)
    except json.JSONDecodeError:
        # Ignore packets with invalid JSON payloads
        return

filter_exp = "src host 172.17.0.1 and dst host 172.17.0.2"

# Define the function to handle each captured packet
def handle_packet(packet):
    # Check if the packet has a payload
    if packet.payload is not None:
        # Do something with the packet's payload
        print(packet.payload)
        handle_json_packet(packet)

# Start the capture on the docker0 interface with the specified filter expression and packet handler
sniff(iface="docker0", filter=filter_exp, prn=handle_packet)

class TestOWASPJuiceShop(unittest.TestCase):

    def test_sql_injection(self):
        url = "http://localhost:3000"
        email = "admin@juice-sh.op'OR 1=1;"
        password = "password'OR 1=1;"
        payload = {
            "email": email,
            "password": password
        }
        response = requests.post(url+"/rest/user/login", data=payload)
        self.assertNotEqual(response.status_code, 200)
        self.assertEqual(response.text, "Invalid email or password.")


    def test_authorization_bypass(self):
        
        admin_payload = { # Admin Payload To Add Item to Shopping Basket
            "BasketId": '1',
            "ProductId": '1', 
            "quantity": '1'
            }
        

        adminlogin_response = requests.post("http://localhost:3000/rest/user/login", data = { "email": "admin@juice-sh.op","password": "admin123" }) # Log in as the admin
        adminToken = adminlogin_response.json()['authentication']['token'] # Capture the access token
        
        adminHeaders = { # Set the request headers for the next API call
            "Authorization": "Bearer " + adminToken,
            "User-Agent": str(adminlogin_response.request.headers.get('User-Agent')),
            "Accept": "application/json",
            "Accept-Language": "en-us",
            "Content-Type": "application/json"
        }

        requests.post("http://localhost:3000/api/BasketItems/", headers=adminHeaders, json=admin_payload) # API request to add an item to the admins basket
        

        userlogin_response = requests.post("http://localhost:3000/rest/user/login", data = { "email": "cys444@gmail.com","password": "tester" })
        userToken = userlogin_response.json()['authentication']['token'] # Capture the access token
        userHeaders = {
            "Authorization": "Bearer " + userToken,
            "User-Agent": str(userlogin_response.request.headers.get('User-Agent')),
            "Accept": "application/json",
            "Accept-Language": "en-us",
            "Content-Type": "application/json"
        }


        getBasket_response = requests.get("http://localhost:3000/rest/basket/1", headers=userHeaders)

        self.assertNotEqual(getBasket_response.status_code, 200)

    def test_weak_password_requirements(self):
        url = "http://localhost:3000/api/Users/"
        payload = { # Payload for a new unique user
            "email": "test2@test.com",
            "password": "12345",
            "passwordRepeat": "12345",
            "securityAnswer": "mom",
            "securityQuestion": {
                "id": "2",
                "question": "Mother's maiden name?"
            }
        }
        response = requests.post(url, data=payload)
        print('Content is:\n', response.content)
        self.assertNotEqual(response.status_code, 201)

    def test_cleartext_transmission(self):
        url = "http://localhost:3000"
        email = "admin@juice-sh.op"
        password = "admin123"
        payload = {
            "email": email,
            "password": password
        }
        response = requests.post(url+"/rest/user/login", data=payload)
        self.assertIn("email", response.text)
        self.assertIn("password", response.text)

    def test_improper_input_validation(self):
        url = "http://localhost:3000"
        credentials = {
            "email": "admin@juice-sh.op",
            "password": "admin123"
        }
        session = requests.Session()
        session.post(url+"/rest/user/login", data=credentials)
        product_id = session.get(url+"/api/products").json()[0]["id"]
        response = session.put(url+f"/api/BasketItems/{product_id}", json={"quantity": -10})
        self.assertNotEqual(response.status_code, 200)


#if __name__ == '__main__':
    #unittest.main()

