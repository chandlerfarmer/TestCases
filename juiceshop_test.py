import unittest # Used to execute the unit tests
import requests # Used for HTTP & API Calls
from scapy.all import *
import json


def handle_packet(packet): # Checks if the packet payload contains the credentials in clear text 
        try:
            payload = packet.load # Check if the packet has a payload
            if b"admin@juice-sh.op" and b"admin123" in payload: # Check if the credentials are in the payload
                result = True
                return result # Packet Contains Clear Text
            
        except AttributeError: # Packet doesn't contain a payload
            print('No Payload Found')
        return False


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
        response.close()

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
        getBasket_response.close()
        self.assertNotEqual(getBasket_response.status_code, 200)

    def test_weak_password_requirements(self):
        url = "http://localhost:3000/api/Users/"
        payload = { # Payload for a new unique user (must change each run)
            "email": "testerm22rtfasfest@test.com",
            "password": "12345",
            "passwordRepeat": "12345",
            "securityAnswer": "mom",
            "securityQuestion": {
                "id": "2",
                "question": "Mother's maiden name?"
            }
        }
        response = requests.post(url, data=payload)
        self.assertNotEqual(response.status_code, 201)

    """
    THIS TEST CASE DOESN'T WORK HOWEVER IF YOU MANUALLY ENTER CREDENTIALS IN BROWSER THE "handle_packet" FUNCTION CONFIRMS THEY'RE BEING CAPTURED.
    def test_cleartext_transmission(self):

        filter_expression = "tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354" # HTTP POST METHOD
        packet = sniff(iface="docker0", filter=filter_expression, prn=handle_packet, count=1)
                  
        self.assertNotEqual(packet, True)
    """

    def test_improper_input_validation(self):
        url = "http://localhost:3000"
        
        credentials = { # Credentials to Log in
            "email": "admin@juice-sh.op",
            "password": "admin123"
        }
        adminlogin_response = requests.post(url+"/rest/user/login", data=credentials) # Stores the Log in Response

        adminToken = adminlogin_response.json()['authentication']['token'] # Capture the Admins access token

        adminHeaders = {
            "Authorization": "Bearer " + adminToken,
            "User-Agent": str(adminlogin_response.request.headers.get('User-Agent')),
            "Accept": "application/json",
            "Accept-Language": "en-us",
            "Content-Type": "application/json"
        }

        requests.post(url+f"/api/BasketItems/", headers=adminHeaders, data={"BasketId": "1", "ProductId": 1, "quantity": 1})
        real_response = requests.get(url+f"/rest/basket/1", headers=adminHeaders)
        json_content = real_response.json()
        val = json_content['data']['Products'][0]['BasketItem']['id']


        response1 = requests.put(url+f"/api/BasketItems/{val}", headers=adminHeaders, json={"quantity": -10})
        self.assertNotEqual(response1.status_code, 200)


if __name__ == '__main__':
    unittest.main()

