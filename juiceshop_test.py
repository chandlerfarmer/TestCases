import unittest # Used to execute the unit tests
import requests # Used for HTTP & API Calls
from scapy.all import *
import json

def extract_fields(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        # Check if the packet contains a POST request
        if "POST" in str(packet[TCP].payload):
            print(packet)
            # Extract the body of the POST request
            body = str(packet[TCP].payload).split("\r\n\r\n")[1]
            # Extract the email and password fields from the body
            email = body.split("&")[0].split("=")[1]
            password = body.split("&")[1].split("=")[1]
            print(f"Email: {email}, Password: {password}")

sniff(filter="tcp and dst port 80", iface="lo", prn=extract_fields)




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

