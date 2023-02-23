import unittest # Used to execute the unit tests
import requests # Used for HTTP & API Calls
from scapy.all import *
import json
import threading
import time



def makeRequest():
    time.sleep(2)
    url = "http://localhost:3000"
    email = "admin@juice-sh.op"
    password = "admin123"
    payload = {
        "email": email,
        "password": password
    }
    requests.post(url+"/rest/user/login", data=payload)
    print("made Request")


def capture_packets():
        filter_expression = "tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354" # HTTP POST METHOD
        sniff(iface="lo", filter= filter_expression, prn=handle_packet, count=2) 
        print("SNIFFING")


def handle_packet(packet): # Checks if the packet payload contains the credentials in clear text 
        try:
            payload = packet.load # Check if the packet has a payload
            if b"admin@juice-sh.op" and b"admin123" in payload: # Check if the credentials are in the payload
                print("capturing packet")
                result = True
                return result # Packet Contains Clear Text
            
        except AttributeError: # Packet doesn't contain a payload
            print('No Payload Found')
        return


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
            "email": "test20222222222222222220@test.com",
            "password": "12345",
            "passwordRepeat": "12345",
            "securityAnswer": "mom",
            "securityQuestion": {
                "id": "2",
                "question": "Mother's maiden name?"
            }
        }
        response = requests.post(url, data=payload)
        response.close()
        self.assertNotEqual(response.status_code, 200)

    #def test_cleartext_transmission(self):

        #sniffer_thread = threading.Thread(target=capture_packets)
        #packetSend_thread = threading.Thread(target=makeRequest)
        #sniffer_thread.start()
        #packetSend_thread.start()
        #time.sleep(3)
        #filter_expression = "tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354" # HTTP POST METHOD
        #val = sniff(iface="lo", filter= filter_expression, prn=handle_packet, count=2) 
        #my_thread = threading.Thread(target=handle_packet(sniff(iface="lo", filter= filter_expression, prn=handle_packet, count=2)))
       # my_thread.daemon = True  # set the thread as a daemon thread
        #my_thread.start()
        #if (sniffer_thread == True):
         #   comparator = True
        #else:
        #    comparator = False
        #self.assertNotEqual(comparator, True) 

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
        }
        response = requests.post(url+f"/api/BasketItems/", headers=adminHeaders, data={"BasketId": "1", "ProductId": 1, "quantity": 1})
        iD = response.json()['data']['id']
        response = requests.put(url+f"/api/BasketItems/{iD}", headers=adminHeaders, json={"quantity": -10})
        self.assertNotEqual(response.status_code, 200)


if __name__ == '__main__':
    unittest.main()

