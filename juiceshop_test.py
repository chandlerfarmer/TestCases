import unittest
import requests
# Here is a new comment.


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
        

        admin_credentials = { # Admin Credentials For Test
            "email": "admin@juice-sh.op",
            "password": "admin123"
        }
        normal_user_credentials = { # Normal User Credentials For Test
            "email": "cys444@gmail.com",
            "password": "tester"
        }

        normal_user_basketID = '8' # Shopping Basket Id of Normal User


        admin_payload = { # Admin Payload To Add Item to Shopping Basket
            "BasketId": '1',
            "ProductId": '1', 
            "quantity": '1'
            }
        

        login_response = requests.post("http://localhost:3000/rest/user/login", data=admin_credentials) # Login as Admin
        
        headers = {
            "Cookie": str(login_response.cookies.get('Cookie')),
            "Authorization": str(login_response.request.headers.get('Authorization')),
            "User-Agent": str(login_response.request.headers.get('User-Agent')),
            "Accept": "application/json",
            "Accept-Language": "en-us",
            "Content-Type": "application/json"
        }

        modifyBasket_response = requests.post("http://localhost:3000/api/BasketItems/", headers=headers, json=admin_payload)
        print(headers)
        print(modifyBasket_response.content)
        
        # Log in as normal user and access admin's basket
        requests.post(loginURL, data=normal_user_credentials)
        basket_id = session.get(url+"/rest/basket/" + admin_user_basketID)
        headers = {
            "Authorization": session.cookies.get_dict()["token"]
        }
        response = requests.get(url+f"/rest/basket/{basket_id}", headers=headers)
        self.assertEqual(response.status_code, 403)

    def test_weak_password_requirements(self):
        url = "http://localhost:3000"
        payload = {
            "email": "test@test.com",
            "password": "12345",
            "securityQuestion": "Question",
            "securityAnswer": "Answer"
        }
        response = requests.post(url+"/rest/user/register", data=payload)
        self.assertNotEqual(response.status_code, 200)

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


if __name__ == '__main__':
    unittest.main()
