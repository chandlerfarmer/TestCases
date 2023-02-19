import unittest
import requests
import logging
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
        response = requests.post(url+"/#/login", data=payload)
        self.assertNotEqual(response.status_code, 200)
        self.assertEqual(response.text, "Invalid email or password.")

    def test_authorization_bypass(self):
        url = "http://localhost:3000"
        admin_credentials = {
            "email": "admin@juice-sh.op",
            "password": "admin123"
        }
        normal_user_credentials = {
            "email": "normal@user.com",
            "password": "password"
        }
        # Log in as admin and add product to basket
        session = requests.Session()
        session.post(url+"/rest/user/login", data=admin_credentials)
        product = session.get(url+"/api/products").json()[0]
        session.put(url+f"/api/BasketItems/{product['id']}")
        session.post(url+"/rest/user/logout")
        # Log in as normal user and access admin's basket
        session.post(url+"/rest/user/login", data=normal_user_credentials)
        basket_id = session.get(url+"/rest/basket").json()["id"]
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
