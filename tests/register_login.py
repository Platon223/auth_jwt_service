import unittest
from service import create_service

test_app = create_service

class RLTestCase(unittest.TestCase):
    def setUp(self):
        test_app.config["TESTING"] = True
        self.client = test_app.test_client()

    def test(self):
        register_response = self.client.post("/auth/register", data={
            "username": "test",
            "password": "test123",
            "email": "testemail.com",
            "job": "testJob"
        })

        self.assertEqual(register_response.status_code, 200)
        self.assertIn("success", register_response.data)



        login_response = self.client.post("/auth/login?step=first_entry", data={
            "username": "test",
            "password": "test123"
        })

        self.assertEqual(login_response.status_code, 200)
        self.assertIn("verify page", login_response.data)

