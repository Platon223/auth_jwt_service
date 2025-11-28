import unittest
from service import create_service
from extensions.db import db

test_app = create_service()

class RLTestCase(unittest.TestCase):
    def setUp(self):
        test_app.config["TESTING"] = True

        test_app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///./rl_test.db"
        self.app_context = test_app.app_context()
        self.app_context.push()

        db.create_all()

        self.client = test_app.test_client()

    def tearDown(self):
        
        db.session.remove()
        db.drop_all()

        self.app_context.pop()

    def test(self):
        register_response = self.client.post("/auth/register", json={
            "username": "test",
            "password": 123,
            "email": "testemail.com",
            "job": "testJob"
        })

        self.assertEqual(register_response.status_code, 200)
        self.assertIn("success", register_response.data.decode("utf-8"))



        login_response = self.client.post("/auth/login?step=first_entry", json={
            "username": "test",
            "password": "test123"
        })

        self.assertEqual(login_response.status_code, 200)
        self.assertIn("verify page", login_response.data.decode("utf-8"))

