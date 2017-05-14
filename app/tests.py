import json

from django.contrib.auth.models import User
from django.test import TestCase
from rest_framework import status
from rest_framework.test import APIClient
from rest_framework_jwt import utils

from app.models import Book


class AuthTest(TestCase):
    def setUp(self):
        """
        prepare tests
        """
        self.client = APIClient()
        Book.objects.create(title="book1", author="author1", year=2001)
        Book.objects.create(title="book2", author="author2", year=2002)
        Book.objects.create(title="book3", author="author3", year=2003)
        self.admin_user = User.objects.create_superuser('admin', 'myemail@test.com', "password123")
        self.data = {
            'username': 'admin',
            'password': 'password123'
        }

    def test_jwt_login(self):
        """
        ensure JWT JSON POST works.
        """
        client = APIClient(enforce_csrf_checks=True)
        response = client.post('/api-token-auth/', self.data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        payload = utils.jwt_decode_handler(response.data['token'])
        self.assertEqual(payload['username'], self.data['username'])

    def test_jwt_login_wrong_creds(self):
        """
        ensure JWT login using JSON POST fails
        if credentials are wrong.
        """
        client = APIClient(enforce_csrf_checks=True)
        self.data['password'] = 'wrong'
        response = client.post('/api-token-auth/', self.data, format='json')
        self.assertEqual(response.status_code, 400)

    def test_jwt_login_json_missing_fields(self):
        """
        ensure JWT login using JSON POST fails if missing fields.
        """
        client = APIClient(enforce_csrf_checks=True)
        response = client.post('/api-token-auth/',
                               {'username': "admin"}, format='json')
        self.assertEqual(response.status_code, 400)

    def test_not_auth_request(self):
        """
        verifying that resources are not accessible w/o authentication
        """
        resp = self.client.get("/api/books/")
        self.assertEqual(resp.status_code, 401)
        resp = self.client.post("/api/books/", data=None)
        self.assertEqual(resp.status_code, 401)
        resp = self.client.get("/api/book/1/")
        self.assertEqual(resp.status_code, 401)
        resp = self.client.put("/api/book/1/", data=None)
        self.assertEqual(resp.status_code, 401)
        resp = self.client.delete("/api/book/1/")
        self.assertEqual(resp.status_code, 401)

    def test_auth_request_get_list(self):
        """
        test retrieve list of books
        """
        self.client.force_authenticate(self.admin_user)
        resp = self.client.get("/api/books/")
        self.assertEqual(resp.status_code, 200)
        j = json.loads(json.dumps(resp.data))
        self.assertEqual(len(j), 3)
        self.client.logout()

    def test_auth_request_get_details(self):
        """
        test retrieve book details
        """
        self.client.force_authenticate(self.admin_user)
        resp = self.client.get("/api/book/1/")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.content, b'{"id":1,"title":"book1","author":"author1","year":2001}')
        self.client.logout()

    def test_auth_request_put_details(self):
        """
        test update book
        """
        self.client.force_authenticate(self.admin_user)
        book = Book.objects.all()[0]
        resp = self.client.get("/api/book/" + str(book.id) + "/")
        old_book_json = json.loads(json.dumps(resp.data))
        new_book_obj = {"id": old_book_json['id'], "title": old_book_json['title'], "author": old_book_json['author'],
                        "year": 2017}
        resp = self.client.put("/api/book/" + str(book.id) + "/", new_book_obj)
        self.assertEqual(resp.status_code, 200)
        resp = self.client.get("/api/book/" + str(book.id) + "/")
        new_book_json = json.loads(json.dumps(resp.data))
        self.assertEqual(new_book_json['year'], 2017)
        self.client.logout()

    def test_auth_request_delete_book(self):
        """
        test delete book
        """
        self.client.force_authenticate(self.admin_user)
        new_book = {"title": "New World", "author": "Bon Axe", "year": 1988}
        self.client.post("/api/books/", data=new_book)
        book = Book.objects.get(title="New World")

        self.client.delete("/api/book/" + str(book.id) + "/")
        with self.assertRaises(Book.DoesNotExist):
            Book.objects.get(title="New World")
        self.client.logout()

    def test_auth_request_post_list(self):
        """
        test add new book
        """
        self.client.force_authenticate(self.admin_user)
        new_book = {"id": 55, "title": "New World", "author": "Bon Axe", "year": 1988}
        post_resp = self.client.post("/api/books/", data=new_book)
        get_resp = self.client.get("/api/books/")
        j = json.loads(json.dumps(get_resp.data))
        self.assertEqual(post_resp.status_code, 201)
        self.assertEqual(len(j), 4)
        Book.objects.filter(id=5).delete()
        self.client.logout()
