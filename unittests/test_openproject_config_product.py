from django.urls import reverse
from .dojo_test_case import DojoTestCase
from dojo.models import OpenProject_Instance, Product
from django.utils.http import urlencode
from unittest.mock import patch, call
from pyopenproject.business.exception.business_error import BusinessError
# from pyopenproject.api_connection.exceptions.request_exception import RequestError
import requests
import dojo.openproject_link.helper as openproject_helper
# from unittest import skip
import logging

logger = logging.getLogger(__name__)


class OpenProjectConfigProductTest(DojoTestCase):
    fixtures = ['dojo_testdata.json']

    data_openproject_instance = {
            'configuration_name': 'something_openproject',
            'url': 'https://127.0.0.1',
            'username': 'defectdojo',
            'password': 'defectdojo-password',
            'default_issue_type': 'Bug',
            'epic_name_id': 1,
            'open_status_key': 1,
            'close_status_key': 1,
            'info_mapping_severity': 'Info',
            'low_mapping_severity': 'Low',
            'medium_mapping_severity': 'Medium',
            'high_mapping_severity': 'High',
            'critical_mapping_severity': 'Critical',
            # finding_text': '',
            'accepted_mapping_resolution': 'Fixed',
            'false_positive_mapping_resolution': 'False Positive',
            # global_openproject_sla_notification': '',
    }

    # openproject_mock = MagicMock()

    def __init__(self, *args, **kwargs):
        DojoTestCase.__init__(self, *args, **kwargs)

    def setUp(self):
        self.system_settings(enable_openproject=True)
        self.client.force_login(self.get_test_admin())

    @patch('dojo.openproject_link.views.openproject_helper.get_openproject_connection_raw')
    def add_openproject_instance(self, data, openproject_mock):
        response = self.client.post(reverse('add_openproject'), urlencode(data), content_type='application/x-www-form-urlencoded')
        # check that storing a new config triggers a login call to OpenProject
        call_1 = call(data['url'], data['username'], data['password'])
        call_2 = call(data['url'], data['username'], data['password'])
        # openproject_mock.assert_called_once_with(data['url'], data['username'], data['password'])
        openproject_mock.assert_has_calls([call_1, call_2])
        # succesful, so should redirect to list of OpenProject instances
        self.assertRedirects(response, '/openproject')

        openproject_instance = OpenProject_Instance.objects.filter(configuration_name=data['configuration_name'], url=data['url']).last()
        return response, openproject_instance

    def test_add_openproject_instance(self):
        response, openproject_instance = self.add_openproject_instance(self.data_openproject_instance)

    def test_add_openproject_instance_with_issue_template_dir(self):
        # make sure we get no error when specifying template
        data = self.data_openproject_instance.copy()
        data['issue_template_dir'] = 'issue-trackers/openproject/openproject_full'
        response, openproject_instance = self.add_openproject_instance(data)

    # no mock so we can assert the exception raised
    def test_add_openproject_instance_unknown_host(self):
        data = self.data_openproject_instance
        data['url'] = 'https://openproject.hj23412341hj234123421341234ljl.nl'

        # test UI validation error

        # self.client.force_login('admin', backend='django.contrib.auth.backends.ModelBackend')
        # Client.raise_request_exception = False  # needs Django 3.0
        # can't use helper method which has patched connection raw method
        response = self.client.post(reverse('add_openproject'), urlencode(data), content_type='application/x-www-form-urlencoded')

        self.assertEqual(200, response.status_code)
        content = response.content.decode('utf-8')
        self.assertTrue('Name or service not known' in content)

        # test raw connection error
        with self.assertRaises(BusinessError):
            openproject = openproject_helper.get_openproject_connection_raw(data['url'], data['username'], data['password'])

    @patch('dojo.openproject_link.views.openproject_helper.get_openproject_connection_raw')
    def test_add_openproject_instance_invalid_credentials(self, openproject_mock):
        openproject_mock.side_effect = BusinessError('Login failed')
        data = self.data_openproject_instance

        # test UI validation error

        # self.client.force_login('admin', backend='django.contrib.auth.backends.ModelBackend')
        # Client.raise_request_exception = False  # needs Django 3.0
        # can't use helper method which has patched connection raw method
        response = self.client.post(reverse('add_openproject'), urlencode(data), content_type='application/x-www-form-urlencoded')

        self.assertEqual(200, response.status_code)
        content = response.content.decode('utf-8')
        self.assertTrue('Login failed' in content)
        self.assertTrue('Unable to authenticate to OpenProject' in content)

    @patch('dojo.openproject_link.views.openproject_helper.is_openproject_project_valid')
    def test_add_openproject_project_to_product_without_openproject_project(self, openproject_mock):
        openproject_mock.return_value = True  # cannot set return_value in decorated AND have the mock into the method
        # TODO: add product also via API, but let's focus on OpenProject here
        product = self.add_product_without_openproject_project(expected_delta_openproject_project_db=0)
        response = self.edit_openproject_project_for_product(product, expected_delta_openproject_project_db=1)
        self.assertEqual(openproject_mock.call_count, 1)

    @patch('dojo.openproject_link.views.openproject_helper.is_openproject_project_valid')
    def test_add_empty_openproject_project_to_product_without_openproject_project(self, openproject_mock):
        openproject_mock.return_value = True  # cannot set return_value in decorater AND have the mock into the method
        product = self.add_product_without_openproject_project(expected_delta_openproject_project_db=0)
        response = self.empty_openproject_project_for_product(product, expected_delta_openproject_project_db=0)
        self.assertEqual(openproject_mock.call_count, 0)

    @patch('dojo.openproject_link.views.openproject_helper.is_openproject_project_valid')
    def test_edit_openproject_project_to_product_with_openproject_project(self, openproject_mock):
        openproject_mock.return_value = True  # cannot set return_value in decorated AND have the mock into the method
        product = self.add_product_with_openproject_project(expected_delta_openproject_project_db=1)
        response = self.edit_openproject_project_for_product2(product, expected_delta_openproject_project_db=0)
        self.assertEqual(openproject_mock.call_count, 2)

    @patch('dojo.openproject_link.views.openproject_helper.is_openproject_project_valid')
    def test_edit_empty_openproject_project_to_product_with_openproject_project(self, openproject_mock):
        openproject_mock.return_value = True  # cannot set return_value in decorated AND have the mock into the method
        product = self.add_product_with_openproject_project(expected_delta_openproject_project_db=1)
        # clearing out openproject config used to be possible. what todo?
        # - delete openproject project? would disconnect all existing openproject issues in defect dojo from the config?
        # - allow openproject project with empty openproject instance and/or empty project_key? unpredictable behaviour
        # - so prevent clearing out these values
        # response = self.empty_openproject_project_for_product(Product.objects.get(id=3), -1)
        # errors means it won't redirect to view_product, but returns a 200 and redisplays the edit product page
        response = self.empty_openproject_project_for_product(product, expected_delta_openproject_project_db=0, expect_200=True)
        self.assertEqual(openproject_mock.call_count, 1)

    @patch('dojo.openproject_link.views.openproject_helper.is_openproject_project_valid')
    def test_add_openproject_project_to_product_without_openproject_project_invalid_project(self, openproject_mock):
        openproject_mock.return_value = False  # cannot set return_value in decorated AND have the mock into the method
        # errors means it won't redirect to view_product, but returns a 200 and redisplays the edit product page
        response = self.edit_openproject_project_for_product(Product.objects.get(id=3), expected_delta_openproject_project_db=0, expect_200=True)
        self.assertEqual(openproject_mock.call_count, 1)

    @patch('dojo.openproject_link.views.openproject_helper.is_openproject_project_valid')
    def test_edit_openproject_project_to_product_with_openproject_project_invalid_project(self, openproject_mock):
        openproject_mock.return_value = True  # cannot set return_value in decorated AND have the mock into the method
        product = self.add_product_with_openproject_project(expected_delta_openproject_project_db=1)
        openproject_mock.return_value = False
        #  openproject key is changed, so openproject project will be checked
        response = self.edit_openproject_project_for_product2(product, expected_delta_openproject_project_db=0, expect_200=True)
        self.assertEqual(openproject_mock.call_count, 2)

    @patch('dojo.openproject_link.views.openproject_helper.is_openproject_project_valid')
    def test_add_product_with_openproject_project(self, openproject_mock):
        openproject_mock.return_value = True  # cannot set return_value in decorated AND have the mock into the method
        product = self.add_product_with_openproject_project(expected_delta_openproject_project_db=1)
        self.assertIsNotNone(product)
        self.assertEqual(openproject_mock.call_count, 1)

    @patch('dojo.openproject_link.views.openproject_helper.is_openproject_project_valid')
    def test_add_product_with_openproject_project_invalid_openproject_project(self, openproject_mock):
        openproject_mock.return_value = False  # cannot set return_value in decorated AND have the mock into the method
        product = self.add_product_with_openproject_project(expected_delta_openproject_project_db=0, expect_redirect_to='/product/%i/edit')
        # product is still saved, even with invalid openproject project key
        self.assertIsNotNone(product)
        self.assertEqual(openproject_mock.call_count, 1)

    @patch('dojo.openproject_link.views.openproject_helper.is_openproject_project_valid')
    def test_add_product_without_openproject_project(self, openproject_mock):
        openproject_mock.return_value = True  # cannot set return_value in decorated AND have the mock into the method
        product = self.add_product_without_openproject_project(expected_delta_openproject_project_db=0)
        self.assertIsNotNone(product)
        self.assertEqual(openproject_mock.call_count, 0)

    # with openproject disabled the openprojectform should not be checked at all
    @patch('dojo.forms.OpenProjectProjectForm.is_valid')
    def test_add_product_with_openproject_project_to_product_openproject_disabled(self, openproject_mock):
        openproject_mock.return_value = True  # cannot set return_value in decorated AND have the mock into the method
        self.system_settings(enable_openproject=False)
        product = self.add_product_with_openproject_project(expected_delta_openproject_project_db=0)
        self.assertIsNotNone(product)
        self.assertEqual(openproject_mock.call_count, 0)

    # with openproject disabled the openprojectform should not be checked at all
    @patch('dojo.forms.OpenProjectProjectForm.is_valid')
    def test_edit_openproject_project_to_product_with_openproject_project_invalid_project_openproject_disabled(self, openproject_mock):
        self.system_settings(enable_openproject=False)
        openproject_mock.return_value = True  # cannot set return_value in decorated AND have the mock into the method
        response = self.edit_openproject_project_for_product(Product.objects.get(id=3), expected_delta_openproject_project_db=0)
        response = self.edit_openproject_project_for_product2(Product.objects.get(id=3), expected_delta_openproject_project_db=0)
        self.assertEqual(openproject_mock.call_count, 0)


# TODO UI
# linking / unlinking
