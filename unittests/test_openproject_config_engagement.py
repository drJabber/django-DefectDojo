from django.urls import reverse
from .dojo_test_case import DojoTestCase
from dojo.models import Engagement, Product
# from dojo.models import OpenProject_Project
from django.utils.http import urlencode
from unittest.mock import patch
from dojo.openproject_link import helper as openproject_helper
# from unittest import skip
import logging

logger = logging.getLogger(__name__)


class OpenProjectConfigEngagementBase(object):
    def get_new_engagement_with_openproject_project_data(self):
        return {
            'name': 'new engagement',
            'description': 'new description',
            'lead': 1,
            'product': self.product_id,
            'target_start': '2070-11-27',
            'target_end': '2070-12-04',
            'status': 'Not Started',
            # 'openproject-project-form-inherit_from_product': 'on', # absence = False in html forms
            'openproject-project-form-openproject_instance': 2,
            'openproject-project-form-project_key': 'IUNSEC',
            'openproject-project-form-product_openproject_sla_notification': 'on',
        }

    def get_new_engagement_with_openproject_project_data_and_epic_mapping(self):
        return {
            'name': 'new engagement',
            'description': 'new description',
            'lead': 1,
            'product': self.product_id,
            'target_start': '2070-11-27',
            'target_end': '2070-12-04',
            'status': 'Not Started',
            # 'openproject-project-form-inherit_from_product': 'on', # absence = False in html forms
            'openproject-project-form-openproject_instance': 2,
            'openproject-project-form-project_key': 'IUNSEC',
            'openproject-project-form-product_openproject_sla_notification': 'on',
            'openproject-project-form-enable_engagement_epic_mapping': 'on',
            'openproject-epic-form-push_to_openproject': 'on',
        }

    def get_new_engagement_without_openproject_project_data(self):
        return {
            'name': 'new engagement',
            'description': 'new description',
            'lead': 1,
            'product': self.product_id,
            'target_start': '2070-11-27',
            'target_end': '2070-12-04',
            'status': 'Not Started',
            'openproject-project-form-inherit_from_product': 'on',
            # 'project_key': 'IFFF',
            # 'openproject_instance': 2,
            # 'enable_engagement_epic_mapping': 'on',
            # 'push_notes': 'on',
            # 'openproject-project-form-product_openproject_sla_notification': 'on'
        }

    def get_engagement_with_openproject_project_data(self, engagement):
        return {
            'name': engagement.name,
            'description': engagement.description,
            'lead': 1,
            'product': engagement.product.id,
            'target_start': '2070-11-27',
            'target_end': '2070-12-04',
            'status': 'Not Started',
            # 'openproject-project-form-inherit_from_product': 'on', # absence = False in html forms
            'openproject-project-form-openproject_instance': 2,
            'openproject-project-form-project_key': 'ISEC',
            'openproject-project-form-product_openproject_sla_notification': 'on',
        }

    def get_engagement_with_openproject_project_data2(self, engagement):
        return {
            'name': engagement.name,
            'description': engagement.description,
            'lead': 1,
            'product': engagement.product.id,
            'target_start': '2070-11-27',
            'target_end': '2070-12-04',
            'status': 'Not Started',
            # 'openproject-project-form-inherit_from_product': 'on', # absence = False in html forms
            'openproject-project-form-openproject_instance': 2,
            'openproject-project-form-project_key': 'ISEC2',
            'openproject-project-form-product_openproject_sla_notification': 'on',
        }

    def get_engagement_with_empty_openproject_project_data(self, engagement):
        return {
            'name': engagement.name,
            'description': engagement.description,
            'lead': 1,
            'product': engagement.product.id,
            'target_start': '2070-11-27',
            'target_end': '2070-12-04',
            'status': 'Not Started',
            'openproject-project-form-inherit_from_product': 'on',
            # 'project_key': 'IFFF',
            # 'openproject_instance': 2,
            # 'enable_engagement_epic_mapping': 'on',
            # 'push_notes': 'on',
            # 'openproject-project-form-product_openproject_sla_notification': 'on'
        }

    def get_expected_redirect_engagement(self, engagement):
        return '/engagement/%i' % engagement.id

    def get_expected_redirect_edit_engagement(self, engagement):
        return '/engagement/edit/%i' % engagement.id

    def add_engagement_openproject(self, data, expect_redirect_to=None, expect_200=False):
        response = self.client.get(reverse('new_eng_for_prod', args=(self.product_id, )))

        # logger.debug('before: OpenProject_Project last')
        # self.log_model_instance(OpenProject_Project.objects.last())

        if not expect_redirect_to and not expect_200:
            expect_redirect_to = '/engagement/%i'

        response = self.client.post(reverse('new_eng_for_prod', args=(self.product_id, )), urlencode(data), content_type='application/x-www-form-urlencoded')

        # logger.debug('after: OpenProject_Project last')
        # self.log_model_instance(OpenProject_Project.objects.last())

        engagement = None
        if expect_200:
            self.assertEqual(response.status_code, 200)
        elif expect_redirect_to:
            self.assertEqual(response.status_code, 302)
            # print('response: ' + response)
            # print('url: ' + response.url)
            try:
                engagement = Engagement.objects.get(id=response.url.split('/')[-1])
            except:
                try:
                    engagement = Engagement.objects.get(id=response.url.split('/')[-2])
                except:
                    raise ValueError('error parsing id from redirect uri: ' + response.url)
            self.assertTrue(response.url == (expect_redirect_to % engagement.id))
        else:
            self.assertEqual(response.status_code, 200)

        return engagement

    def add_engagement_openproject_with_data(self, data, expected_delta_openproject_project_db, expect_redirect_to=None, expect_200=False):
        openproject_project_count_before = self.db_openproject_project_count()

        response = self.add_engagement_openproject(data, expect_redirect_to=expect_redirect_to, expect_200=expect_200)

        self.assertEqual(self.db_openproject_project_count(), openproject_project_count_before + expected_delta_openproject_project_db)

        return response

    def add_engagement_with_openproject_project(self, expected_delta_openproject_project_db=0, expect_redirect_to=None, expect_200=False):
        return self.add_engagement_openproject_with_data(self.get_new_engagement_with_openproject_project_data(), expected_delta_openproject_project_db, expect_redirect_to=expect_redirect_to, expect_200=expect_200)

    def add_engagement_without_openproject_project(self, expected_delta_openproject_project_db=0, expect_redirect_to=None, expect_200=False):
        return self.add_engagement_openproject_with_data(self.get_new_engagement_without_openproject_project_data(), expected_delta_openproject_project_db, expect_redirect_to=expect_redirect_to, expect_200=expect_200)

    def add_engagement_with_openproject_project_and_epic_mapping(self, expected_delta_openproject_project_db=0, expect_redirect_to=None, expect_200=False):
        return self.add_engagement_openproject_with_data(self.get_new_engagement_with_openproject_project_data_and_epic_mapping(), expected_delta_openproject_project_db, expect_redirect_to=expect_redirect_to, expect_200=expect_200)

    def edit_engagement_openproject(self, engagement, data, expect_redirect_to=None, expect_200=False):
        response = self.client.get(reverse('edit_engagement', args=(engagement.id, )))

        # logger.debug('before: OpenProject_Project last')
        # self.log_model_instance(OpenProject_Project.objects.last())

        response = self.client.post(reverse('edit_engagement', args=(engagement.id, )), urlencode(data), content_type='application/x-www-form-urlencoded')
        # logger.debug('after: OpenProject_Project last')
        # self.log_model_instance(OpenProject_Project.objects.last())

        if expect_200:
            self.assertEqual(response.status_code, 200)
        elif expect_redirect_to:
            self.assertRedirects(response, expect_redirect_to)
        else:
            self.assertEqual(response.status_code, 200)
        return response

    def edit_openproject_project_for_engagement_with_data(self, engagement, data, expected_delta_openproject_project_db=0, expect_redirect_to=None, expect_200=None):
        openproject_project_count_before = self.db_openproject_project_count()

        if not expect_redirect_to and not expect_200:
            expect_redirect_to = self.get_expected_redirect_engagement(engagement)

        response = self.edit_engagement_openproject(engagement, data, expect_redirect_to=expect_redirect_to, expect_200=expect_200)

        self.assertEqual(self.db_openproject_project_count(), openproject_project_count_before + expected_delta_openproject_project_db)
        return response

    def edit_openproject_project_for_engagement(self, engagement, expected_delta_openproject_project_db=0, expect_redirect_to=None, expect_200=False):
        return self.edit_openproject_project_for_engagement_with_data(engagement, self.get_engagement_with_openproject_project_data(engagement), expected_delta_openproject_project_db, expect_redirect_to=expect_redirect_to, expect_200=expect_200)

    def edit_openproject_project_for_engagement2(self, engagement, expected_delta_openproject_project_db=0, expect_redirect_to=None, expect_200=False):
        return self.edit_openproject_project_for_engagement_with_data(engagement, self.get_engagement_with_openproject_project_data2(engagement), expected_delta_openproject_project_db, expect_redirect_to=expect_redirect_to, expect_200=expect_200)

    def empty_openproject_project_for_engagement(self, engagement, expected_delta_openproject_project_db=0, expect_redirect_to=None, expect_200=False, expect_error=False):
        openproject_project_count_before = self.db_openproject_project_count()

        if not expect_redirect_to and not expect_200:
            expect_redirect_to = self.get_expected_redirect_engagement(engagement)

        response = None
        if expect_error:
            with self.assertRaisesRegex(ValueError, "Not allowed to remove existing OpenProject Config for an engagement"):
                response = self.edit_engagement_openproject(engagement, self.get_engagement_with_empty_openproject_project_data(engagement), expect_redirect_to=expect_redirect_to, expect_200=expect_200)
        else:
            response = self.edit_engagement_openproject(engagement, self.get_engagement_with_empty_openproject_project_data(engagement), expect_redirect_to=expect_redirect_to, expect_200=expect_200)

        self.assertEqual(self.db_openproject_project_count(), openproject_project_count_before + expected_delta_openproject_project_db)
        return response


class OpenProjectConfigEngagementTest(DojoTestCase, OpenProjectConfigEngagementBase):
    fixtures = ['dojo_testdata.json']

    product_id = 999

    def __init__(self, *args, **kwargs):
        DojoTestCase.__init__(self, *args, **kwargs)

    def setUp(self):
        self.system_settings(enable_openproject=True)
        self.user = self.get_test_admin()
        self.client.force_login(self.user)
        self.user.usercontactinfo.block_execution = True
        self.user.usercontactinfo.save()
        # product 3 has no openproject project config, double check to make sure someone didn't molest the fixture
        # running this in __init__ throws database access denied error
        self.product_id = 3
        product = Product.objects.get(id=self.product_id)
        self.assertIsNone(openproject_helper.get_openproject_project(product))

    @patch('dojo.openproject_link.views.openproject_helper.is_openproject_project_valid')
    def test_add_openproject_project_to_engagement_without_openproject_project(self, openproject_mock):
        openproject_mock.return_value = True  # cannot set return_value in decorated AND have the mock into the method
        # TODO: add engagement also via API, but let's focus on openproject here
        engagement = self.add_engagement_without_openproject_project(expected_delta_openproject_project_db=0)
        response = self.edit_openproject_project_for_engagement(engagement, expected_delta_openproject_project_db=1)
        self.assertEqual(openproject_mock.call_count, 1)

    @patch('dojo.openproject_link.views.openproject_helper.is_openproject_project_valid')
    def test_add_empty_openproject_project_to_engagement_without_openproject_project(self, openproject_mock):
        openproject_mock.return_value = True  # cannot set return_value in decorated AND have the mock into the method
        engagement = self.add_engagement_without_openproject_project(expected_delta_openproject_project_db=0)
        response = self.empty_openproject_project_for_engagement(engagement, expected_delta_openproject_project_db=0)
        self.assertEqual(openproject_mock.call_count, 0)

    @patch('dojo.openproject_link.views.openproject_helper.is_openproject_project_valid')
    def test_edit_openproject_project_to_engagement_with_openproject_project(self, openproject_mock):
        openproject_mock.return_value = True  # cannot set return_value in decorated AND have the mock into the method
        engagement = self.add_engagement_with_openproject_project(expected_delta_openproject_project_db=1)
        response = self.edit_openproject_project_for_engagement2(engagement, expected_delta_openproject_project_db=0)
        self.assertEqual(openproject_mock.call_count, 2)

    @patch('dojo.openproject_link.views.openproject_helper.is_openproject_project_valid')
    def test_edit_empty_openproject_project_to_engagement_with_openproject_project(self, openproject_mock):
        openproject_mock.return_value = True  # cannot set return_value in decorated AND have the mock into the method
        engagement = self.add_engagement_with_openproject_project(expected_delta_openproject_project_db=1)
        # clearing out openproject config used to be possible. what todo?
        # - delete openproject project? would disconnect all existing openproject issues in defect dojo from the config?
        # - allow openproject project with empty openproject instance and/or empty project_key? unpredictable behaviour
        # - so prevent clearing out these values
        # response = self.empty_openproject_project_for_engagement(Engagement.objects.get(id=3), -1)
        # expecting ValueError as we can't delete existing OpenProject Projects
        response = self.empty_openproject_project_for_engagement(engagement, expected_delta_openproject_project_db=0, expect_error=True)
        self.assertEqual(openproject_mock.call_count, 1)

    @patch('dojo.openproject_link.views.openproject_helper.is_openproject_project_valid')
    def test_add_openproject_project_to_engagement_without_openproject_project_invalid_project(self, openproject_mock):
        openproject_mock.return_value = False  # cannot set return_value in decorated AND have the mock into the method
        # errors means it won't redirect to view_engagement, but returns a 200 and redisplays the edit engagement page
        response = self.edit_openproject_project_for_engagement(Engagement.objects.get(id=3), expected_delta_openproject_project_db=0, expect_200=True)
        self.assertEqual(openproject_mock.call_count, 1)

    @patch('dojo.openproject_link.views.openproject_helper.is_openproject_project_valid')
    def test_edit_openproject_project_to_engagement_with_openproject_project_invalid_project(self, openproject_mock):
        openproject_mock.return_value = True  # cannot set return_value in decorated AND have the mock into the method
        engagement = self.add_engagement_with_openproject_project(expected_delta_openproject_project_db=1)
        openproject_mock.return_value = False
        #  openproject key is changed, so openproject project will be checked
        response = self.edit_openproject_project_for_engagement2(engagement, expected_delta_openproject_project_db=0, expect_200=True)
        self.assertEqual(openproject_mock.call_count, 2)

    @patch('dojo.openproject_link.views.openproject_helper.is_openproject_project_valid')
    def test_add_engagement_with_openproject_project(self, openproject_mock):
        openproject_mock.return_value = True  # cannot set return_value in decorated AND have the mock into the method
        engagement = self.add_engagement_with_openproject_project(expected_delta_openproject_project_db=1)
        self.assertIsNotNone(engagement)
        self.assertEqual(openproject_mock.call_count, 1)

    @patch('dojo.openproject_link.views.openproject_helper.is_openproject_project_valid')
    def test_add_engagement_with_openproject_project_invalid_openproject_project(self, openproject_mock):
        openproject_mock.return_value = False  # cannot set return_value in decorated AND have the mock into the method
        engagement = self.add_engagement_with_openproject_project(expected_delta_openproject_project_db=0, expect_redirect_to='/engagement/%i/edit')
        # engagement still added even while openproject errors
        self.assertIsNotNone(engagement)
        self.assertEqual(openproject_mock.call_count, 1)

    @patch('dojo.openproject_link.views.openproject_helper.is_openproject_project_valid')
    def test_add_engagement_without_openproject_project(self, openproject_mock):
        openproject_mock.return_value = True  # cannot set return_value in decorated AND have the mock into the method
        engagement = self.add_engagement_without_openproject_project(expected_delta_openproject_project_db=0)
        self.assertIsNotNone(engagement)
        self.assertEqual(openproject_mock.call_count, 0)

    # with openproject disabled the openprojectform should not be checked at all
    @patch('dojo.forms.OpenProjectProjectForm.is_valid')
    def test_add_engagement_with_openproject_project_to_engagement_openproject_disabled(self, openproject_mock):
        openproject_mock.return_value = True  # cannot set return_value in decorated AND have the mock into the method
        self.system_settings(enable_openproject=False)
        engagement = self.add_engagement_with_openproject_project(expected_delta_openproject_project_db=0)
        self.assertIsNotNone(engagement)
        self.assertEqual(openproject_mock.call_count, 0)

    # with openproject disabled the openprojectform should not be checked at all
    @patch('dojo.forms.OpenProjectProjectForm.is_valid')
    def test_edit_openproject_project_to_engagement_with_openproject_project_invalid_project_openproject_disabled(self, openproject_mock):
        self.system_settings(enable_openproject=False)
        openproject_mock.return_value = True  # cannot set return_value in decorated AND have the mock into the method
        response = self.edit_openproject_project_for_engagement(Engagement.objects.get(id=3), expected_delta_openproject_project_db=0)
        response = self.edit_openproject_project_for_engagement2(Engagement.objects.get(id=3), expected_delta_openproject_project_db=0)
        self.assertEqual(openproject_mock.call_count, 0)


# inheriting a OepnProject Project config from a product can influence some logic and field mandatoriness etc.
# so run all the same test again, but with the product above it having a OpenProject Project Config
class OpenProjectConfigEngagementTest_Inheritance(OpenProjectConfigEngagementTest):
    def __init__(self, *args, **kwargs):
        OpenProjectConfigEngagementTest.__init__(self, *args, **kwargs)

    @patch('dojo.openproject_link.views.openproject_helper.is_openproject_project_valid')
    def setUp(self, openproject_mock, *args, **kwargs):
        openproject_mock.return_value = True
        OpenProjectConfigEngagementTest.setUp(self, *args, **kwargs)
        # product 2 has openproject project config, double check to make sure someone didn't molest the fixture
        self.product_id = 2
        product = Product.objects.get(id=self.product_id)
        self.assertIsNotNone(openproject_helper.get_openproject_project(product))

# TODO UI
# linking / unlinking
