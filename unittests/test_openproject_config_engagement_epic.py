from .test_openproject_config_engagement import OpenProjectConfigEngagementBase
from vcr import VCR
from .dojo_test_case import DojoVCRTestCase, get_unit_tests_path
# from unittest import skip
import logging

logger = logging.getLogger(__name__)


class OpenProjectConfigEngagementEpicTest(DojoVCRTestCase, OpenProjectConfigEngagementBase):
    fixtures = ['dojo_testdata.json']

    product_id = 999

    def __init__(self, *args, **kwargs):
        # TODO remove __init__ if it does nothing...
        DojoVCRTestCase.__init__(self, *args, **kwargs)

    def assert_cassette_played(self):
        if True:  # set to True when committing. set to False when recording new test cassettes
            self.assertTrue(self.cassette.all_played)

    def _get_vcr(self, **kwargs):
        my_vcr = super(DojoVCRTestCase, self)._get_vcr(**kwargs)
        my_vcr.record_mode = 'once'
        my_vcr.path_transformer = VCR.ensure_suffix('.yaml')
        my_vcr.filter_headers = ['Authorization', 'X-Atlassian-Token']
        my_vcr.cassette_library_dir = get_unit_tests_path() + '/vcr/openproject/'
        # filters headers doesn't seem to work for cookies, so use callbacks to filter cookies from being recorded
        my_vcr.before_record_request = self.before_record_request
        my_vcr.before_record_response = self.before_record_response
        return my_vcr

    def setUp(self):
        super().setUp()
        self.system_settings(enable_openproject=True)
        self.user = self.get_test_admin()
        self.client.force_login(self.user)
        self.user.usercontactinfo.block_execution = True
        self.user.usercontactinfo.save()
        # product 3 has no openproject project config, double check to make sure someone didn't molest the fixture
        # running this in __init__ throws database access denied error
        self.product_id = 1  # valid openproject config
        # product = Product.objects.get(id=self.product_id)
        # self.assertIsNone(openproject_helper.get_openproject_project(product))

    def get_new_engagement_with_openproject_project_data_and_epic_mapping(self):
        return {
            'name': 'new engagement',
            'description': 'new description',
            'lead': 1,
            'product': self.product_id,
            'target_start': '2070-11-27',
            'target_end': '2070-12-04',
            'status': 'Not Started',
            'openproject-project-form-openproject_instance': 2,
            'openproject-project-form-project_key': '2222',
            'openproject-project-form-product_openproject_sla_notification': 'on',
            'openproject-project-form-enable_engagement_epic_mapping': 'on',
            'openproject-epic-form-push_to_openproject': 'on',
        }

    def add_engagement_with_openproject_project_and_epic_mapping(self, expected_delta_openproject_project_db=0, expect_redirect_to=None, expect_200=False):
        return self.add_engagement_openproject_with_data(self.get_new_engagement_with_openproject_project_data_and_epic_mapping(), expected_delta_openproject_project_db, expect_redirect_to=expect_redirect_to, expect_200=expect_200)

    def test_add_engagement_with_openproject_project_and_epic_mapping(self):
        engagement = self.add_engagement_with_openproject_project_and_epic_mapping(expected_delta_openproject_project_db=1)
        self.assertIsNotNone(engagement)
        self.assertIsNotNone(engagement.openproject_project)
        self.assertTrue(engagement.has_openproject_issue)
