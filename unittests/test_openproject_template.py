from .dojo_test_case import DojoTestCase
from dojo.models import Product
from dojo.openproject_link import helper as openproject_helper
# from unittest import skip
import logging

logger = logging.getLogger(__name__)


class OpenProjectTemplatetTest(DojoTestCase):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        DojoTestCase.__init__(self, *args, **kwargs)

    def setUp(self):
        self.system_settings(enable_openproject=True)

    def test_get_openproject_issue_template_dir_from_project(self):
        product = Product.objects.get(id=1)
        openproject_project = openproject_helper.get_openproject_project(product)
        # filepathfield contains full path
        openproject_project.issue_template_dir = 'issue-trackers/openproject/openproject_full_extra'
        openproject_project.save()

        self.assertEqual(openproject_helper.get_openproject_issue_template(product), 'issue-trackers/openproject/openproject_full_extra/openproject-description.tpl')

    def test_get_openproject_issue_template_dir_from_instance(self):
        product = Product.objects.get(id=1)
        openproject_project = openproject_helper.get_openproject_project(product)
        openproject_project.issue_template_dir = None
        openproject_project.save()
        self.assertEqual(openproject_helper.get_openproject_issue_template(product), 'issue-trackers/openproject/openproject_full/openproject-description.tpl')

    def test_get_openproject_project_and_instance_no_issue_template_dir(self):
        product = Product.objects.get(id=1)
        openproject_project = openproject_helper.get_openproject_project(product)
        openproject_project.issue_template_dir = None
        openproject_project.save()
        openproject_instance = openproject_helper.get_openproject_instance(product)
        openproject_instance.issue_template_dir = None
        openproject_instance.save()
        # no template should return default
        self.assertEqual(openproject_helper.get_openproject_issue_template(product), 'issue-trackers/openproject/openproject_full/openproject-description.tpl')
