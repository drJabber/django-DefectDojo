from django.core.management.base import BaseCommand
from dojo.models import OpenProject_Issue, OpenProject_Instance
import dojo.openproject_link.helper as openproject_helper
import logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):

    help = 'Command to move data from some tables to other tables as part of https://github.com/DefectDojo/django-DefectDojo/pull/3200' + \
        'Should normally be handled by the migration in that PR, but if that causes errors, this command can help to get the data migrated anyway.'

    def move_openproject_creation_changed(self):
        logger.info('migrating finding.openproject_creation and openproject_change fields to OpenProject_Issue model')
        for openproject_issue in OpenProject_Issue.objects.all().select_related('finding'):
            # try:
            if openproject_issue.finding:
                logger.debug('populating openproject_issue: %s', openproject_issue.openproject_id)
                openproject_issue.openproject_creation = openproject_issue.finding.openproject_creation
                openproject_issue.openproject_change = openproject_issue.finding.openproject_change
                openproject_issue.save()
            else:
                logger.debug('no finding: skipping openproject_issue: %s', openproject_issue.openproject_id)

    def populate_openproject_project(self):
        logger.info('populating openproject_issue.openproject_project to point to openproject configuration of the product in defect dojo')
        for openproject_issue in OpenProject_Issue.objects.all().select_related('openproject_project').prefetch_related('finding__test__engagement__product'):
            # try:
            if not openproject_issue.openproject_project and openproject_issue.finding:
                logger.info('populating openproject_issue from finding: %s', openproject_issue.openproject_id)
                openproject_project = openproject_helper.get_openproject_project(openproject_issue.finding)
                # openproject_project = openproject_issue.finding.test.engagement.product.openproject_project_set.all()[0]
                logger.debug('openproject_project: %s', openproject_project)
                openproject_issue.openproject_project = openproject_project
                openproject_issue.save()
            elif not openproject_issue.openproject_project and openproject_issue.engagement:
                logger.debug('populating openproject_issue from engagement: %s', openproject_issue.openproject_id)
                openproject_project = openproject_helper.get_openproject_project(openproject_issue.finding)
                # openproject_project = openproject_issue.engagement.product.openproject_project_set.all()[0]
                logger.debug('openproject_project: %s', openproject_project)
                openproject_issue.openproject_project = openproject_project
                openproject_issue.save()
            elif not openproject_issue.openproject_project:
                logger.info('skipping %s as there is no finding or engagment', openproject_issue.openproject_id)

    def populate_openproject_instance_name_if_empty(self):
        logger.info('populating OpenProject_Instance.configuration_name with url if empty')
        for openproject_instance in OpenProject_Instance.objects.all():
            # try:
            if not openproject_instance.configuration_name:
                openproject_instance.configuration_name = openproject_instance.url
                openproject_instance.save()
            else:
                logger.debug('configuration_name already set for %i %s', openproject_instance.id, openproject_instance.url)

    def handle(self, *args, **options):

        self.move_openproject_creation_changed()
        self.populate_openproject_project()
        self.populate_openproject_instance_name_if_empty()

        logger.info('now this script is completed, you can run the migration 0063_openproject_refactor_populate as normal. it will skip over the data because it has already been populated')
        logger.info('if it still fails, comment out all the runpython parts, but leave the operations on the database fields in place')
