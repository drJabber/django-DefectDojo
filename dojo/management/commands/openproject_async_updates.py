from django.core.management.base import BaseCommand
from django.utils import timezone
from pyopenproject.business.exception.business_error import BusinessError
import dojo.openproject_link.helper as openproject_helper

from dojo.models import Finding, Notes, User, Dojo_User

"""
Author: Aaron Weaver
This script will locate open, active findings and update them in OpenProject.
Useful if you need to make bulk changes with OpenProject:
"""


class Command(BaseCommand):
    help = 'No input commands for OpenProject bulk update.'

    def handle(self, *args, **options):

        findings = Finding.objects.exclude(openproject_issue__isnull=True)
        findings = findings.filter(verified=True, active=True)
        findings = findings.prefetch_related('openproject_issue')
        # finding = Finding.objects.get(id=1)
        for finding in findings:
            #    try:
            # BusinessError.log_to_tempfile = False
            openproject = openproject_helper.get_openproject_connection(finding)
            j_issue = finding.openproject_issue
            issue = openproject.issue(j_issue.openproject_id)

            # Issue Cloned
            print(issue.fields.issuelinks[0])

            print("OpenProject Issue: " + str(issue))
            print("Resolution: " + str(issue.fields.resolution))

            if issue.fields.resolution is not None \
                    and not finding.under_defect_review:
                # print issue.fields.__dict__
                print("OpenProject Issue: " + str(issue) + " changed status")

                # Create OpenProject Note
                now = timezone.now()
                new_note = Notes()
                new_note.entry = "Please Review OpenProject Request: " + str(
                    issue) + ". Review status has changed to " + str(
                    issue.fields.resolution) + "."
                new_note.author = User.objects.get(username='OpenProject')
                new_note.date = now
                new_note.save()
                finding.notes.add(new_note)
                finding.under_defect_review = True
                dojo_user = Dojo_User.objects.get(username='OpenProject')
                finding.defect_review_requested_by = dojo_user

                # Create alert to notify user
                openproject_helper.log_openproject_message("OpenProject issue status change, please review.",
                                 finding)
                finding.save()
            else:
                print("No update necessary")
