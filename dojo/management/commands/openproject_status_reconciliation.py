from dateutil.relativedelta import relativedelta
from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from dojo.models import Engagement, Finding, Product
import dojo.openproject_link.helper as openproject_helper
import logging
logger = logging.getLogger(__name__)


def openproject_status_reconciliation(*args, **kwargs):
    mode = kwargs['mode']
    product = kwargs['product']
    engagement = kwargs['engagement']
    daysback = kwargs['daysback']
    dryrun = kwargs['dryrun']

    logger.debug('mode: %s product:%s engagement: %s dryrun: %s', mode, product, engagement, dryrun)

    if mode and mode not in ('push_status_to_openproject', 'import_status_from_openproject', 'reconcile'):
        print('mode must be one of reconcile, push_status_to_openproject or import_status_from_openproject')
        return False

    if not mode:
        mode = 'reconcile'

    findings = Finding.objects.all()
    if product:
        product = Product.objects.filter(name=product).first()
        findings = findings.filter(test__engagement__product=product)

    if engagement:
        engagement = Engagement.objects.filter(name=engagement).first()
        findings = findings.filter(test__engagement=engagement)

    if daysback:
        timestamp = timezone.now() - relativedelta(days=int(daysback))
        findings = findings.filter(created__gte=timestamp)

    findings = findings.exclude(openproject_issue__isnull=True)

    # order by product, engagement to increase the cance of being able to reuse openproject_instance + openproject connection
    findings = findings.order_by('test__engagement__product__id', 'test__engagement__id')

    findings = findings.prefetch_related('openproject_issue__openproject_project__openproject_instance')
    findings = findings.prefetch_related('test__engagement__openproject_project__openproject_instance')
    findings = findings.prefetch_related('test__engagement__product__openproject_project_set__openproject_instance')

    logger.debug(findings.query)

    messages = ['openproject_key;finding_url;resolution_or_status;find.openproject_issue.openproject_change;issue_from_openproject.fields.updated;find.last_status_update;issue_from_openproject.fields.updated;find.last_reviewed;issue_from_openproject.fields.updated;flag1;flag2;flag3;action;change_made']
    for find in findings:
        logger.debug('openproject status reconciliation for: %i:%s', find.id, find)

        issue_from_openproject = openproject_helper.get_openproject_issue_from_openproject(find)

        if not issue_from_openproject:
            message = '%s;%s/finding/%d;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;unable to retrieve openproject Issue;%s' % \
                (find.openproject_issue.openproject_id, settings.SITE_URL, find.id, find.status(), None, None, None, None,
                            find.openproject_issue.openproject_change, None, find.last_status_update, None, find.last_reviewed, None, 'error')
            messages.append(message)
            logger.info(message)
            continue

        assignee = issue_from_openproject.fields.assignee if hasattr(issue_from_openproject.fields, 'assignee') else None
        assignee_name = assignee.displayName if assignee else None
        resolution = issue_from_openproject.fields.resolution if issue_from_openproject.fields.resolution and issue_from_openproject.fields.resolution != "None" else None
        resolution_id = resolution.id if resolution else None
        resolution_name = resolution.name if resolution else None

        # convert from str to datetime
        issue_from_openproject.fields.updated = parse_datetime(issue_from_openproject.fields.updated)

        find.openproject_issue.openproject_change, issue_from_openproject.fields.updated, find.last_status_update, issue_from_openproject.fields.updated, find.last_reviewed, issue_from_openproject.fields.updated,

        flag1, flag2, flag3 = None, None, None

        if mode == 'reconcile' and not find.last_status_update:
            message = '%s; %s/finding/%d;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;skipping finding with no last_status_update;%s' % \
                (find.openproject_issue.openproject_id, settings.SITE_URL, find.id, find.status(), None, None, None, None,
                find.openproject_issue.openproject_change, issue_from_openproject.fields.updated, find.last_status_update, issue_from_openproject.fields.updated, find.last_reviewed, issue_from_openproject.fields.updated, 'skipped')
            messages.append(message)
            logger.info(message)
            continue
        elif find.risk_accepted:
            message = '%s; %s/finding/%d;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%sskipping risk accepted findings;%s' % \
                (find.openproject_issue.openproject_id, settings.SITE_URL, find.id, find.status(), resolution_name, None, None, None,
                find.openproject_issue.openproject_change, issue_from_openproject.fields.updated, find.last_status_update, issue_from_openproject.fields.updated, find.last_reviewed, issue_from_openproject.fields.updated, 'skipped')
            messages.append(message)
            logger.info(message)
        elif openproject_helper.issue_from_openproject_is_active(issue_from_openproject) and find.active:
            message = '%s; %s/finding/%d;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;no action both sides are active/open;%s' % \
                (find.openproject_issue.openproject_id, settings.SITE_URL, find.id, find.status(), resolution_name, None, None, None,
                    find.openproject_issue.openproject_change, issue_from_openproject.fields.updated, find.last_status_update, issue_from_openproject.fields.updated, find.last_reviewed, issue_from_openproject.fields.updated, 'equal')
            messages.append(message)
            logger.info(message)
        elif not openproject_helper.issue_from_openproject_is_active(issue_from_openproject) and not find.active:
            message = '%s; %s/finding/%d;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;no action both sides are inactive/closed;%s' % \
                (find.openproject_issue.openproject_id, settings.SITE_URL, find.id, find.status(), resolution_name, None, None, None,
                find.openproject_issue.openproject_change, issue_from_openproject.fields.updated, find.last_status_update, issue_from_openproject.fields.updated, find.last_reviewed, issue_from_openproject.fields.updated, 'equal')
            messages.append(message)
            logger.info(message)

        else:
            # statuses are different
            if mode in ('push_status_to_openproject', 'import_status_from_openproject'):
                action = mode
            else:
                # reconcile
                # Status is openproject is newer if:
                # dojo.openproject_change < openproject.updated, and
                # dojo.last_status_update < openproject.updated, and
                # dojo.last_reviewed < openproject.update,

                flag1 = (not find.openproject_issue.openproject_change or (find.openproject_issue.openproject_change < issue_from_openproject.fields.updated))
                flag2 = not find.last_status_update or (find.last_status_update < issue_from_openproject.fields.updated)
                flag3 = (not find.last_reviewed or (find.last_reviewed < issue_from_openproject.fields.updated))

                logger.debug('%s,%s,%s,%s', resolution_name, flag1, flag2, flag3)

                if flag1 and flag2 and flag3:
                    action = 'import_status_from_openproject'

                else:
                    # Status is DOJO is newer if:
                    # dojo.openproject_change > openproject.updated or # can't happen
                    # dojo.last_status_update > openproject.updated or
                    # dojo.last_reviewed > openproject.updated
                    # dojo.mitigated > dojo.openproject_change

                    flag1 = not find.openproject_issue.openproject_change or (find.openproject_issue.openproject_change > issue_from_openproject.fields.updated)
                    flag2 = find.last_status_update > issue_from_openproject.fields.updated
                    flag3 = find.is_mitigated and find.mitigated and find.openproject_issue.openproject_change and find.mitigated > find.openproject_issue.openproject_change

                    logger.debug('%s,%s,%s,%s', resolution_name, flag1, flag2, flag3)

                    if flag1 or flag2 or flag3:
                        action = 'push_status_to_openproject'

            prev_openproject_instance, openproject = None, None

            if action == 'import_status_from_openproject':
                message_action = 'deactivating' if find.active else 'reactivating'

                status_changed = openproject_helper.process_resolution_from_openproject(find, resolution_id, resolution_name, assignee_name, issue_from_openproject.fields.updated) if not dryrun else 'dryrun'
                if status_changed:
                    message = '%s; %s/finding/%d;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s finding in defectdojo;%s' % \
                        (find.openproject_issue.openproject_id, settings.SITE_URL, find.id, find.status(), resolution_name, flag1, flag2, flag3,
                        find.openproject_issue.openproject_change, issue_from_openproject.fields.updated, find.last_status_update, issue_from_openproject.fields.updated, find.last_reviewed, issue_from_openproject.fields.updated, message_action, status_changed)
                    messages.append(message)
                    logger.info(message)
                else:
                    message = '%s; %s/finding/%d;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;no changes made from openproject resolution;%s' % \
                        (find.openproject_issue.openproject_id, settings.SITE_URL, find.id, find.status(), resolution_name, flag1, flag2, flag3,
                        find.openproject_issue.openproject_change, issue_from_openproject.fields.updated, find.last_status_update, issue_from_openproject.fields.updated, find.last_reviewed, issue_from_openproject.fields.updated, status_changed)
                    messages.append(message)
                    logger.info(message)

            elif action == 'push_status_to_openproject':
                openproject_instance = openproject_helper.get_openproject_instance(find)
                if not prev_openproject_instance or (openproject_instance.id != prev_openproject_instance.id):
                    # only reconnect to openproject if the instance if different from the previous finding
                    openproject = openproject_helper.get_openproject_connection(openproject_instance)

                message_action = 'reopening' if find.active else 'closing'

                status_changed = openproject_helper.push_status_to_openproject(find, openproject_instance, openproject, issue_from_openproject, save=True) if not dryrun else 'dryrun'

                if status_changed:
                    message = '%s; %s/finding/%d;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s openproject issue;%s;' % \
                        (find.openproject_issue.openproject_id, settings.SITE_URL, find.id, find.status(), resolution_name, flag1, flag2, flag3, message_action,
                        find.openproject_issue.openproject_change, issue_from_openproject.fields.updated, find.last_status_update, issue_from_openproject.fields.updated, find.last_reviewed, issue_from_openproject.fields.updated, status_changed)
                    messages.append(message)
                    logger.info(message)
                else:
                    if status_changed is None:
                        status_changed = 'Error'
                    message = '%s; %s/finding/%d;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;no changes made while pushing status to openproject;%s' % \
                        (find.openproject_issue.openproject_id, settings.SITE_URL, find.id, find.status(), resolution_name, flag1, flag2, flag3,
                        find.openproject_issue.openproject_change, issue_from_openproject.fields.updated, find.last_status_update, issue_from_openproject.fields.updated, find.last_reviewed, issue_from_openproject.fields.updated, status_changed)
                    messages.append(message)

                    logger.info(message)
            else:
                message = '%s; %s/finding/%d;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;unable to determine source of truth;%s' % \
                    (find.openproject_issue.openproject_id, settings.SITE_URL, find.id, find.status(), resolution_name, flag1, flag2, flag3,
                    find.openproject_issue.openproject_change, issue_from_openproject.fields.updated, find.last_status_update, issue_from_openproject.fields.updated, find.last_reviewed, issue_from_openproject.fields.updated, status_changed)
                messages.append(message)

                logger.info(message)

    logger.info('results (semicolon seperated)')
    for message in messages:
        print(message)


class Command(BaseCommand):
    """
    Reconcile finding status with openproject issue status, stdout will contain semicolon seperated CSV results.
    Risk Accepted findings are skipped.'

    modes:
    - reconcile: reconcile any differences in status between Defect Dojo and OpenProject, will look at the latest status update in Defect Dojo and the 'updated' field in the OpenProject Issue.
    - push_to_openproject: overwrite status in OpenProject with status in Defect Dojo
    - sync_from_openproject: overwrite status in Defect Dojo with status from OpenProject
    """

    help = 'Reconcile finding status with OpenProject issue status, stdout will contain semicolon seperated CSV results. \
        Risk Accepted findings are skipped. Findings created before 1.14.0 are skipped.'

    mode_help = \
        '- reconcile: (default)reconcile any differences in status between Defect Dojo and OpenProject, will look at the latest status change timestamp in both systems to determine which one is the correct status' \
        '- push_status_to_openproject: update OpenProject status for all OpenProject issues connected to a Defect Dojo finding (will not push summary/description, only status)' \
        '- import_status_from_openproject: update Defect Dojo finding status from OpenProject'

    def add_arguments(self, parser):
        parser.add_argument('--mode', help=self.mode_help)
        parser.add_argument('--product', help='Only process findings in this product (name)')
        parser.add_argument('--engagement', help='Only process findings in this product (name)')
        parser.add_argument('--daysback', type=int, help='Only process findings created in the last \'daysback\' days')
        parser.add_argument('--dryrun', action='store_true', help='Only print actions to be performed, but make no modifications.')

    def handle(self, *args, **options):
        # mode = options['mode']
        # product = options['product']
        # engagement = options['engagement']
        # daysback = options['daysback']
        # dryrun = options['dryrun']

        return openproject_status_reconciliation(*args, **options)
