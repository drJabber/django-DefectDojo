import logging
from dojo.utils import add_error_message_to_response, get_system_setting, to_str_typed
import os
import io
import json
import requests
from django.conf import settings
from django.template import TemplateDoesNotExist
from django.template.loader import render_to_string
from django.utils import timezone
from pyopenproject.openproject import OpenProject
from pyopenproject.model.work_package import WorkPackage
from pyopenproject.business.exception.business_error import BusinessError
from pyopenproject.api_connection.exceptions.request_exception import RequestError
from pyopenproject.business.util.filter import Filter
from dojo.models import Finding, Finding_Group, Risk_Acceptance, Stub_Finding, Test, Engagement, Product, \
    OpenProject_Issue, OpenProject_Project, System_Settings, Notes, OpenProject_Instance, User
from requests.auth import HTTPBasicAuth
from dojo.notifications.helper import create_notification
from django.contrib import messages
from dojo.celery import app
from dojo.decorators import dojo_async_task, dojo_model_from_id, dojo_model_to_id
from dojo.utils import truncate_with_dots, prod_name, get_file_images
from django.urls import reverse
from dojo.forms import OpenProjectProjectForm, OpenProjectEngagementForm
from urllib3.exceptions import NewConnectionError

logger = logging.getLogger(__name__)

RESOLVED_STATUS = [
    'Inactive',
    'Mitigated',
    'False Positive',
    'Out of Scope',
    'Duplicate'
]

OPEN_STATUS = [
    'Active',
    'Verified'
]


def is_openproject_enabled():
    if not get_system_setting('enable_openproject'):
        logger.debug('OpenProject is disabled, not doing anything')
        return False

    return True


def is_openproject_configured_and_enabled(obj):
    if not is_openproject_enabled():
        return False

    if get_openproject_project(obj) is None:
        logger.debug('OpenProject project not found for: "%s" not doing anything', obj)
        return False

    return True


def is_push_to_openproject(instance, push_to_openproject_parameter=None):
    if not is_openproject_configured_and_enabled(instance):
        return False

    openproject_project = get_openproject_project(instance)

    # caller explicitly stated true or false (False is different from None!)
    if push_to_openproject_parameter is not None:
        return push_to_openproject_parameter

    # push_to_openproject was not specified, so look at push_all_issues in OpenProject_Project
    return openproject_project.push_all_issues


def is_push_all_issues(instance):
    if not is_openproject_configured_and_enabled(instance):
        return False

    openproject_project = get_openproject_project(instance)
    if openproject_project:
        return openproject_project.push_all_issues


# checks if a finding can be pushed to OpenRpoject
# optionally provides a form with the new data for the finding
# any finding that already has a OpenProject issue can be pushed again to OpenProject
# returns True/False, error_message, error_code
def can_be_pushed_to_openproject(obj, form=None):
    # logger.debug('can be pushed to JIRA: %s', finding_or_form)
    if not get_openproject_project(obj):
        return False, '%s cannot be pushed to openproject as there is no jira project configuration for this product.' % to_str_typed(obj), 'error_no_jira_project'

    if not hasattr(obj, 'has_openproject_issue'):
        return False, '%s cannot be pushed to openproject as there is no jira_issue attribute.' % to_str_typed(obj), 'error_no_openproject_issue_attribute'

    if isinstance(obj, Stub_Finding):
        # stub findings don't have active/verified/etc and can always be pushed
        return True, None, None

    if obj.has_openproject_issue:
        # findings or groups already having an existing openproject issue can always be pushed
        return True, None, None

    if type(obj) == Finding:
        if form:
            active = form['active'].value()
            verified = form['verified'].value()
            severity = form['severity'].value()
        else:
            active = obj.active
            verified = obj.verified
            severity = obj.severity

        logger.debug('can_be_pushed_to_jira: %s, %s, %s', active, verified, severity)

        if not active or not verified:
            logger.debug('Findings must be active and verified to be pushed to OpenProject')
            return False, 'Findings must be active and verified to be pushed to OpenProject', 'not_active_or_verified'

        openproject_minimum_threshold = None
        if System_Settings.objects.get().openproject_minimum_severity:
            openproject_minimum_threshold = Finding.get_number_severity(System_Settings.objects.get().openproject_minimum_severity)

            if openproject_minimum_threshold and openproject_minimum_threshold > Finding.get_number_severity(severity):
                logger.debug('Finding below the minimum OpenProject severity threshold (%s).' % System_Settings.objects.get().openproject_minimum_severity)
                return False, 'Finding below the minimum OpenProject severity threshold (%s).' % System_Settings.objects.get().openproject_minimum_severity, 'below_minimum_threshold'
    elif type(obj) == Finding_Group:
        if not obj.findings.all():
            return False, '%s cannot be pushed to openproject as it is empty.' % to_str_typed(obj), 'error_empty'
        if 'Active' not in obj.status():
            return False, '%s cannot be pushed to openproject as it is not active.' % to_str_typed(obj), 'error_inactive'

    else:
        return False, '%s cannot be pushed to openprojectas it is of unsupported type.' % to_str_typed(obj), 'error_unsupported'

    return True, None, None


# use_inheritance=True means get openproject_project config from product if engagement itself has none
def get_openproject_project(obj, use_inheritance=True):
    if not is_openproject_enabled():
        return None

    if obj is None:
        return None

    # logger.debug('get openproject project for: ' + str(obj.id) + ':' + str(obj))

    if isinstance(obj, OpenProject_Project):
        return obj

    if isinstance(obj, OpenProject_Issue):
        if obj.openproject_project:
            return obj.openproject_project
        elif hasattr(obj, 'finding') and obj.finding:
            return get_openproject_project(obj.finding, use_inheritance=use_inheritance)
        elif hasattr(obj, 'engagement') and obj.engagement:
            return get_openproject_project(obj.finding, use_inheritance=use_inheritance)
        else:
            return None

    if isinstance(obj, Finding) or isinstance(obj, Stub_Finding):
        finding = obj
        return get_openproject_project(finding.test)

    if isinstance(obj, Finding_Group):
        return get_openproject_project(obj.test)

    if isinstance(obj, Test):
        test = obj
        return get_openproject_project(test.engagement)

    if isinstance(obj, Engagement):
        engagement = obj
        op_project = None
        if use_inheritance:
            logger.debug('delegating to product %s for %s', engagement.product, engagement)
            return get_openproject_project(engagement.product)
        else:
            logger.debug('not delegating to product %s for %s', engagement.product, engagement)
            return None

    if isinstance(obj, Product):
        # TODO refactor relationships, but now this would brake APIv1 (and v2?)
        product = obj
        op_projects = product.openproject_project_set.all()  # first() doesn't work with prefetching
        op_project = op_projects[0] if len(op_projects) > 0 else None
        if op_project:
            logger.debug('found openproject_project %s for %s', op_project, product)
            return op_project

    logger.debug('no openproject_project found for %s', obj)
    return None


def get_openproject_instance(obj):
    if not is_openproject_enabled():
        return None

    op_project = get_openproject_project(obj)
    if op_project:
        logger.debug('found openproject_instance %s for %s', op_project.openproject_instance, obj)
        return op_project.openproject_instance

    return None


def get_openproject_url(obj):
    logger.debug('getting openproject url')

    # finding + engagement
    issue = get_openproject_issue(obj)
    if issue is not None:
        return get_openproject_issue_url(issue)
    elif isinstance(obj, Finding):
        # finding must only have url if there is a openproject_issue
        # engagement can continue to show url of openproject project instead of openproject issue
        return None

    if isinstance(obj, OpenProject_Project):
        return get_openproject_project_url(obj)

    return get_openproject_project_url(get_openproject_project(obj))


def get_openproject_issue_url(issue):
    logger.debug('getting openproject issue url')
    op_project = get_openproject_project(issue)
    op_instance = get_openproject_instance(op_project)
    if op_instance is None:
        return None

    return op_instance.url + '/projects/' + issue.openproject_key


def get_openproject_project_url(obj):
    logger.debug('getting openproject project url')
    if not isinstance(obj, OpenProject_Project):
        op_project = get_openproject_project(obj)
    else:
        op_project = obj

    if op_project:
        logger.debug('getting openproject project url2')
        op_instance = get_openproject_instance(obj)
        if op_project and op_instance:
            logger.debug('getting openproject project url3')
            return op_project.openproject_instance.url + '/projects/' + op_project.project_key

    return None


def get_openproject_key(obj):
    if hasattr(obj, 'has_openproject_issue') and obj.has_openproject_issue:
        return get_openproject_issue_key(obj)

    if isinstance(obj, OpenProject_Project):
        return get_openproject_project_key(obj)

    return get_openproject_project_key(get_openproject_project(obj))


def get_openproject_issue_key(obj):
    if obj.has_openproject_issue:
        return obj.openproject_issue.openproject_key

    return None


def get_openproject_project_key(obj):
    openproject_project = get_openproject_project(obj)

    if not get_openproject_project:
        return None

    return openproject_project.project_key


def get_openproject_issue_template(obj):
    openproject_project = get_openproject_project(obj)

    template_dir = openproject_project.issue_template_dir
    if not template_dir:
        openproject_instance = get_openproject_instance(obj)
        template_dir = openproject_instance.issue_template_dir

    # fallback to default as before
    if not template_dir:
        template_dir = 'issue-trackers/openproject_full/'

    if isinstance(obj, Finding_Group):
        return os.path.join(template_dir, 'openproject-finding-group-description.tpl')
    else:
        return os.path.join(template_dir, 'openproject-description.tpl')


def get_openproject_creation(obj):
    if isinstance(obj, Finding) or isinstance(obj, Engagement) or isinstance(obj, Finding_Group):
        if obj.has_openproject_issue:
            return obj.openproject_issue.openproject_creation
    return None


def get_openproject_change(obj):
    if isinstance(obj, Finding) or isinstance(obj, Engagement) or isinstance(obj, Finding_Group):
        if obj.has_openproject_issue:
            return obj.openproject_issue.openproject_change
    else:
        logger.debug('get_openproject_change unsupported object type: %s', obj)
    return None


def get_epic_name_field_name(openproject_instance):
    if not openproject_instance or not openproject_instance.epic_name_id:
        return None

    return 'customfield_' + str(openproject_instance.epic_name_id)


def has_openproject_issue(obj):
    return get_openproject_issue(obj) is not None


def get_openproject_issue(obj):
    if isinstance(obj, Finding) or isinstance(obj, Engagement) or isinstance(obj, Finding_Group):
        try:
            return obj.openproject_issue
        except OpenProject_Issue.DoesNotExist:
            return None


def has_openproject_configured(obj):
    return get_openproject_project(obj) is not None


def get_openproject_connection_raw(openproject_server, openproject_username, openproject_password):
    try:
        op = OpenProject(openproject_server, openproject_password)
        svc = op.get_user_preferences_service()
        data = svc.find()

        logger.info('logged in to OpenProject ''%s'' successfully', openproject_server)

        return op
    except BusinessError as e:
        logger.exception(e)

        error_message = e.text if hasattr(e, 'text') else e.message if hasattr(e, 'message') else e.args[0]
        
        original_http_error = None
        original = e.__cause__
        if type(original) is RequestError:
            original = original.__cause__
            if type(original) is requests.exceptions.HTTPError:
                original_http_error = original

        if original_http_error and original_http_error.response.status_code in [401, 403]:
            log_openproject_generic_alert('OpenProject Authentication Error', error_message)
        else:
            log_openproject_generic_alert('Unknown OpenProject Connection Error', error_message)

        add_error_message_to_response('Unable to authenticate to OpenProject. Please check the URL, username, authkey, captcha challenge, Network connection. Details in alert on top right. ' + str(error_message))
        raise e

    except NewConnectionError as re:
        logger.exception(re)
        error_message = re.text if hasattr(re, 'text') else re.message if hasattr(re, 'message') else re.args[0]
        log_openproject_generic_alert('Unknown OpenProject Connection Error', error_message)

        add_error_message_to_response('Unable to authenticate to OpenProject. Please check the URL, username, authkey, captcha challenge, Network connection. Details in alert on top right. ' + str(error_message))

        raise re

    except SystemExit as se:
        logger.exception(se)

        error_message = se.text if hasattr(se, 'text') else se.message if hasattr(se, 'message') else se.args[0]

        log_openproject_generic_alert('Unknown OpenProject Connection Error', error_message)

        add_error_message_to_response('Unable to authenticate to OpenProject. Please check the url, username, authkey, captcha challenge, Network connection. Details in alert on top right. ' + str(error_message))

        raise BusinessError("Unknown OpenProject Connection Error") from se


# Gets a connection to a OpenProject server based on the finding
def get_openproject_connection(obj):
    op = None

    openproject_instance = obj
    if not isinstance(openproject_instance, OpenProject_Instance):
        openproject_instance = get_openproject_instance(obj)

    if openproject_instance is not None:
        return get_openproject_connection_raw(openproject_instance.url, openproject_instance.username, openproject_instance.password)


def openproject_get_resolution_id(openproject, issue, status):
    transitions = openproject.transitions(issue)
    resolution_id = None
    for t in transitions:
        if t['name'] == "Resolve Issue":
            resolution_id = t['id']
            break
        if t['name'] == "Reopen Issue":
            resolution_id = t['id']
            break

    return resolution_id


def openproject_transition(openproject, issue, transition_id):
    try:
        if issue and transition_id:
            openproject.transition_issue(issue, transition_id)
            return True
    except BusinessError as jira_error:
        logger.debug('error transisioning openproject issue ' + issue.key + ' ' + str(jira_error))
        logger.exception(jira_error)
        log_openproject_generic_alert('error transitioning jira issue ' + issue.key, str(jira_error))
        return None


# Used for unit testing so geting all the connections is manadatory
def get_openproject_updated(finding):
    if finding.has_openproject_issue:
        op_issue = finding.openproject_issue.jira_id
    elif finding.finding_group and finding.finding_group.has_jira_issue:
        op_issue = finding.finding_group.openproject_issue.openproject_id

    if op_issue:
        project = get_openproject_project(finding)
        issue = openproject_get_issue(project, op_issue)
        return issue.fields.updated


# Used for unit testing so geting all the connections is manadatory
def get_openproject_status(finding):
    if finding.has_openproject_issue:
        op_issue = finding.openproject_issue.openproject_id
    elif finding.finding_group and finding.finding_group.has_jira_issue:
        op_issue = finding.finding_group.openproject_issue.openproject_id

    if op_issue:
        project = get_openproject_project(finding)
        issue = openproject_get_issue(project, op_issue)
        return issue.fields.status


# Logs the error to the alerts table, which appears in the notification toolbar
def log_openproject_generic_alert(title, description):
    create_notification(
        event='openproject_update',
        title=title,
        description=description,
        icon='bullseye',
        source='OpenProject')


# Logs the error to the alerts table, which appears in the notification toolbar
def log_openproject_alert(error, obj):
    create_notification(
        event='openproject_update',
        title='Error pushing to OpenProject ' + '(' + truncate_with_dots(prod_name(obj), 25) + ')',
        description=to_str_typed(obj) + ', ' + error,
        url=obj.get_absolute_url(),
        icon='bullseye',
        source='Push to OpenProject',
        obj=obj)


# Displays an alert for OpenProject notifications
def log_openproject_message(text, finding):
    create_notification(
        event='openproject_update',
        title='Pushing to OpenProject: ',
        description=text + " Finding: " + str(finding.id),
        url=reverse('view_finding', args=(finding.id, )),
        icon='bullseye',
        source='OpenProject', finding=finding)


def get_labels(obj):
    # Update Label with system setttings label
    labels = []
    system_settings = System_Settings.objects.get()
    system_labels = system_settings.jira_labels
    if system_labels:
        system_labels = system_labels.split()
        for system_label in system_labels:
            labels.append(system_label)
        # Update the label with the product name (underscore)
        labels.append(prod_name(obj).replace(" ", "_"))
    return labels


def get_tags(obj):
    # Update Label with system setttings label
    tags = []
    if isinstance(obj, Finding) or isinstance(obj, Engagement):
        obj_tags = obj.tags.all()
        if obj_tags:
            for tag in obj_tags:
                tags.append(str(tag.name))
    return tags


def openproject_summary(obj):
    summary = ''

    if type(obj) == Finding:
        summary = obj.title

    if type(obj) == Finding_Group:
        summary = obj.name

    return summary.replace('\r', '').replace('\n', '')[:255]


def openproject_description(obj):
    template = get_openproject_issue_template(obj)

    logger.debug('rendering description for openproject from: %s', template)

    kwargs = {}
    if isinstance(obj, Finding):
        kwargs['finding'] = obj
    elif isinstance(obj, Finding_Group):
        kwargs['finding_group'] = obj

    description = render_to_string(template, kwargs)
    logger.debug('rendered description: %s', description)
    return description


def openproject_priority(obj):
    return get_openproject_instance(obj).get_priority(obj.severity)


def openproject_environment(obj):
    if type(obj) == Finding:
        return "\n".join([str(endpoint) for endpoint in obj.endpoints.all()])
    elif type(obj) == Finding_Group:
        return "\n".join([openproject_environment(finding) for finding in obj.findings.all()])
    else:
        return ''


def push_to_openproject(obj, *args, **kwargs):
    if obj is None:
        raise ValueError('Cannot push None to OpenProject')

    if isinstance(obj, Finding):
        finding = obj
        if finding.has_jira_issue:
            return update_openproject_issue_for_finding(finding, *args, **kwargs)
        else:
            return add_openproject_issue_for_finding(finding, *args, **kwargs)

    elif isinstance(obj, Engagement):
        engagement = obj
        if engagement.has_openproject_issue:
            return update_epic(engagement, *args, **kwargs)
        else:
            return add_epic(engagement, *args, **kwargs)

    elif isinstance(obj, Finding_Group):
        group = obj
        if group.has_openproject_issue:
            return update_openproject_issue_for_finding_group(group, *args, **kwargs)
        else:
            return add_openproject_issue_for_finding_group(group, *args, **kwargs)

    else:
        logger.error('unsupported object passed to push_to_openproject: %s %i %s', obj.__name__, obj.id, obj)


def add_issues_to_epic(openproject, obj, epic_id, issue_keys, ignore_epics=True):
    try:
        return openproject.add_issues_to_epic(epic_id=epic_id, issue_keys=issue_keys, ignore_epics=ignore_epics)
    except BusinessError as e:
        logger.error('error adding issues %s to epic %s for %s', issue_keys, epic_id, obj.id)
        logger.exception(e)
        log_openproject_alert(e.text, obj)
        return False


# we need two separate celery tasks due to the decorators we're using to map to/from ids

@dojo_model_to_id
@dojo_async_task
@app.task
@dojo_model_from_id
def add_openproject_issue_for_finding(finding, *args, **kwargs):
    return add_openproject_issue(finding, *args, **kwargs)


@dojo_model_to_id
@dojo_async_task
@app.task
@dojo_model_from_id(model=Finding_Group)
def add_openproject_issue_for_finding_group(finding_group, *args, **kwargs):
    return add_openproject_issue(finding_group, *args, **kwargs)


def add_openproject_issue(obj, *args, **kwargs):
    logger.info('trying to create a new openproject issue for %d:%s', obj.id, to_str_typed(obj))

    if not is_openproject_enabled():
        return False

    if not is_openproject_configured_and_enabled(obj):
        message = 'Object %s cannot be pushed to OpenProject as there is no OpenProject configuration for %s.' % (obj.id, to_str_typed(obj))
        logger.error(message)
        log_openproject_alert(message, obj)
        return False

    openproject_project = get_openproject_project(obj)
    openproject_instance = get_openproject_instance(obj)

    obj_can_be_pushed_to_openproject, error_message, error_code = can_be_pushed_to_openproject(obj)
    if not obj_can_be_pushed_to_openproject:
        log_openproject_alert(error_message, obj)
        logger.warn("%s cannot be pushed to OpenProject: %s.", to_str_typed(obj), error_message)
        logger.warn("The OpenProject issue will NOT be created.")
        return False
    logger.debug('Trying to create a new OpenProject issue for %s...', to_str_typed(obj))
    meta = None
    try:
        # JIRAError.log_to_tempfile = False
        openproject = get_openproject_connection(openproject_instance)

        fields = {
                'project': {
                    'key': openproject_project.project_key
                },
                'summary': openproject_summary(obj),
                'description': openproject_description(obj),
                'issuetype': {
                    'name': openproject_instance.default_issue_type
                },
        }

        # if openproject_project.component:
        #     fields['components'] = [
        #             {
        #                 'name': openproject_project.component
        #             },
        #     ]

        # populate duedate field, but only if it's available for this project + issuetype
        if not meta:
            meta = get_openproject_meta(openproject, openproject_project)

        epic_name_field = get_epic_name_field_name(openproject_instance)
        if epic_name_field in meta['projects'][0]['issuetypes'][0]['fields']:
            # epic name is present in this issuetype
            # epic name is always mandatory in openproject, so we populate it
            fields[epic_name_field] = fields['summary']

        if 'priority' in meta['projects'][0]['issuetypes'][0]['fields']:
            fields['priority'] = {
                                    'name': openproject_priority(obj)
                                }

        labels = get_labels(obj)
        tags = get_tags(obj)
        openproject_labels = labels + tags
        if openproject_labels:
            if 'labels' in meta['projects'][0]['issuetypes'][0]['fields']:
                fields['labels'] = openproject_labels

        if System_Settings.objects.get().enable_finding_sla:

            if 'duedate' in meta['projects'][0]['issuetypes'][0]['fields']:
                # jira wants YYYY-MM-DD
                duedate = obj.sla_deadline()
                if duedate:
                    fields['duedate'] = duedate.strftime('%Y-%m-%d')

        if not meta:
            meta = get_openproject_meta(openproject, openproject_project)

        if 'environment' in meta['projects'][0]['issuetypes'][0]['fields']:
            fields['environment'] = openproject_environment(obj)

        logger.debug('sending fields to OpenProject: %s', fields)

        new_issue = openproject.create_issue(fields)

        # Upload dojo finding screenshots to OpenProject
        findings = [obj]
        if type(obj) == Finding_Group:
            findings = obj.findings.all()

        for find in findings:
            for pic in get_file_images(find):
                # It doesn't look like the celery cotainer has anything in the media
                # folder. Has this feature ever worked?
                try:
                    openproject_attachment(
                        find, openproject, new_issue,
                        settings.MEDIA_ROOT + '/' + pic)
                except FileNotFoundError as e:
                    logger.info(e)

        if openproject_project.enable_engagement_epic_mapping:
            eng = obj.test.engagement
            logger.debug('Adding to EPIC Map: %s', eng.name)
            epic = get_openproject_issue(eng)
            if epic:
                add_issues_to_epic(openproject, obj, epic_id=epic.openproject_id, issue_keys=[str(new_issue.id)], ignore_epics=True)
            else:
                logger.info('The following EPIC does not exist: %s', eng.name)

        # only link the new issue if it was successfully created, incl attachments and epic link
        logger.debug('saving OpenProject_Issue for %s finding %s', new_issue.key, obj.id)
        op_issue = OpenProject_Issue(
            openproject_id=new_issue.id, jira_key=new_issue.key, openproject_project=openproject_project)
        op_issue.set_obj(obj)

        op_issue.openproject_creation = timezone.now()
        op_issue.openproject_change = timezone.now()
        op_issue.save()
        issue = openproject.issue(new_issue.id)

        logger.info('Created the following openproject issue for %d:%s', obj.id, to_str_typed(obj))
        return True
    except TemplateDoesNotExist as e:
        logger.exception(e)
        log_openproject_alert(str(e), obj)
        return False
    except BusinessError as e:
        logger.exception(e)
        logger.error("openproject_meta for project: %s and url: %s meta: %s", openproject_project.project_key, openproject_project.jira_instance.url, json.dumps(meta, indent=4))  # this is None safe
        log_openproject_alert(e.text, obj)
        return False


# we need two separate celery tasks due to the decorators we're using to map to/from ids

@dojo_model_to_id
@dojo_async_task
@app.task
@dojo_model_from_id
def update_openproject_issue_for_finding(finding, *args, **kwargs):
    return update_openproject_issue(finding, *args, **kwargs)


@dojo_model_to_id
@dojo_async_task
@app.task
@dojo_model_from_id(model=Finding_Group)
def update_openproject_issue_for_finding_group(finding_group, *args, **kwargs):
    return update_openproject_issue(finding_group, *args, **kwargs)


def update_openproject_issue(obj, *args, **kwargs):
    logger.debug('trying to update a linked openproject issue for %d:%s', obj.id, to_str_typed(obj))

    if not is_openproject_enabled():
        return False

    openproject_project = get_openproject_project(obj)
    openproject_instance = get_openproject_instance(obj)

    if not is_openproject_configured_and_enabled(obj):
        message = 'Object %s cannot be pushed to OpenProject as there is no OpenProject configuration for %s.' % (obj.id, to_str_typed(obj))
        logger.error(message)
        log_openproject_alert(message, obj)
        return False

    op_issue = obj.openproject_issue
    meta = None
    try:
        # BusinessError.log_to_tempfile = False
        openproject = get_openproject_connection(openproject_instance)

        issue = openproject.issue(op_issue.openproject_id)

        fields = {}
        # # Only update the component if it didn't exist earlier in OpenProject, this is to avoid assigning multiple components to an item
        # if issue.fields.components:
        #     log_openproject_alert(
        #         "Component not updated, exists in OpenProject already. Update from OpenProject instead.",
        #         obj)
        # elif jira_project.component:
        #     # Add component to the Jira issue
        #     component = [
        #         {
        #             'name': jira_project.component
        #         },
        #     ]
        #     fields = {"components": component}

        if not meta:
            meta = get_openproject_meta(openproject, openproject_project)

        labels = get_labels(obj)
        tags = get_tags(obj)
        openproject_labels = labels + tags
        if openproject_labels:
            if 'labels' in meta['projects'][0]['issuetypes'][0]['fields']:
                fields['labels'] = openproject_labels

        if 'environment' in meta['projects'][0]['issuetypes'][0]['fields']:
            fields['environment'] = openproject_environment(obj)

        logger.debug('sending fields to OpenProject: %s', fields)

        issue.update(
            summary=openproject_summary(obj),
            description=openproject_description(obj),
            priority={'name': openproject_priority(obj)},
            fields=fields)

        push_status_to_openproject(obj, openproject_instance, openproject, issue)

        # Upload dojo finding screenshots to Jira
        findings = [obj]
        if type(obj) == Finding_Group:
            findings = obj.findings.all()

        for find in findings:
            for pic in get_file_images(find):
                # It doesn't look like the celery cotainer has anything in the media
                # folder. Has this feature ever worked?
                try:
                    openproject_attachment(
                        find, openproject, issue,
                        settings.MEDIA_ROOT + '/' + pic)
                except FileNotFoundError as e:
                    logger.info(e)

        if openproject_project.enable_engagement_epic_mapping:
            eng = find.test.engagement
            logger.debug('Adding to EPIC Map: %s', eng.name)
            epic = get_openproject_issue(eng)
            if epic:
                add_issues_to_epic(openproject, obj, epic_id=epic.jira_id, issue_keys=[str(op_issue.openproject_id)], ignore_epics=True)
            else:
                logger.info('The following EPIC does not exist: %s', eng.name)

        op_issue.jira_change = timezone.now()
        op_issue.save()

        logger.debug('Updated the following linked jira issue for %d:%s', find.id, find.title)
        return True

    except BusinessError as e:
        logger.exception(e)
        logger.error("openproject_meta for project: %s and url: %s meta: %s", openproject_project.project_key, openproject_project.jira_instance.url, json.dumps(meta, indent=4))  # this is None safe
        log_openproject_alert(e.text, obj)
        return False


# def get_jira_issue_from_jira(find):
#     logger.debug('getting jira issue from JIRA for %d:%s', find.id, find)

#     if not is_jira_enabled():
#         return False

#     jira_project = get_jira_project(find)
#     jira_instance = get_jira_instance(find)

#     j_issue = find.jira_issue
#     if not jira_project:
#         logger.error("Unable to retrieve latest status change from JIRA %s for finding %s as there is no JIRA_Project configured for this finding.", j_issue.jira_key, format(find.id))
#         log_jira_alert("Unable to retrieve latest status change from JIRA %s for finding %s as there is no JIRA_Project configured for this finding." % (j_issue.jira_key, find), find)
#         return False

#     meta = None
#     try:
#         JIRAError.log_to_tempfile = False
#         jira = get_jira_connection(jira_instance)

#         logger.debug('getting issue from JIRA')
#         issue_from_jira = jira.issue(j_issue.jira_id)

#         return issue_from_jira

#     except JIRAError as e:
#         logger.exception(e)
#         logger.error("jira_meta for project: %s and url: %s meta: %s", jira_project.project_key, jira_project.jira_instance.url, json.dumps(meta, indent=4))  # this is None safe
#         log_jira_alert(e.text, find)
#         return None


def issue_from_openproject_is_active(issue_from_openproject):
    #         "resolution":{
    #             "self":"http://www.testjira.com/rest/api/2/resolution/11",
    #             "id":"11",
    #             "description":"Cancelled by the customer.",
    #             "name":"Cancelled"
    #         },

    # or
    #         "resolution": null

    # or
    #         "resolution": "None"

    if not hasattr(issue_from_openproject.fields, 'resolution'):
        print(vars(issue_from_openproject))
        return True

    if not issue_from_openproject.fields.resolution:
        return True

    if issue_from_openproject.fields.resolution == "None":
        return True

    # some kind of resolution is present that is not null or None
    return False


def push_status_to_openproject(obj, openproject_instance, openproject, issue, save=False):
    status_list = obj.status()
    issue_closed = False
    # check RESOLVED_STATUS first to avoid corner cases with findings that are Inactive, but verified
    if any(item in status_list for item in RESOLVED_STATUS):
        if issue_from_openproject_is_active(issue):
            logger.debug('Transitioning OpenProject issue to Resolved')
            updated = openproject_transition(openproject, issue, openproject_instance.close_status_key)
        else:
            logger.debug('Jira issue already Resolved')
            updated = False
        issue_closed = True

    if not issue_closed and any(item in status_list for item in OPEN_STATUS):
        if not issue_from_openproject_is_active(issue):
            logger.debug('Transitioning OpenProject issue to Active (Reopen)')
            updated = openproject_transition(openproject, issue, openproject_instance.open_status_key)
        else:
            logger.debug('OpenProject issue already Active')
            updated = False

    if updated and save:
        obj.openproject_issue.openproject_change = timezone.now()
        obj.openproject_issue.save()


# gets the metadata for the default issue type in this openproject project
def get_openproject_meta(op, openproject_project):
    op_type = list(filter(
        lambda t: t.name==openproject_project.openproject_instance.default_issue_type,
        op.get_type_service().find_all()))[0].id

    flt = Filter("id", "=", [f'{openproject_project.project_key}-{op_type}',])
    meta = op.get_work_package_service().find_all_schemas(
        [
            flt
        ]
    )

    meta_data_error = False
    
    if not meta:
        meta_data_error = True
        message = 'unable to retrieve metadata from OpenProject %s for issuetype %s in project %s. Invalid default issue type configured in Defect Dojo?' % (openproject_project.openproject_instance, openproject_project.openproject_instance.default_issue_type, openproject_project.project_key)

    if not meta[0].project:
        meta_data_error = True
        message = 'unable to retrieve metadata from OpenProject %s for project %s. Invalid project key or no permissions to this project?' % (openproject_project.openproject_instance, openproject_project.project_key)

    elif not meta[0].type:
        meta_data_error = True
        message = 'unable to retrieve metadata from OpenProject %s for issuetype %s in project %s. Invalid default issue type configured in Defect Dojo?' % (openproject_project.openproject_instance, openproject_project.openproject_instance.default_issue_type, openproject_project.project_key)

    if meta_data_error:
        logger.warn(message)
        logger.warn("get_openproject_meta: %s", json.dumps(meta, indent=4))  # this is None safe

        add_error_message_to_response(message)

        raise BusinessError(text=message)
    else:
        return meta


def is_openproject_project_valid(openproject_project):
    try:
        meta = get_openproject_meta(get_openproject_connection(openproject_project), openproject_project)
        return True
    except BusinessError as e:
        logger.debug(e)
        logger.debug(e.__cause__)
        logger.debug('invalid OpenProject Project Config, can''t retrieve metadata for: ''%s''', openproject_project)
        return False


def openproject_attachment(finding, openproject, issue, file, openproject_filename=None):
    basename = file
    if openproject_filename is None:
        basename = os.path.basename(file)

    # Check to see if the file has been uploaded to OpenProject
    # TODO: OpenProject: check for local existince of attachment as it currently crashes if local attachment doesn't exist
    if openproject_check_attachment(issue, basename) is False:
        try:
            if openproject_filename is not None:
                attachment = io.StringIO()
                attachment.write(openproject_filename)
                openproject.add_attachment(
                    issue=issue, attachment=attachment, filename=openproject_filename)
            else:
                # read and upload a file
                with open(file, 'rb') as f:
                    openproject.add_attachment(issue=issue, attachment=f)
            return True
        except BusinessError as e:
            logger.exception(e)
            log_openproject_alert("Attachment: " + e.text, finding)
            return False


def openproject_check_attachment(issue, source_file_name):
    file_exists = False
    for attachment in issue.fields.attachment:
        filename = attachment.filename

        if filename == source_file_name:
            file_exists = True
            break

    return file_exists


# @dojo_model_to_id
# @dojo_async_task
# @app.task
# @dojo_model_from_id(model=Engagement)
# def close_epic(eng, push_to_jira, **kwargs):
#     engagement = eng
#     if not is_jira_enabled():
#         return False

#     if not is_jira_configured_and_enabled(engagement):
#         return False

#     jira_project = get_jira_project(engagement)
#     jira_instance = get_jira_instance(engagement)
#     if jira_project.enable_engagement_epic_mapping:
#         if push_to_jira:
#             try:
#                 jissue = get_jira_issue(eng)
#                 if jissue is None:
#                     logger.warn("JIRA close epic failed: no issue found")
#                     return False

#                 req_url = jira_instance.url + '/rest/api/latest/issue/' + \
#                     jissue.jira_id + '/transitions'
#                 json_data = {'transition': {'id': jira_instance.close_status_key}}
#                 r = requests.post(
#                     url=req_url,
#                     auth=HTTPBasicAuth(jira_instance.username, jira_instance.password),
#                     json=json_data)
#                 if r.status_code != 204:
#                     logger.warn("JIRA close epic failed with error: {}".format(r.text))
#                     return False
#                 return True
#             except JIRAError as e:
#                 logger.exception(e)
#                 log_jira_generic_alert('Jira Engagement/Epic Close Error', str(e))
#                 return False
#     else:
#         add_error_message_to_response('Push to JIRA for Epic skipped because enable_engagement_epic_mapping is not checked for this engagement')
#         return False


@dojo_model_to_id
@dojo_async_task
@app.task
@dojo_model_from_id(model=Engagement)
def update_epic(engagement, **kwargs):
    logger.debug('trying to update openproject EPIC for %d:%s', engagement.id, engagement.name)

    if not is_openproject_configured_and_enabled(engagement):
        return False

    logger.debug('config found')

    openproject_project = get_openproject_project(engagement)
    openproject_instance = get_openproject_instance(engagement)
    if openproject_project.enable_engagement_epic_mapping:
        try:
            openproject = get_openproject_connection(openproject_instance)
            op_issue = get_openproject_issue(engagement)
            issue = openproject.issue(op_issue.openproject_id)
            issue.update(summary=engagement.name, description=engagement.name)
            return True
        except BusinessError as e:
            logger.exception(e)
            log_openproject_generic_alert('OpenProject Engagement/Epic Update Error', str(e))
            return False
    else:
        add_error_message_to_response('Push to OpenProject for Epic skipped because enable_engagement_epic_mapping is not checked for this engagement')

        return False


@dojo_model_to_id
@dojo_async_task
@app.task
@dojo_model_from_id(model=Engagement)
def add_epic(engagement, **kwargs):
    logger.debug('trying to create a new openproject EPIC for %d:%s', engagement.id, engagement.name)

    if not is_openproject_configured_and_enabled(engagement):
        return False

    logger.debug('config found')

    openproject_project = get_openproject_project(engagement)
    openproject_instance = get_openproject_instance(engagement)
    if openproject_project.enable_engagement_epic_mapping:
        try:
            openproject = get_openproject_connection(openproject_instance)
            logger.debug('add_epic: %s', engagement.name)
            op_project_service = openproject.get_project_service()
            op_project = op_project_service.find_all([Filter("id", "=", [openproject_project.project_key])])[0]
            wp_form = op_project_service.create_work_package_form(op_project, WorkPackage({}))
            wp = WorkPackage(wp_form._embedded["payload"])            
            wp.subject = engagement.name
            wp.description["format"] = 'markdown'
            wp.description["raw"]= engagement.description
            wp.description["html"] = f'<p>{engagement.description}</p>'
            wp._links["type"]["href"] = f'/api/v3/types/{openproject_instance.epic_name_id}'
            wp._links["type"]["title"] = 'Epic'
            new_wp = op_project_service.create_work_package(op_project, wp)

            op_issue = OpenProject_Issue(
                openproject_id=new_wp.id,
                engagement=engagement,
                openproject_project=openproject_project)

            op_issue.save()
            return True
        except BusinessError as e:
            logger.exception(e)
            error = str(e)
            message = "The 'Project key ' or 'Epic name id' in your DefectDojo OpenProject Configuration does not appear to be correct. Please visit, " + openproject_instance.url + \
                "/api/v3/types and search for Epic Name. Copy the number out of type['id'] and place in your DefectDojo settings for OpenProject and try again) \n\n"

            log_openproject_generic_alert('OpenProject Engagement/Epic Creation Error',
                                   message + error)
            return False
    else:
        add_error_message_to_response('Push to OpenProject for Epic skipped because enable_engagement_epic_mapping is not checked for this engagement')
        return False


def openproject_get_issue(openproject_project, issue_key):
    try:
        openproject_instance = openproject_project.openproject_instance
        openproject = get_openproject_connection(openproject_instance)
        issue = openproject.issue(issue_key)

        return issue
    except BusinessError as openproject_error:
        logger.debug('error retrieving openproject issue ' + issue_key + ' ' + str(openproject_error))
        logger.exception(openproject_error)
        log_openproject_generic_alert('error retrieving openproject issue ' + issue_key, str(openproject_error))
        return None


@dojo_model_to_id(parameter=1)
@dojo_model_to_id
@dojo_async_task
@app.task
@dojo_model_from_id(model=Notes, parameter=1)
@dojo_model_from_id
def add_comment(obj, note, force_push=False, **kwargs):
    if not is_openproject_configured_and_enabled(obj):
        return False

    logger.debug('trying to add a comment to a linked openproject issue for: %d:%s', obj.id, obj)
    if not note.private:
        openproject_project = get_openproject_project(obj)
        openproject_instance = get_openproject_instance(obj)

        if openproject_project.push_notes or force_push is True:
            try:
                openproject = get_openproject_connection(openproject_instance)
                op_issue = obj.openproject_issue
                openproject.add_comment(
                    op_issue.openproject_id,
                    '(%s): %s' % (note.author.get_full_name() if note.author.get_full_name() else note.author.username, note.entry))
                return True
            except BusinessError as e:
                log_openproject_generic_alert('OpenProject Add Comment Error', str(e))
                return False


# def add_simple_jira_comment(jira_instance, jira_issue, comment):
#     try:
#         jira = get_jira_connection(jira_instance)

#         jira.add_comment(
#             jira_issue.jira_id, comment
#         )
#         return True
#     except Exception as e:
#         log_jira_generic_alert('Jira Add Comment Error', str(e))
#         return False


# def finding_link_jira(request, finding, new_jira_issue_key):
#     logger.debug('linking existing jira issue %s for finding %i', new_jira_issue_key, finding.id)

#     existing_jira_issue = jira_get_issue(get_jira_project(finding), new_jira_issue_key)

#     jira_project = get_jira_project(finding)

#     if not existing_jira_issue:
#         raise ValueError('JIRA issue not found or cannot be retrieved: ' + new_jira_issue_key)

#     jira_issue = JIRA_Issue(
#         jira_id=existing_jira_issue.id,
#         jira_key=existing_jira_issue.key,
#         finding=finding,
#         jira_project=jira_project)

#     jira_issue.jira_key = new_jira_issue_key
#     # jira timestampe are in iso format: 'updated': '2020-07-17T09:49:51.447+0200'
#     # seems to be a pain to parse these in python < 3.7, so for now just record the curent time as
#     # as the timestamp the jira link was created / updated in DD
#     jira_issue.jira_creation = timezone.now()
#     jira_issue.jira_change = timezone.now()

#     jira_issue.save()

#     finding.save(push_to_jira=False, dedupe_option=False, issue_updater_option=False)

#     jira_issue_url = get_jira_url(finding)

#     return True


# def finding_unlink_jira(request, finding):
#     return unlink_jira(request, finding)


# def unlink_jira(request, obj):
#     logger.debug('removing linked jira issue %s for %i:%s', obj.jira_issue.jira_key, obj.id, to_str_typed(obj))
#     obj.jira_issue.delete()
#     # finding.save(push_to_jira=False, dedupe_option=False, issue_updater_option=False)
#     # jira_issue_url = get_jira_url(finding)
#     return True


# return True if no errors
def process_openproject_project_form(request, instance=None, target=None, product=None, engagement=None):
    if not get_system_setting('enable_openproject'):
        return True, None

    error = False
    openproject_project = None
    # supply empty instance to form so it has default values needed to make has_changed() work
    opform = OpenProjectProjectForm(request.POST, instance=instance, target=target, product=product, engagement=engagement)
    # logging has_changed because it sometimes doesn't do what we expect
    logger.debug('opform has changed: %s', str(opform.has_changed()))

    if opform.has_changed():  # if no data was changed, no need to do anything!
        logger.debug('opform changed_data: %s', opform.changed_data)
        logger.debug('opform: %s', vars(opform))
        logger.debug('request.POST: %s', request.POST)

        # calling opform.is_valid() here with inheritance enabled would call clean() on the OpenProject_Project model
        # resulting in a validation error if no openproject_instance or project_key is provided
        # this validation is done because the form is a model form and cannot be skipped
        # so we check for inheritance checkbox before validating the form.
        # seems like it's impossible to write clean code with the Django forms framework.
        if request.POST.get('openproject-project-form-inherit_from_product', False):
            logger.debug('inherit chosen')
            if not instance:
                logger.debug('inheriting but no existing OpenProject Project for engagement, so nothing to do')
            else:
                error = True
                raise ValueError('Not allowed to remove existing OpenProject Config for an engagement')
        elif opform.is_valid():
            try:
                openproject_project = opform.save(commit=False)
                # could be a new openproject_project, so set product_id
                if engagement:
                    openproject_project.engagement_id = engagement.id
                    obj = engagement
                elif product:
                    openproject_project.product_id = product.id
                    obj = product

                if not openproject_project.product_id and not openproject_project.engagement_id:
                    raise ValueError('encountered OpenProject_Project without product_id and without engagement_id')

                # only check openproject project if form is sufficiently populated
                if openproject_project.openproject_instance and openproject_project.project_key:
                    # is_openproject_project_valid already adds messages if not a valid openproject project
                    if not is_openproject_project_valid(openproject_project):
                        logger.debug('unable to retrieve openproject project from openproject instance, invalid?!')
                        error = True
                    else:
                        logger.debug(vars(openproject_project))
                        openproject_project.save()
                        # update the in memory instance to make openproject_project attribute work and it can be retrieved when pushing
                        # an epic in the next step

                        obj.openproject_project = openproject_project

                        messages.add_message(request,
                                                messages.SUCCESS,
                                                'OpenProject Project config stored successfully.',
                                                extra_tags='alert-success')
                        error = False
                        logger.debug('stored OpenProject_Project successfully')
            except Exception as e:
                error = True
                logger.exception(e)
                pass
        else:
            logger.debug(opform.errors)
            error = True

        if error:
            messages.add_message(request,
                                    messages.ERROR,
                                    'OpenProject Project config not stored due to errors.',
                                    extra_tags='alert-danger')
    return not error, opform


# return True if no errors
def process_openproject_epic_form(request, engagement=None):
    if not get_system_setting('enable_openproject'):
        return True, None

    logger.debug('checking openproject epic form for engagement: %i:%s', engagement.id if engagement else 0, engagement)
    # push epic
    error = False
    openproject_epic_form = OpenProjectEngagementForm(request.POST, instance=engagement)

    openproject_project = get_openproject_project(engagement)  # uses inheritance to get from product if needed

    if openproject_project:
        if openproject_epic_form.is_valid():
            if openproject_epic_form.cleaned_data.get('push_to_openproject'):
                logger.debug('pushing engagement to OPenProject')
                if push_to_openproject(engagement):
                    logger.debug('Push to OpenProject for Epic queued successfully')
                    messages.add_message(
                        request,
                        messages.SUCCESS,
                        'Push to OpenProject for Epic queued succesfully, check alerts on the top right for errors',
                        extra_tags='alert-success')
                else:
                    error = True
                    logger.debug('Push to OpenProject for Epic failey')
                    messages.add_message(
                        request,
                        messages.ERROR,
                        'Push to OpenProject for Epic failed, check alerts on the top right for errors',
                        extra_tags='alert-danger')
        else:
            logger.debug('invalid openproject epic form')
    else:
        logger.debug('no openproject_project for this engagement, skipping epic push')
    return not error, openproject_epic_form


# # some character will mess with JIRA formatting, for example when constructing a link:
# # [name|url]. if name contains a '|' is will break it
# # so [%s|%s] % (escape_for_jira(name), url)
# def escape_for_jira(text):
#     return text.replace('|', '%7D')


# def process_resolution_from_jira(finding, resolution_id, resolution_name, assignee_name, jira_now, jira_issue) -> bool:
#     """ Processes the resolution field in the JIRA issue and updated the finding in Defect Dojo accordingly """
#     import dojo.risk_acceptance.helper as ra_helper
#     status_changed = False
#     resolved = resolution_id is not None
#     jira_instance = get_jira_instance(finding)

#     if resolved:
#         if jira_instance and resolution_name in jira_instance.accepted_resolutions:
#             if not finding.risk_accepted:
#                 logger.debug("Marking related finding of {} as accepted. Creating risk acceptance.".format(jira_issue.jira_key))
#                 finding.active = False
#                 finding.mitigated = None
#                 finding.is_mitigated = False
#                 finding.false_p = False
#                 ra = Risk_Acceptance.objects.create(
#                     accepted_by=assignee_name,
#                     owner=finding.reporter
#                 )
#                 finding.test.engagement.risk_acceptance.add(ra)
#                 ra_helper.add_findings_to_risk_acceptance(ra, [finding])
#                 status_changed = True
#         elif jira_instance and resolution_name in jira_instance.false_positive_resolutions:
#             if not finding.false_p:
#                 logger.debug("Marking related finding of {} as false-positive".format(jira_issue.jira_key))
#                 finding.active = False
#                 finding.verified = False
#                 finding.mitigated = None
#                 finding.is_mitigated = False
#                 finding.false_p = True
#                 ra_helper.risk_unaccept(finding)
#                 status_changed = True
#         else:
#             # Mitigated by default as before
#             if not finding.is_mitigated:
#                 logger.debug("Marking related finding of {} as mitigated (default)".format(jira_issue.jira_key))
#                 finding.active = False
#                 finding.mitigated = jira_now
#                 finding.is_mitigated = True
#                 finding.mitigated_by, created = User.objects.get_or_create(username='JIRA')
#                 finding.endpoints.clear()
#                 finding.false_p = False
#                 ra_helper.risk_unaccept(finding)
#                 status_changed = True
#     else:
#         if not finding.active:
#             # Reopen / Open Jira issue
#             logger.debug("Re-opening related finding of {}".format(jira_issue.jira_key))
#             finding.active = True
#             finding.mitigated = None
#             finding.is_mitigated = False
#             finding.false_p = False
#             ra_helper.risk_unaccept(finding)
#             status_changed = True

#     # for findings in a group, there is no jira_issue attached to the finding
#     jira_issue.jira_change = jira_now
#     jira_issue.save()
#     if status_changed:
#         finding.save()
#     return status_changed
