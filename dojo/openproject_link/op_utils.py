import logging
from pyopenproject.model.work_package import WorkPackage
from pyopenproject.business.util.filter import Filter
from pyopenproject.business.exception.business_error import BusinessError
from pyopenproject.api_connection.requests.post_request import PostRequest
from pyopenproject.business.services.command.work_package.add_attachment import AddAttachment
from pyopenproject.business.services.command.work_package.create_activity import CreateActivity
from pyopenproject.api_connection.exceptions.request_exception import RequestError
from pyopenproject.model import attachment
from dojo.models import System_Settings
import json

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


def op_add_epic(op_connection, engagement, openproject_project, openproject_instance):
    logger.debug('add_epic: eng %s, op key %s', engagement.name, openproject_project)
    op_project_service = op_connection.get_project_service()
    op_project = op_project_service.find_all([Filter("id", "=", [openproject_project.project_key])])[0]
    wp_form = op_project_service.create_work_package_form(op_project, WorkPackage({}))
    wp = WorkPackage(wp_form._embedded["payload"])            
    wp.subject = engagement.name
    wp.description["format"] = 'markdown'
    wp.description["raw"]= engagement.description
    wp.description["html"] = f'<p>{engagement.description}</p>'
    wp._links["type"]["href"] = f'/api/v3/types/{openproject_instance.epic_name_id}'
    wp._links["type"]["title"] = 'Epic'

    return op_project_service.create_work_package(op_project, wp)

    
def op_update_epic(op_connection, op_issue, **kwargs):
    subject = kwargs['subject']
    description = kwargs['issue_description']
    html_description = kwargs['html_description']
    
    work_package = WorkPackage({"id": op_issue.openproject_id})
    wp_service = op_connection.get_work_package_service()
    wp = wp_service.find(work_package)
    new_wp = WorkPackage(
        {
            "id": wp.id, 
            "subject": subject, 
            "description": {
                "format": "markdown",
                "raw": description,
                "html": html_description 
            },
            "lockVersion": wp.lockVersion
        }
    )

    return wp_service.update(new_wp)


def op_issue_type_key(op_connection, issue_type):
    return list(filter(lambda t: t.name==issue_type, op_connection.get_type_service().find_all()))[0].id


def op_issue_priority_key(op_connection, priority):
    result = list(filter(lambda t: t.name==priority, op_connection.get_priority_service().find_all()))
    if len(result) > 0:
        return result[0].id
    else:
        raise BusinessError(f"Bad Openproject priority key: {priority}")


def     op_add_issue(op_connection, obj, **kwargs):
    project_id = kwargs['project_id']
    subject = kwargs['subject'] 
    description = kwargs['description'] 
    environment = kwargs['environment']
    issue_type = kwargs['issue_type']
    issue_priority = kwargs['issue_priority']

    op_project_service = op_connection.get_project_service()
    logger.debug(f'------------------- op_add_issue project_id={project_id}')
    op_project = op_project_service.find_all([Filter("id", "=", [project_id])])[0]
    logger.debug(f'------------------- op_project={op_project}')
    wp_form = op_project_service.create_work_package_form(op_project, WorkPackage({}))

    wp = WorkPackage(wp_form._embedded["payload"]) 
    wp.subject = subject
    wp_descr = ''
    if description:
        wp_descr = wp_descr + 'Description:\n    '+description + '\n'
    if environment:
        wp_descr = wp_descr + 'Environment:\n    '+environment + '\n'
    wp_html_descr = ''
    if description:
        wp_html_descr = wp_html_descr + '<p>Description:</p><p>    '+description + '</p>'
    if environment:
        wp_html_descr = wp_html_descr + '<p>Environment:</p><p>    '+environment + '</p>'

    wp.description["format"] = 'markdown'
    wp.description["raw"]= wp_descr
    wp.description["html"] = wp_html_descr

    op_type = op_issue_type_key(op_connection, issue_type)
    wp._links["type"]["href"] = f'/api/v3/types/{op_type}'
    wp._links["type"]["title"] = f'{issue_type}'
    
    op_priority_key = op_issue_priority_key(op_connection, issue_priority)
    wp.priority = op_priority_key
    wp._links["priority"]["href"] = f'/api/v3/priorities/{op_priority_key}'
    wp._links["priority"]["title"] = f'{issue_priority}'
    
    if System_Settings.objects.get().enable_finding_sla:
        duedate = obj.sla_deadline()
        if duedate:
            wp.dueDate = duedate.strftime('%Y-%m-%d')

    return op_project_service.create_work_package(op_project, wp)


def op_close_issue(op_connection, op_issue, **kwargs):
    op_close_status_key = kwargs['op_close_status_key']

    work_package = WorkPackage({"id": op_issue.openproject_id})
    wp_service = op_connection.get_work_package_service()
    wp = wp_service.find(work_package)

    new_wp = WorkPackage(
        {
            "id": wp.id, 
            "lockVersion": wp.lockVersion,
            "_links":{
                "status": {
                     'href': f'/api/v3/statuses/{op_close_status_key}'
                }
            }
        }
    )
    return wp_service.update(new_wp)


def op_reopen_issue(op_connection, op_issue, **kwargs):
    op_open_status_key = kwargs['op_open_status_key']

    work_package = WorkPackage({"id": op_issue.openproject_id})
    wp_service = op_connection.get_work_package_service()
    wp = wp_service.find(work_package)

    new_wp = WorkPackage(
        {
            "id": wp.id, 
            "lockVersion": wp.lockVersion,
            "_links":{
                "status": {
                     'href': f'/api/v3/statuses/{op_open_status_key}'
                }
            }
        }
    )
    return wp_service.update(new_wp)


def op_update_issue(op_connection, op_issue, obj, **kwargs):
    subject = kwargs['subject']
    description = kwargs['issue_description']
    html_description = kwargs['html_description']
    
    op_close_status_key = kwargs['op_close_status_key']
    op_open_status_key = kwargs['op_open_status_key']
    issue_priority = kwargs['issue_priority']

    work_package = WorkPackage({"id": op_issue.openproject_id})
    wp_service = op_connection.get_work_package_service()
    wp = wp_service.find(work_package)

    op_priority_key = op_issue_priority_key(op_connection, issue_priority)

    new_wp = WorkPackage(
        {
            "id": wp.id, 
            "subject": subject, 
            "description": {
                "format": "markdown",
                "raw": description,
                "html": html_description 
            },
            "lockVersion": wp.lockVersion,
            "_links":{
                "status": {
                },
                "priority":{
                    "href": f'/api/v3/priorities/{op_priority_key}',
                    "title": f'{issue_priority}'
                }
            }
        }
    )
    op_push_status(obj, wp, new_wp, op_open_status_key, op_close_status_key)
    logger.debug(f'---------------------- update issue: {new_wp}')
    return wp_service.update(new_wp)


def op_issue_is_active(issue_from_openproject):
    status = issue_from_openproject._embedded['status']
    if  'isClosed' not in status:
        return True

    if status['isClosed'] == "True":
        return False

    if status['isClosed']:
        return False

    return True


def op_push_status(obj, old_wp, new_wp, op_open_status_key, op_close_status_key, save=False):
    status_list = obj.status()
    issue_closed = False

    # check RESOLVED_STATUS first to avoid corner cases with findings that are Inactive, but verified
    if any(item in status_list for item in RESOLVED_STATUS):
        if op_issue_is_active(old_wp):
            logger.debug(f'Transitioning OpenProject issue status to Resolved: {old_wp}')
            new_wp._links['status']['href'] = f'/api/v3/statuses/{op_close_status_key}'
            updated = True
        else:
            logger.debug(f'Openproject issue already Resolved: {obj.openproject_issue.openproject_id}')
            updated = False
        issue_closed = True

    if not issue_closed and any(item in status_list for item in OPEN_STATUS):
        if not op_issue_is_active(old_wp):
            logger.debug('Transitioning OpenProject issue to Active (Reopen)')
            new_wp._links['status']['href'] = f'/api/v3/statuses/{op_open_status_key}'
            updated = True
        else:
            logger.debug(f'OpenProject issue already Active: {obj.openproject_issue.openproject_id}')
            updated = False

    return updated and save


def op_check_attachment(op_issue, source_file_name):
    file_exists = False
    attachments = op_issue._embedded['attachments']['_embedded']['elements']
    for attachment in attachments:
        filename = attachment['fileName']
        if filename == source_file_name:
            file_exists = True
            break

    return file_exists


def op_add_attachment(op_connection, op_issue, file, file_name, file_description):
    add_cmd = AddAttachment(op_connection,op_issue,None)    
    try:
        metadata = {"fileName": file_name, "description": {"raw": file_description}}
        json_result = PostRequest(connection=op_connection.conn,
                        context=f"{add_cmd.CONTEXT}/{op_issue.id}/attachments",
                        files={
                            'file': (file_name, file),
                            'metadata': (None, json.dumps(metadata))
                        }
                    ).execute()
        return attachment.Attachment(json_result)
    except RequestError as re:
        raise BusinessError(f"Error adding new attachment: {file_name}") from re

def op_add_comment(op_connection, op_issue, comment):
    wp = WorkPackage({"id": op_issue.openproject_id})
    add_cmd = CreateActivity(op_connection.conn, wp, '(%s): %s' % (comment.author.get_full_name() if comment.author.get_full_name() else comment.author.username, comment.entry), False)    
    return add_cmd.execute()
