---
title: "OpenProject integration"
description: "Bidirectional integration of DefectDojo findings with OpenProject issues."
draft: false
weight: 4
---

DefectDojo\'s OpenProject integration is bidirectional. You may push findings
to OpenProject and share comments. If an issue is closed in OpenProject it will
automatically be closed in Dojo.

**NOTE:** These steps will configure the necessary webhook in OpenProject and add OpenProject integration into DefectDojo. This isn\'t sufficient by itself, you will need to configure products and findings to push to OpenProject. On a product\'s settings page you will need to define a:

-   Project Key (and this project must exist in OpenProject)
-   OpenProject Configuration (select the OpenProject configuration that you
        create in the steps below)
-   Component (can be left blank)

Then elect (via tickbox) whether you want to \'Push all issues\',
\'Enable engagement epic mapping\' and/or \'Push notes\'. Then click on
\'Submit\'.

If creating a Finding, ensure to tick \'Push to OpenProject\' if desired.

Enabling the Webhook
--------------------

1.  Visit <https://>\<**YOUR OpenProject URL**\>/plugins/servlet/webhooks
2.  Click \'Create a Webhook\'
3.  For the field labeled \'URL\' enter: <https://>\<**YOUR DOJO
    DOMAIN**\>/openproject/webhook/<**YOUR GENERATED WEBHOOK SECRET**>
    This value can be found under Defect Dojo System settings
4.  Under \'Comments\' enable \'Created\'. Under Issue enable
    \'Updated\'.

Configurations in Dojo
----------------------

1.  Navigate to the System Settings from the menu on the left side
    or by directly visiting \<your url\>/system\_settings.
2.  Enable \'Enable OpenProject integration\' and click submit.
3.  For the webhook created in Enabling the Webhook, enable
    \'Enable OpenProject web hook\' and click submit.

Adding OpenProject to Dojo
-------------------

1.  Click \'OpenProject\' from the left hand menu.
2.  Select \'Add Configuration\' from the drop-down.
3.  For OpenProject Server: 
    
    Enter the _Username_ & _Password_. A _Username_ and OpenProject _Personal Access Token_ will not necessarily work.
    
    For OpenProject Cloud:
    
    Enter _Email Address_ & [API token for OpenProject](https://support.atlassian.com/atlassian-account/docs/manage-api-tokens-for-your-atlassian-account/)
4.  To obtain the \'open status key\' and \'closed status key\'
    visit <https://>\<**YOUR OpenProject
    URL**\>/rest/api/latest/issue/\<**ANY VALID ISSUE
    KEY**\>/transitions?expand=transitions.fields
5.  The \'id\' for \'Todo\' should be filled in as the \'open status
    key\'
6.  The \'id\' for \'Done\' should be filled in as the \'closed
    status key\'

To obtain \'epic name id\': If you have admin access to OpenProject:

1.  visit: <https://>\<**YOUR OpenProject
    URL**\>/secure/admin/ViewCustomFields.jspa
2.  Click on the cog next to \'Epic Name\' and select view.
3.  The numeric value for \'epic name id\' will be displayed in the
    URL
4.  **Note**: dojoopenproject uses the same celery functionality as
    reports. Make sure the celery runner is setup correctly as
    described:
    <https://defectdojo.github.io/django-DefectDojo/basics/features/#reports>

Or

1.  login to OpenProject
2.  visit <https://youropenprojecturl/rest/api/2/field> and use control+F
    or grep to search for \'Epic Name\' it should look something
    like this:

{
    "id":"customfield_122",
    "key":"customfield_122",
    "name":"Epic Name",
    "custom":true,
    "orderable":true,
    "navigable":true,
    "searchable":true,
    "clauseNames":"cf[122]",
    "Epic Name"\],
    "schema":{"type":"string","custom":"com.pyxis.greenhopper.openproject:gh-epic-label","customId":122}
}

**In the above example 122 is the number needed**

## Customize OpenProject issue description

By default Defect Dojo uses the `dojo/templates/issue-trackers/openproject_full/openproject-description.tpl` template to render the description of the 'to be' created OpenProject issue.
This file can be modified to your needs, rebuild all containers afterwards. There's also a more limited template available, which can be chosen when
configuring a OpenProject Instance or OpenProject Project for a Product or Engagement:

![image](../../images/openproject_issue_templates.png)

Any folder added to  `dojo/templates/issue-trackers/` will be added to the dropdown (after rebuilding/restarting the containers).

## Engagement Epic Mapping

If creating an Engagement, ensure to tick 'Enable engagement epic mapping' if desired. This can also be done after engagement creation on the edit engagement page.
This will create an 'Epic' type issue within OpenProject. All findings in the engagement pushed to OpenProject will have a link to this Epic issue.
If Epic Mapping was enabled after associated findings have already been pushed to OpenProject, simply pushing them again will link the OpenProject issue to the Epic issue.

## Pushing findings

Findings can be pushed to OpenProject in a number of ways:

1. When importing scanner reports, select 'Push to OpenProject' to push every single finding in the report to OpenProject
2. When creating a new finding, select 'Push to OpenProject' and submit. This will create the finding in DefectDojo and OpenProject simultaneously
3. If a finding already exist, visit the edit finding page and find the 'Push to OpenProject' tick box at the bottom
4. When viewing a list of findings, select each relevant tick boxes to the left of the finding, and click the 'Bulk Edit' button at the top. find 'Push to OpenProject' at the bottom of the menu

## Status Sync

DefectDojo will try to keep the status in sync with the status in OpenProject
using the Close and Reopen transition IDs configured for each OpenProject instance. This
will only work if your workflow in OpenProject allows the Close transition to be
performed from every status a OpenProject issue can be in.

## Known Issues

The Risk Acceptance feature
in DefectDojo will (for that reason) not (yet) try to sync statuses. A
comment will be pushed to OpenProject if a finding is risk accepted or
unaccepted. Contributions are welcome to enhance the integration.

## Status reconciliation

Sometimes OpenProject is down, or Defect Dojo is down, or there was bug in a webhook. In this case
OpenProject can become out of sync with Defect Dojo. If this is the case for lots of issues, manual reconciliation
might not be feasible. For this scenario there is the management command 'openproject_status_reconciliation'.

{{< highlight bash >}}
usage: manage.py openproject_status_reconciliation [-h] [--mode MODE] [--product PRODUCT] [--engagement ENGAGEMENT] [--dryrun] [--version] [-v {0,1,2,3}]

Reconcile finding status with OpenProject issue status, stdout will contain semicolon seperated CSV results.
Risk Accepted findings are skipped. Findings created before 1.14.0 are skipped.

optional arguments:
  -h, --help            show this help message and exit
  --mode MODE           - reconcile: (default)reconcile any differences in status between Defect Dojo and OpenProject, will look at the latest status change
                        timestamp in both systems to determine which one is the correct status
                        - push_status_to_openproject: update OpenProject status for all OpenProject issues
                        connected to a Defect Dojo finding (will not push summary/description, only status)
                        - import_status_from_openproject: update Defect Dojo
                        finding status from OpenProject
  --product PRODUCT     Only process findings in this product (name)
  --engagement ENGAGEMENT
                        Only process findings in this product (name)
  --dryrun              Only print actions to be performed, but make no modifications.
  -v {0,1,2,3}, --verbosity {0,1,2,3}
                        Verbosity level; 0=minimal output, 1=normal output, 2=verbose output, 3=very verbose output
{{< /highlight >}}

This can be executed from the uwsgi docker container using:

{{< highlight bash >}}
$ docker-compose exec uwsgi /bin/bash -c 'python manage.py openproject_status_reconciliation'
{{< /highlight >}}

DEBUG output can be obtains via `-v 3`, but only after increasing the logging to DEBUG level in your settings.dist.py or local_settings.py file

{{< highlight bash >}}
$ docker-compose exec uwsgi /bin/bash -c 'python manage.py openproject_status_reconciliation -v 3'
{{< /highlight >}}

At the end of the command a semicolon seperated CSV summary will be printed. This can be captured by redirecting stdout to a file:

{{< highlight bash >}}
$ docker-compose exec uwsgi /bin/bash -c 'python manage.py openproject_status_reconciliation > openproject_reconciliation.csv'
{{< /highlight >}}


## Troubleshooting OpenProject integration

OpenProject actions are typically performed in the celery background process.
Errors are logged as alerts/notifications to be seen on the top right of
the DefectDojo UI and in stdout of the celery workers.
