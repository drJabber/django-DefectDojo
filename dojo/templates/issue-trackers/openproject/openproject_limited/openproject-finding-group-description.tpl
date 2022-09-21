{% load navigation_tags %}
{% load display_tags %}
{% url 'view_finding_group' finding_group.id as finding_group_url %}
{% url 'view_product' finding.test.engagement.product.id as product_url %}
{% url 'view_engagement' finding.test.engagement.id as engagement_url %}
{% url 'view_test' finding.test.id as test_url %}

A group of Findings has been pushed to OpenProject to be investigated and fixed:

*Group*: [{{ finding_group.name|openprojectencode}}|{{ finding_group_url|full_url }}] in [{{ finding_group.test.engagement.product.name|openprojectencode }}|{{ product_url|full_url }}] / [{{ finding_group.test.engagement.name|openprojectencode }}|{{ engagement_url|full_url }}] / [{{ finding_group.test|stringformat:'s'|openprojectencode }}|{{ test_url|full_url }}]

Findings:
{% for finding in finding_group.findings.all %}
- [{{ finding.title|openprojectencode}}|{{ finding_url|full_url }}]{% endfor %}

{% if finding_group.test.engagement.branch_tag %}
*Branch/Tag:* {{ finding_group.test.engagement.branch_tag }}
{% endif %}

{% if finding_group.test.engagement.build_id %}
*BuildID:* {{ finding_group.test.engagement.build_id }}
{% endif %}

{% if finding_group.test.engagement.commit_hash %}
*Commit hash:* {{ finding_group.test.engagement.commit_hash }}
{% endif %}
