from crum import get_current_user
from django.db.models import Exists, OuterRef, Q
from dojo.models import OpenProject_Issue, OpenProject_Project, Product_Member, Product_Type_Member, \
    Product_Group, Product_Type_Group
from dojo.authorization.authorization import get_roles_for_permission, user_has_global_permission

def get_authorized_openrpoject_projects(permission, user=None):

    if user is None:
        user = get_current_user()

    if user is None:
        return OpenProject_Project.objects.none()

    openproject_projects = OpenProject_Project.objects.all()

    if user.is_superuser:
        return openproject_projects

    if user_has_global_permission(user, permission):
        return openproject_projects

    roles = get_roles_for_permission(permission)
    engagement_authorized_product_type_roles = Product_Type_Member.objects.filter(
        product_type=OuterRef('engagement__product__prod_type_id'),
        user=user,
        role__in=roles)
    engagement_authorized_product_roles = Product_Member.objects.filter(
        product=OuterRef('engagement__product_id'),
        user=user,
        role__in=roles)
    engagement_authorized_product_type_groups = Product_Type_Group.objects.filter(
        product_type=OuterRef('engagement__product__prod_type_id'),
        group__users=user,
        role__in=roles)
    engagement_authorized_product_groups = Product_Group.objects.filter(
        product=OuterRef('engagement__product_id'),
        group__users=user,
        role__in=roles)
    product_authorized_product_type_roles = Product_Type_Member.objects.filter(
        product_type=OuterRef('product__prod_type_id'),
        user=user,
        role__in=roles)
    product_authorized_product_roles = Product_Member.objects.filter(
        product=OuterRef('product_id'),
        user=user,
        role__in=roles)
    product_authorized_product_type_groups = Product_Type_Group.objects.filter(
        product_type=OuterRef('product__prod_type_id'),
        group__users=user,
        role__in=roles)
    product_authorized_product_groups = Product_Group.objects.filter(
        product=OuterRef('product_id'),
        group__users=user,
        role__in=roles)
    openproject_projects = openproject_projects.annotate(
        engagement__product__prod_type__member=Exists(engagement_authorized_product_type_roles),
        engagement__product__member=Exists(engagement_authorized_product_roles),
        engagement__product__prod_type__authorized_group=Exists(engagement_authorized_product_type_groups),
        engagement__product__authorized_group=Exists(engagement_authorized_product_groups),
        product__prod_type__member=Exists(product_authorized_product_type_roles),
        product__member=Exists(product_authorized_product_roles),
        product__prod_type__authorized_group=Exists(product_authorized_product_type_groups),
        product__authorized_group=Exists(product_authorized_product_groups))
    openproject_projects = openproject_projects.filter(
        Q(engagement__product__prod_type__member=True) |
        Q(engagement__product__member=True) |
        Q(engagement__product__prod_type__authorized_group=True) |
        Q(engagement__product__authorized_group=True) |
        Q(product__prod_type__member=True) |
        Q(product__member=True) |
        Q(product__prod_type__authorized_group=True) |
        Q(product__authorized_group=True))

    return openproject_projects


def get_authorized_openproject_issues(permission):
    user = get_current_user()

    if user is None:
        return OpenProject_Issue.objects.none()

    openproject_issues = OpenProject_Issue.objects.all()

    if user.is_superuser:
        return openproject_issues

    if user_has_global_permission(user, permission):
        return openproject_issues

    roles = get_roles_for_permission(permission)
    engagement_authorized_product_type_roles = Product_Type_Member.objects.filter(
        product_type=OuterRef('engagement__product__prod_type_id'),
        user=user,
        role__in=roles)
    engagement_authorized_product_roles = Product_Member.objects.filter(
        product=OuterRef('engagement__product_id'),
        user=user,
        role__in=roles)
    engagement_authorized_product_type_groups = Product_Type_Group.objects.filter(
        product_type=OuterRef('engagement__product__prod_type_id'),
        group__users=user,
        role__in=roles)
    engagement_authorized_product_groups = Product_Group.objects.filter(
        product=OuterRef('engagement__product_id'),
        group__users=user,
        role__in=roles)
    finding_group_authorized_product_type_roles = Product_Type_Member.objects.filter(
        product_type=OuterRef('finding_group__test__engagement__product__prod_type_id'),
        user=user,
        role__in=roles)
    finding_group_authorized_product_roles = Product_Member.objects.filter(
        product=OuterRef('finding_group__test__engagement__product_id'),
        user=user,
        role__in=roles)
    finding_group_authorized_product_type_groups = Product_Type_Group.objects.filter(
        product_type=OuterRef('finding_group__test__engagement__product__prod_type_id'),
        group__users=user,
        role__in=roles)
    finding_group_authorized_product_groups = Product_Group.objects.filter(
        product=OuterRef('finding_group__test__engagement__product_id'),
        group__users=user,
        role__in=roles)
    finding_authorized_product_type_roles = Product_Type_Member.objects.filter(
        product_type=OuterRef('finding__test__engagement__product__prod_type_id'),
        user=user,
        role__in=roles)
    finding_authorized_product_roles = Product_Member.objects.filter(
        product=OuterRef('finding__test__engagement__product_id'),
        user=user,
        role__in=roles)
    finding_authorized_product_type_groups = Product_Type_Group.objects.filter(
        product_type=OuterRef('finding__test__engagement__product__prod_type_id'),
        group__users=user,
        role__in=roles)
    finding_authorized_product_groups = Product_Group.objects.filter(
        product=OuterRef('finding__test__engagement__product_id'),
        group__users=user,
        role__in=roles)
    openproject_issues = openproject_issues.annotate(
        engagement__product__prod_type__member=Exists(engagement_authorized_product_type_roles),
        engagement__product__member=Exists(engagement_authorized_product_roles),
        engagement__product__prod_type__authorized_group=Exists(engagement_authorized_product_type_groups),
        engagement__product__authorized_group=Exists(engagement_authorized_product_groups),
        finding_group__test__engagement__product__prod_type__member=Exists(finding_group_authorized_product_type_roles),
        finding_group__test__engagement__product__member=Exists(finding_group_authorized_product_roles),
        finding_group__test__engagement__product__prod_type__authorized_group=Exists(finding_group_authorized_product_type_groups),
        finding_group__test__engagement__product__authorized_group=Exists(finding_group_authorized_product_groups),
        finding__test__engagement__product__prod_type__member=Exists(finding_authorized_product_type_roles),
        finding__test__engagement__product__member=Exists(finding_authorized_product_roles),
        finding__test__engagement__product__prod_type__authorized_group=Exists(finding_authorized_product_type_groups),
        finding__test__engagement__product__authorized_group=Exists(finding_authorized_product_groups))
    openproject_issues = openproject_issues.filter(
        Q(engagement__product__prod_type__member=True) |
        Q(engagement__product__member=True) |
        Q(engagement__product__prod_type__authorized_group=True) |
        Q(engagement__product__authorized_group=True) |
        Q(finding_group__test__engagement__product__prod_type__member=True) |
        Q(finding_group__test__engagement__product__member=True) |
        Q(finding_group__test__engagement__product__prod_type__authorized_group=True) |
        Q(finding_group__test__engagement__product__authorized_group=True) |
        Q(finding__test__engagement__product__prod_type__member=True) |
        Q(finding__test__engagement__product__member=True) |
        Q(finding__test__engagement__product__prod_type__authorized_group=True) |
        Q(finding__test__engagement__product__authorized_group=True))

    return openproject_issues
