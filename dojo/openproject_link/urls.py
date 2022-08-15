from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^webhook/(?P<secret>[\w-]+)$', views.webhook, name='web_hook_secret'),
    url(r'^webhook/', views.webhook, name='web_hook'),
    url(r'^openproject/webhook/(?P<secret>[\w-]+)$', views.webhook, name='openproject_web_hook_secret'),
    url(r'^openproject/webhook/', views.webhook, name='openproject_web_hook'),
    url(r'^openproject/add', views.new_openproject, name='add_openproject'),
    url(r'^openproject/(?P<opid>\d+)/edit$', views.edit_openproject,
        name='edit_openproject'),
    url(r'^openproject/(?P<tid>\d+)/delete$', views.delete_openproject,
        name='delete_openproject'),
    url(r'^openproject/express', views.express_new_openproject, name='express_openproject'),
    url(r'^openproject$', views.openproject, name='openproject'),

    ]
