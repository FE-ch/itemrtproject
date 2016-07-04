from django.conf.urls import patterns, include, url
from django.contrib.auth.views import login, logout
from django.views.generic import TemplateView
from django.views.generic.base import RedirectView

from itemrtweb.views import *

# Uncomment the next two lines to enable the admin:
from django.contrib import admin
admin.autodiscover()

urlpatterns = patterns('',
    url(r'^$', home),

    url(r'^home/$', user_home),

    url(r'^question/(?P<id>\d+)/view/$', question_view, {'practiced': True}),
    url(r'^question/flag/(?P<question_id>\d+)/$', flag_question),

    url(r'^practice/$', practice_home),
    url(r'^practice/(\d+)/$', practice_question),
    url(r'^practice/resume/$', practice_resume),
    url(r'^practice/end/$', practice_end),

    url(r'^labtest/$', labtest),

    url(r'^trialtest/$', trialtest),
    url(r'^trialtest/generate/$', trialtest_generate),
    url(r'^trialtest/go/(?P<test_id>\w+)/$', trialtest_go),
    url(r'^trialtest/(?P<test_id>\w+)/(?P<util_name>\w+)/$', 'itemrtweb.views.trialtestutil'),

    url(r'^cattest/$', trialtest),

    url(r'^papertest/$', papertest),
    url(r'^papertest/(?P<test_id>\w+)/$', 'itemrtweb.views.papertest'),
    url(r'^papertest/submit/(?P<test_id>\w+)/$', 'itemrtweb.views.papertestsubmit'),
    url(r'^papertest/(?P<test_id>\w+)/(?P<util_name>\w+)/$', 'itemrtweb.views.papertestutil'),

    url(r'^feedback/$', feedback),
    url(r'^survey/$', 'itemrtweb.views.survey'),

    # Login, Logout and accounts
    url(r'^accounts/login/$', account_login),
    url(r'^accounts/logout/$', account_logout),
    url(r'^accounts/register/$', account_register),
    url(r'^accounts/activate/$', account_activate),
    url(r'^accounts/forgot/$', account_forgot),
    url(r'^accounts/reset/$', account_reset),
    url(r'^accounts/profile/$', RedirectView.as_view(url='/home/')),

    # Debug functions
    url(r'^debug/mode/(\d+)/$', debug_changemode),
    url(r'^debug/clearresponse/$', debug_clearresponses),

    # Control Panel
    url(r'^control/$', control),
    url(r'^control/cattest/settings/$', control_cattest_settings),
    url(r'^control/newtest/$', 'itemrtweb.views.controlnewtest'),
    url(r'^control/newtest/submit/$', 'itemrtweb.views.controlnewtest_submit'),
    url(r'^control/view/(\w+)/$', 'itemrtweb.views.controlviewpaper'),

    url(r'^control/download/(\w+)/$', 'itemrtweb.views.controldownloadpaper'),
    url(r'^control/flaggedqn/$', 'itemrtweb.views.flag_display'),

    # Tag Search for Users
    url(r'^search/$', 'itemrtweb.views.search'),

    url(r'^postdata/$', postdata),

    url(r'^prototype/$', 'itemrtweb.views.prototype'),
    url(r'^prototype/edit/question/(?P<question_id>\d+)/$', 'itemrtweb.views.prototype'),
    url(r'^prototype/delete/question/(?P<question_id>\d+)/$', 'itemrtweb.views.prototype3'),
    url(r'^prototype/preview/question/(?P<question_id>\d+)/$', 'itemrtweb.views.preview'),
    url(r'^prototype2/$', 'itemrtweb.views.prototype2'),
    url(r'^prototype2/list/topic/(?P<topic_id>\d+)/$', 'itemrtweb.views.prototype2'),
    url(r'^prototype2/list/tags/$', 'itemrtweb.views.prototype2a'),

    # Temp
    url(r'^prototype/test/question/(?P<question_id>\d+)/$', 'itemrtweb.views.testquestion'),

    # Prod static files
    url(r'^static/(?P<path>.*)$', 'django.views.static.serve', {'document_root': settings.STATIC_ROOT}),

    # Examples:
    # url(r'^$', 'itemrtproject.views.home', name='home'),
    # url(r'^itemrtproject/', include('itemrtproject.foo.urls')),

    # Uncomment the admin/doc line below to enable admin documentation:
    # url(r'^admin/doc/', include('django.contrib.admindocs.urls')),

    # Uncomment the next line to enable the admin:
    url(r'^admin/', include(admin.site.urls)),
    url(r'^comments/', include('django.contrib.comments.urls')),
)

# Append staticfiles into urlpatterns
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
urlpatterns += staticfiles_urlpatterns()