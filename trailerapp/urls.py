from django.conf.urls import patterns, include, url
from django.contrib import admin
from django.views.generic import TemplateView

from conv.views import S3SignView

urlpatterns = patterns('',
    # Examples:
    # url(r'^$', 'trailerapp.views.home', name='home'),
    # url(r'^blog/', include('blog.urls')),

    url(r'^admin/', include(admin.site.urls)),
    url(r'^$', TemplateView.as_view(template_name='chat.html') ),
    url(r'^sign_s3$', S3SignView.as_view() )
)
