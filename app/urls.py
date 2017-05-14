from django.conf.urls import url
from rest_framework import routers
from rest_framework.urlpatterns import format_suffix_patterns

from app.views import BookDetails, BookList

router = routers.DefaultRouter()
urlpatterns = [
    url(r'^books/$', BookList.as_view()),
    url(r'^book/(?P<pk>[0-9]+)/$', BookDetails.as_view()),
]
urlpatterns = format_suffix_patterns(urlpatterns)
