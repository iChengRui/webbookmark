#!/user/bin/env python3
# -*- coding:utf-8 -*-

from . import views
from django.conf.urls.i18n import urlpatterns
from django.urls import path


app_name="webbookmark"
urlpatterns=[
    path("reg",views.uregister),
    path("login",views.ulogin),
    path("logout",views.ulogout),
    path("cu",views.cupdate),
    path("cup",views.piece_cupdate),
    path("fu",views.fupdate),
    path("del",views.udelete),
    ]