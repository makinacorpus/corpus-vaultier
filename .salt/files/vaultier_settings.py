#!/usr/bin/env python
# -*- coding: utf-8 -*-
__docformat__ = 'restructuredtext en'
from settings.prod import *
from localsettings import *
CELERYBEAT_SCHEDULE.pop('usage_statistics', None)
# vim:set et sts=4 ts=4 tw=80:
