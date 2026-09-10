#!/usr/bin/env python

import hxtool_global
from .task_module import *
from hx_lib import *

class hunt_search_task_module(task_module):
    def __init__(self, parent_task):
        super(type(self), self).__init__(parent_task)

    @staticmethod
    def input_args():
        return [
            {
                'name': 'query',
                'type': list,
                'required': True,
                'user_supplied': True,
                'description': 'HX query array: [{"field": "...", "operator": "...", "value": "..."}]',
            },
            {
                'name': 'hostset_id',
                'type': int,
                'required': True,
                'user_supplied': True,
                'description': 'Host set ID to sweep.',
            },
            {
                'name': 'displayname',
                'type': str,
                'required': False,
                'user_supplied': True,
                'description': 'Display name for the search.',
            },
        ]

    @staticmethod
    def output_args():
        return [
            {
                'name': 'enterprise_search_id',
                'type': int,
                'required': True,
                'description': 'The Enterprise Search ID assigned by the controller.',
            }
        ]

    def run(self, query=None, hostset_id=None, displayname=None):
        ret = False
        result = {}
        if query:
            hx_api_object = self.get_task_api_object()
            if hx_api_object and hx_api_object.restIsSessionValid():
                (ret, response_code, response_data) = hx_api_object.restSubmitQuerySearch(
                    query, hostset_id, displayname=displayname)
                if ret:
                    result['enterprise_search_id'] = response_data['data']['_id']
                    self.parent_task.name = f"Hunt Search ID: {response_data['data']['_id']}"
                    self.logger.info(f"Hunt Search ID: {result['enterprise_search_id']} submitted.")
                else:
                    self.logger.error(
                        f"Hunt search submission failed. Code: {response_code}, data: {response_data}")
            else:
                self.logger.warning(f"No task API session for profile: {self.parent_task.profile_id}")
        return (ret, result)
