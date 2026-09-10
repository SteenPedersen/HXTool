#!/usr/bin/env python

import threading
import logging
from multiprocessing import Queue, RLock


root_logger_name = "hxtool"

def setLoggerClass():
	logging.setLoggerClass(hxtool_logger)

def getLoggerName(name):
	return f"{root_logger_name}.{name}"

def getLogger(name = None):
	_name = root_logger_name
	if name is not None:
		_name = getLoggerName(name)
		
	return logging.getLogger(_name)
	
class hxtool_logger(logging.Logger):
	def __init__(self, name, level=logging.NOTSET):
		super().__init__(name, level=level)
		
	def callHandlers(self, record):
		with RLock():
			_thread = threading.Thread(target=super().callHandlers(record))
			_thread.start()
			_thread.join()
			
