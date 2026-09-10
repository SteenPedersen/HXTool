#!/usr/bin/env python

class hxtool_db:
	def __init__(self):
		pass

	@property
	def database_engine(self):
		raise NotImplementedError("You must override this in your database class.")