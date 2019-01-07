#!/usr/bin/python


from ds_store import DSStore

with DSStore.open('DS_Store', 'r+') as d:
	print '\n'.join(map(str, list(d)))