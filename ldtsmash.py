#!/usr/bin/env python

__libname__ = 'ldtsmash'
__description__ = 'LEGO Desktop Toy Smash Archive Tool'
__version__ = '1.0.1'
__copyright__ = 'Copyright (c) 2019 JrMasterModelBuilder'
__license__ = 'Licensed under the Mozilla Public License, v. 2.0'

import os
import sys
import errno
import struct
import json
import argparse

def mkdirp(path):
	try:
		os.makedirs(path)
	except OSError as ex:
		if ex.errno == errno.EEXIST and os.path.isdir(path):
			pass
		else:
			raise ex

def openp(path, mode):
	base = os.path.dirname(path)
	if base:
		mkdirp(base)
	return open(path, mode)

def read_write_buffered(reader, writter, total, chunk):
	if chunk is None:
		writter.write(reader.read())
		return
	read = 0
	while read < total:
		size = total - read
		if size > chunk:
			size = chunk
		writter.write(reader.read(size))
		read += size

def class_str(instance):
	return class_repr(instance)

def class_repr(instance):
	return '<%s: %s>' % (instance.__class__, instance.__dict__)

class Error(Exception):
	pass

class TypeError(Error):
	pass

class FileReadError(Error):
	pass

class FileWriteError(Error):
	pass

class File():
	def __str__(self):
		return class_str(self)

	def __repr__(self):
		return class_repr(self)

	def __init__(self, fio, offset=None, size=None):
		# If offset no set, use current input offset.
		if offset is None:
			offset = fio.tell()

		# If a size is not set, base it on file seek end.
		if size is None:
			before = fio.tell()
			fio.seek(0, os.SEEK_END)
			size = fio.tell() - offset
			fio.seek(before, os.SEEK_SET)

		self.fio = fio
		self.offset = offset
		self.size = size
		self.__pos = 0

	def tell(self):
		return self.__pos

	def seek(self, offset, from_what=os.SEEK_SET):
		pos = None
		if from_what == os.SEEK_CUR:
			pos = self.__pos + offset
		elif from_what == os.SEEK_END:
			pos = self.__pos - offset
		elif from_what == os.SEEK_SET:
			pos = offset
		else:
			raise TypeError('Invalid seek from type: %s' % (from_what))

		if pos < 0 or pos > self.size:
			raise FileReadError('Cannot seek to: %s' % (pos))

		self.__pos = pos

	def can_read(self, size):
		return self.__pos + size <= self.size

	def read(self, size=None):
		pos = self.__pos
		fio = self.fio
		before = fio.tell()

		if size is None:
			size = self.size - pos

		if pos + size > self.size:
			raise FileReadError('Cannot read past end of file')

		fio.seek(self.offset + pos, os.SEEK_SET)
		try:
			ret = fio.read(size)
		finally:
			fio.seek(before, os.SEEK_SET)
		read_size = len(ret)

		if read_size != size:
			raise FileReadError('Read an unexpected size %s' % (read_size))

		self.__pos = pos + read_size
		return ret

	def write(self, data):
		pos = self.__pos
		fio = self.fio
		before = fio.tell()
		seekto = self.offset + pos

		if seekto > self.size:
			raise BLKFileWriteError('Cannot seek past end of file')

		fio.seek(seekto, os.SEEK_SET)
		try:
			fio.write(data)
		finally:
			fio.seek(before, os.SEEK_SET)

		self.__pos = pos + len(data)
		if self.__pos > self.size:
			self.size = self.__pos

	def can_read_struct(self, structure):
		return self.can_read(structure.size)

	def read_struct(self, structure):
		return structure.unpack_from(self.read(structure.size))

	def write_struct(self, structure, *args):
		self.write(structure.pack(*args))

	def sub(self, offset=None, size=None):
		if offset is None:
			offset = self.tell()
		if size is None:
			size = self.size - offset
		return self.__class__(self.fio, self.offset + offset, size)

class Entry():
	def __str__(self):
		return class_str(self)

	def __repr__(self):
		return class_repr(self)

	structure = struct.Struct(''.join([
		'<',   # little endian
		'16s', # name
		'I',   # offset
		'I'    # size
	]))
	size = structure.size
	size_name = 16
	size_offset = 4
	size_size = 4

	def __init__(self, name=None, offset=None, size=None):
		self.name = name
		self.offset = offset
		self.size = size

	def read_from(self, io):
		(name_enc, offset, size) = io.read_struct(self.structure)
		name = name_enc.split(b'\x00')[0].decode('ascii')
		self.name = name
		self.offset = offset
		self.size = size

	def write_to(self, io, name_buffer=None):
		name = self.name
		offset = self.offset
		size = self.size

		name_enc = name.encode('ascii')
		name_enc_len = len(name_enc)
		size_name = self.size_name
		if not (name_enc_len < size_name):
			raise FileWriteError(
				'File name longer than %s characters: %s' % (size_name - 1, name)
			)

		# Copy name bytes into name buffer, if provided.
		name_write = None
		if name_buffer:
			for i in range(name_enc_len):
				name_buffer[i] = name_enc[i]
			name_buffer[name_enc_len] = 0
			name_write = bytes(name_buffer)
		else:
			name_write = name_enc

		io.write_struct(self.structure, name_write, offset, size)

	def format_string(self):
		return '0x%08X 0x%08X %s' % (self.offset, self.size, self.name)

class Reader():
	Entry = Entry

	def __str__(self):
		return class_str(self)

	def __repr__(self):
		return class_repr(self)

	def __init__(self, file_idx, file_wad):
		self.file_idx = file_idx
		self.file_wad = file_wad

	def count(self):
		return self.file_idx.size // self.Entry.size

	def read(self):
		file_idx = self.file_idx
		file_wad = self.file_wad
		if file_idx.can_read(self.Entry.size):
			entry = self.Entry()
			entry.read_from(file_idx)
			io = None
			if file_wad:
				io = file_wad.sub(entry.offset, entry.size)
			return [entry, io]
		return None

	def reader(self):
		while True:
			read = self.read()
			if not read:
				return
			yield read

class Writter():
	Entry = Entry

	def __str__(self):
		return class_str(self)

	def __repr__(self):
		return class_repr(self)

	def __init__(self, file_idx, file_wad):
		self.file_idx = file_idx
		self.file_wad = file_wad

		# Name buffer, reusable to mirror the original encoder.
		self.name_buffer = bytearray(self.Entry.size_name)

	def write(self, entry, io, buffer_size=None, use_buffer=True):
		file_idx = self.file_idx
		file_wad = self.file_wad
		entry.offset = file_wad.tell()
		entry.size = io.size
		buf = None
		if use_buffer:
			buf = self.name_buffer
		entry.write_to(file_idx, buf)
		read_write_buffered(io, file_wad, io.size, buffer_size)

class FilelistReader():
	def __init__(self, fio):
		self.fio = fio

	def read(self):
		fio = self.fio
		while True:
			line = fio.readline()
			if not line:
				break
			s = line.strip()
			if s.startswith('"') and s.endswith('"'):
				return json.loads(s)
		return None

	def reader(self):
		while True:
			d = self.read()
			if d is None:
				break
			yield d

class FilelistWritter():
	def __init__(self, fio):
		self.fio = fio

	def write(self, filename):
		fio = self.fio
		fio.write(json.dumps(filename))
		fio.write('\n')

	def comment(self, lines):
		fio = self.fio
		for line in lines.split('\n'):
			fio.write('# ')
			fio.write(line)
			fio.write('\n')

class Process():
	filelist_name = '_ldtsmashlist.txt'
	filelist_comment = 'ldtsmash ordered list of file (JSON encoded strings)'
	buffer_size = 0x4000

	File = File
	Entry = Entry
	Reader = Reader
	Writter = Writter
	FilelistReader = FilelistReader
	FilelistWritter = FilelistWritter

	def __init__(self, options):
		self.options = options

	def realp(self, path):
		return path.replace('\\', '/')

	def filelist_open_r(self, directory):
		return open(os.path.join(directory, self.filelist_name), 'r')

	def filelist_open_w(self, directory):
		return openp(os.path.join(directory, self.filelist_name), 'w')

	def filelist_reader_next(self, fio):
		while True:
			line = fio.readline()
			if not line:
				break
			s = line.strip()
			if s.startswith('"') and s.endswith('"'):
				return json.loads(s)
		return None

	def filelist_reader_itter(self, fio):
		while True:
			d = self.filelist_reader_next(fio)
			if d is None:
				break
			yield d

	def entry_to_file(self, directory, entry, io):
		filepath = os.path.join(
			directory,
			self.realp(entry.name)
		)
		with openp(filepath, 'wb') as fio:
			read_write_buffered(io, fio, io.size, self.buffer_size)
			fio.close()

	def entry_from_file(self, directory, filename, writter):
		entry = self.Entry(filename)
		filepath = os.path.join(
			directory,
			self.realp(entry.name)
		)
		with open(filepath, 'rb') as fio:
			io = self.File(fio)
			writter.write(entry, io, self.buffer_size)
			fio.close()
		return entry

	def run_l(self):
		ndx = self.options.ndx
		with open(ndx, 'rb') as fio_nxd:
			reader = self.Reader(self.File(fio_nxd), None)

			for [entry, _] in reader.reader():
				print(entry.format_string())

			fio_nxd.close()
		return 0

	def run_e(self):
		ndx = self.options.ndx
		wad = self.options.wad
		directory = self.options.dir
		mkdirp(directory)

		with self.filelist_open_w(directory) as fl:
			fl_writter = self.FilelistWritter(fl)
			fl_writter.comment(self.filelist_comment)

			with open(ndx, 'rb') as fio_nxd:
				with open(wad, 'rb') as fio_wad:
					reader = self.Reader(self.File(fio_nxd), self.File(fio_wad))

					for [entry, io] in reader.reader():
						print(entry.format_string())
						fl_writter.write(entry.name)
						self.entry_to_file(directory, entry, io)
					fio_wad.close()
				fio_nxd.close()
			fl.close()
		return 0

	def run_c(self):
		ndx = self.options.ndx
		wad = self.options.wad
		directory = self.options.dir

		with self.filelist_open_r(directory) as fl:
			fl_reader = self.FilelistReader(fl)

			with openp(ndx, 'wb') as fio_nxd:
				with openp(wad, 'wb') as fio_wad:
					writter = self.Writter(self.File(fio_nxd), self.File(fio_wad))

					for fn in fl_reader.reader():
						entry = self.entry_from_file(directory, fn, writter)
						print(entry.format_string())
					fio_wad.close()
				fio_nxd.close()
			fl.close()
		return 0

	def run(self):
		c = self.options.command
		return getattr(self, 'run_%s' % (c))()

def main():
	parser = argparse.ArgumentParser(
		description=os.linesep.join([
			'%s - %s' % (__libname__, __description__),
			'Version: %s' % (__version__)
		]),
		epilog=os.linesep.join([
			__copyright__,
			__license__
		]),
		formatter_class=argparse.RawTextHelpFormatter
	)
	parser.add_argument(
		'-v', '--version',
		action='version',
		version=__version__
	)
	subparsers = parser.add_subparsers(help='command', dest='command')

	parser_l = subparsers.add_parser('l', help='list')
	parser_l.add_argument('ndx', help='in nxd file')

	parser_e = subparsers.add_parser('e', help='extract')
	parser_e.add_argument('ndx', help='in nxd file')
	parser_e.add_argument('wad', help='in wad file')
	parser_e.add_argument('dir', help='out directory')

	parser_c = subparsers.add_parser('c', help='compile')
	parser_c.add_argument('dir', help='in directory')
	parser_c.add_argument('ndx', help='out nxd file')
	parser_c.add_argument('wad', help='out wad file')

	return Process(parser.parse_args()).run()

if __name__ == '__main__':
	sys.exit(main())
