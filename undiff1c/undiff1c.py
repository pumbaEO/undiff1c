#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import logging
import os
import platform
import re
import subprocess
import shutil
import sys
import tempfile
from unidiff import PatchSet
import codecs

__version__ = '1.0.1'

logging.basicConfig(level=logging.ERROR)  # DEBUG => print ALL msgs
log = logging.getLogger('undiff1c')

modified = re.compile('^(?:M|A)(\s+)(?P<name>.*)')


def get_config_param(param):
    """
    Parse config file and find source dir in it
    """
    curdir = os.curdir
    if '__file__' in globals():
        curdir = os.path.dirname(os.path.abspath(__file__))

    config = None
    for loc in curdir, os.curdir, os.path.expanduser('~'):
        try:
            with open(os.path.join(loc, 'precommit1c.ini')) as source:
                if sys.version_info < (3, 0, 0):
                    from ConfigParser import ConfigParser  # @NoMove @UnusedImport
                else:
                    from configparser import ConfigParser

                config = ConfigParser()
                config.read_file(source)
                break
        except IOError:
            pass

    if config is not None and config.has_option('default', param):
        value = config.get('default', param)
        return value

    return None

def get_list_of_comitted_files():
    """
    Return the list of files to be decompiled
    """
    files = []
    output = []
    try:
        output = subprocess.check_output(['git', 'diff-index', '--name-status', '--cached', 'HEAD']).decode('utf-8')
    except subprocess.CalledProcessError:
        try:
            output = subprocess.check_output(['git', 'status', '--porcelain']).decode('utf-8')
        except subprocess.CalledProcessError:
            print('Error diff files get')
            return files

    for result in output.split('\n'):
        log.info(result)
        if result != '':
            match = modified.match(result.strip())
            if match:
                files.append(match.group('name'))

    return files

def get_diff_forfile(file):
    tmppath = tempfile.mktemp()
    command = ['git', 'diff', 'HEAD', file]
    log.debug("{}".format(command))
    try:
        output = subprocess.check_output(command).decode('utf-8')
    except subprocess.CalledProcessError:
        logging.error('Error diff files {}'.format(file))
        return None
    lines = output.split('\r\n') # [x.replace("\n", "") for x in output.split('\r\n')]
    with open(tmppath, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
    log.debug("{}".format(tmppath))
    return tmppath

def save_text(file, text):
    with codecs.open(file, 'wb', encoding='utf-8') as w:
        w.write(text)

def read_file(file):
    result = ''
    with codecs.open(file, 'rb', encoding='utf-8') as r:
        result = r.read()
    return result

def git_add_files(pathlists):
    for l in pathlists:
        result = subprocess.check_call(['git', 'add', '--all', l])
        if not result == 0:
            log.error(result)
            exit(result)


def replace_old_form_attr(filelists):

    flags = re.MULTILINE|re.IGNORECASE
    attributes = []
    attributes.append(
        (re.compile('(\s?<SearchControlAddition name="[А-я]*)SearchControl(")', flags), r'\1УправлениеПоиском\2'))
    attributes.append(
        (re.compile('(\s?<ContextMenu name="[А-я]*)ViewStatusContextMenu(")', flags), r'\1СостояниеПросмотраКонтекстноеМеню\2'))
    attributes.append(
        (re.compile('(\s?<ExtendedTooltip name="[А-я]*)ViewStatusExtendedTooltip(")', flags), r'\1СостояниеПросмотраРасширеннаяПодсказка\2'))
    attributes.append(
        (re.compile('(\s?<SearchStringAddition name="[А-я]*)SearchString(")', flags), r'\1СтрокаПоиска\2'))
    attributes.append(
        (re.compile('(\s?<ViewStatusAddition name="[А-я]*)ViewStatus(")', flags), r'\1СостояниеПросмотра\2'))
    
    changedfiles = []
    for file in filelists:
        filename = os.path.basename(file)
        if not file.lower() == "form.xml":
            continue
        replacecount = 0
        lines = read_file(file)
        for reg in attributes:
            result = re.subn(reg[0], reg[1], lines)
            lines, replacecount = result[0], replacecount+result[1]
            replacecount = replacecount+result[1]
        if replacecount > 0:
            save_text(file, lines)
            changedfiles.append(file)
            log.info("changed {}".format(file))
            
    git_add_files(changedfiles)

    
def git_reset_file(file, sha):
    output = subprocess.check_output(['git', 'reset', sha, file]).decode('utf-8')
    output = subprocess.check_output(['git', 'checkout', file]).decode('utf-8')

def main():
    parser = argparse.ArgumentParser(description='Утилита для проверки ошибочно изменных файлов в индексе')
    parser.add_argument('--version', action='version', version='%(prog)s {}'.format(__version__))
    parser.add_argument('-v', '--verbose', dest='verbose_count', action='count', default=0,
                        help='Increases log verbosity for each occurence.')
    parser.add_argument('--g', action='store_true', default=False,
                        help='Запустить чтение индекса из git и определить список файлов для разбора')
    
    args = parser.parse_args()

    log.setLevel(max(3 - args.verbose_count, 0) * 10)
    
    taglistchange = ('<d3p1:id>', '<d3p1:fullIntervalBegin>',
                     '<d3p1:fullIntervalEnd>', '<d3p1:visualBegin>',
                     '<xr:TypeId>',
                     '<xr:ValueId>',
                     '<d4p1:id>'
                     )
    typefiles = ('template.xml', 
                 'form.xml'
                )

    if args.g is True:
        files = get_list_of_comitted_files()
        for file in files:
            filename = os.path.basename(file)
            if not (filename.lower() in typefiles or filename[-3:]=="xml"):
                log.debug("пропускаем файл {} расширение {}".format(file, filename[-3:]))
                continue
                
            data = get_diff_forfile(file)
            if data is None:
                log.error("diff file not exists {}".format(file))
                continue
            pathc = PatchSet.from_filename(data, encoding='utf-8')
            for f in pathc.modified_files:
                log.debug('file is {}'.format(f))
                modifiedsource, modifiedtarget = [],[]
                for hunk in f:
                    modifiedsource = modifiedsource + list(filter(lambda x: not x[:1] == " ", hunk.source))
                    modifiedtarget = modifiedtarget + list(filter(lambda x: not x[:1] == " ", hunk.target))
                
                
                sourcetags = list(filter(lambda x: x[1:].strip().startswith(taglistchange), modifiedsource))
                targettags = list(filter(lambda x: x[1:].strip().startswith(taglistchange), modifiedtarget))
                log.debug("sourcetags:{} targettags:{}".format(sourcetags, targettags))
                
                if not (len(sourcetags) == len(modifiedsource) and \
                    len(targettags) == len(modifiedtarget) and \
                    len(sourcetags) == len(targettags)):
                    continue
            
                #Теперь надо будет отменить изменения в индексе для файла. 
                log.info("удалем из индекса файл {}".format(file))
                git_reset_file(file, 'HEAD')
                break
        replace_old_form_attr(files)

if __name__ == '__main__':
    sys.exit(main())


