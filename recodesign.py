#!/usr/bin/env python
# coding=utf-8

""" inject.py: Injection to an iOS app or re-codesign it.

Created by gogleyin on 26/12/2016.
"""

import os
import time
import logging
import shutil
from tempfile import mkdtemp
import pkg_resources
import zipfile
import json
import stat
from contextlib import contextmanager
from subprocess import Popen, PIPE, check_call, CalledProcessError

logger = logging.getLogger(__name__ if __name__ != '__main__' else os.path.splitext(os.path.basename(__file__))[0])
logger.setLevel(logging.DEBUG)

INJECTOR_PATH = 'insert_dylib'


@contextmanager
def pushd(new_dir):
    """ Temporarily changing working directory. See a usage in 'app2ipa'. """
    origin_dir = os.getcwd()
    os.chdir(new_dir)
    try:
        yield
    finally:
        os.chdir(origin_dir)


def app2ipa(app_path, ipa_path):
    if os.path.isfile(ipa_path):
        os.remove(ipa_path)
    with TempDir() as temp_dir:
        temp_payload_dir = os.path.join(temp_dir, 'Payload')
        if os.path.isdir(temp_payload_dir):
            shutil.rmtree(temp_payload_dir)
        os.mkdir(temp_payload_dir)
        new_app_path = os.path.join(temp_payload_dir, os.path.basename(app_path))
        logger.debug('Copying app files...')
        shutil.copytree(app_path, new_app_path)
        logger.debug('Zipping app files...')
        with pushd(temp_dir):
            cmd = 'zip -qyr {ipa} Payload'.format(ipa=ipa_path)
            return os.system(cmd) == 0


class PackageType(object):
    ipa = 'ipa'
    app = 'app'
    dylib = 'dylib'
    framework = 'framework'

    @staticmethod
    def get_type(file_path):
        if file_path.endswith('.ipa'):
            return PackageType.ipa
        elif file_path.endswith('.app'):
            return PackageType.app
        elif file_path.endswith('.framework'):
            return PackageType.framework
        elif file_path.endswith('.dylib'):
            return PackageType.dylib


def safe_check_call(cmd, shell=True):
    try:
        logger.debug('$ %s' % cmd)
        check_call(cmd, shell=shell)
        return True
    except CalledProcessError, e:
        logger.error('Failed: %s' % e.output)
        return False


def get_app_executable_path(app_path):
    """ Support .app .framework """
    return os.path.join(app_path, get_app_properties(app_path)['CFBundleExecutable'])


class TempDir(object):
    def __init__(self):
        self._path = mkdtemp()

    def __enter__(self):
        return self._path

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.remove()

    def remove(self):
        if not self._path or not os.path.exists(self._path):
            return
        shutil.rmtree(self._path)


def extract_app_from_ipa(ipa_file_path, to_dir):
    logger.debug('Extracting IPA to APP...')
    unzip(ipa_file_path, to_dir)
    payload_dir = os.path.join(os.path.join(to_dir, 'Payload'))
    for f in os.listdir(payload_dir):
        if not f.endswith('.app'):
            continue
        app_file_name = f
        break
    else:
        raise RuntimeError('Could not find app file under Payload folder: {payload}'.format(payload=payload_dir))

    from_path = os.path.join(payload_dir, app_file_name)
    output_path = os.path.join(to_dir, app_file_name)
    if os.path.isdir(output_path):
        shutil.rmtree(output_path)
    shutil.move(from_path, output_path)
    shutil.rmtree(payload_dir)
    logger.debug('Done.')

    # In some cases, the CFBundleExecutable file of newly-generated app file may not be executable
    executable_file_name = get_app_properties(output_path)['CFBundleExecutable']
    executable_file = os.path.join(output_path, executable_file_name)
    make_file_executable(executable_file)

    return output_path


def make_file_executable(file_path):
    if not os.path.isfile(file_path):
        return
    st = os.stat(file_path)
    os.chmod(file_path, st.st_mode | stat.S_IEXEC)


def get_app_properties(app_path):
    """ Support: .app .framework
    Return Property Dict (with keys like: CFBundleIdentifier, CFBundleName, CFBundleExecutable
    """
    info_plist_path = os.path.join(app_path, 'Info.plist')
    if not os.path.isfile(info_plist_path):
        logger.warning('Info.plist not exist: %s' % (app_path,))
        return
    return parse_plist(info_plist_path)


def parse_plist(filename):
    """ Pipe the binary plist through plutil and parse the JSON output
    plutil is part of libimobiledevice.
    plistlib.readPlist(filepath) from python 2.6 cannot parse binary plist
    """
    with open(filename, "rb") as f:
        content = f.read()
    args = ["plutil", "-convert", "json", "-o", "-", "--", "-"]
    p = Popen(args, stdin=PIPE, stdout=PIPE)
    p.stdin.write(content)
    out, err = p.communicate()
    try:
        return json.loads(out)
    except Exception, e:
        logger.debug('Plutil convert plist to json failed: [out] %s; [err] %s' % (out, err))
        raise e

def unzip(zipfile_path, to_dir):
    # logger.debug('zipfile_path: %s' % zipfile_path)
    try:
        zip_file = zipfile.ZipFile(zipfile_path)
        for file_name in zip_file.namelist():
            zip_file.extract(file_name, path=to_dir)
        zip_file.close()
    except zipfile.BadZipfile as e:
        logger.error('[from built-in zipfile module] %s' % e.message)
        unzip_via_mac_tool(zipfile_path, to_dir)


def unzip_via_mac_tool(filepath, to_dir):
    """ Using Archive Utility to unzip a zip file """
    # Using Archive Utility to open a ZIP file
    begin_time = time.time()
    time.sleep(1)
    cmd = 'open -a "Archive Utility" %s' % (filepath,)
    logger.debug('executing: %s' % cmd)
    os.system(cmd)
    # Wait for the spawned process (Archive Utility) to finish
    # Sadly we don't know when it will end
    time.sleep(8)
    # Using Archive Utility to open a ZIP file
    # will unzip the file into the same folder.
    # We will find the output by files creating time.
    directory = os.path.dirname(filepath)
    filepaths = [os.path.join(directory, fn) for fn in os.listdir(directory) if not fn.startswith('.')]
    filepaths = [fp for fp in filepaths if os.stat(fp).st_ctime > begin_time]
    # filepaths.sort(key=lambda x: os.stat(x).st_ctime, reverse=True)
    if len(filepaths) != 1:
        raise RuntimeError('Unzip via mac tool (Archive Utility) failed!')
    dest = os.path.join(to_dir, os.path.basename(filepaths[0]))
    os.rename(filepaths[0], dest)


def _inject(bundle_path, dylib_path, injector_path=INJECTOR_PATH, inject_subpath=None):
    """ Inject a dylib into a bundle, or bundle's bundle (e.g. MyApp/Frameworks/AFNetwork.framework
    Cautious: This method will modify app's content.
    :param bundle_path: the origin bundle
    :param dylib_path: filepath of dylib
    :param injector_path: filepath of injector
    :param inject_subpath: Component of the bundle to be injected. If set to None, we will inject bundle itself
    :return: Bool indicating injection success or not
    """
    injectee = os.path.join(bundle_path, inject_subpath) if inject_subpath else bundle_path
    if inject_subpath:
        logger.debug('Injecting bundle\'s component: %s %s' % (bundle_path, inject_subpath))
    else:
        logger.debug('Injecting bundle: %s' % (bundle_path,))
    if not os.path.isfile(dylib_path):
        logger.error('Dylib not exist: %s' % dylib_path)
        return False
    if not os.path.isdir(injectee):
        logger.error('Bundle to inject not exist: %s' % injectee)
        return False
    if not os.path.isfile(injector_path):
        logger.error('Injector not exist: %s' % injector_path)
        return False
    # 获取app的路径
    executable_path = get_app_executable_path(injectee)

    # shutil.copy(dylib_path, app_path)
    # fixed_dylib_path = '@executable_path/%s' % (os.path.basename(dylib_path))
    # 把dylib文件copy进app路径
    frameworks_path = os.path.join(injectee, 'Frameworks')
    if not os.path.isdir(frameworks_path):
        os.mkdir(frameworks_path)
    shutil.copy(dylib_path, frameworks_path)
    if not inject_subpath:
        fixed_dylib_path = '@executable_path/Frameworks/%s' % (os.path.basename(dylib_path))
    else:
        fixed_dylib_path = os.path.join('@executable_path', inject_subpath, 'Frameworks/%s' % os.path.basename(dylib_path))

    # if creat_flag:
    #     fixed_dylib_path = '@executable_path/Frameworks/%s' % (os.path.basename(dylib_path))
    # else:
    #     fixed_dylib_path = '@rpath/%s' % (os.path.basename(dylib_path))

    logger.debug('Fixed dylib path: %s' % fixed_dylib_path)
    inject_cmd = '%s %s %s %s' % (injector_path, fixed_dylib_path, executable_path, executable_path)
    # 子线程调用call()方法,底层是调用popen方法
    if not safe_check_call(inject_cmd):
        return False
    logger.debug('Done.')
    return True


def _inject_framework(bundle_path, framework_to_inject, injector_path=INJECTOR_PATH, inject_subpath=None):
    """ Inject a framework into a bundle, or bundle's bundle (e.g. MyApp/Frameworks/AFNetwork.framework)
    Cautious: This method will modify app's content.
    :param bundle_path: the origin bundle to be injected
    :param framework_to_inject: path of the framework to be injected into the bundle
    :param injector_path: filepath of injector
    :param inject_subpath: Component of the bundle to be injected. If set to None, we will inject bundle itself
    :return: Bool indicating injection success or not
    """
    injectee = os.path.join(bundle_path, inject_subpath) if inject_subpath else bundle_path
    if inject_subpath:
        logger.debug('Injecting bundle\'s component: %s %s' % (bundle_path, inject_subpath))
    else:
        logger.debug('Injecting bundle: %s' % (bundle_path,))

    exec_path_for_inject = get_app_executable_path(framework_to_inject)

    if not os.path.isfile(exec_path_for_inject):
        logger.error('Executable for injection not exist: %s' % exec_path_for_inject)
        return False
    if not os.path.isdir(injectee):
        logger.error('Bundle to inject not exist: %s' % injectee)
        return False
    if not os.path.isfile(injector_path):
        logger.error('Injector not exist: %s' % injector_path)
        return False
    executable_path = get_app_executable_path(injectee)

    host_frameworks_path = os.path.join(injectee, 'Frameworks')
    if not os.path.isdir(host_frameworks_path):
        os.mkdir(host_frameworks_path)
    framework_name = os.path.basename(framework_to_inject)
    dest = os.path.join(host_frameworks_path, framework_name)
    if os.path.exists(dest):
        logger.warning('Framework for injection already exist, will overwrite.')
        shutil.rmtree(dest)
    shutil.copytree(framework_to_inject, dest)

    if not inject_subpath:
        fixed_dylib_path = '@executable_path/Frameworks/%s/%s' % (framework_name, os.path.basename(exec_path_for_inject))
    else:
        fixed_dylib_path = os.path.join('@executable_path', inject_subpath, 'Frameworks/%s' % os.path.basename(exec_path_for_inject))

    logger.debug('Fixed dylib path: %s' % fixed_dylib_path)
    inject_cmd = '%s %s %s %s' % (injector_path, fixed_dylib_path, executable_path, executable_path)
    if not safe_check_call(inject_cmd):
        return False
    logger.debug('Done.')
    return True


def _re_codesign_framework(framework_path, signing_identity):
    if not os.path.exists(framework_path):
        return
    sub_framework_dir = os.path.join(framework_path, 'Frameworks')
    if os.path.exists(sub_framework_dir):
        for sub_framework in os.listdir(sub_framework_dir):
            if not sub_framework.endswith('.framework'):
                continue
            sub_framework_path = os.path.join(sub_framework_dir, sub_framework)
            _re_codesign_framework(sub_framework_path, signing_identity)
    _cmd = '/usr/bin/codesign -f -s "%s" %s' % (signing_identity, framework_path)
    if not safe_check_call(_cmd):
        return False


def _re_codesign(app_path, signing_identity, provision_path=None):
    """ This method will modify app's content.
    Now support all kinds of bundle (app, framework, dylib) except IPA
    """
    bundle_type = PackageType.get_type(app_path)
    logger.debug('Re-codesigning %s...' % (bundle_type,))
    if bundle_type == PackageType.framework or bundle_type == PackageType.dylib:
        _cmd = '/usr/bin/codesign -f -s "%s" %s' % (signing_identity, app_path)
        if not safe_check_call(_cmd):
            return False
        return True

    code_signature_folder = os.path.join(app_path, '_CodeSignature')
    if os.path.isdir(code_signature_folder):
        shutil.rmtree(code_signature_folder)
    code_signature_file = os.path.join(app_path, 'CodeResources')
    if os.path.isfile(code_signature_file):
        os.remove(code_signature_file)

    app_provision_path = os.path.join(app_path, 'embedded.mobileprovision')
    if provision_path:
        shutil.copy(provision_path, app_provision_path)

    entitlement_plist_path = os.path.join('/tmp', 'entitlements%s.plist' % int(time.time()))
    if os.path.isfile(entitlement_plist_path):
        os.remove(entitlement_plist_path)
    _cmd = '/usr/libexec/PlistBuddy -x -c "print :Entitlements " /dev/stdin <<< ' \
           '$(security cms -D -i %s) > %s' % (app_provision_path, entitlement_plist_path)
    if not safe_check_call(_cmd):
        return False
    _cmd = "/usr/libexec/PlistBuddy -c 'Set :get-task-allow true' %s" % entitlement_plist_path
    if not safe_check_call(_cmd):
        return False

    frameworks_path = os.path.join(app_path, 'Frameworks')
    if os.path.isdir(frameworks_path):
        # _cmd = '/usr/bin/codesign -f -s "%s" %s/*' % (signing_identity, frameworks_path)
        # if not safe_check_call(_cmd):
        #     return False
        for framework in os.listdir(frameworks_path):
            framework_path = os.path.join(frameworks_path, framework)
            _re_codesign_framework(framework_path, signing_identity)

    rule_file = os.path.join(app_path, 'ResourceRules.plist')
    if os.path.isfile(rule_file):
        _cmd = '/usr/bin/codesign -f -s "%s" ' \
               '--resource-rules %s ' \
               '--entitlements %s %s' % (signing_identity, rule_file, entitlement_plist_path, app_path)
    else:
        _cmd = '/usr/bin/codesign -f -s "%s" ' \
               '--no-strict --entitlements %s %s' % (signing_identity, entitlement_plist_path, app_path)
    if not safe_check_call(_cmd):
        return False
    if os.path.isfile(entitlement_plist_path):
        os.remove(entitlement_plist_path)
    logger.debug('Done.')
    return True


def inject(app_or_ipa, dylib_or_framework, output_path, injector_path=INJECTOR_PATH, inject_subpath=None):
    file_name = os.path.basename(app_or_ipa)
    # file_name_without_extension = os.path.splitext(file_name)[0]
    # output_file_name = file_name.replace(file_name_without_extension, file_name_without_extension + '_injected')
    # output_path = os.path.join(to_dir, output_file_name)
    package_type = PackageType.get_type(app_or_ipa)
    if not package_type:
        logger.error('Unknown filetype to inject: %s' % app_or_ipa)
        return
    if os.path.isdir(output_path):
        shutil.rmtree(output_path)
    if os.path.isfile(output_path):
        os.remove(output_path)
    with TempDir() as temp_dir:
        if package_type == PackageType.app:
            new_app_path = os.path.join(temp_dir, file_name)
            shutil.copytree(app_or_ipa, new_app_path)
        else:
            new_app_path = extract_app_from_ipa(app_or_ipa, temp_dir)

        #如果是dylib则调用_inject方法,如果是framework,则调用_inject_framework方法
        inject_method = _inject if PackageType.get_type(dylib_or_framework) == PackageType.dylib else _inject_framework
        if not inject_method(new_app_path, dylib_or_framework, injector_path, inject_subpath=inject_subpath):
            logger.error('Injection failed.')
            return

        if output_path.endswith('.ipa'):
            if not app2ipa(new_app_path, output_path):
                return False
        else:
            shutil.move(new_app_path, output_path)
        return True


def re_codesign(app_or_ipa, signing_identity, output_path, provision_path=None):
    """
    Re-codesign APP (or IPA with output_ipa=True) file.
    :param app_or_ipa: filepath of app or ipa
    :param provision_path: filepath of mobile provisioning profile
    :param signing_identity: code signing identity (e.g. iPhone Developer: XXX (XXXXX) )
    :param to_dir: output directory
    :param output_ipa: Will return IPA rather than APP if set to True
    :return: output file path
    """
    file_name = os.path.basename(app_or_ipa)
    # file_name_without_extension = os.path.splitext(file_name)[0]
    # output_file_name = file_name.replace(file_name_without_extension, file_name_without_extension + '_resigned')
    # output_path = os.path.join(to_dir, output_file_name)
    package_type = PackageType.get_type(app_or_ipa)
    if not package_type:
        logger.error('Unknown filetype to re-codesign: %s' % app_or_ipa)
        return
    with TempDir() as temp_dir:
        if package_type == PackageType.app:
            new_app_path = os.path.join(temp_dir, file_name)
            shutil.copytree(app_or_ipa, new_app_path)
        elif package_type == PackageType.ipa:
            new_app_path = extract_app_from_ipa(app_or_ipa, temp_dir)
        elif package_type == PackageType.dylib or package_type == PackageType.framework:
            shutil.copy(app_or_ipa, output_path)
            new_app_path = output_path

        if not _re_codesign(new_app_path, signing_identity, provision_path=provision_path):
            logger.error('Re-codesigning failed.')
            return

        if output_path.endswith('.ipa'):
            if not app2ipa(new_app_path, output_path):
                return False
        else:
            shutil.move(new_app_path, output_path)
        return True


def inject_and_recodesign(app_or_ipa, dylib_or_framework, output_path, provision_path=None, signing_identity=None,
                          injector_path=INJECTOR_PATH, inject_subpath=None):
    file_name = os.path.basename(app_or_ipa)
    package_type = PackageType.get_type(app_or_ipa)
    if not package_type:
        logger.error('Unknown filetype to process: %s' % app_or_ipa)
        return
    if os.path.exists(output_path):
        shutil.rmtree(output_path) if os.path.isdir(output_path) else os.remove(output_path)
    with TempDir() as temp_dir:
        if package_type == PackageType.app or package_type == PackageType.framework:
            new_app_path = os.path.join(temp_dir, file_name)
            shutil.copytree(app_or_ipa, new_app_path)
        else:
            # 如果是ipa,解压获取app
            new_app_path = extract_app_from_ipa(app_or_ipa, temp_dir)

        inject_method = _inject if PackageType.get_type(dylib_or_framework) == PackageType.dylib else _inject_framework
        if not inject_method(new_app_path, dylib_or_framework, injector_path, inject_subpath=inject_subpath):
            logger.error('Injection failed.')
            return

        if provision_path and signing_identity:
            if not _re_codesign(new_app_path, signing_identity, provision_path=provision_path):
                logger.error('Re-codesigning failed.')
                return

        if output_path.endswith('.ipa'):
            if not app2ipa(new_app_path, output_path):
                return False
        else:
            shutil.move(new_app_path, output_path)
        return True


def recodesign_framework_recursively(framework_path, signing_identity, output_file_path=None):
    input_path = framework_path
    if output_file_path:
        shutil.copy(framework_path, output_file_path)
        input_path = output_file_path

    frameworks_dir = os.path.join(input_path, 'Frameworks')
    if os.path.isdir(frameworks_dir):
        for framework in os.listdir(frameworks_dir):
            if not framework.endswith('.framework'):
                continue
            if not recodesign_framework_recursively(os.path.join(frameworks_dir, framework), signing_identity):
                return False

    _cmd = '/usr/bin/codesign -f -s "%s" %s' % (signing_identity, input_path)
    if not safe_check_call(_cmd):
        return False
    return True


def set_start_arguments():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--app', dest='app', required=True, help='filepath of .app or .ipa')
    parser.add_argument('-d', '--dylib', dest='dylib', required=False, help='filepath of dylib')
    parser.add_argument('-o', '--output', dest='output', required=True, help='filepath of output')
    parser.add_argument('-p', '--provision', dest='provision', required=False,
                        help='filepath of mobile provisioning profile')
    parser.add_argument('-c', '--code_sign', dest='code_sign', required=False,
                        help='code signing identity')
    args = parser.parse_args()
    if not args.dylib:
        if not args.code_sign:
            raise RuntimeError('CODE_SIGNING_IDENTITY is required!')
        if not args.provision:
            raise RuntimeError('PROVISIONING_PROFILE is required!')
        re_codesign(args.app, args.code_sign, args.output, provision_path=args.provision)
    else:
        inject_and_recodesign(args.app, args.dylib, args.output, provision_path=args.provision,
                              signing_identity=args.code_sign)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    set_start_arguments()

