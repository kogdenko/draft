#!/usr/bin/python
# SPDX-License-Identifier: GPL-2.0
import os
import sys
import time
import argparse
import shutil
import psutil
import traceback
import selenium
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.action_chains import ActionChains
import selenium.webdriver.support.ui as ui
from selenium.webdriver.support import expected_conditions as EC

import mimetypes


g_verbose = 0
g_download_path = None
g_driver = None
g_downloaded = 0


def print_log(level, *args):
    if level >= g_verbose:
        print(*args)


class FirefoxDriver(webdriver.Firefox):
    def __init__(self, home):
        options = webdriver.firefox.options.Options()
        options.set_preference("browser.download.dir", g_download_path)

        self.profile_path = "%s/firefox" % home
        if not os.path.isdir(self.profile_path):
            os.mkdir(self.profile_path)
        #options.set_preference('profile', self.profile_path)

        savetodisk = ""
        for mimetype in mimetypes.mimetypes:
            if savetodisk:
                savetodisk += ";"
            savetodisk += mimetype

        options.set_preference("browser.download.folderList", 2)
        options.set_preference("browser.download.dir", g_download_path)
        options.set_preference("browser.download.useDownloadDir", True);
        options.set_preference("browser.download.viewableInternally.enabledTypes", "");
        options.set_preference("browser.helperApps.alwaysAsk.force", False)
        options.set_preference("browser.download.manager.showWhenStarting", False)
        options.set_preference("browser.helperApps.neverAsk.saveToDisk", savetodisk)

        profile = webdriver.FirefoxProfile(self.profile_path)
        options.profile = profile
        super().__init__(options=options)
        self.maximize_window()


class ChromeDriver(webdriver.Chrome):
    def __init__(self, home):
        options = webdriver.ChromeOptions()
        options.add_argument("user-data-dir=%s/google-chrome" % home)
        options.add_argument("--start-maximized")
        prefs = {"download.default_directory" : g_download_path }
        options.add_experimental_option("prefs", prefs)
        super().__init__(options=options)


def argparse_dir(s):                                                                           
    error = argparse.ArgumentTypeError("invalid directory '%s'" % s)
                           
    try:
        path = os.path.abspath(s)
        if os.path.isdir(path):
            return path
        else:
            raise error
    except:
        raise error


def wait_element(by, value, timeout):
    return ui.WebDriverWait(g_driver, timeout).until(lambda g_driver:
            g_driver.find_element(by=by, value=value))


def wait_elements(by, value, timeout):
    return ui.WebDriverWait(g_driver, timeout).until(lambda g_driver:
            g_driver.find_elements(by=by, value=value))


def wait_to_be_clickable(e, timeout):
     ui.WebDriverWait(g_driver, 3).until(EC.element_to_be_clickable(e))


def do_click(e):
    wait_to_be_clickable(e, 1000)
    while True:
        try:
            e.click()
            #print(e.location)
            #print(e.size)
            return
        except selenium.common.exceptions.ElementClickInterceptedException:
            print_log(0, "ElementClickInterceptedError")
            time.sleep(10)
            # TODO: Close popup
            #popup = g_driver.switch_to().active_element();
            #popup.close()


 
def list_view(timeout):
    try:
        # Вид
        toolbar = wait_element(By.CLASS_NAME,
                "ToolbarItem__dropdownIcon--2Z2TV", timeout)
    except selenium.common.exceptions.TimeoutException:
        return False

    do_click(toolbar)

    # Списком
    view = g_driver.find_element(by=By.CLASS_NAME, value="DropdownItemAction__text--3Xxmc")
    do_click(view)

    return True

 
def is_file(e):
    try:
        e.find_element(by=By.CLASS_NAME, value="DataListItemRow__date--JMvpW")
    except:
        return False
    return True


def do_ls():
    try:
        return wait_elements(By.CLASS_NAME, "DataListItemRow__root--39hIM", 2)
    except selenium.common.exceptions.TimeoutException:
        return []


def get_name(e):
    ne = e.find_element(by=By.CLASS_NAME, value="DataListItemRow__name--39Wrn")
    name = ne.text
    if len(name) > 0 and name[0] == '.':
        # Someone (google-chrome or js script) remove '.' at the begin of the file name
        name = name[1:]
    return name.replace('\n', '').replace('\r', '')
  

def center(e):
    g_driver.execute_script("arguments[0].scrollIntoView({'block':'center','inline':'center'})", e)
    wait_to_be_clickable(e, 3)


def download_file(e):
    shutil.rmtree(g_download_path, True)
    os.mkdir(g_download_path)

    d = e.find_element(by=By.CLASS_NAME, value="DataListItemRow__download--YSHnR")
    center(d)
    do_click(d)


def open_in_new_tab(e):
    center(e)
    actions = ActionChains(g_driver)
    actions.context_click(e).perform()
    o = wait_element(By.XPATH, "//div[@data-name='newTab']", 3)
    do_click(o)


def find_downloaded(name):
    entries =  os.listdir(g_download_path)
    for entry in entries:
        if entry.replace(' ', '') == name.replace(' ', ''):
            return entry, entries
    return None, entries


def process_element(dst, path, depth, e):
    center(e)
    download = depth >= len(path)
    name = get_name(e)
    #print("process", name)
    if is_file(e):
        if download:
            dst_file_path = dst + "/" + name
            if os.path.exists(dst_file_path):
                return

            print_log(1, "Downloading", name)
            download_file(e)
            tries = 0
            while True:
                entry, entries = find_downloaded(name)
                tries += 1
                if entry == None:
                    if tries == 1000:
                        if len(entries) == 0:
                            print_log(0, "Download seems not started, restarting...")
                            download_file(e)
                            tries = 0
                else:
                    src_file_path = g_download_path + "/" + entry
                    print_log(1, "Downloaded", name)
                    shutil.move(src_file_path, dst_file_path)
                    global g_downloaded
                    g_downloaded += 1
                    break
                time.sleep(0.01)
    else:
        if download:
            found = False
        else:
            if path[depth] == name:
                # Find folder in path, do not traverse siblings
                found = True
            else:
                return False
        open_in_new_tab(e)
        g_driver.switch_to.window(g_driver.window_handles[-1])
        traverse(dst + "/" + name, path, depth + 1)
        g_driver.close()
        g_driver.switch_to.window(g_driver.window_handles[-1]) 
        return found
    return False


def process_elements(dst, path, depth):
    name = None
    tries = 0
    while True:
        try:
            tries += 1
            elements = do_ls()
            n = len(elements)
            if n == 0:
                return
            if name == None:
                e = elements[0]
            else:
                e = None
                for i in range(n):
                    if elements[i].text == name:
                        if i == n - 1:
                            return
                        else:
                            e = elements[i + 1]
                            break
                assert(e != None)
            if process_element(dst, path, depth, e):
                return
            name = e.text
            tries = 0
        except selenium.common.exceptions.StaleElementReferenceException:
            print_log(0, "%s: StaleElementReferenceException" % dst)
            if tries > 10:
                raise RuntimeError("Traverse tries exceeded")
#        except selenium.common.exceptions.ElementClickInterceptedException:
#            # Advertisment on a way, try to close it
#            print_log(0, "Some element on the way, supposed advertisment. Please, close it")
#            time.sleep(10)

#        except:
#            print("Internal error")
#            print(traceback.format_exc())
#            if tries > 3:
#                sys.exit(1)
#            g_driver.refresh()
#            name = None

           
def traverse(dst, path, depth):
    if not os.path.exists(dst):
        os.mkdir(dst)
    print_log(1, "enter", dst)
    list_view(3)
    process_elements(dst, path, depth)
    print_log(1, "leave", dst)


def usage():
    print("mrcloudget.py [options] {-D path}")


def main():
    global g_driver
    global g_verbose
    global g_download_path

    ap = argparse.ArgumentParser()
    ap.add_argument("-v", action='store_true', help="Be verbose")
    ap.add_argument("-D", metavar="path", required=True, help="Destination directory")
    ap.add_argument("--driver", metavar="name",
            choices=["firefox", "chrome"], default="chrome",
            help="driver/browser to use")
    ap.add_argument("--path", metavar="path", type=argparse_dir,
            help="Source directory in cloud")

    args = ap.parse_args()

    destination_path = args.D
    if args.v:
        g_verbose += 1
    if args.path:
        cloud_path = args.path.split('/')
    else:
        cloud_path = []

    home = os.path.expanduser("~") + "/.mrcloudget"
    try:
        os.mkdir(home)
    except:
        pass

    g_download_path = "%s/downloads" % home
    returncode = 1

    try:
        if args.driver == "chrome":
            g_driver = ChromeDriver(home)
        elif args.driver == "firefox":
            g_driver = FirefoxDriver(home)
        else:
            assert(0)

        g_driver.get("http://cloud.mail.ru")

        rc = list_view(120)
        if rc:
            print_log(1, "Logined")
        else:
            print_log(0, "Login timeout expired")
            return 1

        traverse(destination_path, cloud_path, 0)
    except selenium.common.exceptions.NoSuchWindowException:
        print_log(0, "Window closed")
    except KeyboardInterrupt:
        print_log(0, "Interrupted")
    except:
        print_log(0, "Internal error")
        print_log(1, traceback.format_exc())
    else:
        print_log(0, "Done")
        returncode = 0
    finally:
        g_driver.quit()
        print_log(0, "Downloaded", g_downloaded, "files")
        return returncode


if __name__ == "__main__":
    sys.exit(main())
