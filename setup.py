"""
This is a setup.py script generated by py2applet

Usage:
    python setup.py py2app
"""

from setuptools import setup

APP = ['url-open-handler.py']
DATA_FILES = []
OPTIONS = {
    'argv_emulation': False,
    'plist' : {
        'CFBundleDevelopmentRegion' : 'en',
        'NSPrincipalClass' : 'NSApplication',
        'NSAppleScriptEnabled' : 'YES',
        'LSUIElement' : 'YES',
        'CFBundleIdentifier' : 'org.merly.custom_url_handler',
        'CFBundleURLTypes' : [
            {
                'CFBundleURLName' : 'http URL',
                'CFBundleURLSchemes' : [
                    'http',
                ]
            },
            {
                'CFBundleURLName' : 'Secure http URL',
                'CFBundleURLSchemes' : [
                    'https',
                ]
            },
        ]
    }
}

setup(
    app=APP,
    data_files=DATA_FILES,
    options={'py2app': OPTIONS},
    setup_requires=['py2app'],
)
