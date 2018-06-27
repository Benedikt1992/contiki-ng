#!/usr/bin/env python

import os
import shutil
import distutils.cmd
import distutils.log

from setuptools import setup, find_packages

with open(os.path.join('base_station', 'VERSION')) as version_file:
    version = version_file.read().strip()


class CleanAllCommand(distutils.cmd.Command):
    """A custom command to clean the project directory."""

    description = 'remove build artifacts from build, *dist, etc'
    user_options = [
        # The format is (long option, short option, description).
        ('includeDistributions', 'd', 'removes distributions inside the `dist` folder as well'),
    ]
    boolean_options = ['includeDistributions']

    def initialize_options(self):
        """Set default values for options."""
        self.includeDistributions = None


    def finalize_options(self):
        """ check provided args """
        pass


    def run(self):
        for directory in ('build', 'base_station.egg-info', 'base_station.dist-info'):
            if os.path.exists(directory):
                shutil.rmtree(directory)
        
        if self.includeDistributions and os.path.exists('dist'):
            shutil.rmtree('dist')


# end class CleanAllCommand

setup(
    name='Base Station',
    version=version,
    description='Base Station for revoking nodes.',
    author='Benedikt Bock, Jan-Tobias Matysik',
    author_email='benedikt.bock@student.hpi.de, Jan-Tobias.Matysik@student.hpi.de',
    url='https://github.com/Benedikt1992/contiki-ng/tree/akes_revocation_linklayer/examples/akes/revocation_base_station',
    license='MIT',

    # own commands
    cmdclass={
        'cleanAll': CleanAllCommand,
    },

    # dependencies
    install_requires=[
    ],

    # packages
    packages=['base_station'],
    package_dir={'base_station': './base_station'},

    # executable scripts
    entry_points={
        'console_scripts': [
            'base_station=base_station'
        ],
    },
)
