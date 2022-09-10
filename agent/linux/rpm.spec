# Copyright 2022 Devoteam Revolve (D2SI SAS)
# This file is part of `Sovereign Keys`.
#
# `Sovereign Keys` is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# `Sovereign Keys` is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with `Sovereign Keys`. If not, see <http://www.gnu.org/licenses/>.

###############################################################################
# Spec file for Sovereign Keys
################################################################################
#
Summary: Sovereign Key agent managing the encryption of the data volumes
Name: sovereign-keys
Version: 1.1.0
Release: 1
License: GPL
URL: http://revolve.team
Group: System
Packager: Devoteam Revolve
Requires: bash
Requires: openssl
Requires: jq
BuildRoot: ~/rpmbuild/

# Build with the following syntax:
# rpmbuild --target noarch -bb rpm.spec

%description
Sovereign Key agent managing the encryption of the data volumes.

%prep
################################################################################
# Create the build tree and copy the files from the development directories    #
# into the build tree.                                                         #
################################################################################
echo "CODEBUILD_SRC_DIR = $CODEBUILD_SRC_DIR"
echo "BUILDROOT = $RPM_BUILD_ROOT"

mkdir -p $RPM_BUILD_ROOT
cp -r $CODEBUILD_SRC_DIR/agent/linux/sources/* $RPM_BUILD_ROOT/

exit

%files
%attr(0755, root, root) /usr/bin/*
%attr(0644, root, root) /usr/lib/sovereign-keys/*
%attr(0644, root, root) /etc/sovereign-keys/*

%pre

%post
# Executing sk-automount at boot
if ! grep -q '/bin/sk-automount' /etc/crontab ; then
  echo '@reboot root /bin/sk-automount' >> /etc/crontab
fi

%postun

%clean
rm -rf $RPM_BUILD_ROOT/usr/local/bin
rm -rf $RPM_BUILD_ROOT/usr/local/share/utils

%changelog
* Thu Mar 25 2021 Jérémie RODON <jeremie.rodon@revolve.team>
  - Initial release.
